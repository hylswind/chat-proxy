#!/bin/bash
set -euxo pipefail

# Trap errors and exit immediately
function on_error {
    exit 1
}
trap on_error ERR

# ----------------------------------------------------
# Configuration
# ----------------------------------------------------
RAMDISK_FOLDER="$1"
VENV_PATH="$(dirname "$0")/venv"
PYTHON_BIN="$VENV_PATH/bin/python"
PIP_BIN="$VENV_PATH/bin/pip"
SERVICE_NAME="agent-api"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
AGENT_PATH="$(realpath "$(dirname "$0")")"

# ----------------------------------------------------
# EC2 metadata
# ----------------------------------------------------
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s "http://169.254.169.254/latest/api/token")
CURR_INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
CURR_REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)

# Get instance mode from AGENT_MODE tag
AGENT_MODE=$(aws ec2 describe-tags --region "$CURR_REGION" \
  --filters "Name=resource-id,Values=$CURR_INSTANCE_ID" "Name=key,Values=AGENT_MODE" \
  --query "Tags[0].Value" --output text)

# ----------------------------------------------------
# Register instance into target group
# ----------------------------------------------------

# Read TG_ARN tag from the instance
TG_ARN=$(aws ec2 describe-tags --region "$CURR_REGION" \
  --filters "Name=resource-id,Values=$CURR_INSTANCE_ID" "Name=key,Values=TG_ARN" \
  --query "Tags[0].Value" --output text)

# Register current instance into the target group
aws elbv2 register-targets --region "$CURR_REGION" \
  --target-group-arn "$TG_ARN" \
  --targets Id="$CURR_INSTANCE_ID"

# ----------------------------------------------------
# Primary mode
# ----------------------------------------------------
if [ "$AGENT_MODE" == "primary" ]; then
    # Generate 256-bit AES key for primary encryption
    openssl rand -out "$RAMDISK_FOLDER/primary.key" 32

    # Retrieve HOSTNAME tag to use as CN in cert
    HOSTNAME=$(aws ec2 describe-tags --region "$CURR_REGION" \
      --filters "Name=resource-id,Values=$CURR_INSTANCE_ID" "Name=key,Values=HOSTNAME" \
      --query "Tags[0].Value" --output text)
    
    # Generate RSA private key and CSR
    openssl req -new -newkey rsa:2048 -nodes \
      -keyout "$RAMDISK_FOLDER/https.key" \
      -out "$RAMDISK_FOLDER/https.csr" \
      -subj "/CN=$HOSTNAME"

    # Encrypt HTTPS private key using AES key
    openssl enc -aes-256-cbc -pbkdf2 -salt \
      -in "$RAMDISK_FOLDER/https.key" \
      -out "$RAMDISK_FOLDER/https.key.enc" \
      -pass file:"$RAMDISK_FOLDER/primary.key"

# ----------------------------------------------------
# Sync mode
# ----------------------------------------------------
elif [ "$AGENT_MODE" == "sync" ]; then
    # Generate communication RSA key pair
    openssl genrsa -out "$RAMDISK_FOLDER/comm.key" 2048
    openssl rsa -in "$RAMDISK_FOLDER/comm.key" -pubout -out "$RAMDISK_FOLDER/comm.pub"
    
    # Print SHA-256 hash of public key to console
    COMM_PUB_HASH=$(sha256sum "$RAMDISK_FOLDER/comm.pub" | awk '{print $1}')
    echo "COMM_PUB_KEY_HASH=$COMM_PUB_HASH" | tee /dev/console

    # Wait for hash to appear in console output
    FOUND_HASH_IN_CONSOLE=false
    for i in {1..6}; do
        CONSOLE_OUTPUT=$(aws ec2 get-console-output --region "$CURR_REGION" \
            --instance-id "$CURR_INSTANCE_ID" --latest \
            --query "Output" --output text 2>/dev/null || true)

        if echo "$CONSOLE_OUTPUT" | grep -q "COMM_PUB_KEY_HASH=$COMM_PUB_HASH"; then
            FOUND_HASH_IN_CONSOLE=true
            break
        fi
        sleep 5
    done

    if [ "$FOUND_HASH_IN_CONSOLE" != true ]; then
        exit 1
    fi

    # Get primary instance ID from PRIMARY_VM tag
    PRIMARY_VM_ID=$(aws ec2 describe-tags --region "$CURR_REGION" \
    --filters "Name=resource-id,Values=$CURR_INSTANCE_ID" "Name=key,Values=PRIMARY_VM" \
    --query "Tags[0].Value" --output text)

    # Verify primary instance is in at least one target group
    TARGET_GROUP_ARN_LIST=$(aws elbv2 describe-target-groups --region "$CURR_REGION" \
        --query 'TargetGroups[*].TargetGroupArn' --output text)

    PRIMARY_VM_IN_TG=false
    for TG_ARN in $TARGET_GROUP_ARN_LIST; do
        TARGETS=$(aws elbv2 describe-target-health --region "$CURR_REGION" \
            --target-group-arn "$TG_ARN" \
            --query 'TargetHealthDescriptions[*].Target.Id' --output text || true)
        if echo "$TARGETS" | grep -qw "$PRIMARY_VM_ID"; then
            PRIMARY_VM_IN_TG=true
            break
        fi
    done

    if [ "$PRIMARY_VM_IN_TG" != true ]; then
        exit 1
    fi
    
    # Get primary VM's private IP address
    PRIMARY_VM_IP=$(aws ec2 describe-instances --region "$CURR_REGION" \
      --instance-ids "$PRIMARY_VM_ID" \
      --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)

    # Encode communication public key for JSON
    COMM_PUB_KEY=$(awk 'NF {sub(/\r/, ""); printf "%s\\n", $0;}' "$RAMDISK_FOLDER/comm.pub")
    
    # Call /sync-key API on primary instance
    SYNC_RESPONSE=$(curl -s --fail-with-body -X POST "http://$PRIMARY_VM_IP:9900/sync-key" \
        -H "Content-Type: application/json" \
        -d "{
            \"instanceID\": \"$CURR_INSTANCE_ID\",
            \"region\": \"$CURR_REGION\",
            \"commPubKey\": \"$COMM_PUB_KEY\"
        }")

    # Extract and decode encrypted payloads
    echo "$SYNC_RESPONSE" | jq -r .encPrimaryKey | base64 -d > "$RAMDISK_FOLDER/primary.key.enc"
    echo "$SYNC_RESPONSE" | jq -r .encHttpsKey   | base64 -d > "$RAMDISK_FOLDER/https.key.enc"
    echo "$SYNC_RESPONSE" | jq -r .httpsCert     > "$RAMDISK_FOLDER/https.pem"

    # Decrypt primary.key using communication RSA private key
    openssl pkeyutl -decrypt \
    -inkey "$RAMDISK_FOLDER/comm.key" \
    -in "$RAMDISK_FOLDER/primary.key.enc" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -out "$RAMDISK_FOLDER/primary.key"

    # Decrypt HTTPS private key using AES primary key
    openssl enc -d -aes-256-cbc -pbkdf2 \
    -in "$RAMDISK_FOLDER/https.key.enc" \
    -out "$RAMDISK_FOLDER/https.key" \
    -pass file:"$RAMDISK_FOLDER/primary.key"

# ----------------------------------------------------
# Unknow mode
# ----------------------------------------------------
else
    exit 1
fi

# ----------------------------------------------------
# Python venv setup
# ----------------------------------------------------
python3 -m venv "$VENV_PATH"
"$PIP_BIN" install -r "$AGENT_PATH/requirements.txt"

# ----------------------------------------------------
# Systemd service setup
# ----------------------------------------------------
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=FastAPI Agent API Service
After=network.target

[Service]
ExecStart=$PYTHON_BIN -m uvicorn agent:app --host 0.0.0.0 --port 9900 --workers 2
WorkingDirectory=$AGENT_PATH
Restart=always
RestartSec=5
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Reload and start the service
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

# ----------------------------------------------------
# Wait for all required files to exist
# ----------------------------------------------------
REQUIRED_FILES=(
  "$RAMDISK_FOLDER/primary.key"
  "$RAMDISK_FOLDER/https.key"
  "$RAMDISK_FOLDER/https.pem"
)

while true; do
    ALL_EXIST=true
    for FILE in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$FILE" ]; then
            ALL_EXIST=false
            break
        fi
    done

    if [ "$ALL_EXIST" = true ]; then
        echo "All required files are present."
        break
    fi

    sleep 5
done
