#!/bin/bash
set -euxo pipefail

function on_error {
    exit 1
}
trap on_error ERR

# Read RAM disk folder path from first argument
RAMDISK_FOLDER="$1"

# Fetch EC2 metadata token (IMDSv2)
TOKEN=$(curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" -s "http://169.254.169.254/latest/api/token")

# Get current instance ID and AWS region
CURR_INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
CURR_REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)

# Query AGENT_MODE tag (primary or sync)
AGENT_MODE=$(aws ec2 describe-tags --region "$CURR_REGION" \
  --filters "Name=resource-id,Values=$CURR_INSTANCE_ID" "Name=key,Values=AGENT_MODE" \
  --query "Tags[0].Value" --output text)

# ----- PRIMARY MODE -----
if [ "$AGENT_MODE" == "primary" ]; then
    # Generate a 256-bit (32-byte) AES key as primary key
    openssl rand -out "$RAMDISK_FOLDER/primary.key" 32

    # Get HOSTNAME tag to set as CN in the certificate
    HOSTNAME=$(aws ec2 describe-tags --region "$CURR_REGION" \
      --filters "Name=resource-id,Values=$CURR_INSTANCE_ID" "Name=key,Values=HOSTNAME" \
      --query "Tags[0].Value" --output text)
    
    # Generate RSA private key and CSR
    openssl req -new -newkey rsa:2048 -nodes \
      -keyout "$RAMDISK_FOLDER/https.key" \
      -out "$RAMDISK_FOLDER/https.csr" \
      -subj "/CN=$HOSTNAME"

    # Encrypt the HTTPS private key using the AES key
    openssl enc -aes-256-cbc -pbkdf2 -salt \
    -in "$RAMDISK_FOLDER/https.key" \
    -out "$RAMDISK_FOLDER/https.key.enc" \
    -pass file:"$RAMDISK_FOLDER/primary.key"

# ----- SYNC MODE -----
elif [ "$AGENT_MODE" == "sync" ]; then
    # Generate RSA key pair for communication
    openssl genrsa -out "$RAMDISK_FOLDER/comm.key" 2048
    openssl rsa -in "$RAMDISK_FOLDER/comm.key" -pubout -out "$RAMDISK_FOLDER/comm.pub"
    
    # Compute SHA-256 hash of the public key and print it to console for primary instance to read
    COMM_PUB_HASH=$(sha256sum "$RAMDISK_FOLDER/comm.pub" | awk '{print $1}')
    echo "COMM_PUB_KEY_HASH=$COMM_PUB_HASH" | tee /dev/console

    # Retry up to 30 seconds to find the COMM_PUB_KEY_HASH in the console output
    FOUND_HASH_IN_CONSOLE=false
    for i in {1..6}; do
        CONSOLE_OUTPUT=$(aws ec2 get-console-output \
            --region "$CURR_REGION" \
            --instance-id "$CURR_INSTANCE_ID" \
            --query "Output" \
            --output text 2>/dev/null || true)

        if echo "$CONSOLE_OUTPUT" | grep -q "COMM_PUB_KEY_HASH=$COMM_PUB_HASH"; then
            FOUND_HASH_IN_CONSOLE=true
            break
        fi

        sleep 5
    done

    if [ "$FOUND_HASH_IN_CONSOLE" != true ]; then
        echo "Timed out waiting for COMM_PUB_KEY_HASH to appear in console output" >&2
        exit 1
    fi

    # Get the instance ID of the primary VM from PRIMARY_VM tag
    PRIMARY_VM_ID=$(aws ec2 describe-tags --region "$CURR_REGION" \
    --filters "Name=resource-id,Values=$CURR_INSTANCE_ID" "Name=key,Values=PRIMARY_VM" \
    --query "Tags[0].Value" --output text)
    
    # Lookup private IP of the primary VM
    PRIMARY_VM_IP=$(aws ec2 describe-instances --region "$CURR_REGION" \
    --instance-ids "$PRIMARY_VM_ID" \
    --query "Reservations[0].Instances[0].PrivateIpAddress" --output text)

    # Prepare public key content with newlines properly escaped
    COMM_PUB_KEY=$(awk 'NF {sub(/\r/, ""); printf "%s\\n", $0;}' "$RAMDISK_FOLDER/comm.pub")
    
    # Call sync API on primary to receive encrypted secrets and cert
    SYNC_RESPONSE=$(curl -s -X POST "https://$PRIMARY_VM_IP/sync" \
        -H "Content-Type: application/json" \
        -d "{
            \"instanceID\": \"$CURR_INSTANCE_ID\",
            \"commPubKey\": \"$COMM_PUB_KEY\"
        }")

    # Parse response: base64-encoded encrypted primary key, https key, and PEM cert
    ENC_PRIMARY_KEY=$(echo "$SYNC_RESPONSE" | jq -r .encPrimaryKey)
    ENC_HTTPS_KEY=$(echo "$SYNC_RESPONSE" | jq -r .encHttpsKey)
    HTTPS_CERT=$(echo "$SYNC_RESPONSE" | jq -r .httpsCert)

    # Decrypt primary.key using our RSA communication private key
    echo "$ENC_PRIMARY_KEY" | base64 -d > "$RAMDISK_FOLDER/primary.key.enc"
    openssl pkeyutl -decrypt \
    -inkey "$RAMDISK_FOLDER/comm.key" \
    -in "$RAMDISK_FOLDER/primary.key.enc" \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 \
    -out "$RAMDISK_FOLDER/primary.key"

    # Decrypt https.key using the recovered primary AES key
    echo "$ENC_HTTPS_KEY" | base64 -d > "$RAMDISK_FOLDER/https.key.enc"
    openssl enc -d -aes-256-cbc -pbkdf2 \
    -in "$RAMDISK_FOLDER/https.key.enc" \
    -out "$RAMDISK_FOLDER/https.key" \
    -pass file:"$RAMDISK_FOLDER/primary.key"

    # Save certificate
    echo "$HTTPS_CERT" > "$RAMDISK_FOLDER/https.cert"

# ----- UNKNOWN MODE -----
else
    echo "Unknown AGENT_MODE: $AGENT_MODE"
    exit 1
fi

# ----- INSTALL PYTHON DEPENDENCIES -----
pip3 install -r "$(dirname "$0")/requirements.txt"

# ----- SETUP SYSTEMD SERVICE -----
SERVICE_NAME="agent-api"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
AGENT_PATH="$(realpath "$(dirname "$0")/agent")"

cat > "$SERVICE_FILE" <<EOF
[Unit]
[Unit]
Description=FastAPI Agent API Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 -m uvicorn agent:app --host 0.0.0.0 --port 9900 --workers 2
WorkingDirectory=$AGENT_PATH
Restart=always
RestartSec=5
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd, enable and start the service
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"