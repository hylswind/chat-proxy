#!/bin/bash
set -euxo pipefail

# Trap errors and exit immediately
function on_error {
    exit 1
}
trap on_error ERR

TARGET_DIR="$1"
DOCKER_COMPOSE_FILE="$TARGET_DIR/litellm/docker-compose.yaml"
SECRET_MANAGER_NAME="chat_proxy_test"

# Replace dummy key in config with a real API key
LITELLM_MASTER_KEY="sk-$(openssl rand -hex 32)"
sed -i "s|DUMMY_LITELLM_MASTER_KEY|$LITELLM_MASTER_KEY|" "$DOCKER_COMPOSE_FILE"

# Retrieve secrets from AWS Secrets Manager and inject into Docker Compose file
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id $SECRET_MANAGER_NAME --query SecretString --output text)
AWS_ACCESS_KEY_ID=$(echo "$SECRET_JSON" | jq -r .AWS_ACCESS_KEY_ID)
AWS_SECRET_ACCESS_KEY=$(echo "$SECRET_JSON" | jq -r .AWS_SECRET_ACCESS_KEY)
DYNAMODB_TABLE=$(echo "$SECRET_JSON" | jq -r .DYNAMODB_TABLE)
DYNAMODB_REGION_NAME=$(echo "$SECRET_JSON" | jq -r .DYNAMODB_REGION_NAME)
SQS_URL=$(echo "$SECRET_JSON" | jq -r .SQS_URL)
SQS_REGION_NAME=$(echo "$SECRET_JSON" | jq -r .SQS_REGION_NAME)

sed -i "s|DUMMY_AWS_ACCESS_KEY_ID|$AWS_ACCESS_KEY_ID|" "$DOCKER_COMPOSE_FILE"
sed -i "s|DUMMY_AWS_SECRET_ACCESS_KEY|$AWS_SECRET_ACCESS_KEY|" "$DOCKER_COMPOSE_FILE"
sed -i "s|DUMMY_DYNAMODB_TABLE|$DYNAMODB_TABLE|" "$DOCKER_COMPOSE_FILE"
sed -i "s|DUMMY_DYNAMODB_REGION_NAME|$DYNAMODB_REGION_NAME|" "$DOCKER_COMPOSE_FILE"
sed -i "s|DUMMY_SQS_URL|$SQS_URL|" "$DOCKER_COMPOSE_FILE"
sed -i "s|DUMMY_SQS_REGION_NAME|$SQS_REGION_NAME|" "$DOCKER_COMPOSE_FILE"

# Start the chat proxy as a Docker Compose service
docker compose -f "$DOCKER_COMPOSE_FILE" up -d
