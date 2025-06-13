import os
import hashlib

import boto3
from litellm.proxy._types import UserAPIKeyAuth


async def user_api_key_auth(request, api_key) -> UserAPIKeyAuth:
    try:
        aws_key_id = os.environ["AWS_ACCESS_KEY_ID"]
        aws_key_secret = os.environ["AWS_SECRET_ACCESS_KEY"]
        dynamodb_table = os.environ["DYNAMODB_TABLE"]
        dynamodb_region_name = os.environ["DYNAMODB_REGION_NAME"]

        api_key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()

        dynamodb_client = boto3.client("dynamodb", region_name=dynamodb_region_name,
                                aws_access_key_id=aws_key_id, aws_secret_access_key=aws_key_secret)
        response = dynamodb_client.get_item(
            TableName=dynamodb_table,
            Key={
                "API_KEY_HASH": {"S": api_key_hash}
            }
        )

        if "Item" not in response:
            raise Exception

        return UserAPIKeyAuth(api_key=api_key)
    except:
        raise Exception
