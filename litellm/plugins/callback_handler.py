import os
import json

import boto3
import litellm
from litellm.integrations.custom_logger import CustomLogger


class CallbackHandler(CustomLogger):
    def log_pre_api_call(self, model, messages, kwargs):
        pass

    def log_post_api_call(self, kwargs, response_obj, start_time, end_time):
        pass

    def log_success_event(self, kwargs, response_obj, start_time, end_time):
        pass

    def log_failure_event(self, kwargs, response_obj, start_time, end_time):
        pass

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        try:
            aws_key_id = os.environ["AWS_ACCESS_KEY_ID"]
            aws_key_secret = os.environ["AWS_SECRET_ACCESS_KEY"]
            sqs_url = os.environ["SQS_URL"]
            sqs_region_name = os.environ["SQS_REGION_NAME"]

            model = kwargs["model"]
            prompt_tokens = response_obj["usage"].prompt_tokens
            completion_tokens = response_obj["usage"].completion_tokens
            total_tokens = response_obj["usage"].total_tokens
            user_api_key_hash = kwargs["litellm_params"]["metadata"]["user_api_key_hash"]

            usage_data = {
                "userAPIKeyHash": user_api_key_hash,
                "momdel": model,
                "startTime": int(start_time.timestamp()),
                "endTime": int(end_time.timestamp()),
                "usage": {
                    "promptTokens": prompt_tokens,
                    "completionTokens": completion_tokens,
                    "totalTokens": total_tokens
                }
            }

            sqs_client = boto3.client("sqs", region_name=sqs_region_name,
                                      aws_access_key_id=aws_key_id, aws_secret_access_key=aws_key_secret)
            sqs_client.send_message(
                QueueUrl=sqs_url,
                MessageBody=json.dumps(usage_data)
            )
        except Exception as e:
            print(f"Exception: {e}")

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        pass


proxy_handler_instance = CallbackHandler()
