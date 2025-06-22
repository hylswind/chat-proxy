import os
import re
import base64
import hashlib
from pathlib import Path

import boto3
from OpenSSL import crypto
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

RAMDISK_ROOT_PATH = "/mnt/ramdisk"


class PutCertBody(BaseModel):
    cert: str


class SyncKeyBody(BaseModel):
    instanceID: str
    commPubKey: str


def is_instance_in_any_target_group(elbv2_client, instance_id):
    paginator = elbv2_client.get_paginator("describe_target_groups")
    for page in paginator.paginate():
        for tg in page["TargetGroups"]:
            try:
                tg_arn = tg["TargetGroupArn"]
                health_desc = elbv2_client.describe_target_health(
                    TargetGroupArn=tg_arn)
                for desc in health_desc["TargetHealthDescriptions"]:
                    if desc["Target"]["Id"] == instance_id:
                        return True
            except Exception:
                continue
    return False


app = FastAPI()


@app.get("/get-csr")
async def get_csr():
    csr_path = Path(RAMDISK_ROOT_PATH) / "https.csr"
    if not os.path.exists(csr_path):
        raise HTTPException(status_code=500, detail="CSR file not found")

    with open(csr_path, "r") as f:
        csr_content = f.read()

    return {"csr": csr_content}


@app.post("/put-cert")
async def put_cert(body: PutCertBody):
    params = body.model_dump()

    key_path = Path(RAMDISK_ROOT_PATH) / "https.key"
    cert_path = Path(RAMDISK_ROOT_PATH) / "https.pem"

    if not os.path.exists(key_path):
        raise HTTPException(status_code=500, detail="Private key not found")

    client_cert = crypto.load_certificate(crypto.FILETYPE_PEM, params["cert"])
    pub_from_cert = client_cert.get_pubkey().to_cryptography_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend())
    pub_from_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    if pub_from_cert != pub_from_key:
        raise HTTPException(
            status_code=400, detail="Certificate does not match private key")

    with open(cert_path, "w") as f:
        f.write(params["cert"])

    return ""


@app.post("/sync-key")
async def sync_key(body: SyncKeyBody):
    params = body.model_dump()

    ec2_client = boto3.client("ec2", region_name="us-east-1")
    elbv2_client = boto3.client("elbv2", region_name="us-east-1")

    if not is_instance_in_any_target_group(elbv2_client, params["instanceID"]):
        raise HTTPException(
            status_code=403, detail="Instance not in any target group")

    try:
        output = ec2_client.get_console_output(
            InstanceId=params["instanceID"], Latest=True)
        content = output.get("Output", "")
        match = re.search(r"COMM_PUB_KEY_HASH=([a-fA-F0-9]+)", content)

        if not match:
            raise HTTPException(
                status_code=400, detail="COMM_PUB_KEY_HASH not found")

        expected_hash = match.group(1)
    except Exception as e:
        print(str(e))
        raise HTTPException(
            status_code=500, detail=f"Failed to read console output")

    try:
        digest = hashlib.sha256(params["commPubKey"].encode()).hexdigest()
        if digest != expected_hash:
            raise HTTPException(
                status_code=400, detail="Public key hash mismatch")
    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Public key hash check failed")

    try:
        from cryptography.hazmat.primitives import serialization

        comm_pub_key = serialization.load_pem_public_key(
            params["commPubKey"].encode(), backend=default_backend())

        key_path = Path(RAMDISK_ROOT_PATH) / "primary.key"
        with open(key_path, "rb") as f:
            plaintext = f.read()

        encrypted_primary = comm_pub_key.encrypt(
            plaintext,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(str(e))
        raise HTTPException(status_code=500, detail=f"Encryption failed")

    try:
        https_key_enc_path = Path(RAMDISK_ROOT_PATH) / "https.key.enc"
        with open(https_key_enc_path, "rb") as f:
            https_key_enc = f.read()

        https_cert_path = Path(RAMDISK_ROOT_PATH) / "https.pem"
        with open(https_cert_path, "rb") as f:
            https_cert = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read files")

    return {
        "encPrimaryKey": base64.b64encode(encrypted_primary).decode(),
        "encHttpsKey": base64.b64encode(https_key_enc).decode(),
        "httpsCert": https_cert.decode()
    }
