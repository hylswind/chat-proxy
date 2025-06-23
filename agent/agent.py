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
    leafCert: str
    intermediateCert: str


class SyncKeyBody(BaseModel):
    instanceID: str
    commPubKey: str
    region: str


# Check if the EC2 instance is registered with any target group
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
    """Returns the current CSR content from the RAM disk."""
    csr_path = Path(RAMDISK_ROOT_PATH) / "https.csr"
    if not csr_path.exists():
        raise HTTPException(status_code=500, detail="CSR file not found")

    return {"csr": csr_path.read_text()}


@app.post("/put-cert")
async def put_cert(body: PutCertBody):
    """Validates and stores the client certificate if it matches the private key."""
    leaf_cert_pem = body.leafCert
    intermediate_cert_pem = body.intermediateCert

    key_path = Path(RAMDISK_ROOT_PATH) / "https.key"
    cert_path = Path(RAMDISK_ROOT_PATH) / "https.pem"

    # Check if cert file already exists
    if cert_path.exists():
        raise HTTPException(
            status_code=400, detail="Certificate file already exists"
        )

    try:
        # Load the certificate and extract the public key
        client_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, leaf_cert_pem)
        cert_pub_key = client_cert.get_pubkey().to_cryptography_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Load private key and extract public portion
        private_key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None, backend=default_backend()
        )
        key_pub_key = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if cert_pub_key != key_pub_key:
            raise HTTPException(
                status_code=400, detail="Certificate does not match private key")

        fullchain_pem = f"{leaf_cert_pem.strip()}\n{intermediate_cert_pem.strip()}\n"
        cert_path.write_text(fullchain_pem)

        return {}

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Certificate validation failed")


@app.post("/sync-key")
async def sync_key(body: SyncKeyBody):
    """
    Verifies instance trust and returns:
    - AES-encrypted primary key encrypted with the instance communication key
    - Previously AES-encrypted HTTPS key
    - PEM certificate
    """
    instance_id = body.instanceID
    comm_pub_key_pem = body.commPubKey
    region = body.region

    # AWS clients
    ec2_client = boto3.client("ec2", region_name=region)
    elbv2_client = boto3.client("elbv2", region_name=region)

    # Validate instance is in target group
    if not is_instance_in_any_target_group(elbv2_client, instance_id):
        raise HTTPException(
            status_code=403, detail="Instance not in any target group")

    # Extract COMM_PUB_KEY_HASH from instance console output
    try:
        output = ec2_client.get_console_output(
            InstanceId=instance_id, Latest=True)
        console_content = output.get("Output", "")
        match = re.search(r"COMM_PUB_KEY_HASH=([a-fA-F0-9]+)", console_content)

        if not match:
            raise HTTPException(
                status_code=400, detail="COMM_PUB_KEY_HASH not found")
        expected_hash = match.group(1)

        # Verify the hash of the provided communication public key
        actual_hash = hashlib.sha256(comm_pub_key_pem.encode()).hexdigest()
        if actual_hash != expected_hash:
            raise HTTPException(
                status_code=400, detail="Public key hash mismatch")
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to validate instance console output")

    # Encrypt the primary key using the communication public key
    try:
        comm_pub_key = serialization.load_pem_public_key(
            comm_pub_key_pem.encode(), backend=default_backend()
        )

        primary_key_path = Path(RAMDISK_ROOT_PATH) / "primary.key"
        primary_plaintext = primary_key_path.read_bytes()
        encrypted_primary = comm_pub_key.encrypt(
            primary_plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption failed")

    # Load encrypted https key and certificate
    try:
        https_key_enc_path = Path(RAMDISK_ROOT_PATH) / "https.key.enc"
        https_cert_path = Path(RAMDISK_ROOT_PATH) / "https.pem"

        https_key_enc = https_key_enc_path.read_bytes()
        https_cert = https_cert_path.read_text()
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to load encrypted files")

    return {
        "encPrimaryKey": base64.b64encode(encrypted_primary).decode(),
        "encHttpsKey": base64.b64encode(https_key_enc).decode(),
        "httpsCert": https_cert
    }
