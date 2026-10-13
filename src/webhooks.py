"""
Standard Webhooks signature utilities.
Signature: Mourad.Soltani
"""

import base64
import hashlib
import hmac
import time
from typing import Optional


def decode_secret(secret: str) -> bytes:
    """Decode whsec_ prefixed or raw base64 secret to key bytes."""
    if secret.startswith("whsec_"):
        secret = secret[6:]
    try:
        return base64.b64decode(secret)
    except Exception as e:
        raise ValueError(f"Invalid secret encoding: {e}") from e


def generate_signature(
    secret: str,
    body: str | bytes,
    webhook_id: Optional[str] = None,
    timestamp: Optional[int] = None,
) -> dict:
    """Generate Standard Webhooks headers for a payload.

    Returns dict with webhook-id, webhook-timestamp, webhook-signature.
    """
    key = decode_secret(secret)
    if isinstance(body, str):
        body_bytes = body.encode("utf-8")
    else:
        body_bytes = body

    if webhook_id is None:
        import uuid
        webhook_id = f"msg_{uuid.uuid4().hex}"
    if timestamp is None:
        timestamp = int(time.time())

    signed_content = f"{webhook_id}.{timestamp}.".encode() + body_bytes
    signature = base64.b64encode(
        hmac.new(key, signed_content, hashlib.sha256).digest()
    ).decode()

    return {
        "webhook-id": webhook_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": f"v1,{signature}",
    }


def verify_signature(
    secret: str,
    body: str | bytes,
    webhook_id: str,
    timestamp: str | int,
    signature_header: str,
    tolerance: int = 300,
) -> bool:
    """Verify a Standard Webhooks signature.

    Returns True if valid and within tolerance, False otherwise.
    """
    try:
        key = decode_secret(secret)
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = body

        ts = int(timestamp)
        now = int(time.time())
        if abs(now - ts) > tolerance:
            return False

        # signature_header is like "v1,base64sig" or "v1,sig1 v1,sig2"
        signatures = []
        for part in signature_header.split():
            if part.startswith("v1,"):
                signatures.append(part[3:])

        if not signatures:
            return False

        signed_content = f"{webhook_id}.{ts}.".encode() + body_bytes
        expected = base64.b64encode(
            hmac.new(key, signed_content, hashlib.sha256).digest()
        ).decode()

        return any(hmac.compare_digest(expected, sig) for sig in signatures)
    except Exception:
        return False
