# Mourad.Soltani — stdhook-cli
"""Standard Webhooks signing and verification (HMAC-SHA256).

Implements the Standard Webhooks spec:
  signed content = "{webhook-id}.{webhook-timestamp}.{body}"
  signature     = base64(HMAC-SHA256(key, signed_content))
  header        = "v1,<signature>"  (space-separated for multiple)

Secret may be raw base64 or prefixed with "whsec_".
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Optional, Tuple

PREFIX = "whsec_"
DEFAULT_TOLERANCE = 300  # seconds


class WebhookError(Exception):
    """Base error for signing/verification failures."""


class SignatureVerificationError(WebhookError):
    """Raised when a signature does not match or is outside tolerance."""


def _decode_secret(secret: str) -> bytes:
    s = secret.strip()
    if s.startswith(PREFIX):
        s = s[len(PREFIX) :]
    try:
        key = base64.b64decode(s)
    except Exception as exc:
        raise WebhookError(f"Invalid secret (expected base64, optional whsec_ prefix): {exc}") from exc
    if not key:
        raise WebhookError("Secret decodes to empty key")
    return key


def sign(
    secret: str,
    msg_id: str,
    timestamp: int,
    body: bytes | str,
) -> str:
    """Return the webhook-signature value: 'v1,<base64-hmac>'."""
    key = _decode_secret(secret)
    if isinstance(body, str):
        body = body.encode("utf-8")
    to_sign = f"{msg_id}.{timestamp}.".encode("utf-8") + body
    dig = hmac.new(key, to_sign, hashlib.sha256).digest()
    return "v1," + base64.b64encode(dig).decode("ascii")


def verify(
    secret: str,
    msg_id: str,
    timestamp: int | str,
    body: bytes | str,
    signature_header: str,
    tolerance: int = DEFAULT_TOLERANCE,
    now: Optional[int] = None,
) -> bool:
    """Verify signature header. Returns True on success, raises SignatureVerificationError otherwise."""
    if now is None:
        now = int(time.time())
    try:
        ts = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise SignatureVerificationError(f"Invalid timestamp: {timestamp}") from exc

    if abs(now - ts) > tolerance:
        raise SignatureVerificationError(
            f"Timestamp outside tolerance (delta={abs(now - ts)}s, allowed={tolerance}s)"
        )

    expected = sign(secret, msg_id, ts, body)
    expected_sig = expected.split(",", 1)[1]

    # Header may contain multiple space-separated "v1,..." values
    candidates = signature_header.strip().split()
    for cand in candidates:
        parts = cand.split(",", 1)
        if len(parts) != 2:
            continue
        version, sig = parts
        if version != "v1":
            continue
        if hmac.compare_digest(sig, expected_sig):
            return True

    raise SignatureVerificationError("No matching signature found")


def make_headers(
    secret: str,
    body: bytes | str,
    msg_id: Optional[str] = None,
    timestamp: Optional[int] = None,
) -> dict[str, str]:
    """Generate the three Standard Webhooks headers for a payload."""
    import uuid

    if msg_id is None:
        msg_id = f"msg_{uuid.uuid4().hex}"
    if timestamp is None:
        timestamp = int(time.time())
    sig = sign(secret, msg_id, timestamp, body)
    return {
        "webhook-id": msg_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": sig,
    }
