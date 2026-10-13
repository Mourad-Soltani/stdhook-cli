"""
Health tests for stdhook-cli.
Signature: Mourad.Soltani
"""

import json
import time
import unittest
from src.webhooks import generate_signature, verify_signature, decode_secret


class TestWebhooks(unittest.TestCase):
    def test_roundtrip(self):
        secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
        body = '{"event":"test","status":"ok"}'
        headers = generate_signature(secret, body)
        self.assertTrue(
            verify_signature(
                secret, body, headers["webhook-id"], headers["webhook-timestamp"], headers["webhook-signature"]
            )
        )

    def test_invalid_signature(self):
        secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
        body = '{"event":"test"}'
        headers = generate_signature(secret, body)
        self.assertFalse(
            verify_signature(
                secret, body, headers["webhook-id"], headers["webhook-timestamp"], "v1,invalid"
            )
        )

    def test_timestamp_tolerance(self):
        secret = "whsec_test"
        body = "hello"
        old_ts = int(time.time()) - 400
        headers = generate_signature(secret, body, timestamp=old_ts)
        self.assertFalse(
            verify_signature(
                secret, body, headers["webhook-id"], headers["webhook-timestamp"], headers["webhook-signature"], tolerance=300
            )
        )

    def test_decode_secret(self):
        key = decode_secret("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
        self.assertIsInstance(key, bytes)
        self.assertGreater(len(key), 0)


if __name__ == "__main__":
    unittest.main()
