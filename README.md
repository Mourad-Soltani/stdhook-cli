# stdhook-cli

**Author: Mourad.Soltani**

Minimal zero-dependency Python CLI to **sign** and **verify** [Standard Webhooks](https://www.standardwebhooks.com/) signatures.

Used by Svix, Clerk, Resend, Polar, and any service that sends:

- `webhook-id`
- `webhook-timestamp`
- `webhook-signature: v1,<base64-hmac>`

Perfect for local debugging, CI health checks, and scripting signed requests.

## Install

```bash
pip install -e .
# or run without install
python -m src.cli --help
```

Requires Python 3.9+.

## Usage

### Generate signature

```bash
stdhook sign --secret "whsec_..." --body '{"hello":"world"}'
# v1,AbCdEf...

stdhook sign -s "whsec_..." -f payload.json --json
# {"webhook-id":"msg_...","webhook-timestamp":"...","webhook-signature":"v1,..."}
```

### Verify

```bash
stdhook verify \
  --secret "whsec_..." \
  --id "msg_abc" \
  --timestamp 1720000000 \
  --signature "v1,..." \
  --body '{"hello":"world"}'
# VALID  (exit 0) or INVALID (exit 1)
```

### Full headers (ready for curl)

```bash
stdhook headers -s "whsec_..." --body '{"event":"ping"}'
# webhook-id: msg_...
# webhook-timestamp: 1720000000
# webhook-signature: v1,...
```

Pipe stdin:

```bash
echo '{"a":1}' | stdhook headers -s "$SECRET"
```

## Library API

```python
from src.webhooks import sign, verify, make_headers

sig = sign(secret, msg_id, timestamp, body)
verify(secret, msg_id, timestamp, body, signature_header)
headers = make_headers(secret, body)  # id + timestamp auto-generated
```

## Tests

```bash
pip install pytest
pytest -q
```

All health tests must pass before shipping.

## Spec notes

- Signed content: `{id}.{timestamp}.{raw_body}`
- Key: base64-decode the secret after optional `whsec_` prefix
- Constant-time comparison via `hmac.compare_digest`
- Default replay tolerance: 300 seconds

## License

MIT — Mourad.Soltani
