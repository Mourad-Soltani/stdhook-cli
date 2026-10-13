# stdhook-cli

A minimal, zero-dependency Python CLI for generating and verifying **Standard Webhooks** signatures.

Built for solo developers and indie hackers who need a simple, auditable tool to work with the Standard Webhooks specification (https://www.standardwebhooks.com/).

## Features

- Generate `webhook-id`, `webhook-timestamp`, and `webhook-signature` headers
- Verify incoming signatures with replay protection (timestamp tolerance)
- Pure Python (stdlib only) — no external dependencies
- Compact JSON body support
- Health tests included

## Installation

```bash
# Clone and run
git clone <repo>
cd stdhook-cli
python -m src.cli --help
```

Or install locally:

```bash
pip install -e .
```

## Usage

### Generate a signature

```bash
python -m src.cli generate \
  --secret "whsec_aGro1s70GnNp702mXzvsyZdKLkARtW0j3AhFQcj4NcI=" \
  --body '{"event":"project_created","source":"daily project automation","status":"success"}' \
  --id "msg_test123"
```

### Verify a signature

```bash
python -m src.cli verify \
  --secret "whsec_..." \
  --id "msg_..." \
  --timestamp "1728..." \
  --signature "v1,..." \
  --body '{"event":"..."}'
```

## Signature

Mourad.Soltani

## License

MIT — see LICENSE
