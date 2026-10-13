# Buyer Notes — stdhook-cli

**Seller: Mourad.Soltani**

## What you get

- Complete zero-dependency Python package (`src/webhooks.py` + `src/cli.py`)
- Working CLI: `sign`, `verify`, `headers`
- Full pytest suite (health tests)
- MIT license
- Ready-to-publish `pyproject.toml`

## Who buys this

- Indie developers integrating Svix / Clerk / Resend / Polar webhooks
- Teams that need a scriptable local verifier without pulling a full SDK
- Course creators / SaaS builders who want a clean teaching example of Standard Webhooks

## Suggested positioning

- Price point: $9–$29 one-time (source + commercial use)
- Bundle idea: “Webhook toolkit” (this CLI + a small Next.js middleware snippet)

## One-to-one outreach templates

### Template A — developer who just shipped a webhook receiver

Subject: Quick CLI for Standard Webhooks signatures

Hi {{name}},

Saw you’re working with {{provider}} webhooks. I built a tiny zero-dep Python CLI (`stdhook`) that signs and verifies the Standard Webhooks headers (webhook-id / timestamp / signature) — same scheme Svix, Clerk, and Resend use.

Happy to share the source if it would save you a few minutes of HMAC debugging.

— Mourad.Soltani

### Template B — indie hacker / Gumroad audience

Subject: stdhook-cli — sign & verify Standard Webhooks from the terminal

Hey {{name}},

If you ever need to generate or check `v1,<base64>` signatures locally (CI, curl tests, debugging), this is a minimal MIT-licensed CLI I just shipped.

No dependencies, pure Python 3.9+, full tests included.

Let me know if you’d like a copy or a walkthrough.

— Mourad

## Do NOT

- Send bulk / cold email blasts
- Claim exclusivity if the code is also public
