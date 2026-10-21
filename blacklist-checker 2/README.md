# ArrowInBox Blacklist Checker

A standalone email blacklist checker. Enter a domain or IP and it runs live lookups
against major **IP-based DNSBLs** (Spamhaus, Barracuda, SpamCop, SORBS, PSBL, …) and
**domain/URI blacklists** (SURBL, Spamhaus DBL, URIBL, SEM, SORBS RHSBL, …).

Because the lookups run **server-side from this app's own resolver**, lists such as
SURBL, URIBL and Spamhaus — which refuse queries from public browser resolvers —
return accurate results, matching tools like MXToolbox at low volume.

- Plain PHP 8.1+, zero dependencies (built-in UDP DNS client, all lookups run in parallel).
- One HTTP endpoint: `GET api/blacklist.php?host=example.com` → JSON.

## Project layout
```
public/              web root
  index.html         the checker UI
  logo.png
  api/blacklist.php  JSON endpoint
src/blacklist.php    lookup logic (kept outside the web root)
Dockerfile           PHP + Apache image (for Render or any Docker host)
```

## Run locally
```bash
php -S localhost:8000 -t public     # then open http://localhost:8000
```

## Deploy on shared hosting (cPanel etc.)
Upload `public/` as your site's web root and `src/` next to it (one level up), so
`public/api/blacklist.php` can load `../../src/blacklist.php`. The host must allow
outbound UDP on port 53 (most do).

## Deploy on Render (from GitHub)
Render has no native PHP runtime, so this uses the included `Dockerfile`.
1. In Render, click **New → Web Service** and connect this repo
   (or **New → Blueprint** to use `render.yaml`).
2. Runtime: **Docker**. If this folder isn't the repo root, set **Root Directory**
   to it.
3. Deploy. Render sets `PORT` automatically; Apache listens on it.

## Optional configuration
- `RESOLVERS` — comma-separated DNS resolvers to use, e.g. `RESOLVERS=1.1.1.1,8.8.8.8`.
  Leave unset to use the platform's default resolver (recommended).
- Lock down CORS: in `public/api/blacklist.php`, change `Access-Control-Allow-Origin: *`
  to your own domain before production.

## Accuracy: Spamhaus DQS + resolver notes

Some lists refuse queries from shared cloud/public resolvers and will show **Unavailable**:

- **Spamhaus (ZEN/SBL/XBL/PBL/DBL)** — get a free **Data Query Service (DQS)** key at
  spamhaus.com, then set it as an environment variable in Render:
  `SPAMHAUS_DQS_KEY=your_key_here`. The app then queries the DQS zones, which return
  accurate results from any resolver.
- **SURBL / URIBL** — these refuse big public resolvers (they answer `127.0.0.1` to mean
  "blocked"). If they show Unavailable, your host's resolver is being refused. Options:
  set `RESOLVERS` to a resolver they permit, or use their data feed for guaranteed results.

Response decoding: `127.0.0.1` and `127.255.255.x` mean the query was **refused** (shown
as Unavailable); any other `127.x.x.x` is a real **listing** — e.g. SURBL `127.0.0.64`
is the ABUSE sub-list. Hover any result in the UI to see the raw DNS code.

## Notes & credits
- Keep query volume modest — most blacklists are free only for low-volume,
  non-commercial lookups. High volume requires their official data feeds/APIs.
- IP/DNSBL zone list based on the open-source project
  [`molodsom/rbl-check`](https://github.com/molodsom/rbl-check).

## License
MIT
