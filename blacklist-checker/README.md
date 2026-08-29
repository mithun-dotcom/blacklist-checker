# ArrowInBox Blacklist Checker

A standalone email blacklist checker. Enter a domain or IP and it runs live lookups
against major **IP-based DNSBLs** (Spamhaus, Barracuda, SpamCop, SORBS, PSBL, …) and
**domain/URI blacklists** (SURBL, Spamhaus DBL, URIBL, SEM, SORBS RHSBL, …).

Because the lookups run **server-side from this app's own resolver**, lists such as
SURBL, URIBL and Spamhaus — which refuse queries from public browser resolvers —
return accurate results, matching tools like MXToolbox at low volume.

- Zero dependencies (Node's built-in `http` + `dns`).
- One HTTP endpoint: `GET /api/blacklist?host=example.com` → JSON.

## Run locally
```bash
npm start          # then open http://localhost:3000
```

## Deploy on Render (from GitHub)
1. Push this folder to a new GitHub repository.
2. In Render, click **New → Web Service** and connect that repo
   (the included `render.yaml` also works as a Blueprint: **New → Blueprint**).
3. Settings (auto-detected from render.yaml):
   - Runtime: **Node**
   - Build command: `npm install`
   - Start command: `npm start`
4. Deploy. Render sets `PORT` automatically; the app reads it.

## Optional configuration
- `RESOLVERS` — comma-separated DNS resolvers to use, e.g. `RESOLVERS=1.1.1.1,8.8.8.8`.
  Leave unset to use the platform's default resolver (recommended).
- Lock down CORS: in `server.js`, change `Access-Control-Allow-Origin: *`
  to your own domain before production.

## Notes & credits
- Keep query volume modest — most blacklists are free only for low-volume,
  non-commercial lookups. High volume requires their official data feeds/APIs.
- IP/DNSBL zone list based on the open-source project
  [`molodsom/rbl-check`](https://github.com/molodsom/rbl-check).

## License
MIT
