# Port-Scanning Backend

Flask REST API powering the Devil Scan frontend: JWT auth, threaded port scanning (TCP / UDP), ARP resolution, ICMP ping & subnet sweep, scan persistence in MongoDB.

## API

| Method | Route | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | – | Create account |
| POST | `/auth/login` | – | Get JWT token |
| GET | `/auth/me` | Bearer | Current user |
| GET | `/api/health` | – | Health check |
| POST | `/api/scan` | Bearer | Run a scan (`target`, `mode`, optional `range`/`customPorts`/`timeout`/`concurrency`/`serviceDetection`) |
| GET | `/api/scans` | Bearer | Scan history for the user |
| GET | `/api/scans/<id>` | Bearer | Full result of one scan |
| DELETE | `/api/scans/<id>` | Bearer | Delete a scan |

## Environment variables

| Name | Required | Description |
|---|---|---|
| `MONGODB_URL` | yes | MongoDB connection string (Atlas or local) |
| `SECRET_KEY` | yes | HMAC key for JWT signing (32+ bytes) |

## Run locally

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
export MONGODB_URL="mongodb://127.0.0.1:27017/Scanner"
export SECRET_KEY="some-long-random-string"
flask --app api.index run --port 5000
```

## Deploy on Vercel

The repo ships `vercel.json` mapping all routes to `api/index.py`. Import the repo in Vercel, set the two environment variables above, and deploy — no build step needed.

> Note: ARP/ICMP scans require raw-socket privileges that serverless platforms don't provide; they degrade gracefully. TCP/UDP/Ping work everywhere.
