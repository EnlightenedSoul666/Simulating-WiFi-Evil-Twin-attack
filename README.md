# Secure Wi-Fi Simulator — Ed25519/X25519 (Micro-dots)
- Beacons: Ed25519-signed `{ apName, ts }` (verify vs preinstalled repo). Tolerance default **30 s**.
- Packets: Ed25519 sign, X25519 ECDH → HKDF → AES-GCM (with nonce + replay cache).
- OSCP-like routing; reroute around evil APs; hop-based cost; live **graph** for cost & delivery.
- Speed up to **20 cm/s**; **50 pkts/s** bursts; micro-dots UI; Inter font.

## Run
```bash
npm install
node server.js
# Main UI:   http://localhost:3000
# Graphs:    http://localhost:3000/graph.html
```
