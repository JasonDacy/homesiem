# 🛡️ HomeSIEM

A lightweight, self-hosted **SIEM (Security Information and Event Management)**
tool for monitoring your own home network and devices. Built in Python, runs on
a Windows 11 desktop (or any Python 3.10+ machine), and ships security alerts to
Discord.

> Built for monitoring **networks and devices you own**. Only deploy this on a
> network you are authorized to monitor.

## Features

- **Multi-source collection**
  - 🪟 **Windows Event Log** collector (logons, process creation, account changes)
  - 📡 **Syslog listener** for your router, Linux/Mac machines, and network gear
  - 🔎 **Network discovery** that sweeps the subnet and detects new/again-seen
    devices — so even "silent" IoT devices that can't forward logs still appear
- **Normalization** — every source is mapped into one common event schema
- **Detection engine** with rules mapped to **MITRE ATT&CK**:
  - Brute-force logins (`TA0006` Credential Access / `T1110`)
  - New device on network (`TA0007` Discovery)
  - Privileged account changes (`TA0003` Persistence / `TA0004` Priv. Esc.)
- **SQLite storage** — zero external database to manage
- **Web dashboard** — searchable events, alerts, and severity overview
- **Discord alerting** via webhook

## Architecture

```
 collectors          detection         storage        presentation
┌───────────┐      ┌────────────┐    ┌──────────┐    ┌─────────────┐
│ syslog     │     │            │    │          │    │ Flask        │
│ win eventlog├────▶│  engine +  ├───▶│ SQLite   ├───▶│ dashboard    │
│ net discovery│    │  rules     │    │          │    │ (localhost)  │
└───────────┘      └─────┬──────┘    └──────────┘    └─────────────┘
                         │
                         ▼
                   Discord webhook
```

## Requirements

- Python 3.10+
- Windows 11 (for the Windows Event Log collector; other collectors are
  cross-platform)

## Installation

```bash
git clone https://github.com/JasonDacy/homesiem.git
cd homesiem
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

```bash
copy config.example.yaml config.yaml   # Windows
# cp config.example.yaml config.yaml   # macOS/Linux
```

Edit `config.yaml`:
- Set `subnet` to match your LAN (find it with `ipconfig` / `ifconfig`).
- Paste your **Discord webhook URL** into `discord_webhook_url`.
  - In Discord: *Server Settings → Integrations → Webhooks → New Webhook → Copy URL*.
  - ⚠️ **Keep this secret.** `config.yaml` is gitignored so it is never committed.

## Running

```bash
python run.py
```

Then open the dashboard at **http://127.0.0.1:8080**.

### Sending logs to HomeSIEM
- **Router:** enable remote/syslog logging and point it at your desktop's IP,
  port `5140` (or `514`).
- **Linux/Mac:** configure `rsyslog`/`syslog-ng` to forward to the same address.
- Allow the syslog port through **Windows Defender Firewall** (inbound rule).

## Detection rules & MITRE ATT&CK

| Rule | Trigger | ATT&CK |
|------|---------|--------|
| `brute_force_login` | ≥5 failed logins from one source in 2 min | TA0006 / T1110 |
| `new_device_joined` | Unknown device appears on the LAN | TA0007 |
| `privileged_account_change` | Account created / added to privileged group | TA0003 / TA0004 |

Add your own rules in `homesiem/detection/rules.py` and register them in
`default_rules()`.

## Testing

```bash
pip install pytest
pytest
```

## Roadmap

- [ ] Windows Event Forwarding ingestion
- [ ] GeoIP enrichment for external IPs
- [ ] Sigma rule import
- [ ] Email / ntfy alert channels
- [ ] Log retention & rotation policy

## Security & privacy

This tool is intended for monitoring networks and devices **you own or are
authorized to manage**. The dashboard binds to `localhost` by default. Secrets
(the Discord webhook) live only in your local `config.yaml`, which is excluded
from version control.

## License

MIT — see [LICENSE](LICENSE).
