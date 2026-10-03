# 0x41 Recon

```
 ██████╗ ██╗  ██╗██╗  ██╗ ██╗
██╔═████╗╚██╗██╔╝██║  ██║███║
██║██╔██║ ╚███╔╝ ███████║╚██║
████╔╝██║ ██╔██╗ ╚════██║ ██║
╚██████╔╝██╔╝ ██╗     ██║ ██║
 ╚═════╝ ╚═╝  ╚═╝     ╚═╝ ╚═╝
```

**Passive domain reconnaissance with AI-written analysis.**

Most recon tools hand you a raw list of hostnames. 0x41 Recon collects a domain's public footprint and then has Claude explain it in plain English: how the infrastructure is organized, what deserves a closer look, and what the owner can do about it.

> ⚠️ **Authorized use only.** 0x41 Recon is fully passive: it reads public Certificate Transparency logs and never sends traffic to the target. Even so, only assess domains you own or have permission to review.

---

## Features

- **Subdomain discovery** from Certificate Transparency logs via two sources:
  - [crt.sh](https://crt.sh) (broadest coverage, includes expired certificates)
  - [Cert Spotter](https://sslmate.com/certspotter/) (currently valid certificates, more reliable)
- **Automatic fallback:** if one source is down, the scan continues with the other
- **Merged, de-duplicated results**
- **AI analysis (optional):** Claude groups hosts by purpose, flags names worth reviewing (High / Medium / Low), suggests defensive steps, and states the limits of the data
- **Saved reports:** each AI analysis is written to `reports/<domain>_<timestamp>.md`
- **JSON export** for use in other tools

## Installation

Requires Python 3.10+.

```bash
git clone https://github.com/<your-username>/0x41-recon.git
cd 0x41-recon
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### API key (only for `--ai`)

The AI analysis uses the Claude API. Get a key at [console.anthropic.com](https://console.anthropic.com), then:

```bash
export ANTHROPIC_API_KEY="your-key-here"
```

Never commit your key. The tool reads it from the environment only.

By default the tool uses the newest Claude Sonnet model available to your key. To choose a specific model:

```bash
export CLAUDE_MODEL="model-id-here"
```

## Usage

```bash
# Subdomain discovery only (no API key needed)
python recon.py example.com

# With AI analysis + saved Markdown report
python recon.py example.com --ai

# Save raw results as JSON
python recon.py example.com --json results.json
```

### Example output

```
[*] Target: example.com
[*] Querying certificate transparency logs (crt.sh)...
[+] crt.sh: 412 certificates -> 37 hostnames
[*] Querying certificate transparency logs (Cert Spotter)...
[+] Cert Spotter: 130 certificates -> 29 hostnames

[+] 41 unique hostnames total:

    api.example.com
    status.example.com
    www.example.com
    ...

[*] Asking Claude to analyze the results...
[+] Report saved to reports/example.com_2026-10-03_0643.md
```

A report includes:

1. **Overview** of the public footprint
2. **Infrastructure layout:** hosts grouped by apparent purpose, plus naming patterns
3. **Worth reviewing:** prioritized hosts whose names suggest they may not need to be public
4. **Recommendations:** concrete defensive steps
5. **Limitations:** what passive data can and can't tell you

## How it works

```
domain ──► crt.sh ───────┐
                         ├──► merge + de-duplicate ──► terminal / JSON
domain ──► Cert Spotter ─┘                │
                                          └──► Claude (--ai) ──► Markdown report
```

Certificate Transparency (CT) is a public log of every TLS certificate issued by trusted authorities. Certificates list the hostnames they cover, so CT logs reveal subdomains an organization has requested certificates for, without touching the organization's servers.

## Project structure

```
0x41-recon/
├── recon.py              # CLI entry point
├── analysis.py           # Claude analysis layer
├── collectors/
│   ├── crtsh.py          # crt.sh collector (with retries)
│   └── certspotter.py    # Cert Spotter collector (with pagination)
├── reports/              # generated reports (git-ignored)
└── requirements.txt
```

## Limitations

- CT logs only show hosts that have had TLS certificates; hosts behind wildcard certificates or without TLS won't appear.
- A hostname appearing in CT logs doesn't mean it's currently live.
- AI analysis is based on hostnames alone. Treat its findings as leads to verify, not confirmed issues.
- crt.sh and Cert Spotter are free services and are sometimes slow or rate-limited.

## Roadmap

- [ ] Liveness checks for discovered hosts
- [ ] Scheduled monitoring with alerts on new hostnames
- [ ] Installable package (`pip install 0x41-recon`)
- [ ] Web interface

## License

MIT. See [LICENSE](LICENSE).

---

Built by **0x41**.
