## ioc-pipeline

Go-based IoC pipeline that pulls threat indicators, deduplicates them, writes JSON for your website, and updates daily through GitHub Actions.

### What it does
- Fetches from URLhaus and FeodoTracker (abuse.ch)
- Normalizes to a single `IOC` format
- Derives domains from fetched URLs
- Deduplicates records
- Optional **enrichment** (research-oriented): [VirusTotal](https://www.virustotal.com/gui/home/upload) v3 last-analysis stats + permalink, and [AlienVault OTX](https://otx.alienvault.com/) pulse metadata, community tags, and MITRE ATT&CK technique IDs when pulses include them
- Writes output to:
  - `data/processed/` (repository artifacts)
  - `web/public/iocs/` (website-consumable JSON)

### Output files
- `latest.json` - full snapshot + metadata
- `urls.json`
- `domains.json`
- `ips.json`
- `hashes.json`

### Run locally
```bash
go run ./cmd/collector/main.go
```

### Enrichment (optional)

Set API keys and limits. Only the first `ENRICH_MAX` indicators are enriched per run (priority: hash → IP → domain → URL) to stay within quotas.

| Variable | Meaning |
|----------|---------|
| `VT_API_KEY` | VirusTotal API key |
| `OTX_API_KEY` | OTX API key (free registration) |
| `ENRICH_MAX` | Max indicators to enrich (unset + keys present defaults to `12`; use `0` to disable while keys exist) |
| `ENRICH_SLEEP_MS` | Pause after each OTX call (default `2000`) |
| `VT_MIN_INTERVAL_MS` | Pause after **each VirusTotal** call (default `16000`). Free VT API allows **4 lookups/min** (~15s minimum between VT requests). |

VirusTotal URL lookups are not implemented yet (two-step API); URLs are still enriched via OTX when configured.

#### VirusTotal free “standard” API (typical limits)

Per VirusTotal’s public documentation and account dashboard, free access is usually capped around **4 lookups/minute**, **500 lookups/day**, and **~15.5k/month**, and the **standard free API must not be used in business workflows, commercial products, or commercial services**. Use your own judgment: a **personal research / hobby** site is different from a paid product or enterprise pipeline, but VT’s terms are binding on your account—read the latest terms on [virustotal.com](https://www.virustotal.com/) and upgrade if you need commercial use or higher limits.

**Never commit API keys.** If a key was pasted into chat, issues, or logs, **revoke and regenerate** it in your VirusTotal profile.

### GitHub Actions
Workflow: `.github/workflows/update.yml`

- Runs daily at `02:00 UTC`
- Runs collector
- Passes `VT_API_KEY` and `OTX_API_KEY` from repository **Secrets** (`ENRICH_MAX` / `ENRICH_SLEEP_MS` are set in the workflow file)
- Auto-commits updated JSON files

### Website integration
```javascript
fetch("/iocs/latest.json")
  .then((r) => r.json())
  .then((data) => console.log(data.total, data.generated_at));
```


