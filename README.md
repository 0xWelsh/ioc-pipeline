## ioc-pipeline

Go-based IoC pipeline that pulls threat indicators, deduplicates them, writes JSON for your website, and updates daily through GitHub Actions.

### What it does
- Fetches from URLhaus and FeodoTracker (abuse.ch)
- Normalizes to a single `IOC` format
- Derives domains from fetched URLs
- Deduplicates records
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

### GitHub Actions
Workflow: `.github/workflows/update.yml`

- Runs daily at `02:00 UTC`
- Runs collector
- Auto-commits updated JSON files

### Website integration
```javascript
fetch("/iocs/latest.json")
  .then((r) => r.json())
  .then((data) => console.log(data.total, data.generated_at));
```


