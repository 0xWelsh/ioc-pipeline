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
- `new_since_last.json` - newly added IoCs since previous run
- `removed_since_last.json` - IoCs removed since previous run

### Run locally
```bash
go run ./cmd/collector/main.go
```

### GitHub Actions
Workflow: `.github/workflows/update.yml`

- Runs daily at `00:00 UTC` (midnight UTC)
- Runs collector
- Auto-commits updated JSON files

### Website integration
```javascript
fetch("/iocs/latest.json")
  .then((r) => r.json())
  .then((data) => console.log(data.total, data.generated_at));
```




### If your website files are only on local storage
GitHub Actions runs in the cloud, so it cannot write directly to files that only exist on your local machine.

Use one of these patterns:
- Keep your website in this repo (or another GitHub repo) and deploy from committed `web/public/iocs/*.json`.
- Download the `ioc-outputs` workflow artifact and copy it into your local website folder.
- Run a self-hosted GitHub runner on your machine if you need direct write access to local disk.
