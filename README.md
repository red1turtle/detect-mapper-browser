# detect-mapper-browser

ATT&CK Detect Map is an offline-first toolkit and browser UI for exploring MITRE ATT&CK detection content with practical telemetry enrichment.

## What this repository contains

This repo is organized as a small pipeline:

1. **Acquire ATT&CK enterprise data** (`mitre_deteciton_map/get-mitreEnterpriseData.ps1`).
2. **Build a detection map JSON** from ATT&CK STIX objects (`mitre_deteciton_map/build_detection_map.ps1`).
3. **Optionally enrich with Sigma packs** (`sigma_enrichment/Combine-SigmaRules.ps1`).
4. **Optionally enrich with Windows event message metadata** (`windows_event_message_templates/get-providerMessages.ps1`).
5. **Explore interactively in-browser** with `detect-mapper-browser.html` (no backend required).

## Quick start

### 1) Build the detection map data

```powershell
pwsh ./mitre_deteciton_map/get-mitreEnterpriseData.ps1
pwsh ./mitre_deteciton_map/build_detection_map.ps1 \
  -In ./mitre_deteciton_map/enterprise_attack.zip \
  -Out ./mitre_deteciton_map/detection_map.json \
  -IncludeObjectFields
```

### 2) Open the browser UI

Open `detect-mapper-browser.html` directly in your browser, then use:

- **Load JSON…** to load your detection map.
- **WinEvent Pack…** to load Windows provider/event templates.
- **Sigma Pack…** to load a combined Sigma pack.

### 3) Investigate coverage

Use tactic and technique filters, global search, and object detail panes to trace:

- ATT&CK tactic → technique/sub-technique
- detection strategy
- analytics
- log source references


## Screenshot previews for docs

You can generate documentation-ready UI previews with the built-in sample archives in this repo.

1. Extract sample JSON files from the bundled ZIP artifacts:

```bash
python - <<'PY2'
import zipfile, pathlib
out = pathlib.Path('.tmp_preview')
out.mkdir(exist_ok=True)
for z in [
    'mitre_deteciton_map/detection_map.zip',
    'sigma_enrichment/sigma.combined.pack.zip',
    'windows_event_message_templates/message.zip',
]:
    with zipfile.ZipFile(z) as f:
        f.extractall(out)
print('Extracted into', out)
PY2
```

2. Serve the repository root and open `detect-mapper-browser.html`:

```bash
python -m http.server 4173
```

3. Capture screenshots with your browser automation workflow and place PNG files under `docs/screenshots/`.

Suggested scenarios and output names:

- `docs/screenshots/preview-empty.png` — fresh UI before loading data.
- `docs/screenshots/preview-loaded.png` — detection map loaded and a tactic selected.
- `docs/screenshots/preview-enriched.png` — detection map + optional packs loaded.
- `docs/screenshots/preview-winevent-enrichment.png` — technique details showing **Windows Event Enrichment** after loading `message.json`.
- `docs/screenshots/preview-sysmon-snippet-modal.png` — **Sysmon refs/snippet helper** modal for a selected Event ID.
- `docs/screenshots/preview-sysmon-cart-checkout.png` — **Sysmon snippet cart checkout** showing generated config output.
- `docs/screenshots/preview-sigma-enrichment.png` — **Sigma Rule Enrichment** card with matched rules in the details pane.
- `docs/screenshots/preview-sigma-cart.png` — **Sigma cart checkout** modal with YAML export.

### Feature gallery (documentation-friendly)

Use these image blocks in docs once screenshots are captured and saved with the filenames above.

#### Windows Event enrichment

![Windows Event enrichment card](docs/screenshots/preview-winevent-enrichment.png)

#### Sysmon snippet workflow (refs → cart → checkout)

![Sysmon snippet helper modal](docs/screenshots/preview-sysmon-snippet-modal.png)
![Sysmon snippet cart checkout](docs/screenshots/preview-sysmon-cart-checkout.png)

#### Sigma enrichment + cart

![Sigma enrichment details panel](docs/screenshots/preview-sigma-enrichment.png)
![Sigma cart checkout modal](docs/screenshots/preview-sigma-cart.png)

## Repository map

- `detect-mapper-browser.html`: standalone viewer UI.
- `mitre_deteciton_map/`: ATT&CK data retrieval + detection map build scripts.
- `sigma_enrichment/`: Sigma aggregation tooling and prebuilt archives.
- `windows_event_message_templates/`: Windows provider message extraction scripts and packs.
- `sysmon_enrichment/`: Sysmon configs and schema references used for enrichment context.

Each folder includes its own `README.md` with usage details.

## How-to guides

- Build ATT&CK detection map: see `mitre_deteciton_map/README.md`.
- Build Sigma pack from ZIP sources: see `sigma_enrichment/README.md`.
- Export Windows provider message templates: see `windows_event_message_templates/README.md`.
- Work with Sysmon config/schema assets: see `sysmon_enrichment/README.md`.

## Reference data and artifacts

This repo includes source archives (`*.zip`), exported XML templates, and `.url` pointers to upstream resources to support offline or repeatable workflows.

## Shoutouts

- MITRE ATT&CK for ATT&CK STIX data and detection strategy/analytic modeling.
- Sigma project and community maintainers for rule content and format conventions.
- SwiftOnSecurity and Ion-Storm for widely used Sysmon configuration baselines.
- Windows eventing ecosystem contributors whose provider metadata makes telemetry interpretation feasible.
