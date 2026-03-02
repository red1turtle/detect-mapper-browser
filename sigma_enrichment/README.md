# Sigma Enrichment

This folder contains Sigma source archives and a PowerShell combiner that emits a single JSON Sigma pack suitable for enrichment workflows.

## Files

- `Combine-SigmaRules.ps1`: combines Sigma YAML rules from folders/ZIPs into one JSON pack.
- `sigma.combined.pack.zip`: packaged combined output snapshot.
- `sigma_all_rules.zip`, `sigma_core.zip`, `sigma_core++.zip`, `sigma-master.zip`, `sigma_emerging_threats_addon.zip`: source packs.

## What the script does

`Combine-SigmaRules.ps1`:

- Accepts one or more input paths (`-InputPath`) pointing to ZIPs/folders/files.
- Parses YAML Sigma rules (parallel parsing in PowerShell 7+).
- Groups/combines rules by log source or log source + timeframe.
- Emits `sigma.combined.pack.json` style output.
- Optionally emits YAML bundle/files and manifest metadata.

## How to run

```powershell
pwsh ./sigma_enrichment/Combine-SigmaRules.ps1 \
  -InputPath ./sigma_enrichment/sigma_all_rules.zip,./sigma_enrichment/sigma-master.zip \
  -OutputDir ./sigma_enrichment/out \
  -OutputPackFile sigma.combined.pack.json \
  -ThrottleLimit 12
```

Optional switches:

- `-WriteYamlBundle`
- `-WriteYamlFiles`
- `-WriteManifestJson`
- `-CompressJson`
- `-PassThru`

## Requirements

- PowerShell 7+ recommended for parallel parsing.
- `powershell-yaml` module (`ConvertFrom-Yaml` and `ConvertTo-Yaml`).

## References

- Sigma HQ: <https://github.com/SigmaHQ/sigma>
- Sigma rule spec: <https://sigmahq.io/>
