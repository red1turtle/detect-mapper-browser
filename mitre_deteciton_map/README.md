# MITRE Detection Map

This folder contains scripts and artifacts for turning MITRE ATT&CK Enterprise STIX data into a nested detection map JSON consumed by the browser UI.

## Files

- `get-mitreEnterpriseData.ps1`: downloads ATT&CK enterprise JSON into `C:\temp\enterprise_attack.json`.
- `build_detection_map.ps1`: builds the detection map JSON from a STIX JSON or ZIP bundle.
- `enterprise_attack.zip`: ATT&CK enterprise bundle archive (input option).
- `detection_map.zip`, `detection_map_dep.zip`: packaged map outputs/snapshots.

## Data model built by `build_detection_map.ps1`

Output shape:

- tactic
  - technique
    - sub-technique
    - `x_mitre_detection_strategies`
      - `x_mitre_analytics`
        - `x_mitre_log_source_references`

Relationships resolved:

- `subtechnique-of`: links sub-techniques to parent techniques.
- `detects`: links detection strategies to techniques/sub-techniques.

## How to run

```powershell
pwsh ./mitre_deteciton_map/build_detection_map.ps1 \
  -In ./mitre_deteciton_map/enterprise_attack.zip \
  -Out ./mitre_deteciton_map/detection_map.json \
  -IncludeObjectFields
```

Useful flags:

- `-IncludeRevokedDeprecated`: includes revoked/deprecated STIX objects.
- `-IncludeObjectFields`: passes through extra descriptive ATT&CK fields.

## Notes

- Input can be either plain JSON or ZIP with one JSON file.
- Script enforces strict mode and fails fast on malformed bundles.
- Final output is JSON, intended for direct loading in `detect-mapper-browser.html`.

## References

- ATT&CK STIX data repo: <https://github.com/mitre-attack/attack-stix-data>
- ATT&CK website: <https://attack.mitre.org/>
