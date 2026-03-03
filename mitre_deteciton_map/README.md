# MITRE detection map

This folder contains scripts and snapshots for turning **MITRE ATT&CK Enterprise STIX** into the nested *detection map JSON* consumed by the browser UI.

If you just want to *use* the viewer, you can start with the snapshot:
- `detection_map.zip` → `detection_map.json`

If you want to *regenerate* the map (new ATT&CK release, include extra fields, include revoked/deprecated), use the PowerShell scripts.

---

## Outputs

- `detection_map.json` (generated) — the file loaded by `detect-mapper-browser.html`
- `detection_map.zip` — snapshot packaging of the JSON
- `detection_map_dep.zip` — snapshot that includes revoked/deprecated objects (if built that way)

The generated JSON forms this hierarchy:

**TACTIC → TECHNIQUE → SUB-TECHNIQUE → Detection Strategies → Analytics → Log Source References**

---

## Build / regenerate the detection map

### 1) Get the ATT&CK Enterprise STIX bundle

Option A — download a pinned version via the helper script:
```powershell
pwsh ./mitre_deteciton_map/get-mitreEnterpriseData.ps1
# writes: .\enterprise_attack.json  (script uses C:\temp as a working dir)
```

Option B — use the included snapshot:
- `enterprise_attack.zip`

### 2) Build the detection map JSON

```powershell
pwsh ./mitre_deteciton_map/build_detection_map.ps1 `
  -In  ./mitre_deteciton_map/enterprise_attack.zip `
  -Out ./mitre_deteciton_map/detection_map.json `
  -IncludeObjectFields
```

Useful switches:
- `-IncludeObjectFields` — pass through descriptions, platforms, detection text, and add convenience `url` fields.
- `-IncludeRevokedDeprecated` — include revoked / deprecated objects (default is excluded).

### 3) Load it in the browser

Serve the repo and open:

```
http://localhost:8080/detect-mapper-browser.html?src=mitre_deteciton_map/detection_map.json
```

<a href="../docs/screenshots/loaded_detection_map.png">
  <img src="../docs/screenshots/loaded_detection_map.png" width="900"/>
</a>

---

## Notes / troubleshooting

- The build script reads `enterprise_attack.json` directly **or** a ZIP containing a single JSON bundle.
- If your output is missing extra fields, ensure you used `-IncludeObjectFields` (it is off by default).
