# Sysmon baseline configs

This folder stores **reference links and exports** for common baseline Sysmon configurations:

- **Ion-Storm** baseline
- **SwiftOnSecurity** baseline

The viewer’s Sysmon enrichment uses these baselines to:
- show “mentions” counts per Event ID / EventType
- generate copyable snippets per baseline
- assemble cart checkouts (wrapped Sysmon config)

Files of interest:
- `ion-strom_sysmonconfig-export.xml`
- `swiftonsecurity_sysmonconfig-export.xml`

If you update these exports, re-run your screenshots and validate:
- “mentions” counts still line up
- snippet rendering still produces valid XML
