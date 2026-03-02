# Sysmon Configs

This directory contains exported Sysmon configuration snapshots and URL shortcuts to upstream baselines.

## Files

- `ion-strom_sysmonconfig-export.xml`: Ion-Storm baseline export.
- `swiftonsecurity_sysmonconfig-export.xml`: SwiftOnSecurity baseline export.
- `ion-storm - sysmon-config.url`: source URL pointer.
- `SwiftOnSecurity - sysmon-config.url`: source URL pointer.

## How-to compare configs

1. Parse both XML files and compare enabled event groups.
2. Compare included fields/rules by event ID (e.g., Event ID 1 ProcessCreate).
3. Use differences to guide telemetry tuning for your environment.

## Shoutouts

- Ion-Storm maintainers.
- SwiftOnSecurity maintainers.
