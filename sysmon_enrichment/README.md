# Sysmon Enrichment

This folder hosts Sysmon-related reference material used to map detection log source hints to concrete Sysmon event schemas and configuration behavior.

## Subfolders

- `configs/`: exported Sysmon configurations and source links.
- `schema/`: Sysmon XML schema templates and notes.

## Included assets

- `Sysinternal's Sysmon.url`: upstream Sysmon reference.
- `SysmonForLinux.url`: Sysmon for Linux reference.

## How to use these assets

- Use `configs/*.xml` to understand field coverage and event selection differences between baseline configs.
- Use `schema/*.xml` template files to inspect expected event/data definitions.
- Pair with browser UI Sysmon enrichment features after loading detection map data.

## References

- Sysmon docs: <https://learn.microsoft.com/sysinternals/downloads/sysmon>
- Sysmon for Linux: <https://github.com/microsoft/SysmonForLinux>
