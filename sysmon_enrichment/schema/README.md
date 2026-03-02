# Sysmon Schema

This directory contains Sysmon schema/template artifacts used as references for event structures and field names.

## Files

- `sysmon_sample_template.xml`: sample event manifest/template content.
- `sysmon_wrapper_template.xml`: wrapper template for schema-style processing.
- `sysmon_15_shema.txt`: Sysmon 15 schema notes/text export.

## How to use

- Inspect XML `event` + `data` nodes to understand canonical field names.
- Map expected fields to detection logic and ATT&CK analytic references.
- Validate config exports against schema expectations.
