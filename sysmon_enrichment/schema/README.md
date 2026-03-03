# Sysmon schema + templates

This folder contains schema notes and XML templates used by the Sysmon enrichment “cart checkout”.

- `sysmon_wrapper_template.xml` — wraps selected snippets under `<EventFiltering>`
- `sysmon_sample_template.xml` — small example template
- `sysmon_15_shema.txt` — schema notes / reference text

If you bump Sysmon versions or want different wrapper behavior, start by editing
`sysmon_wrapper_template.xml` and confirm the resulting checkout output remains valid XML.
