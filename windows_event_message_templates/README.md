# Windows Event message templates (WinEvent enrichment)

This folder contains tooling and snapshot packs for extracting Windows Event provider metadata
(Event IDs, providers, templates, and message text). The browser can load these packs to enrich
log-source references like `WinEventLog:Security` or `EventCode=4688`.

---

## Use in the browser

1. Open the viewer and load your detection map JSON.
2. Click **WinEvent Pack…**
3. Load one of the snapshot packs (unzipped JSON inside):
   - `message.zip` (contains `message.json`)
   - `notemplate_message.zip`
   - `allprovider_notemplate_message.zip`

<a href="../docs/screenshots/load_winmessages.png?raw=1">
  <img src="../docs/screenshots/load_winmessages.png?raw=1" width="640"/>
</a>

After loading, expand **Windows Event Enrichment** under a technique/strategy to see resolved entries:

<a href="../docs/screenshots/family_detect_winEID_strats.png?raw=1">
  <img src="../docs/screenshots/family_detect_winEID_strats.png?raw=1" width="900"/>
</a>

---

## Build the message catalog yourself (Windows only)

Script: `get-providerMessages.ps1`

What it exports per provider event:
- normalized 16-bit `id`
- full `event_identifier` (32-bit)
- `qualifiers`
- `description`, `template`, level/task/opcode/keywords
- provider/source labels
- deterministic `template_hash`

Example:
```powershell
# Run elevated (recommended)
pwsh ./windows_event_message_templates/get-providerMessages.ps1 |
  ConvertTo-Json -Depth 8 |
  Set-Content ./windows_event_message_templates/message.json
```

Optional behavior (script flags):
- enumerate all registered providers (`-AllProviders`)
- include events without XML templates (`-IncludeNoTemplate`)

---

## Notes

- Uses .NET `ProviderMetadata` APIs → **requires Windows**.
- For large provider sets, JSON output can be big; prefer ZIP for distribution.
