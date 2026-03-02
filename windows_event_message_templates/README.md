# Windows Event Message Templates

This folder contains tooling and data snapshots for extracting Windows event provider metadata (event IDs, templates, and message text).

## Files

- `get-providerMessages.ps1`: exports provider event metadata objects.
- `message.zip`, `notemplate_message.zip`, `allprovider_notemplate_message.zip`: output packs/snapshots.

## What `get-providerMessages.ps1` exports

For each provider event, the script captures:

- normalized `id` (low 16-bit event ID)
- full `event_identifier` (32-bit)
- `qualifiers`
- `description`, `template`, level/task/opcode/keywords
- provider/source labels
- deterministic `template_hash`

It can enumerate:

- classic EventLog registry providers (default), or
- all registered providers (`-AllProviders`).

It can also include events without XML templates (`-IncludeNoTemplate`).

## How to run

```powershell
# run elevated
pwsh ./windows_event_message_templates/get-providerMessages.ps1 |
  ConvertTo-Json -Depth 8 |
  Set-Content ./windows_event_message_templates/provider_messages.json
```

## Notes

- Script uses .NET `ProviderMetadata` APIs and requires Windows.
- Error rows are returned as structured objects per provider, not silently dropped.

## References

- Event provider metadata APIs: <https://learn.microsoft.com/windows/win32/wes/eventschema-elements>
- PowerShell `Get-WinEvent`: <https://learn.microsoft.com/powershell/module/microsoft.powershell.diagnostics/get-winevent>
