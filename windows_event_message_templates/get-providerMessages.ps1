#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Export Windows event provider metadata and optionally enrich the output with MITRE ATT&CK detection-map references.

.DESCRIPTION
  This script enumerates provider metadata exposed by Windows and outputs event definitions in a shape that is
  convenient for downstream parsing and template grouping.

  Each output row represents a provider event template and includes:
    - id                : low 16-bit Event ID as normally shown in Event Viewer
    - event_identifier  : full 32-bit EventIdentifier value exposed by ProviderMetadata
    - qualifiers        : high 16-bit qualifier bits derived from EventIdentifier
    - provider          : provider name
    - source            : preferred singular source/channel
    - sources           : all resolved source/channel values
    - template          : XML template string
    - template_hash     : SHA256 hash of the trimmed template string

  Source behavior:
    - Default mode uses classic EventLog registry roots.
    - -AllProviders enumerates all registered providers and resolves a preferred singular source from provider LogLinks.
    - The full set of candidate channels is preserved in `sources`.

  MITRE enrichment behavior:
    - When MITRE enrichment is enabled, the script loads a MITRE detection-map JSON file and builds an index of
      Windows `WinEventLog:*` references that expose EventCode/EventID values.
    - Matching is best-effort and is based on source/channel alias + event id.
    - Non-Windows references and log-source references without parseable EventCode/EventID values are skipped.
    - Application/System style mappings can be noisy because MITRE references are generally log-centric, not provider-centric.

.PARAMETER IncludeNoTemplate
  Include events even when the provider does not expose an XML template.

.PARAMETER AllProviders
  Enumerate all registered providers via Get-WinEvent -ListProvider * instead of only classic EventLog registry roots.

.PARAMETER EnrichWithMitreDetectionMap
  Enable MITRE ATT&CK detection-map enrichment.

  If this switch is used without -MitreDetectionMapPath, the script looks for detection_map.json in the same directory
  as the script file.

.PARAMETER MitreDetectionMapPath
  Path to the MITRE detection-map JSON file.

  Supplying this parameter automatically enables MITRE enrichment, even if -EnrichWithMitreDetectionMap is omitted.

.EXAMPLE
  .\get-providerMessages.ps1

  Export classic EventLog-backed providers that expose templates.

.EXAMPLE
  .\get-providerMessages.ps1 -IncludeNoTemplate |
    ConvertTo-Json -Depth 8 |
    Out-File .\notemplate_message.json -Encoding utf8

  Export classic providers, including entries with no template, then write JSON.

.EXAMPLE
  .\get-providerMessages.ps1 -AllProviders -IncludeNoTemplate |
    ConvertTo-Json -Depth 8 |
    Out-File .\allprovider_notemplate_message.json -Encoding utf8

  Export all registered providers and include entries with no template.

.EXAMPLE
  .\get-providerMessages.ps1 -AllProviders -IncludeNoTemplate -EnrichWithMitreDetectionMap -MitreDetectionMapPath .\detection_map.json |
    ConvertTo-Json -Depth 10 |
    Out-File .\allprovider_notemplate_message.mitre.json -Encoding utf8

  Export all providers and enrich matching rows with MITRE ATT&CK detection metadata.

.EXAMPLE
  Get-Help .\get-providerMessages.ps1 -Full

  Show the full help for this script.

.OUTPUTS
  PSCustomObject

.NOTES
  ProviderMetadata.Event.Id for classic providers may be the full 32-bit EventIdentifier:
    EventIdentifier = (Qualifiers << 16) + EventId

  This script emits both the low 16-bit Event ID and the full EventIdentifier.

  MITRE enrichment is intentionally conservative:
    - Only Windows WinEventLog references are indexed.
    - Only references with parseable EventCode/EventID values are matched.
    - Matches are heuristic and should be treated as enrichment, not ground truth.
#>

[CmdletBinding()]
param(
  [switch]$IncludeNoTemplate,
  [switch]$AllProviders,
  [switch]$EnrichWithMitreDetectionMap,
  [string]$MitreDetectionMapPath,
  [switch]$IncludeProviderErrors
)

function Get-ProviderMessages {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Provider
  )

  $pm = $null
  $primaryException = $null

  try {
    $pm = [System.Diagnostics.Eventing.Reader.ProviderMetadata]::new($Provider)

    return @(
      $pm.Events |
        Select-Object Id, Version, Level, Task, Opcode, KeywordsDisplayNames, Template, Description,
          @{Name = 'MessageFilePath'; Expression = { $_.MessageFilePath }},
          @{Name = 'ParameterFilePath'; Expression = { $_.ParameterFilePath }} |
        Sort-Object Id, Version
    )
  }
  catch {
    $primaryException = $_.Exception
  }
  finally {
    if ($pm -and $pm -is [System.IDisposable]) {
      $pm.Dispose()
    }
  }

  # Fallback: some providers fail ProviderMetadata construction but still resolve
  # through Get-WinEvent -ListProvider. Keep the output shape identical.
  try {
    $fallbackProvider = Get-WinEvent -ListProvider $Provider -ErrorAction Stop

    if ($null -eq $fallbackProvider -or $null -eq $fallbackProvider.Events) {
      throw "Provider '$Provider' did not expose any events through Get-WinEvent -ListProvider."
    }

    return @(
      $fallbackProvider.Events |
        Select-Object Id, Version, Level, Task, Opcode, KeywordsDisplayNames, Template, Description,
          @{Name = 'MessageFilePath'; Expression = { $_.MessageFilePath }},
          @{Name = 'ParameterFilePath'; Expression = { $_.ParameterFilePath }} |
        Sort-Object Id, Version
    )
  }
  catch {
    if ($primaryException) {
      throw $primaryException
    }

    throw
  }
}
function Get-StringHash {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [AllowEmptyString()]
    [string]$InputString,

    [ValidateSet('SHA256', 'SHA1', 'SHA384', 'SHA512', 'MD5')]
    [string]$Algorithm = 'SHA256',

    [ValidateSet('UTF8', 'Unicode', 'ASCII', 'UTF32')]
    [string]$Encoding = 'UTF8',

    [ValidateSet('Lower', 'Upper')]
    [string]$HexCase = 'Lower'
  )

  begin {
    $enc = switch ($Encoding) {
      'UTF8'    { [System.Text.Encoding]::UTF8 }
      'Unicode' { [System.Text.Encoding]::Unicode }
      'ASCII'   { [System.Text.Encoding]::ASCII }
      'UTF32'   { [System.Text.Encoding]::UTF32 }
    }
  }

  process {
    $bytes = $enc.GetBytes($InputString)
    $hasher = $null

    try {
      $hasher = switch ($Algorithm) {
        'SHA256' { [System.Security.Cryptography.SHA256]::Create() }
        'SHA1'   { [System.Security.Cryptography.SHA1]::Create() }
        'SHA384' { [System.Security.Cryptography.SHA384]::Create() }
        'SHA512' { [System.Security.Cryptography.SHA512]::Create() }
        'MD5'    { [System.Security.Cryptography.MD5]::Create() }
      }

      $hashBytes = $hasher.ComputeHash($bytes)
    }
    finally {
      if ($hasher) {
        $hasher.Dispose()
      }
    }

    $hex = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    if ($HexCase -eq 'Upper') {
      $hex = $hex.ToUpperInvariant()
    }

    $hex
  }
}

function Add-UniqueString {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[string]]$List,

    [AllowNull()]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return
  }

  if ($List -notcontains $Value) {
    $null = $List.Add($Value)
  }
}

function Add-UniqueInt {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[int]]$List,

    [Parameter(Mandatory)]
    [int]$Value
  )

  if ($List -notcontains $Value) {
    $null = $List.Add($Value)
  }
}

function Normalize-SourceToken {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return $null
  }

  $Value.Trim().ToLowerInvariant()
}

function Add-NormalizedAlias {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[string]]$List,

    [AllowNull()]
    [string]$Value
  )

  $normalized = Normalize-SourceToken -Value $Value
  if ([string]::IsNullOrWhiteSpace($normalized)) {
    return
  }

  if ($List -notcontains $normalized) {
    $null = $List.Add($normalized)
  }
}

function Add-SourceValueAliases {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.Collections.Generic.List[string]]$List,

    [AllowNull()]
    [string]$Value
  )

  if ([string]::IsNullOrWhiteSpace($Value)) {
    return
  }

  Add-NormalizedAlias -List $List -Value $Value

  foreach ($segment in @($Value -split ';')) {
    Add-NormalizedAlias -List $List -Value $segment
  }
}

function Get-ClassicProviderRows {
  [CmdletBinding()]
  param()

  (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog' -ErrorAction Stop).PSChildName |
    ForEach-Object {
      $src = $_
      $providers = @(
        (Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$src" -ErrorAction SilentlyContinue).PSChildName |
          Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
      )

      [pscustomobject]@{
        source    = $src
        sources   = @($src)
        providers = $providers
      }
    }
}

function Get-ProviderToClassicSourceMap {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object[]]$ProviderRows
  )

  $map = @{}

  foreach ($row in $ProviderRows) {
    foreach ($provider in @($row.providers)) {
      if ([string]::IsNullOrWhiteSpace($provider)) {
        continue
      }

      if (-not $map.ContainsKey($provider)) {
        $map[$provider] = [System.Collections.Generic.List[string]]::new()
      }

      Add-UniqueString -List $map[$provider] -Value $row.source
    }
  }

  $map
}

function Get-ProviderLogLinks {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Provider
  )

  $links = [System.Collections.Generic.List[string]]::new()
  $pm = $null

  try {
    $pm = [System.Diagnostics.Eventing.Reader.ProviderMetadata]::new($Provider)

    foreach ($link in @($pm.LogLinks)) {
      if ($null -eq $link) {
        continue
      }

      Add-UniqueString -List $links -Value $link.LogName
    }
  }
  catch {
    # Some providers do not expose log links cleanly. Leave empty.
  }
  finally {
    if ($pm -and $pm -is [System.IDisposable]) {
      $pm.Dispose()
    }
  }

  @($links)
}

function Resolve-ProviderSources {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Provider,
    [Parameter(Mandatory)][hashtable]$ProviderToClassicSources
  )

  $classic = [System.Collections.Generic.List[string]]::new()
  $logLinks = [System.Collections.Generic.List[string]]::new()
  $resolved = [System.Collections.Generic.List[string]]::new()

  if ($ProviderToClassicSources.ContainsKey($Provider)) {
    foreach ($value in @($ProviderToClassicSources[$Provider])) {
      Add-UniqueString -List $classic -Value $value
    }
  }

  foreach ($value in @(Get-ProviderLogLinks -Provider $Provider)) {
    Add-UniqueString -List $logLinks -Value $value
  }

  foreach ($value in @($classic)) {
    Add-UniqueString -List $resolved -Value $value
  }

  foreach ($value in @($logLinks)) {
    Add-UniqueString -List $resolved -Value $value
  }

  $preferred = $null

  if ($classic.Count -eq 1) {
    $preferred = $classic[0]
  }
  elseif ($logLinks.Count -gt 0) {
    $preferred = @($logLinks | Where-Object { $_ -match '/Operational$' } | Select-Object -First 1)[0]

    if ([string]::IsNullOrWhiteSpace($preferred)) {
      $preferred = @($logLinks | Where-Object { $_ -match '/Admin$' } | Select-Object -First 1)[0]
    }

    if ([string]::IsNullOrWhiteSpace($preferred)) {
      $preferred = $logLinks[0]
    }
  }
  elseif ($classic.Count -gt 0) {
    $preferred = $classic[0]
  }

  [pscustomobject]@{
    source          = $preferred
    sources         = if ($resolved.Count -gt 0) { @($resolved) } else { $null }
    log_links       = if ($logLinks.Count -gt 0) { @($logLinks) } else { $null }
    classic_sources = if ($classic.Count -gt 0) { @($classic) } else { $null }
  }
}

function Resolve-MitreDetectionMapPath {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Path,
    [switch]$EnableMitreEnrichment
  )

  if (-not $EnableMitreEnrichment -and [string]::IsNullOrWhiteSpace($Path)) {
    return $null
  }

  $resolved = $Path

  if ([string]::IsNullOrWhiteSpace($resolved)) {
    $resolved = Join-Path -Path $PSScriptRoot -ChildPath 'detection_map.json'
  }

  try {
    $item = Get-Item -LiteralPath $resolved -ErrorAction Stop
    return $item.FullName
  }
  catch {
    throw "MITRE detection-map file not found: $resolved"
  }
}

function Get-MitreEventIdsFromChannelText {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$ChannelText
  )

  $ids = [System.Collections.Generic.List[int]]::new()

  if ([string]::IsNullOrWhiteSpace($ChannelText)) {
    return @()
  }

  $regexOptions = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
  $patterns = @(
    '\b(?:Event(?:\s+IDs?|\s+Codes?)|Event(?:Code|ID)|EIDs?)\b[^0-9]{0,16}([0-9][0-9,\s;/-]*(?:\s+(?:and|or|to)\s+[0-9][0-9,\s;/-]*)*)',
    '\b(?:Event(?:Code|ID)|EID)\b\s*[:=]\s*([0-9][0-9,\s;/-]*)',
    '\b(?:Event(?:Code|ID)|EID)\b\s+([0-9][0-9,\s;/-]*)'
  )

  foreach ($pattern in $patterns) {
    foreach ($match in [System.Text.RegularExpressions.Regex]::Matches($ChannelText, $pattern, $regexOptions)) {
      if (-not $match.Success) {
        continue
      }

      $rawValue = $match.Groups[1].Value
      if ([string]::IsNullOrWhiteSpace($rawValue)) {
        continue
      }

      $normalized = $rawValue `
        -replace '(?i)\b(?:and|or)\b', ',' `
        -replace '(?i)\bto\b', '-' `
        -replace '[;/]', ','

      foreach ($token in @($normalized -split ',')) {
        $value = $token.Trim()
        if ([string]::IsNullOrWhiteSpace($value)) {
          continue
        }

        if ($value -match '^(\d+)$') {
          Add-UniqueInt -List $ids -Value ([int]$Matches[1])
          continue
        }

        if ($value -match '^(\d+)\s*-\s*(\d+)$') {
          $start = [int]$Matches[1]
          $end = [int]$Matches[2]
          if ($end -ge $start -and ($end - $start) -le 512) {
            foreach ($i in $start..$end) {
              Add-UniqueInt -List $ids -Value $i
            }
          }
          continue
        }

        foreach ($embedded in [System.Text.RegularExpressions.Regex]::Matches($value, '\d+')) {
          if ($embedded.Success) {
            Add-UniqueInt -List $ids -Value ([int]$embedded.Value)
          }
        }
      }
    }
  }

  @($ids)
}

function Get-MitreWindowsLogSourceAliases {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$ReferenceName
  )

  $aliases = [System.Collections.Generic.List[string]]::new()

  if ([string]::IsNullOrWhiteSpace($ReferenceName)) {
    return @()
  }

  if ($ReferenceName -notmatch '^(?i)WinEventLog:(.+)$') {
    return @()
  }

  $logName = $Matches[1].Trim()

  switch ($logName.ToLowerInvariant()) {
    'security' {
      foreach ($value in @('Security', 'Microsoft-Windows-Security-Auditing')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'system' {
      foreach ($value in @('System')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'application' {
      foreach ($value in @('Application')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'powershell' {
      foreach ($value in @('PowerShell', 'Windows PowerShell', 'Microsoft-Windows-PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-PowerShell/Admin')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'sysmon' {
      foreach ($value in @('Sysmon', 'Microsoft-Windows-Sysmon', 'Microsoft-Windows-Sysmon/Operational')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'wmi' {
      foreach ($value in @('WMI', 'Microsoft-Windows-WMI-Activity', 'Microsoft-Windows-WMI-Activity/Operational')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'kerberos' {
      foreach ($value in @('Kerberos', 'Security', 'Microsoft-Windows-Security-Auditing', 'Microsoft-Windows-Security-Kerberos', 'Microsoft-Windows-Kerberos-Key-Distribution-Center')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'taskscheduler' {
      foreach ($value in @('TaskScheduler', 'Task Scheduler', 'Microsoft-Windows-TaskScheduler', 'Microsoft-Windows-TaskScheduler/Operational')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'windows defender' {
      foreach ($value in @('Windows Defender', 'Microsoft-Windows-Windows Defender', 'Microsoft-Windows-Windows Defender/Operational')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'winrm' {
      foreach ($value in @('WinRM', 'Microsoft-Windows-WinRM', 'Microsoft-Windows-WinRM/Operational')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    'iis' {
      foreach ($value in @('IIS', 'WinEventLog:iis')) {
        Add-NormalizedAlias -List $aliases -Value $value
      }
      break
    }
    default {
      Add-NormalizedAlias -List $aliases -Value $logName

      if ($logName -like 'Microsoft-Windows-*') {
        Add-NormalizedAlias -List $aliases -Value $logName

        if ($logName -notmatch '/') {
          Add-NormalizedAlias -List $aliases -Value "$logName/Operational"
          Add-NormalizedAlias -List $aliases -Value "$logName/Admin"
        }
      }
      elseif ($logName -notin @('Application', 'Security', 'System')) {
        Add-NormalizedAlias -List $aliases -Value "Microsoft-Windows-$logName"
        Add-NormalizedAlias -List $aliases -Value "Microsoft-Windows-$logName/Operational"
        Add-NormalizedAlias -List $aliases -Value "Microsoft-Windows-$logName/Admin"
      }
    }
  }

  @($aliases)
}

function Add-MitreIndexEntry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Index,
    [Parameter(Mandatory)][string]$SourceAlias,
    [Parameter(Mandatory)][int]$EventId,
    [Parameter(Mandatory)][psobject]$Entry
  )

  $key = '{0}|{1}' -f $SourceAlias, $EventId

  if (-not $Index.ContainsKey($key)) {
    $Index[$key] = New-Object System.Collections.ArrayList
  }

  $exists = $false
  foreach ($existing in @($Index[$key])) {
    if ($existing.signature -eq $Entry.signature) {
      $exists = $true
      break
    }
  }

  if (-not $exists) {
    [void]$Index[$key].Add($Entry)
  }
}

function Test-MitreAliasIntersection {
  [CmdletBinding()]
  param(
    [AllowNull()][string[]]$Left,
    [AllowNull()][string[]]$Right
  )

  foreach ($leftValue in @($Left)) {
    if ([string]::IsNullOrWhiteSpace($leftValue)) {
      continue
    }

    if (@($Right) -contains $leftValue) {
      return $true
    }
  }

  $false
}

function Get-MitreDataComponentContext {
  [CmdletBinding()]
  param(
    [AllowNull()][psobject]$Reference,
    [AllowNull()][hashtable]$DataComponentLookup
  )

  if ($null -eq $Reference -or $null -eq $DataComponentLookup) {
    return $null
  }

  $dataComponentId = $null
  if ($Reference.PSObject.Properties.Name -contains 'data_component_external_id') {
    $dataComponentId = [string]$Reference.data_component_external_id
  }

  if ([string]::IsNullOrWhiteSpace($dataComponentId)) {
    return $null
  }

  if (-not $DataComponentLookup.ContainsKey($dataComponentId)) {
    return $null
  }

  $dataComponent = $DataComponentLookup[$dataComponentId]
  if ($null -eq $dataComponent) {
    return $null
  }

  [pscustomobject]@{
    data_component_id          = $dataComponentId
    data_component_name        = $dataComponent.name
    data_component_url         = $dataComponent.url
    data_component_description = if ($dataComponent.PSObject.Properties.Name -contains 'description' -and -not [string]::IsNullOrWhiteSpace([string]$dataComponent.description)) { [string]$dataComponent.description } else { $null }
    data_component_log_sources = if ($dataComponent.PSObject.Properties.Name -contains 'x_mitre_log_sources' -and @($dataComponent.x_mitre_log_sources | Where-Object { $null -ne $_ }).Count -gt 0) { @($dataComponent.x_mitre_log_sources | Where-Object { $null -ne $_ } | ForEach-Object { [pscustomobject]@{ name = $_.name; channel = $_.channel } }) } else { $null }
  }
}

function Get-MitreSupplementalReferenceMappings {
  [CmdletBinding()]
  param(
    [AllowNull()][psobject]$Reference,
    [AllowNull()][hashtable]$DataComponentLookup
  )

  if ($null -eq $Reference -or $null -eq $DataComponentLookup) {
    return @()
  }

  $dataComponentId = $null
  if ($Reference.PSObject.Properties.Name -contains 'data_component_external_id') {
    $dataComponentId = [string]$Reference.data_component_external_id
  }

  if ([string]::IsNullOrWhiteSpace($dataComponentId)) {
    return @()
  }

  if (-not $DataComponentLookup.ContainsKey($dataComponentId)) {
    return @()
  }

  $dataComponent = $DataComponentLookup[$dataComponentId]
  if ($null -eq $dataComponent) {
    return @()
  }

  $referenceAliases = @(Get-MitreWindowsLogSourceAliases -ReferenceName $Reference.name)
  $preferred = New-Object System.Collections.ArrayList
  $fallback = New-Object System.Collections.ArrayList

  foreach ($logSource in @($dataComponent.x_mitre_log_sources | Where-Object { $null -ne $_ })) {
    $aliases = @(Get-MitreWindowsLogSourceAliases -ReferenceName $logSource.name)
    if ($aliases.Count -eq 0) {
      continue
    }

    $eventIds = @(Get-MitreEventIdsFromChannelText -ChannelText $logSource.channel)
    if ($eventIds.Count -eq 0) {
      continue
    }

    $mapping = [pscustomobject]@{
      mapping_origin     = 'data_component_log_source'
      reference_name     = $logSource.name
      reference_channel  = $logSource.channel
      aliases            = if ($aliases.Count -gt 0) { @($aliases) } else { @() }
      event_ids          = if ($eventIds.Count -gt 0) { @($eventIds) } else { @() }
      preferred_for_ref  = (Test-MitreAliasIntersection -Left $referenceAliases -Right $aliases)
    }

    if ($mapping.preferred_for_ref) {
      [void]$preferred.Add($mapping)
    }
    else {
      [void]$fallback.Add($mapping)
    }
  }

  if ($preferred.Count -gt 0) {
    return @($preferred)
  }

  if ($fallback.Count -gt 0) {
    return @($fallback)
  }

  $descriptionEventIds = @(Get-MitreEventIdsFromChannelText -ChannelText $dataComponent.description)
  if ($descriptionEventIds.Count -gt 0 -and $referenceAliases.Count -gt 0) {
    return @(
      [pscustomobject]@{
        mapping_origin     = 'data_component_description'
        reference_name     = $Reference.name
        reference_channel  = $dataComponent.description
        aliases            = @($referenceAliases)
        event_ids          = @($descriptionEventIds)
        preferred_for_ref  = $true
      }
    )
  }

  @()
}

function Add-MitreTechniqueEntries {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][psobject]$Technique,
    [AllowNull()][psobject]$ParentTechnique,
    [Parameter(Mandatory)][psobject]$Tactic,
    [Parameter(Mandatory)][hashtable]$Index,
    [AllowNull()][hashtable]$DataComponentLookup
  )

  if ($null -eq $Technique) {
    return
  }

  $techniqueId = $Technique.external_id
  $techniqueName = $Technique.name
  $subtechniqueId = $null
  $subtechniqueName = $null

  if ($Technique.x_mitre_is_subtechnique -and $ParentTechnique) {
    $techniqueId = $ParentTechnique.external_id
    $techniqueName = $ParentTechnique.name
    $subtechniqueId = $Technique.external_id
    $subtechniqueName = $Technique.name
  }

  foreach ($strategy in @($Technique.x_mitre_detection_strategies | Where-Object { $null -ne $_ })) {
    foreach ($analytic in @($strategy.x_mitre_analytics | Where-Object { $null -ne $_ })) {
      $platforms = @($analytic.x_mitre_platforms | Where-Object { $null -ne $_ })
      $refs = @($analytic.x_mitre_log_source_references | Where-Object { $null -ne $_ })

      if ($refs.Count -eq 0) {
        continue
      }

      foreach ($ref in @($refs | Where-Object { $null -ne $_ })) {
        $mappings = New-Object System.Collections.ArrayList
        $directAliases = @(Get-MitreWindowsLogSourceAliases -ReferenceName $ref.name)
        $directEventIds = @(Get-MitreEventIdsFromChannelText -ChannelText $ref.channel)

        if ($directAliases.Count -gt 0 -and $directEventIds.Count -gt 0) {
          [void]$mappings.Add([pscustomobject]@{
            mapping_origin    = 'analytic_log_source_reference'
            reference_name    = $ref.name
            reference_channel = $ref.channel
            aliases           = @($directAliases)
            event_ids         = @($directEventIds)
          })
        }

        if ($directAliases.Count -gt 0 -and $directEventIds.Count -eq 0) {
          foreach ($supplemental in @(Get-MitreSupplementalReferenceMappings -Reference $ref -DataComponentLookup $DataComponentLookup)) {
            [void]$mappings.Add($supplemental)
          }
        }

        if ($mappings.Count -eq 0) {
          continue
        }

        $dataComponentContext = Get-MitreDataComponentContext -Reference $ref -DataComponentLookup $DataComponentLookup

        foreach ($mapping in @($mappings)) {
          $aliases = @($mapping.aliases | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
          $eventIds = @($mapping.event_ids | Where-Object { $null -ne $_ })

          if ($aliases.Count -eq 0 -or $eventIds.Count -eq 0) {
            continue
          }

          $entry = [pscustomobject]@{
            signature                          = '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}|{8}' -f $Tactic.external_id, $techniqueId, $subtechniqueId, $strategy.external_id, $analytic.external_id, $ref.data_component_external_id, $mapping.reference_name, $mapping.reference_channel, $mapping.mapping_origin
            tactic_id                          = $Tactic.external_id
            tactic_name                        = $Tactic.name
            tactic_url                         = $Tactic.url
            technique_id                       = $techniqueId
            technique_name                     = $techniqueName
            technique_url                      = if ($Technique.x_mitre_is_subtechnique -and $ParentTechnique) { $ParentTechnique.url } else { $Technique.url }
            subtechnique_id                    = $subtechniqueId
            subtechnique_name                  = $subtechniqueName
            subtechnique_url                   = if ($Technique.x_mitre_is_subtechnique) { $Technique.url } else { $null }
            detection_strategy_id              = $strategy.external_id
            detection_strategy_name            = $strategy.name
            detection_strategy_url             = $strategy.url
            detection_strategy_description     = if ($strategy.PSObject.Properties.Name -contains 'description' -and -not [string]::IsNullOrWhiteSpace([string]$strategy.description)) { [string]$strategy.description } elseif (-not [string]::IsNullOrWhiteSpace([string]$analytic.description)) { [string]$analytic.description } else { $null }
            analytic_id                        = $analytic.external_id
            analytic_name                      = $analytic.name
            analytic_url                       = $analytic.url
            analytic_description               = if (-not [string]::IsNullOrWhiteSpace([string]$analytic.description)) { [string]$analytic.description } else { $null }
            analytic_mutable_elements          = if ($analytic.PSObject.Properties.Name -contains 'x_mitre_mutable_elements' -and @($analytic.x_mitre_mutable_elements | Where-Object { $null -ne $_ }).Count -gt 0) { @($analytic.x_mitre_mutable_elements | Where-Object { $null -ne $_ } | ForEach-Object { [pscustomobject]@{ field = $_.field; description = $_.description } }) } else { $null }
            data_component_id                  = $ref.data_component_external_id
            data_component_name                = $ref.data_component_name
            data_component_ref                 = if ($ref.PSObject.Properties.Name -contains 'x_mitre_data_component_ref') { $ref.x_mitre_data_component_ref } else { $null }
            data_component_url                 = if ($null -ne $dataComponentContext) { $dataComponentContext.data_component_url } else { $null }
            data_component_description         = if ($null -ne $dataComponentContext) { $dataComponentContext.data_component_description } else { $null }
            data_component_log_sources         = if ($null -ne $dataComponentContext) { $dataComponentContext.data_component_log_sources } else { $null }
            mitre_log_source                   = $mapping.reference_name
            mitre_channel                      = $mapping.reference_channel
            analytic_log_source_reference_name = $ref.name
            analytic_log_source_reference_channel = $ref.channel
            mitre_mapping_origin               = $mapping.mapping_origin
            platforms                          = if ($platforms.Count -gt 0) { @($platforms) } else { $null }
          }

          foreach ($alias in $aliases) {
            foreach ($eventId in $eventIds) {
              Add-MitreIndexEntry -Index $Index -SourceAlias $alias -EventId $eventId -Entry $entry
            }
          }
        }
      }
    }
  }

  foreach ($subtechnique in @($Technique.subtechniques | Where-Object { $null -ne $_ })) {
    Add-MitreTechniqueEntries -Technique $subtechnique -ParentTechnique $Technique -Tactic $Tactic -Index $Index -DataComponentLookup $DataComponentLookup
  }
}

function Get-MitreDetectionIndex {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
  $map = $raw | ConvertFrom-Json
  $index = @{}
  $dataComponentLookup = @{}

  foreach ($dataComponent in @($map.data_components | Where-Object { $null -ne $_ })) {
    if ($dataComponent.PSObject.Properties.Name -contains 'external_id' -and -not [string]::IsNullOrWhiteSpace([string]$dataComponent.external_id)) {
      $dataComponentLookup[[string]$dataComponent.external_id] = $dataComponent
    }
  }

  foreach ($tactic in @($map.tactics | Where-Object { $null -ne $_ })) {
    foreach ($technique in @($tactic.techniques | Where-Object { $null -ne $_ })) {
      Add-MitreTechniqueEntries -Technique $technique -ParentTechnique $null -Tactic $tactic -Index $index -DataComponentLookup $dataComponentLookup
    }
  }

  [pscustomobject]@{
    path                 = $Path
    index                = $index
    data_component_count = $dataComponentLookup.Count
  }
}

function Get-EventSourceAliases {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$Source,
    [AllowNull()][string[]]$Sources,
    [AllowNull()][string[]]$LogLinks,
    [AllowNull()][string[]]$ClassicSources,
    [AllowNull()][string]$Provider
  )

  $aliases = [System.Collections.Generic.List[string]]::new()

  Add-SourceValueAliases -List $aliases -Value $Source

  foreach ($value in @($Sources)) {
    Add-SourceValueAliases -List $aliases -Value $value
  }

  foreach ($value in @($LogLinks)) {
    Add-SourceValueAliases -List $aliases -Value $value
  }

  foreach ($value in @($ClassicSources)) {
    Add-SourceValueAliases -List $aliases -Value $value
  }

  Add-SourceValueAliases -List $aliases -Value $Provider

  if (-not [string]::IsNullOrWhiteSpace($Provider)) {
    Add-SourceValueAliases -List $aliases -Value "$Provider/Operational"
    Add-SourceValueAliases -List $aliases -Value "$Provider/Admin"
  }

  @($aliases)
}


function New-MitreEmptyResult {
  [CmdletBinding()]
  param()

  [pscustomobject]@{
    mitre_match_count              = 0
    mitre_tactic_ids               = $null
    mitre_tactic_names             = $null
    mitre_technique_ids            = $null
    mitre_technique_names          = $null
    mitre_subtechnique_ids         = $null
    mitre_subtechnique_names       = $null
    mitre_detection_strategy_count = 0
    mitre_detection_strategy_ids   = $null
    mitre_detection_strategy_names = $null
    mitre_analytic_ids             = $null
    mitre_analytic_names           = $null
    mitre_data_component_ids       = $null
    mitre_data_component_names     = $null
    mitre_detection_strategies     = $null
    mitre_matches                  = $null
  }
}

function Get-MitreDetectionStrategyGroups {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [psobject[]]$Matches
  )

  if ($null -eq $Matches -or @($Matches).Count -eq 0) {
    return $null
  }

  $strategyStates = @{}
  $strategyOrder = New-Object System.Collections.ArrayList

  foreach ($match in @($Matches | Where-Object { $null -ne $_ })) {
    $strategyKey = '{0}|{1}|{2}|{3}' -f $match.tactic_id, $match.technique_id, $match.subtechnique_id, $match.detection_strategy_id

    if (-not $strategyStates.ContainsKey($strategyKey)) {
      $strategyOutput = [ordered]@{
        tactic_id                      = $match.tactic_id
        tactic_name                    = $match.tactic_name
        tactic_url                     = $match.tactic_url
        technique_id                   = $match.technique_id
        technique_name                 = $match.technique_name
        technique_url                  = $match.technique_url
        subtechnique_id                = $match.subtechnique_id
        subtechnique_name              = $match.subtechnique_name
        subtechnique_url               = $match.subtechnique_url
        detection_strategy_id          = $match.detection_strategy_id
        detection_strategy_name        = $match.detection_strategy_name
        detection_strategy_url         = $match.detection_strategy_url
        detection_strategy_description = $match.detection_strategy_description
        data_component_ids             = $null
        data_component_names           = $null
        analytics                      = @()
      }

      $strategyStates[$strategyKey] = [pscustomobject]@{
        output             = $strategyOutput
        analytics          = @{}
        dataComponentIds   = [System.Collections.Generic.List[string]]::new()
        dataComponentNames = [System.Collections.Generic.List[string]]::new()
      }

      [void]$strategyOrder.Add($strategyStates[$strategyKey])
    }

    $strategyState = $strategyStates[$strategyKey]
    Add-UniqueString -List $strategyState.dataComponentIds -Value $match.data_component_id
    Add-UniqueString -List $strategyState.dataComponentNames -Value $match.data_component_name

    $analyticKey = '{0}' -f $match.analytic_id
    if (-not $strategyState.analytics.ContainsKey($analyticKey)) {
      $analyticOutput = [ordered]@{
        analytic_id               = $match.analytic_id
        analytic_name             = $match.analytic_name
        analytic_url              = $match.analytic_url
        analytic_description      = $match.analytic_description
        analytic_mutable_elements = $match.analytic_mutable_elements
        platforms                 = $match.platforms
        log_source_references     = @()
      }

      $strategyState.analytics[$analyticKey] = [pscustomobject]@{
        output = $analyticOutput
        refs   = [System.Collections.Generic.HashSet[string]]::new()
      }

      $strategyState.output['analytics'] += [pscustomobject]$analyticOutput
    }

    $analyticState = $strategyState.analytics[$analyticKey]
    $refKey = '{0}|{1}|{2}|{3}|{4}' -f $match.mitre_log_source, $match.mitre_channel, $match.data_component_id, $match.data_component_ref, $match.mitre_mapping_origin

    if ($analyticState.refs.Add($refKey)) {
      $analyticState.output.log_source_references += [pscustomobject]@{
        data_component_id                     = $match.data_component_id
        data_component_name                   = $match.data_component_name
        data_component_ref                    = $match.data_component_ref
        data_component_url                    = $match.data_component_url
        data_component_description            = $match.data_component_description
        mitre_log_source                      = $match.mitre_log_source
        mitre_channel                         = $match.mitre_channel
        analytic_log_source_reference_name    = $match.analytic_log_source_reference_name
        analytic_log_source_reference_channel = $match.analytic_log_source_reference_channel
        mitre_mapping_origin                  = $match.mitre_mapping_origin
      }
    }
  }

  $output = @()

  foreach ($strategyState in @($strategyOrder)) {
    $strategyState.output['data_component_ids'] = if ($strategyState.dataComponentIds.Count -gt 0) { @($strategyState.dataComponentIds) } else { $null }
    $strategyState.output['data_component_names'] = if ($strategyState.dataComponentNames.Count -gt 0) { @($strategyState.dataComponentNames) } else { $null }
    $output += [pscustomobject]$strategyState.output
  }

  @($output)
}

function Get-MitreMatchesForEvent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int]$EventId,
    [AllowNull()][string]$Source,
    [AllowNull()][string[]]$Sources,
    [AllowNull()][string[]]$LogLinks,
    [AllowNull()][string[]]$ClassicSources,
    [AllowNull()][string]$Provider,
    [Parameter(Mandatory)][hashtable]$MitreIndex
  )

  $aliases = @(Get-EventSourceAliases -Source $Source -Sources $Sources -LogLinks $LogLinks -ClassicSources $ClassicSources -Provider $Provider)
  $result = New-Object System.Collections.ArrayList
  $seen = [System.Collections.Generic.HashSet[string]]::new()

  foreach ($alias in $aliases) {
    $key = '{0}|{1}' -f $alias, $EventId
    if (-not $MitreIndex.ContainsKey($key)) {
      continue
    }

    foreach ($entry in @($MitreIndex[$key])) {
      if ($seen.Add($entry.signature)) {
        [void]$result.Add($entry)
      }
    }
  }

  $matches = @($result | ForEach-Object {
    [pscustomobject]@{
      tactic_id                           = $_.tactic_id
      tactic_name                         = $_.tactic_name
      tactic_url                          = $_.tactic_url
      technique_id                        = $_.technique_id
      technique_name                      = $_.technique_name
      technique_url                       = $_.technique_url
      subtechnique_id                     = $_.subtechnique_id
      subtechnique_name                   = $_.subtechnique_name
      subtechnique_url                    = $_.subtechnique_url
      detection_strategy_id               = $_.detection_strategy_id
      detection_strategy_name             = $_.detection_strategy_name
      detection_strategy_url              = $_.detection_strategy_url
      detection_strategy_description      = $_.detection_strategy_description
      analytic_id                         = $_.analytic_id
      analytic_name                       = $_.analytic_name
      analytic_url                        = $_.analytic_url
      analytic_description                = $_.analytic_description
      analytic_mutable_elements           = $_.analytic_mutable_elements
      data_component_id                   = $_.data_component_id
      data_component_name                 = $_.data_component_name
      data_component_ref                  = $_.data_component_ref
      data_component_url                  = $_.data_component_url
      data_component_description          = $_.data_component_description
      data_component_log_sources          = $_.data_component_log_sources
      mitre_log_source                    = $_.mitre_log_source
      mitre_channel                       = $_.mitre_channel
      analytic_log_source_reference_name  = $_.analytic_log_source_reference_name
      analytic_log_source_reference_channel = $_.analytic_log_source_reference_channel
      mitre_mapping_origin                = $_.mitre_mapping_origin
      platforms                           = $_.platforms
    }
  })

  if ($matches.Count -eq 0) {
    return New-MitreEmptyResult
  }

  $tacticIds = [System.Collections.Generic.List[string]]::new()
  $tacticNames = [System.Collections.Generic.List[string]]::new()
  $techniqueIds = [System.Collections.Generic.List[string]]::new()
  $techniqueNames = [System.Collections.Generic.List[string]]::new()
  $subtechniqueIds = [System.Collections.Generic.List[string]]::new()
  $subtechniqueNames = [System.Collections.Generic.List[string]]::new()
  $detectionStrategyIds = [System.Collections.Generic.List[string]]::new()
  $detectionStrategyNames = [System.Collections.Generic.List[string]]::new()
  $analyticIds = [System.Collections.Generic.List[string]]::new()
  $analyticNames = [System.Collections.Generic.List[string]]::new()
  $dataComponentIds = [System.Collections.Generic.List[string]]::new()
  $dataComponentNames = [System.Collections.Generic.List[string]]::new()

  foreach ($match in $matches) {
    Add-UniqueString -List $tacticIds -Value $match.tactic_id
    Add-UniqueString -List $tacticNames -Value $match.tactic_name
    Add-UniqueString -List $techniqueIds -Value $match.technique_id
    Add-UniqueString -List $techniqueNames -Value $match.technique_name
    Add-UniqueString -List $subtechniqueIds -Value $match.subtechnique_id
    Add-UniqueString -List $subtechniqueNames -Value $match.subtechnique_name
    Add-UniqueString -List $detectionStrategyIds -Value $match.detection_strategy_id
    Add-UniqueString -List $detectionStrategyNames -Value $match.detection_strategy_name
    Add-UniqueString -List $analyticIds -Value $match.analytic_id
    Add-UniqueString -List $analyticNames -Value $match.analytic_name
    Add-UniqueString -List $dataComponentIds -Value $match.data_component_id
    Add-UniqueString -List $dataComponentNames -Value $match.data_component_name
  }

  $strategyGroups = @(Get-MitreDetectionStrategyGroups -Matches $matches)

  [pscustomobject]@{
    mitre_match_count              = $matches.Count
    mitre_tactic_ids               = if ($tacticIds.Count -gt 0) { @($tacticIds) } else { $null }
    mitre_tactic_names             = if ($tacticNames.Count -gt 0) { @($tacticNames) } else { $null }
    mitre_technique_ids            = if ($techniqueIds.Count -gt 0) { @($techniqueIds) } else { $null }
    mitre_technique_names          = if ($techniqueNames.Count -gt 0) { @($techniqueNames) } else { $null }
    mitre_subtechnique_ids         = if ($subtechniqueIds.Count -gt 0) { @($subtechniqueIds) } else { $null }
    mitre_subtechnique_names       = if ($subtechniqueNames.Count -gt 0) { @($subtechniqueNames) } else { $null }
    mitre_detection_strategy_count = if ($strategyGroups.Count -gt 0) { $strategyGroups.Count } else { 0 }
    mitre_detection_strategy_ids   = if ($detectionStrategyIds.Count -gt 0) { @($detectionStrategyIds) } else { $null }
    mitre_detection_strategy_names = if ($detectionStrategyNames.Count -gt 0) { @($detectionStrategyNames) } else { $null }
    mitre_analytic_ids             = if ($analyticIds.Count -gt 0) { @($analyticIds) } else { $null }
    mitre_analytic_names           = if ($analyticNames.Count -gt 0) { @($analyticNames) } else { $null }
    mitre_data_component_ids       = if ($dataComponentIds.Count -gt 0) { @($dataComponentIds) } else { $null }
    mitre_data_component_names     = if ($dataComponentNames.Count -gt 0) { @($dataComponentNames) } else { $null }
    mitre_detection_strategies     = if ($strategyGroups.Count -gt 0) { $strategyGroups } else { $null }
    mitre_matches                  = $matches
  }
}


$mitreMapResolvedPath = Resolve-MitreDetectionMapPath -Path $MitreDetectionMapPath -EnableMitreEnrichment:$EnrichWithMitreDetectionMap
$mitreEnabled = -not [string]::IsNullOrWhiteSpace($mitreMapResolvedPath)
$mitreIndex = $null

if ($mitreEnabled) {
  $mitreIndex = (Get-MitreDetectionIndex -Path $mitreMapResolvedPath).index
}

# Build the classic EventLog mapping once so it can also be reused by -AllProviders.
$classicProviderRows = @(Get-ClassicProviderRows)
$providerToClassicSources = Get-ProviderToClassicSourceMap -ProviderRows $classicProviderRows

# Build provider list
$providerRows = @()

if ($AllProviders) {
  $names = @(
    Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty Name |
      Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
      Sort-Object -Unique
  )

  $providerRows = $names | ForEach-Object {
    $provider = $_
    $resolvedSource = Resolve-ProviderSources -Provider $provider -ProviderToClassicSources $providerToClassicSources

    [pscustomobject]@{
      source          = $resolvedSource.source
      sources         = $resolvedSource.sources
      log_links       = $resolvedSource.log_links
      classic_sources = $resolvedSource.classic_sources
      providers       = @($provider)
    }
  }
}
else {
  $providerRows = $classicProviderRows | ForEach-Object {
    [pscustomobject]@{
      source          = $_.source
      sources         = $_.sources
      log_links       = $null
      classic_sources = $_.sources
      providers       = $_.providers
    }
  }
}

$event_msg_table = ($providerRows | Where-Object { $_.providers.Count -gt 0 }) | ForEach-Object {
  $src = $_.source
  $sources = if ($null -eq $_.sources) { $null } else { @($_.sources) }
  $logLinks = if ($null -eq $_.log_links) { $null } else { @($_.log_links) }
  $classicSources = if ($null -eq $_.classic_sources) { $null } else { @($_.classic_sources) }

  $_.providers | ForEach-Object {
    $provider = $_

    try {
      $messages = Get-ProviderMessages -Provider $provider

      if (-not $IncludeNoTemplate) {
        $messages = $messages | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Template) }
      }

      $messages | ForEach-Object {
        $id32 = [uint32]$_.Id
        $eventId = $id32 -band 0xFFFF
        $qualifiers = ($id32 -shr 16) -band 0xFFFF

        $templateStr = if ($null -eq $_.Template) { '' } else { [string]$_.Template }
        $t_hash = $templateStr.Trim() | Get-StringHash

        $baseProps = [ordered]@{
          id                   = [int]$eventId
          event_identifier     = [uint32]$id32
          qualifiers           = [int]$qualifiers
          description          = if ($null -eq $_.Description) { $null } else { [string]$_.Description.Trim([char]0) }
          keywordsdisplayNames = $_.KeywordsDisplayNames
          level                = $_.Level
          opcode               = $_.Opcode
          task                 = $_.Task
          template             = $templateStr
          version              = $_.Version
          source               = $src
          sources              = $sources
          log_links            = $logLinks
          classic_sources      = $classicSources
          provider             = $provider
          template_hash        = $t_hash
        }

        if ($mitreEnabled) {
          $mitre = Get-MitreMatchesForEvent -EventId ([int]$eventId) -Source $src -Sources $sources -LogLinks $logLinks -ClassicSources $classicSources -Provider $provider -MitreIndex $mitreIndex
          $baseProps['mitre_match_count'] = $mitre.mitre_match_count
          $baseProps['mitre_tactic_ids'] = $mitre.mitre_tactic_ids
          $baseProps['mitre_tactic_names'] = $mitre.mitre_tactic_names
          $baseProps['mitre_technique_ids'] = $mitre.mitre_technique_ids
          $baseProps['mitre_technique_names'] = $mitre.mitre_technique_names
          $baseProps['mitre_subtechnique_ids'] = $mitre.mitre_subtechnique_ids
          $baseProps['mitre_subtechnique_names'] = $mitre.mitre_subtechnique_names
          $baseProps['mitre_detection_strategy_count'] = $mitre.mitre_detection_strategy_count
          $baseProps['mitre_detection_strategy_ids'] = $mitre.mitre_detection_strategy_ids
          $baseProps['mitre_detection_strategy_names'] = $mitre.mitre_detection_strategy_names
          $baseProps['mitre_analytic_ids'] = $mitre.mitre_analytic_ids
          $baseProps['mitre_analytic_names'] = $mitre.mitre_analytic_names
          $baseProps['mitre_data_component_ids'] = $mitre.mitre_data_component_ids
          $baseProps['mitre_data_component_names'] = $mitre.mitre_data_component_names
          $baseProps['mitre_detection_strategies'] = $mitre.mitre_detection_strategies
          $baseProps['mitre_matches'] = $mitre.mitre_matches
        }

        [pscustomobject]$baseProps
      }
    }
    catch {
      $providerErrorMessage = $_.Exception.Message

      if ($IncludeProviderErrors) {
        $errorProps = [ordered]@{
          source          = $src
          sources         = $sources
          log_links       = $logLinks
          classic_sources = $classicSources
          provider        = $provider
          error           = $providerErrorMessage
        }

        if ($mitreEnabled) {
          $errorProps['mitre_match_count'] = 0
          $errorProps['mitre_tactic_ids'] = $null
          $errorProps['mitre_tactic_names'] = $null
          $errorProps['mitre_technique_ids'] = $null
          $errorProps['mitre_technique_names'] = $null
          $errorProps['mitre_subtechnique_ids'] = $null
          $errorProps['mitre_subtechnique_names'] = $null
          $errorProps['mitre_detection_strategy_count'] = 0
          $errorProps['mitre_detection_strategy_ids'] = $null
          $errorProps['mitre_detection_strategy_names'] = $null
          $errorProps['mitre_analytic_ids'] = $null
          $errorProps['mitre_analytic_names'] = $null
          $errorProps['mitre_data_component_ids'] = $null
          $errorProps['mitre_data_component_names'] = $null
          $errorProps['mitre_detection_strategies'] = $null
          $errorProps['mitre_matches'] = $null
        }

        [pscustomobject]$errorProps
      }
      else {
        Write-Verbose ("Skipping provider '{0}' because metadata enumeration failed: {1}" -f $provider, $providerErrorMessage)
      }
    }
  }
}

$event_msg_table
