#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Export event-provider metadata (Event IDs, templates, and message text) to the pipeline
  in a form that matches what you see in Event Viewer / Get-WinEvent.

.NOTES
  ProviderMetadata.Event.Id for *classic* providers is the full 32-bit EventIdentifier:
    EventIdentifier = (Qualifiers << 16) + EventId
  Event Viewer typically shows just the low 16-bit EventId.
  This script emits BOTH:
    - id              : EventId (low 16 bits, e.g. 7045)
    - event_identifier: full 32-bit EventIdentifier (e.g. 0x40001B85 = 1073748869)
    - qualifiers      : high 16 bits (e.g. 0x4000 = 16384)
#>

[CmdletBinding()]
param(
  # Include events even when the provider doesn't expose an XML template.
  [switch]$IncludeNoTemplate,

  # Enumerate ALL registered providers (can be much larger) instead of only classic EventLog registry sources.
  [switch]$AllProviders
)

function Get-ProviderMessages {
  param(
    [Parameter(Mandatory)][string]$Provider
  )

  $pm = [System.Diagnostics.Eventing.Reader.ProviderMetadata]::new($Provider)

  $pm.Events |
    Select-Object Id, Version, Level, Task, Opcode, KeywordsDisplayNames, Template, Description,
      @{Name="MessageFilePath";Expression={$_.MessageFilePath}},
      @{Name="ParameterFilePath";Expression={$_.ParameterFilePath}} |
    Sort-Object Id, Version
}

function Get-StringHash {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [AllowEmptyString()]
    [string]$InputString,
    [ValidateSet('SHA256','SHA1','SHA384','SHA512','MD5')]
    [string]$Algorithm = 'SHA256',
    [ValidateSet('UTF8','Unicode','ASCII','UTF32')]
    [string]$Encoding = 'UTF8',
    [ValidateSet('Lower','Upper')]
    [string]$HexCase = 'Lower'
  )

  begin {
    $enc = switch ($Encoding) {
      'UTF8'    { [System.Text.Encoding]::UTF8 }
      'Unicode' { [System.Text.Encoding]::Unicode }  # UTF-16LE
      'ASCII'   { [System.Text.Encoding]::ASCII }
      'UTF32'   { [System.Text.Encoding]::UTF32 }
    }
  }
  process {
    $bytes  = $enc.GetBytes($InputString)
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
      if ($hasher) { $hasher.Dispose() }
    }

    $hex = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    if ($HexCase -eq 'Upper') { $hex = $hex.ToUpperInvariant() }
    $hex
  }
}

# Build provider list
$providerRows = @()

if ($AllProviders) {
  # This enumerates all registered providers (including Applications and Services logs).
  $names = (Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name) |
           Sort-Object -Unique

  $providerRows = $names | ForEach-Object {
    [pscustomobject]@{ source = $null; providers = @($_) }
  }
}
else {
  # Classic EventLog sources (Application/System/Security/...)
  $providerRows = (Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog").PSChildName | ForEach-Object {
    $src = $_
    $providers = (Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$src" -ErrorAction SilentlyContinue).PSChildName
    [pscustomobject]@{ source = $src; providers = $providers }
  }
}

$event_msg_table = ($providerRows | Where-Object { $_.providers.Count -gt 0 }) | ForEach-Object {
  $src = $_.source
  $_.providers | ForEach-Object {
    $provider = $_
    try {
      $messages = Get-ProviderMessages -Provider $provider

      if (-not $IncludeNoTemplate) {
        $messages = $messages | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Template) }
      }

      $messages | ForEach-Object {
        # ProviderMetadata.Event.Id is sometimes the *full* EventIdentifier (classic providers).
        # Normalize to the low 16-bit EventId, and keep the full identifier & qualifiers.
        $id32        = [uint32]$_.Id
        $eventId     = $id32 -band 0xFFFF
        $qualifiers  = ($id32 -shr 16) -band 0xFFFF

        $templateStr = if ($null -eq $_.Template) { "" } else { [string]$_.Template }
        $t_hash      = $templateStr.Trim() | Get-StringHash

        [pscustomobject]@{
          id                  = [int]$eventId            # what Event Viewer / Get-WinEvent typically calls "Id"
          event_identifier    = [uint32]$id32            # full 32-bit identifier (qualifiers<<16 + id)
          qualifiers          = [int]$qualifiers
          description         = if ($null -eq $_.Description) { $null } else { [string]$_.Description.Trim([char]0) }
          keywordsdisplayNames= $_.KeywordsDisplayNames
          level               = $_.Level
          opcode              = $_.Opcode
          task                = $_.Task
          template            = $templateStr
          version             = $_.Version
          source              = $src
          provider            = $provider
          template_hash       = $t_hash
        }
      }
    }
    catch {
      # Keep errors in output but make it explicit what provider/source failed.
      [pscustomobject]@{
        source   = $src
        provider = $provider
        error    = $_.Exception.Message
      }
    }
  }
}

$event_msg_table
