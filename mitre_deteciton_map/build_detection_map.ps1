<#
.SYNOPSIS
Build an ATT&CK detection map from the MITRE ATT&CK Enterprise STIX bundle.

.DESCRIPTION
Creates a nested structure:
  TACTIC > TECHNIQUE (attack-pattern) > x-mitre-detection-strategy > x-mitre-analytic > x_mitre_log_source_references

Optional enrichment:
- -IncludeObjectFields: carries common fields on techniques/strategies/analytics (description/platforms/etc).
- -IncludeDataComponentDetails: captures rich x-mitre-data-component objects referenced by analytics/log-source refs.

This version (v7) expands data-component capture to match the “flattened” view you showed:
- Adds type, x_mitre_modified_by_ref
- Adds external_references_external_id / external_references_url (aliases of mitre-attack external_id/url)
- Keeps nested x_mitre_log_sources, AND adds:
    x_mitre_log_sources_name   (array)
    x_mitre_log_sources_channel(array)

Also keeps a top-level "data_components" array containing only referenced components, with an embedded
"data_source" object (resolved via x_mitre_data_source_ref when present).

.PARAMETER In
Path to enterprise_attack.json OR enterprise_attack.zip (containing a single JSON bundle).

.PARAMETER Out
Output JSON path for the detection map.

.PARAMETER IncludeRevokedDeprecated
Include revoked/x_mitre_deprecated objects. Default: excluded.

.PARAMETER IncludeObjectFields
Pass-through extra fields from technique/strategy/analytic STIX objects.

.PARAMETER IncludeDataComponentDetails
Enrich analytics/log-source references with component identity AND add top-level data_components records.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$In,

  [Parameter(Mandatory=$true)]
  [string]$Out,

  [switch]$IncludeRevokedDeprecated,

  [switch]$IncludeObjectFields,

  [switch]$IncludeDataComponentDetails
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function HasProp { param($Obj,[string]$Name) return ($null -ne $Obj.PSObject.Properties[$Name]) }

function Get-Mitref {
  param($Obj)
  if (-not (HasProp $Obj 'external_references')) { return $null }
  foreach ($er in @($Obj.external_references)) {
    if ($er.source_name -eq 'mitre-attack' -and $er.external_id) { return [string]$er.external_id }
  }
  return $null
}

function Get-MitUrl {
  param($Obj)
  if (-not (HasProp $Obj 'external_references')) { return $null }
  foreach ($er in @($Obj.external_references)) {
    if ($er.source_name -eq 'mitre-attack' -and $er.url) { return [string]$er.url }
  }
  return $null
}

function Read-StixBundleJson {
  param([Parameter(Mandatory=$true)][string]$Path)
  if ($Path.ToLower().EndsWith('.zip')) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
      $entry = $zip.Entries | Where-Object { $_.FullName.ToLower().EndsWith('.json') } | Select-Object -First 1
      if (-not $entry) { throw "No .json file found inside zip: $Path" }
      $sr = New-Object System.IO.StreamReader($entry.Open())
      try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
    } finally { $zip.Dispose() }
  }
  return Get-Content -LiteralPath $Path -Raw
}

function Is-ActiveObject {
  param($Obj)
  if ($IncludeRevokedDeprecated) { return $true }
  $rev = (HasProp $Obj 'revoked') -and [bool]$Obj.revoked
  $dep = (HasProp $Obj 'x_mitre_deprecated') -and [bool]$Obj.x_mitre_deprecated
  return (-not $rev) -and (-not $dep)
}

function Copy-IfPresent {
  param(
    $Src,
    $Dst,                  # MUST be IDictionary (OrderedDictionary / Hashtable)
    [string[]]$FieldNames
  )
  if ($null -eq $Dst -or -not ($Dst -is [System.Collections.IDictionary])) {
    throw "Copy-IfPresent: destination must be IDictionary; got $($Dst.GetType().FullName)"
  }
  foreach ($f in $FieldNames) {
    if (HasProp $Src $f) { $Dst[$f] = $Src.$f }
  }
}

# -------------------- Load bundle --------------------
$jsonText = Read-StixBundleJson -Path $In
$bundle = $jsonText | ConvertFrom-Json -Depth 200
if (-not (HasProp $bundle 'objects')) { throw "Input does not look like a STIX bundle (missing 'objects'): $In" }

$objects = @()
foreach ($o in $bundle.objects) {
  if ($null -eq $o.type -or $null -eq $o.id) { continue }
  if (Is-ActiveObject $o) { $objects += $o }
}

# -------------------- Index by id --------------------
$byId = @{}
foreach ($o in $objects) { $byId[[string]$o.id] = $o }

# Used sets for enrichment
$dataComponentUsed = @{}  # dc_id -> $true
$dataSourceUsed = @{}     # ds_id -> $true

# -------------------- Classify objects --------------------
$tactics = $objects | Where-Object { $_.type -eq 'x-mitre-tactic' }
$attackPatterns = $objects | Where-Object { $_.type -eq 'attack-pattern' }
$parentTechniques = $attackPatterns | Where-Object { -not ((HasProp $_ 'x_mitre_is_subtechnique') -and $_.x_mitre_is_subtechnique -eq $true) }
$relationships = $objects | Where-Object { $_.type -eq 'relationship' }

# -------------------- Relationship maps --------------------
$subtechByParent = @{}                 # ParentTechniqueId -> [SubTechniqueId...]
$strategyByTargetTechnique = @{}       # TechniqueOrSubTechniqueId -> [DetectionStrategyId...]

foreach ($rel in $relationships) {
  if (-not (HasProp $rel 'relationship_type') -or -not (HasProp $rel 'source_ref') -or -not (HasProp $rel 'target_ref')) { continue }
  $rtype = [string]$rel.relationship_type
  $src = [string]$rel.source_ref
  $tgt = [string]$rel.target_ref
  switch ($rtype) {
    'subtechnique-of' {
      if (-not $subtechByParent.ContainsKey($tgt)) { $subtechByParent[$tgt] = @() }
      $subtechByParent[$tgt] += $src
    }
    'detects' {
      if (-not $strategyByTargetTechnique.ContainsKey($tgt)) { $strategyByTargetTechnique[$tgt] = @() }
      $strategyByTargetTechnique[$tgt] += $src
    }
  }
}

# -------------------- Technique -> tactics map --------------------
$techniquesByTactic = @{}  # Tactic shortname -> [TechniqueId...]
foreach ($t in $parentTechniques) {
  if (-not (HasProp $t 'kill_chain_phases')) { continue }
  foreach ($kcp in $t.kill_chain_phases) {
    if ($kcp.kill_chain_name -ne 'mitre-attack') { continue }
    $phase = [string]$kcp.phase_name
    if ([string]::IsNullOrWhiteSpace($phase)) { continue }
    if (-not $techniquesByTactic.ContainsKey($phase)) { $techniquesByTactic[$phase] = @() }
    $techniquesByTactic[$phase] += [string]$t.id
  }
}

# -------------------- Data component builders --------------------
function Build-DataSourceDetails {
  param([string]$DataSourceId)
  if ([string]::IsNullOrWhiteSpace($DataSourceId)) { return $null }
  if (-not $byId.ContainsKey($DataSourceId)) { return $null }
  $ds = $byId[$DataSourceId]
  if ($ds.type -ne 'x-mitre-data-source') { return $null }

  $ext = (Get-Mitref $ds)
  $url = (Get-MitUrl $ds)

  $node = [ordered]@{
    id = [string]$ds.id
    type = [string]$ds.type
    name = [string]$ds.name
    external_id = $ext
    url = $url
    external_references_external_id = $ext
    external_references_url = $url
  }

  Copy-IfPresent $ds $node @(
    'description',
    'x_mitre_platforms',
    'x_mitre_collection_layers',
    'x_mitre_domains',
    'x_mitre_modified_by_ref',
    'x_mitre_version',
    'x_mitre_attack_spec_version',
    'x_mitre_deprecated',
    'revoked',
    'spec_version'
  )

  return [pscustomobject]$node
}

function Build-DataComponentDetails {
  param([string]$DataComponentId)
  if ([string]::IsNullOrWhiteSpace($DataComponentId)) { return $null }
  if (-not $byId.ContainsKey($DataComponentId)) { return $null }
  $dc = $byId[$DataComponentId]
  if ($dc.type -ne 'x-mitre-data-component') { return $null }

  $ext = (Get-Mitref $dc)
  $url = (Get-MitUrl $dc)

  $node = [ordered]@{
    id = [string]$dc.id
    type = [string]$dc.type
    name = [string]$dc.name
    external_id = $ext
    url = $url
    external_references_external_id = $ext
    external_references_url = $url

    # keep nested
    x_mitre_log_sources = @()

    # flattened helpers
    x_mitre_log_sources_name = @()
    x_mitre_log_sources_channel = @()

    x_mitre_data_source_ref = $null
    data_source = $null
  }

  Copy-IfPresent $dc $node @(
    'description',
    'x_mitre_domains',
    'x_mitre_modified_by_ref',
    'x_mitre_version',
    'x_mitre_attack_spec_version',
    'x_mitre_deprecated',
    'revoked',
    'spec_version'
  )

  if (HasProp $dc 'x_mitre_log_sources') {
    $node.x_mitre_log_sources = @($dc.x_mitre_log_sources)

    $names = @()
    $channels = @()
    foreach ($ls in @($dc.x_mitre_log_sources)) {
      if ($null -ne $ls) {
        if (HasProp $ls 'name' -and $ls.name) { $names += [string]$ls.name }
        if (HasProp $ls 'channel') { $channels += $ls.channel } # preserve original (string or null)
      }
    }
    $node.x_mitre_log_sources_name = @($names | Sort-Object -Unique)
    $node.x_mitre_log_sources_channel = @($channels | Sort-Object -Unique)
  }

  if (HasProp $dc 'x_mitre_data_source_ref') {
    $dsid = [string]$dc.x_mitre_data_source_ref
    $node.x_mitre_data_source_ref = $dsid
    if (-not [string]::IsNullOrWhiteSpace($dsid)) {
      $dataSourceUsed[$dsid] = $true
      $node.data_source = Build-DataSourceDetails -DataSourceId $dsid
    }
  }

  return [pscustomobject]$node
}

# -------------------- Node builders --------------------
function Build-AnalyticNode {
  param($AnalyticId)
  $aid = [string]$AnalyticId
  if ([string]::IsNullOrWhiteSpace($aid)) { return $null }
  if (-not $byId.ContainsKey($aid)) { return $null }
  $a = $byId[$aid]
  if ($a.type -ne 'x-mitre-analytic') { return $null }

  # log source references (optionally enriched with component identity)
  $lsOut = @()
  if (HasProp $a 'x_mitre_log_source_references') {
    foreach ($lsr in @($a.x_mitre_log_source_references)) {
      $h = [ordered]@{}
      foreach ($p in $lsr.PSObject.Properties) { $h[$p.Name] = $p.Value }

      if ($IncludeDataComponentDetails -and (HasProp $lsr 'x_mitre_data_component_ref')) {
        $dcid = [string]$lsr.x_mitre_data_component_ref
        if (-not [string]::IsNullOrWhiteSpace($dcid)) {
          $dataComponentUsed[$dcid] = $true
          if ($byId.ContainsKey($dcid) -and $byId[$dcid].type -eq 'x-mitre-data-component') {
            $dcObj = $byId[$dcid]
            $h['data_component_external_id'] = (Get-Mitref $dcObj)
            $h['data_component_name'] = [string]$dcObj.name
            if (HasProp $dcObj 'x_mitre_data_source_ref') {
              $dsid = [string]$dcObj.x_mitre_data_source_ref
              if (-not [string]::IsNullOrWhiteSpace($dsid) -and $byId.ContainsKey($dsid)) {
                $dsObj = $byId[$dsid]
                if ($dsObj.type -eq 'x-mitre-data-source') {
                  $h['data_source_external_id'] = (Get-Mitref $dsObj)
                  $h['data_source_name'] = [string]$dsObj.name
                }
              }
            }
          }
        }
      }

      $lsOut += [pscustomobject]$h
    }
  }

  $node = [ordered]@{
    id = [string]$a.id
    external_id = (Get-Mitref $a)
    url = (Get-MitUrl $a)
    name = [string]$a.name
    x_mitre_log_source_references = @($lsOut)
  }

  if ($IncludeObjectFields) {
    Copy-IfPresent $a $node @('description','x_mitre_platforms','x_mitre_mutable_elements')
  }

  return [pscustomobject]$node
}

function Build-DetectionStrategyNode {
  param($StrategyId)
  $sid = [string]$StrategyId
  if ([string]::IsNullOrWhiteSpace($sid)) { return $null }
  if (-not $byId.ContainsKey($sid)) { return $null }
  $s = $byId[$sid]
  if ($s.type -ne 'x-mitre-detection-strategy') { return $null }

  $analyticsNodes = @()
  if (HasProp $s 'x_mitre_analytic_refs') {
    foreach ($ar in @($s.x_mitre_analytic_refs)) {
      $n = Build-AnalyticNode $ar
      if ($null -ne $n) { $analyticsNodes += $n }
    }
  }

  $node = [ordered]@{
    id = [string]$s.id
    external_id = (Get-Mitref $s)
    url = (Get-MitUrl $s)
    name = [string]$s.name
    x_mitre_analytics = @($analyticsNodes)
  }

  if ($IncludeObjectFields) { Copy-IfPresent $s $node @('description') }
  return [pscustomobject]$node
}

function Build-TechniqueNode {
  param($TechniqueId, [switch]$IsSubTechnique)

  $tid = [string]$TechniqueId
  if ([string]::IsNullOrWhiteSpace($tid)) { return $null }
  if (-not $byId.ContainsKey($tid)) { return $null }
  $t = $byId[$tid]
  if ($t.type -ne 'attack-pattern') { return $null }

  $stratNodes = @()
  if ($strategyByTargetTechnique.ContainsKey($tid)) {
    foreach ($sid in (($strategyByTargetTechnique[$tid] | ForEach-Object { [string]$_ }) | Where-Object { $_ } | Sort-Object -Unique)) {
      $sn = Build-DetectionStrategyNode $sid
      if ($null -ne $sn) { $stratNodes += $sn }
    }
  }

  $node = [ordered]@{
    id = [string]$t.id
    external_id = (Get-Mitref $t)
    url = (Get-MitUrl $t)
    name = [string]$t.name
    x_mitre_detection_strategies = @($stratNodes)
  }

  if ($IncludeObjectFields) {
    Copy-IfPresent $t $node @(
      'description','x_mitre_platforms','x_mitre_detection','kill_chain_phases','x_mitre_domains',
      'x_mitre_contributors','x_mitre_data_sources','x_mitre_defense_bypassed','x_mitre_permissions_required',
      'x_mitre_effective_permissions','x_mitre_system_requirements','x_mitre_remote_support','x_mitre_network_requirements',
      'x_mitre_is_subtechnique'
    )
  }

  if (-not $IsSubTechnique) {
    $subNodes = @()
    if ($subtechByParent.ContainsKey($tid)) {
      $subs = @()
      foreach ($subId in (($subtechByParent[$tid] | ForEach-Object { [string]$_ }) | Where-Object { $_ } | Sort-Object -Unique)) {
        if ($byId.ContainsKey($subId)) { $subs += $byId[$subId] }
      }
      $subs = $subs | Sort-Object { Get-Mitref $_ }, name
      foreach ($sub in $subs) {
        $sn = Build-TechniqueNode ([string]$sub.id) -IsSubTechnique
        if ($null -ne $sn) { $subNodes += $sn }
      }
    }
    $node.subtechniques = @($subNodes)
  }

  return [pscustomobject]$node
}

# -------------------- Build output --------------------
$tacticNodes = @()
foreach ($tac in ($tactics | Sort-Object x_mitre_shortname, name)) {
  $short = if (HasProp $tac 'x_mitre_shortname') { [string]$tac.x_mitre_shortname } else { '' }
  if ([string]::IsNullOrWhiteSpace($short)) { continue }

  $techNodes = @()
  if ($techniquesByTactic.ContainsKey($short)) {
    $techObjs = @()
    foreach ($tid in (($techniquesByTactic[$short] | ForEach-Object { [string]$_ }) | Where-Object { $_ } | Sort-Object -Unique)) {
      if ($byId.ContainsKey($tid)) { $techObjs += $byId[$tid] }
    }
    $techObjs = $techObjs | Sort-Object { Get-Mitref $_ }, name
    foreach ($to in $techObjs) {
      $tn = Build-TechniqueNode ([string]$to.id)
      if ($null -ne $tn) { $techNodes += $tn }
    }
  }

  $tacticNode = [ordered]@{
    id = [string]$tac.id
    external_id = (Get-Mitref $tac)
    url = (Get-MitUrl $tac)
    name = [string]$tac.name
    shortname = $short
    techniques = @($techNodes)
  }
  if ($IncludeObjectFields) { Copy-IfPresent $tac $tacticNode @('description') }

  $tacticNodes += [pscustomobject]$tacticNode
}

$outObj = [ordered]@{
  generated_at_utc = (Get-Date).ToUniversalTime().ToString('o')
  source = [ordered]@{
    input = (Resolve-Path -LiteralPath $In).Path
    include_revoked_deprecated = [bool]$IncludeRevokedDeprecated
    include_object_fields = [bool]$IncludeObjectFields
    include_data_component_details = [bool]$IncludeDataComponentDetails
  }
  tactics = @($tacticNodes)
}

if ($IncludeDataComponentDetails) {
  $dcNodes = @()
  foreach ($dcid in ($dataComponentUsed.Keys | Sort-Object)) {
    $n = Build-DataComponentDetails -DataComponentId $dcid
    if ($null -ne $n) { $dcNodes += $n }
  }
  $outObj.data_components = @($dcNodes)
}

$dir = Split-Path -Parent $Out
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }

$outJson = $outObj | ConvertTo-Json -Depth 80
Set-Content -LiteralPath $Out -Value $outJson -Encoding UTF8
Write-Host "Wrote detection map to: $Out"
