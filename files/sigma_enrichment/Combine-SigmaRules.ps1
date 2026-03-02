<#
.SYNOPSIS
  Combine Sigma YAML rules and emit a single JSON "pack" (sigma.pack.json-style). Optional YAML outputs.
  (PowerShell 7+ supports parallel YAML parsing; falls back to sequential on Windows PowerShell 5.1)

.DESCRIPTION
  Outputs:
    - A single JSON pack file (sigma.pack.json-style) containing ALL combined rules.
    - Optionally: a single multi-document YAML bundle with ALL combined rules.
    - Optionally: per-combined-rule YAML files.

  Noise:
    - By default, prints only a short summary at the end.
    - Use -VerboseBuild to print per-output build lines.

  Parallelism:
    - Parsing YAML is the dominant cost; in PowerShell 7+, this script parses in parallel
      using ForEach-Object -Parallel (controlled via -ThrottleLimit).
    - On Windows PowerShell 5.1, the script automatically falls back to sequential parsing.

.REQUIREMENTS
  Install-Module powershell-yaml -Scope CurrentUser

.EXAMPLES
  # JSON pack only (single file)
  & .\Combine-SigmaRules_Pack_v5.ps1 -InputPath .\sigma_all_rules.zip, .\sigma-master.zip -OutputDir .\out -ThrottleLimit 12

  # JSON pack + single YAML bundle
  & .\Combine-SigmaRules_Pack_v5.ps1 -InputPath .\sigma_all_rules.zip, .\sigma-master.zip -OutputDir .\out -ThrottleLimit 12 -WriteYamlBundle

  # Capture pack objects (can be huge)
  $data = & .\Combine-SigmaRules_Pack_v5.ps1 -InputPath .\sigma_all_rules.zip, .\sigma-master.zip -OutputDir .\out -PassThru
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string[]] $InputPath,

  [Parameter()]
  [string] $OutputDir = (Join-Path -Path (Get-Location) -ChildPath 'out'),

  [Parameter()]
  [string] $OutputPackFile = 'sigma.combined.pack.json',

  [Parameter()]
  [string] $OutputYamlBundleFile = 'sigma.combined.bundle.yml',

  [Parameter()]
  [ValidateSet('Logsource','LogsourceAndTimeframe')]
  [string] $GroupBy = 'LogsourceAndTimeframe',

  # 0 = unlimited (NOT recommended for very large logsource categories)
  [Parameter()]
  [int] $MaxRulesPerCombined = 250,

  # Parallelism for parsing YAML files (PowerShell 7+ only)
  [Parameter()]
  [ValidateRange(1,128)]
  [int] $ThrottleLimit = 8,

  [Parameter()]
  [switch] $WriteYamlFiles,

  [Parameter()]
  [switch] $WriteYamlBundle,

  [Parameter()]
  [switch] $CompressJson,

  [Parameter()]
  [switch] $WriteManifestJson,

  # Print per-output "Built:" lines (debug)
  [Parameter()]
  [switch] $VerboseBuild,

  # Emit the pack array to pipeline (off by default to avoid huge output)
  [Parameter()]
  [switch] $PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-YamlModule {
  if (-not (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)) {
    throw "Missing YAML cmdlets. Install: Install-Module powershell-yaml -Scope CurrentUser"
  }
  if (-not (Get-Command ConvertTo-Yaml -ErrorAction SilentlyContinue)) {
    throw "Missing YAML cmdlets. Install: Install-Module powershell-yaml -Scope CurrentUser"
  }
}

function Resolve-OutputDir {
  param([Parameter(Mandatory)][string] $PathIn)

  $p = [Environment]::ExpandEnvironmentVariables($PathIn)

  # PowerShell quirk: "\out" is rooted at the current drive root (e.g. "C:\out"), not relative.
  if ($p.StartsWith('\') -and -not $p.StartsWith('\\') -and -not ($p -match '^[A-Za-z]:\\')) {
    $driveRoot = (Get-Location).Drive.Root
    $full = Join-Path $driveRoot $p.TrimStart('\')
    Write-Warning "OutputDir '$PathIn' resolves to '$full' (drive root). If you meant a folder under the current directory, use '.\out'."
    return $full
  }

  if (-not [System.IO.Path]::IsPathRooted($p)) {
    return (Join-Path -Path (Get-Location) -ChildPath $p)
  }

  return $p
}

function Get-YamlValue {
  param(
    $Obj,
    [Parameter(Mandatory)][string] $Key
  )

  if ($null -eq $Obj) { return $null }

  if ($Obj -is [System.Collections.IDictionary]) {
    try { if ($Obj.Contains($Key)) { return $Obj[$Key] } } catch {
      try { if ($Obj.Keys -contains $Key) { return $Obj[$Key] } } catch { }
    }
    return $null
  }

  $p = $Obj.PSObject.Properties[$Key]
  if ($p) { return $p.Value }

  return $null
}

function Get-HTValueOrNull {
  param(
    [Parameter(Mandatory)] $HT,
    [Parameter(Mandatory)][string] $Key
  )

  if ($null -eq $HT) { return $null }
  if ($HT -isnot [System.Collections.IDictionary]) { return $null }

  try { if ($HT.Contains($Key)) { return $HT[$Key] } } catch {
    try { if ($HT.Keys -contains $Key) { return $HT[$Key] } } catch { }
  }

  return $null
}

function Get-HTArrayOrEmpty {
  param(
    [Parameter(Mandatory)] $HT,
    [Parameter(Mandatory)][string] $Key
  )

  $v = Get-HTValueOrNull -HT $HT -Key $Key
  if ($null -eq $v) { return @() }

  if ($v -is [string]) { return @($v) }
  if ($v -is [System.Collections.IEnumerable]) { return @($v) }

  return @($v)
}

function ConvertTo-HashtableDeep {
  param([AllowNull()] $Obj)

  if ($null -eq $Obj) { return $null }

  if ($Obj -is [string] -or $Obj.GetType().IsPrimitive) { return $Obj }

  if ($Obj -is [System.Collections.IDictionary]) {
    $h = @{}
    foreach ($k in $Obj.Keys) { $h[[string]$k] = ConvertTo-HashtableDeep $Obj[$k] }
    return $h
  }

  if ($Obj -is [System.Collections.IEnumerable] -and $Obj -isnot [string]) {
    $arr = @()
    foreach ($item in $Obj) { $arr += ,(ConvertTo-HashtableDeep $item) }
    return $arr
  }

  $props = $Obj.PSObject.Properties
  if ($props -and $props.Count -gt 0) {
    $h = @{}
    foreach ($p in $props) { $h[[string]$p.Name] = ConvertTo-HashtableDeep $p.Value }
    return $h
  }

  return $Obj
}

function ConvertFrom-YamlSafe {
  param([Parameter(Mandatory)][string] $YamlText)

  $cmd = Get-Command ConvertFrom-Yaml
  $hasAllDocs = $cmd.Parameters.ContainsKey('AllDocuments')
  $hasYamlParam = $cmd.Parameters.ContainsKey('Yaml')

  try {
    if ($hasAllDocs -and $hasYamlParam) { return @(ConvertFrom-Yaml -Yaml $YamlText -AllDocuments) }
    if ($hasYamlParam) { return @((ConvertFrom-Yaml -Yaml $YamlText)) }
    return @(($YamlText | ConvertFrom-Yaml))
  }
  catch {
    $parts = $YamlText -split "(?m)^\s*---\s*$" | Where-Object { $_.Trim() }
    $objs = New-Object System.Collections.Generic.List[object]
    foreach ($p in $parts) {
      try {
        if ($hasYamlParam) { $objs.Add((ConvertFrom-Yaml -Yaml $p)) }
        else { $objs.Add(($p | ConvertFrom-Yaml)) }
      } catch { }
    }
    return @($objs)
  }
}

function ConvertTo-YamlSafe {
  param([Parameter(Mandatory)][object] $Data)

  $cmd = Get-Command ConvertTo-Yaml
  if ($cmd.Parameters.ContainsKey('Data')) { return (ConvertTo-Yaml -Data $Data) }
  if ($cmd.Parameters.ContainsKey('InputObject')) { return (ConvertTo-Yaml -InputObject $Data) }
  return ($Data | ConvertTo-Yaml)
}

function Try-ParseDate {
  param([object] $Value)
  if ($null -eq $Value) { return $null }

  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  [datetime] $dt = [datetime]::MinValue
  if ([datetime]::TryParse($s, [ref]$dt)) { return $dt }
  return $null
}

function Get-RuleRecency {
  param([Parameter(Mandatory)] $Rule)

  $m = Try-ParseDate (Get-YamlValue $Rule 'modified')
  if ($m) { return $m }

  $d = Try-ParseDate (Get-YamlValue $Rule 'date')
  if ($d) { return $d }

  return [datetime]::MinValue
}

function Get-LogsourceKey {
  param([Parameter(Mandatory)] $Rule)

  $ls = ConvertTo-HashtableDeep (Get-YamlValue $Rule 'logsource')
  if ($null -eq $ls) { return 'cat=|prod=|svc=' }

  $cat = [string](Get-YamlValue $ls 'category')
  $prod = [string](Get-YamlValue $ls 'product')
  $svc = [string](Get-YamlValue $ls 'service')

  return "cat=$cat|prod=$prod|svc=$svc"
}

function Get-GroupKey {
  param(
    [Parameter(Mandatory)] $Rule,
    [Parameter(Mandatory)][string] $GroupByMode
  )

  $lsKey = Get-LogsourceKey $Rule
  if ($GroupByMode -eq 'Logsource') { return $lsKey }

  $tf = ''
  $det = ConvertTo-HashtableDeep (Get-YamlValue $Rule 'detection')
  if ($det) { $tf = [string](Get-YamlValue $det 'timeframe') }

  return "$lsKey|tf=$tf"
}

function Get-LevelRank {
  param([string] $Level)
  switch (($Level ?? '').ToLowerInvariant()) {
    'critical' { return 4 }
    'high'     { return 3 }
    'medium'   { return 2 }
    'low'      { return 1 }
    default    { return 0 }
  }
}

function Rank-ToLevel {
  param([int] $Rank)
  switch ($Rank) {
    4 { 'critical' }
    3 { 'high' }
    2 { 'medium' }
    1 { 'low' }
    default { 'unknown' }
  }
}

function Prefix-Condition {
  param(
    [Parameter(Mandatory)][string] $Condition,
    [Parameter(Mandatory)][hashtable] $KeyMap,   # oldKey -> newKey
    [Parameter(Mandatory)][string] $Prefix
  )

  $out = $Condition

  $keys = $KeyMap.Keys | Sort-Object Length -Descending
  foreach ($old in $keys) {
    $new = [string]$KeyMap[$old]
    $escaped = [regex]::Escape($old)
    $out = [regex]::Replace(
      $out,
      "(?<![A-Za-z0-9_-])$escaped(?![A-Za-z0-9_-])",
      [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $new }
    )
  }

  $out = [regex]::Replace(
    $out,
    "(?<![A-Za-z0-9_-])([A-Za-z0-9_-]+\*)(?![A-Za-z0-9_-])",
    [System.Text.RegularExpressions.MatchEvaluator]{
      param($m)
      $token = $m.Groups[1].Value
      if ($token.StartsWith("$Prefix" + "_")) { return $token }
      return "$Prefix" + "_" + $token
    }
  )

  return $out
}

function Get-ShortHash8 {
  param([Parameter(Mandatory)][string] $Text)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  $sha1 = [System.Security.Cryptography.SHA1]::Create()
  try { $hash = $sha1.ComputeHash($bytes) } finally { $sha1.Dispose() }
  return ([System.BitConverter]::ToString($hash) -replace '-', '').Substring(0,8).ToLowerInvariant()
}

function Sanitize-FileName {
  param(
    [Parameter(Mandatory)][string] $Name,
    [int] $MaxLen = 120
  )

  if ([string]::IsNullOrWhiteSpace($Name)) { return 'unnamed' }

  $out = $Name
  $invalid = [System.IO.Path]::GetInvalidFileNameChars()
  foreach ($c in $invalid) { $out = $out.Replace([string]$c, '_') }
  foreach ($c in @(' ',':',';','|','/','\','?','*','"','<','>')) { $out = $out.Replace([string]$c, '_') }

  $out = $out -replace '\.+$', ''
  $out = $out.Trim().TrimEnd('.')
  $out = $out -replace '_{2,}', '_'
  $out = $out.Trim('_')

  if ([string]::IsNullOrWhiteSpace($out)) { $out = 'unnamed' }

  $reserved = @('CON','PRN','AUX','NUL',
                'COM1','COM2','COM3','COM4','COM5','COM6','COM7','COM8','COM9',
                'LPT1','LPT2','LPT3','LPT4','LPT5','LPT6','LPT7','LPT8','LPT9')
  if ($reserved -contains $out.ToUpperInvariant()) { $out = "_$out" }

  if ($out.Length -gt $MaxLen) {
    $h = Get-ShortHash8 $out
    $keep = [Math]::Max(1, $MaxLen - 9)
    $out = $out.Substring(0, $keep) + '_' + $h
    $out = $out.Trim('_')
  }

  return $out
}

function Build-AttackFromTags {
  param([AllowNull()] [object[]] $Tags)

  $techSet = New-Object System.Collections.Generic.HashSet[string]
  $tacticNameSet = New-Object System.Collections.Generic.HashSet[string]
  $prefixSet = New-Object System.Collections.Generic.HashSet[string]

  foreach ($t in @($Tags)) {
    if ($null -eq $t) { continue }
    $s = [string]$t
    if (-not $s.StartsWith('attack.')) { continue }

    if ($s -match '^attack\.t(\d{4})(\.\d{3})?$') {
      $tech = ('T' + $Matches[1] + ($Matches[2] ?? ''))
      [void]$techSet.Add($tech)
      [void]$prefixSet.Add(('T' + $Matches[1]))
      continue
    }

    $name = $s.Substring(7)
    if (-not [string]::IsNullOrWhiteSpace($name)) { [void]$tacticNameSet.Add($name) }
  }

  return [ordered]@{
    techniques = @(@($techSet) | Sort-Object)
    tactics = @()
    tactic_names = @(@($tacticNameSet) | Sort-Object)
    technique_prefixes = @(@($prefixSet) | Sort-Object)
  }
}

function Normalize-Logsource {
  param([AllowNull()] $Logsource)

  $ls = ConvertTo-HashtableDeep $Logsource
  if ($null -eq $ls) { $ls = @{} }

  $out = [ordered]@{
    category = $null
    product = $null
    service = $null
    definition = $null
  }

  foreach ($k in @('category','product','service','definition')) {
    $v = Get-YamlValue $ls $k
    if ($null -ne $v) { $out[$k] = $v }
  }

  return $out
}

Assert-YamlModule

$ResolvedOutputDir = Resolve-OutputDir $OutputDir
New-Item -ItemType Directory -Path $ResolvedOutputDir -Force | Out-Null

$ResolvedPackPath = $OutputPackFile
if (-not [System.IO.Path]::IsPathRooted($ResolvedPackPath)) {
  $ResolvedPackPath = Join-Path $ResolvedOutputDir $ResolvedPackPath
}

$ResolvedYamlBundlePath = $OutputYamlBundleFile
if (-not [System.IO.Path]::IsPathRooted($ResolvedYamlBundlePath)) {
  $ResolvedYamlBundlePath = Join-Path $ResolvedOutputDir $ResolvedYamlBundlePath
}

$tempRoot = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("sigma_merge_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

try {
  # Expand input roots
  $roots = New-Object System.Collections.Generic.List[string]
  foreach ($p in $InputPath) {
    $rp = (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path

    if ((Test-Path -LiteralPath $rp -PathType Leaf) -and $rp.ToLowerInvariant().EndsWith('.zip')) {
      $dest = Join-Path $tempRoot ([System.IO.Path]::GetFileNameWithoutExtension($rp))
      New-Item -ItemType Directory -Path $dest -Force | Out-Null
      Expand-Archive -LiteralPath $rp -DestinationPath $dest -Force
      $roots.Add($dest) | Out-Null
    }
    elseif (Test-Path -LiteralPath $rp -PathType Container) {
      $roots.Add($rp) | Out-Null
    }
    else {
      Write-Warning "Skipping unsupported input: $p"
    }
  }

  $files = foreach ($r in $roots) {
    Get-ChildItem -LiteralPath $r -Recurse -File -Include *.yml, *.yaml -ErrorAction SilentlyContinue
  }
  $files = @($files)
  $totalYamlFiles = $files.Count

  # Parse step (parallel on PS7+, sequential otherwise)
  $parsed = @()

  if ($PSVersionTable.PSVersion.Major -ge 7 -and (Get-Command ForEach-Object).Parameters.ContainsKey('Parallel')) {
    $parsed = $files | ForEach-Object -Parallel {
      Import-Module powershell-yaml -ErrorAction Stop

      function ConvertTo-HashtableDeepLocal {
        param([AllowNull()] $Obj)
        if ($null -eq $Obj) { return $null }
        if ($Obj -is [string] -or $Obj.GetType().IsPrimitive) { return $Obj }
        if ($Obj -is [System.Collections.IDictionary]) {
          $h = @{}
          foreach ($k in $Obj.Keys) { $h[[string]$k] = ConvertTo-HashtableDeepLocal $Obj[$k] }
          return $h
        }
        if ($Obj -is [System.Collections.IEnumerable] -and $Obj -isnot [string]) {
          $arr = @()
          foreach ($item in $Obj) { $arr += ,(ConvertTo-HashtableDeepLocal $item) }
          return $arr
        }
        $props = $Obj.PSObject.Properties
        if ($props -and $props.Count -gt 0) {
          $h = @{}
          foreach ($p in $props) { $h[[string]$p.Name] = ConvertTo-HashtableDeepLocal $p.Value }
          return $h
        }
        return $Obj
      }

      function Get-YamlValueLocal {
        param($Obj, [Parameter(Mandatory)][string] $Key)
        if ($null -eq $Obj) { return $null }
        if ($Obj -is [System.Collections.IDictionary]) {
          try { if ($Obj.Contains($Key)) { return $Obj[$Key] } } catch {
            try { if ($Obj.Keys -contains $Key) { return $Obj[$Key] } } catch { }
          }
          return $null
        }
        $p = $Obj.PSObject.Properties[$Key]
        if ($p) { return $p.Value }
        return $null
      }

      function Try-ParseDateLocal {
        param([object] $Value)
        if ($null -eq $Value) { return $null }
        $s = [string]$Value
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        [datetime] $dt = [datetime]::MinValue
        if ([datetime]::TryParse($s, [ref]$dt)) { return $dt }
        return $null
      }

      function Get-RuleRecencyLocal {
        param([Parameter(Mandatory)] $Rule)
        $m = Try-ParseDateLocal (Get-YamlValueLocal $Rule 'modified')
        if ($m) { return $m }
        $d = Try-ParseDateLocal (Get-YamlValueLocal $Rule 'date')
        if ($d) { return $d }
        return [datetime]::MinValue
      }

      function ConvertFrom-YamlSafeLocal {
        param([Parameter(Mandatory)][string] $YamlText)

        $cmd = Get-Command ConvertFrom-Yaml
        $hasAllDocs = $cmd.Parameters.ContainsKey('AllDocuments')
        $hasYamlParam = $cmd.Parameters.ContainsKey('Yaml')

        try {
          if ($hasAllDocs -and $hasYamlParam) { return @(ConvertFrom-Yaml -Yaml $YamlText -AllDocuments) }
          if ($hasYamlParam) { return @((ConvertFrom-Yaml -Yaml $YamlText)) }
          return @(($YamlText | ConvertFrom-Yaml))
        }
        catch {
          $parts = $YamlText -split "(?m)^\s*---\s*$" | Where-Object { $_.Trim() }
          $objs = New-Object System.Collections.Generic.List[object]
          foreach ($p in $parts) {
            try {
              if ($hasYamlParam) { $objs.Add((ConvertFrom-Yaml -Yaml $p)) }
              else { $objs.Add(($p | ConvertFrom-Yaml)) }
            } catch { }
          }
          return @($objs)
        }
      }

      $fileFullName = $_.FullName
      try {
        $raw = Get-Content -LiteralPath $fileFullName -Raw -ErrorAction Stop

        if ($raw -notmatch "(?mi)^\s*(title|logsource|detection)\s*:") { return }
        if ($raw -notmatch "(?mi)^\s*detection\s*:") { return }

        $docs = ConvertFrom-YamlSafeLocal -YamlText $raw
        foreach ($doc in @($docs)) {
          if ($null -eq $doc) { continue }

          $rule = ConvertTo-HashtableDeepLocal $doc
          if ($rule -isnot [hashtable] -and $rule -isnot [System.Collections.IDictionary]) { continue }

          $title = Get-YamlValueLocal $rule 'title'
          $logsource = Get-YamlValueLocal $rule 'logsource'
          $detection = Get-YamlValueLocal $rule 'detection'
          if ($null -eq $title -or $null -eq $logsource -or $null -eq $detection) { continue }

          $id = [string](Get-YamlValueLocal $rule 'id')
          $recency = Get-RuleRecencyLocal $rule

          [pscustomobject]@{
            Kind    = 'Rule'
            Id      = $id
            Recency = $recency
            Rule    = $rule
            Source  = $fileFullName
          }
        }
      }
      catch {
        [pscustomobject]@{
          Kind = 'Error'
          File = $fileFullName
          Message = ($_.Exception.Message)
        }
      }
    } -ThrottleLimit $ThrottleLimit
    $parsed = @($parsed)
  }
  else {
    if ($ThrottleLimit -gt 1) {
      Write-Warning "Parallel parsing requires PowerShell 7+. Falling back to sequential parsing (your PS version: $($PSVersionTable.PSVersion))."
    }

    foreach ($f in $files) {
      $fileFullName = $f.FullName
      try {
        $raw = Get-Content -LiteralPath $fileFullName -Raw -ErrorAction Stop
        if ($raw -notmatch "(?mi)^\s*(title|logsource|detection)\s*:") { continue }
        if ($raw -notmatch "(?mi)^\s*detection\s*:") { continue }

        $docs = ConvertFrom-YamlSafe -YamlText $raw
        foreach ($doc in @($docs)) {
          if ($null -eq $doc) { continue }
          $rule = ConvertTo-HashtableDeep $doc
          if ($rule -isnot [hashtable] -and $rule -isnot [System.Collections.IDictionary]) { continue }

          $title = Get-YamlValue $rule 'title'
          $logsource = Get-YamlValue $rule 'logsource'
          $detection = Get-YamlValue $rule 'detection'
          if ($null -eq $title -or $null -eq $logsource -or $null -eq $detection) { continue }

          $id = [string](Get-YamlValue $rule 'id')
          $recency = Get-RuleRecency $rule

          $parsed += [pscustomobject]@{
            Kind    = 'Rule'
            Id      = $id
            Recency = $recency
            Rule    = $rule
            Source  = $fileFullName
          }
        }
      }
      catch {
        $parsed += [pscustomobject]@{
          Kind = 'Error'
          File = $fileFullName
          Message = ($_.Exception.Message)
        }
      }
    }
  }

  $parseErrors = @($parsed | Where-Object { $_.Kind -eq 'Error' }).Count
  $ruleEntries = @($parsed | Where-Object { $_.Kind -eq 'Rule' })

  # Dedupe by id (sequential)
  $byId = @{}  # id -> entry
  $noId = New-Object System.Collections.Generic.List[object]
  foreach ($entry in $ruleEntries) {
    $id = [string]$entry.Id
    if (-not [string]::IsNullOrWhiteSpace($id)) {
      if ($byId.ContainsKey($id)) {
        if ($entry.Recency -gt $byId[$id].Recency) { $byId[$id] = $entry }
      } else {
        $byId[$id] = $entry
      }
    } else {
      $noId.Add($entry) | Out-Null
    }
  }

  $rulesAll = New-Object System.Collections.Generic.List[object]
  foreach ($kv in $byId.GetEnumerator()) { $rulesAll.Add($kv.Value) | Out-Null }
  foreach ($x in $noId) { $rulesAll.Add($x) | Out-Null }

  # Group rules (sequential)
  $groups = @{} # groupKey -> List[object]
  foreach ($entry in $rulesAll) {
    $gk = Get-GroupKey -Rule $entry.Rule -GroupByMode $GroupBy
    if (-not $groups.ContainsKey($gk)) { $groups[$gk] = New-Object System.Collections.Generic.List[object] }
    $groups[$gk].Add($entry) | Out-Null
  }

  $pack = New-Object System.Collections.Generic.List[object]
  $manifest = New-Object System.Collections.Generic.List[object]
  $yamlBundleDocs = New-Object System.Collections.Generic.List[string]

  foreach ($gk in ($groups.Keys | Sort-Object)) {
    $entries = $groups[$gk]
    $sorted = @($entries | Sort-Object -Property Recency -Descending)

    # chunking
    $chunks = @()
    if ($MaxRulesPerCombined -le 0 -or $sorted.Count -le $MaxRulesPerCombined) {
      $chunks = @(@($sorted))
    } else {
      for ($i = 0; $i -lt $sorted.Count; $i += $MaxRulesPerCombined) {
        $end = [Math]::Min($i + $MaxRulesPerCombined - 1, $sorted.Count - 1)
        $chunks += ,(@($sorted[$i..$end]))
      }
    }

    $chunkIndex = 0
    foreach ($chunk in $chunks) {
      $chunkIndex++

      $firstRule = $chunk[0].Rule
      $logsourceNorm = Normalize-Logsource (Get-YamlValue $firstRule 'logsource')

      $combinedDetection = [ordered]@{}
      $conditions = New-Object System.Collections.Generic.List[string]

      $timeframes = New-Object System.Collections.Generic.HashSet[string]
      $tagsSet = New-Object System.Collections.Generic.HashSet[string]
      $fpSet = New-Object System.Collections.Generic.HashSet[string]
      $fieldsSet = New-Object System.Collections.Generic.HashSet[string]
      $refSet = New-Object System.Collections.Generic.HashSet[string]

      $maxLevel = 0

      foreach ($entry in $chunk) {
        $r = $entry.Rule

        $level = [string](Get-YamlValue $r 'level')
        $maxLevel = [Math]::Max($maxLevel, (Get-LevelRank $level))

        foreach ($t in @((Get-YamlValue $r 'tags'))) { if ($t) { [void]$tagsSet.Add([string]$t) } }
        foreach ($fp in @((Get-YamlValue $r 'falsepositives'))) { if ($fp) { [void]$fpSet.Add([string]$fp) } }
        foreach ($f0 in @((Get-YamlValue $r 'fields'))) { if ($f0) { [void]$fieldsSet.Add([string]$f0) } }
        foreach ($rf in @((Get-YamlValue $r 'references'))) { if ($rf) { [void]$refSet.Add([string]$rf) } }

        $det = ConvertTo-HashtableDeep (Get-YamlValue $r 'detection')
        if ($null -eq $det -or ($det -isnot [hashtable] -and $det -isnot [System.Collections.IDictionary])) { continue }

        $tf = [string](Get-YamlValue $det 'timeframe')
        if (-not [string]::IsNullOrWhiteSpace($tf)) { [void]$timeframes.Add($tf) }
      }

      $i = 0
      foreach ($entry in $chunk) {
        $i++
        $r = $entry.Rule
        $prefix = ('r{0:d4}' -f $i)

        $det = ConvertTo-HashtableDeep (Get-YamlValue $r 'detection')
        if ($null -eq $det -or ($det -isnot [hashtable] -and $det -isnot [System.Collections.IDictionary])) { continue }

        $keyMap = @{}
        foreach ($k in $det.Keys) {
          if ($k -in @('condition','timeframe')) { continue }
          $newKey = "${prefix}_$k"
          $keyMap[[string]$k] = $newKey
          $combinedDetection[$newKey] = $det[$k]
        }

        $cond = [string](Get-YamlValue $det 'condition')
        if ([string]::IsNullOrWhiteSpace($cond)) { $cond = "1 of $prefix`_*" }
        else { $cond = Prefix-Condition -Condition $cond -KeyMap $keyMap -Prefix $prefix }

        $conditions.Add("($cond)") | Out-Null
      }

      if ($timeframes.Count -eq 1) {
        $onlyTf = ($timeframes | Select-Object -First 1)
        if (-not [string]::IsNullOrWhiteSpace($onlyTf)) { $combinedDetection['timeframe'] = $onlyTf }
      }

      $combinedDetection['condition'] = ($conditions -join ' or ')

      $lsKeyRaw = Get-LogsourceKey $firstRule
      $safeName = Sanitize-FileName -Name $lsKeyRaw -MaxLen 120

      $relPath = ("combined/{0}/{1:000}.yml" -f $safeName, $chunkIndex)
      $yamlOutFile = Join-Path $ResolvedOutputDir ("combined_{0}_{1:000}.yml" -f $safeName, $chunkIndex)

      $combinedRule = [ordered]@{
        title       = "Combined Sigma Rules ($lsKeyRaw) [chunk $chunkIndex/$($chunks.Count)]"
        id          = ([guid]::NewGuid().ToString())
        status      = 'experimental'
        description = "Auto-generated combined rule from $($chunk.Count) Sigma rules. Each original detection was key-prefixed and conditions were OR-composed."
        author      = 'Combine-SigmaRules_Pack_v5.ps1'
        date        = (Get-Date).ToString('yyyy-MM-dd')
        logsource   = $logsourceNorm
        detection   = $combinedDetection
        level       = (Rank-ToLevel $maxLevel)
      }

      $tags = @(@($tagsSet) | Sort-Object)
      if ($tags.Count -gt 0) { $combinedRule['tags'] = $tags }

      $fps = @(@($fpSet) | Sort-Object)
      if ($fps.Count -gt 0) { $combinedRule['falsepositives'] = $fps }

      $fields = @(@($fieldsSet) | Sort-Object)
      if ($fields.Count -gt 0) { $combinedRule['fields'] = $fields }

      $refs = @(@($refSet) | Sort-Object)
      if ($refs.Count -gt 0) { $combinedRule['references'] = ($refs | Select-Object -First 250) }

      $yamlText = ConvertTo-YamlSafe -Data $combinedRule

      if ($WriteYamlFiles) {
        Set-Content -LiteralPath $yamlOutFile -Value $yamlText -Encoding UTF8
      }

      if ($WriteYamlBundle) {
        $yamlBundleDocs.Add($yamlText.Trim()) | Out-Null
      }

      if ($VerboseBuild) {
        Write-Host ("Built: {0}  (rules: {1})" -f $relPath, $chunk.Count)
      }

      $packTags = Get-HTArrayOrEmpty -HT $combinedRule -Key 'tags'
      $packObj = [ordered]@{
        id             = $combinedRule['id']
        title          = $combinedRule['title']
        description    = $combinedRule['description']
        status         = $combinedRule['status']
        level          = $combinedRule['level']
        author         = $combinedRule['author']
        date           = $combinedRule['date']
        modified       = $null
        references     = (Get-HTArrayOrEmpty -HT $combinedRule -Key 'references')
        falsepositives = (Get-HTArrayOrEmpty -HT $combinedRule -Key 'falsepositives')
        tags           = $packTags
        attack         = (Build-AttackFromTags -Tags $packTags)
        logsource      = $combinedRule['logsource']
        raw            = $yamlText
        path           = $relPath
        source_pack    = 'combined'
      }

      $pack.Add([pscustomobject]$packObj) | Out-Null

      if ($WriteManifestJson) {
        $manifest.Add([ordered]@{
          pack_id     = $combinedRule['id']
          groupKey    = $gk
          rulesInPack = $chunk.Count
          outputsTo   = $relPath
        }) | Out-Null
      }
    }
  }

  # Write JSON pack
  $json = $null
  if ($CompressJson) { $json = ($pack | ConvertTo-Json -Depth 80 -Compress) }
  else { $json = ($pack | ConvertTo-Json -Depth 80) }
  Set-Content -LiteralPath $ResolvedPackPath -Value $json -Encoding UTF8

  if ($WriteYamlBundle) {
    $bundle = (@($yamlBundleDocs | Where-Object { $_ }) -join ("`r`n---`r`n"))
    Set-Content -LiteralPath $ResolvedYamlBundlePath -Value $bundle -Encoding UTF8
  }

  if ($WriteManifestJson) {
    $mfPath = Join-Path $ResolvedOutputDir 'manifest.json'
    ($manifest | ConvertTo-Json -Depth 80) | Set-Content -LiteralPath $mfPath -Encoding UTF8
  }

  $stopwatch.Stop()

  Write-Host ""
  Write-Host "=== Sigma Combine Summary ==="
  Write-Host ("YAML files scanned      : {0}" -f $totalYamlFiles)
  Write-Host ("Rules parsed (kept)     : {0}" -f $ruleEntries.Count)
  Write-Host ("Unique IDs kept         : {0}" -f $byId.Count)
  Write-Host ("Rules without ID kept   : {0}" -f $noId.Count)
  Write-Host ("Groups produced         : {0}  (GroupBy={1})" -f $groups.Count, $GroupBy)
  Write-Host ("Combined objects        : {0}  (MaxRulesPerCombined={1})" -f $pack.Count, $MaxRulesPerCombined)
  Write-Host ("Parse errors            : {0}" -f $parseErrors)
  Write-Host ("Wrote JSON pack         : {0}" -f $ResolvedPackPath)
  if ($WriteYamlBundle) { Write-Host ("Wrote YAML bundle       : {0}" -f $ResolvedYamlBundlePath) }
  if ($WriteYamlFiles) { Write-Host ("Wrote per-rule YAMLs    : {0}" -f $ResolvedOutputDir) }
  Write-Host ("Elapsed                 : {0:n2}s" -f $stopwatch.Elapsed.TotalSeconds)
  Write-Host "============================"
  Write-Host ""

  if ($PassThru) { $pack }
}
finally {
  try { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}
