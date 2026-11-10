# SARIF 2.1.0 result triage shared by the scan step and its self-test (#385). Dot-source; pure
# functions over the parsed SARIF object, no I/O.
#
# Defaults per SARIF 2.1.0 §3.27.9 / §3.27.10: a result with no `kind` IS kind "fail"; a result with
# no `level` is "warning" when its kind is fail and "none" otherwise. BinSkim emits its findings
# this way (BA2024 on hp-thermal.exe carried neither property), so counting `kind -eq 'fail'`
# literally read a finding as nothing and the release gate never fired.

function Get-SarifEffectiveKind {
  param($Result)
  if ($Result.PSObject.Properties['kind'] -and -not [string]::IsNullOrEmpty([string]$Result.kind)) { return [string]$Result.kind }
  return 'fail'
}

function Get-SarifEffectiveLevel {
  param($Result, [string]$Kind)
  if ($Result.PSObject.Properties['level'] -and -not [string]::IsNullOrEmpty([string]$Result.level)) { return [string]$Result.level }
  if ($Kind -eq 'fail') { return 'warning' }
  return 'none'
}

# message.text if present; else the rule's messageStrings[message.id] template formatted with
# message.arguments (how BinSkim encodes every result); else "<ruleId>: <kind>".
function Resolve-SarifMessageText {
  param($Run, $Result, [string]$Kind)
  if ($Result.PSObject.Properties['message'] -and $Result.message -and -not [string]::IsNullOrEmpty([string]$Result.message.text)) {
    return [string]$Result.message.text
  }
  $template = $null
  if ($Result.PSObject.Properties['message'] -and $Result.message -and $Result.message.id -and $Result.PSObject.Properties['ruleIndex']) {
    $rule = @($Run.tool.driver.rules)[[int]$Result.ruleIndex]
    if ($rule -and $rule.PSObject.Properties['messageStrings']) {
      $ms = $rule.messageStrings.PSObject.Properties[[string]$Result.message.id]
      if ($ms -and $ms.Value.text) { $template = [string]$ms.Value.text }
    }
  }
  if ($template) {
    [object[]]$fmtArgs = @($Result.message.arguments | ForEach-Object { [string]$_ })
    try { return [string]::Format($template, $fmtArgs) } catch { return $template }
  }
  return "$($Result.ruleId): $Kind"
}

# Make every result self-describing (explicit kind, level, message.text) IN PLACE and return the
# per-kind counts. Kinds outside the SARIF enumeration count as fail (fail-closed).
function Normalize-SarifRun {
  param($Run)
  $counts = [ordered]@{ pass = 0; fail = 0; review = 0; open = 0; informational = 0; notApplicable = 0 }
  foreach ($r in @($Run.results)) {
    $kind = Get-SarifEffectiveKind $r
    $level = Get-SarifEffectiveLevel $r $kind
    $text = Resolve-SarifMessageText $Run $r $kind
    $r | Add-Member -NotePropertyName kind -NotePropertyValue $kind -Force
    $r | Add-Member -NotePropertyName level -NotePropertyValue $level -Force
    if ($r.PSObject.Properties['message'] -and $r.message) {
      $r.message | Add-Member -NotePropertyName text -NotePropertyValue $text -Force
    } else {
      $r | Add-Member -NotePropertyName message -NotePropertyValue ([pscustomobject]@{ text = $text }) -Force
    }
    if ($counts.Contains($kind)) { $counts[$kind]++ } else { $counts['fail']++ }
  }
  return $counts
}
