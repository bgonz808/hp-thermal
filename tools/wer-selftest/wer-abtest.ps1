#Requires -RunAsAdministrator
<#
  WER opt-out self-test (A/B). Proves that the shipped WER exclusion — a REG_DWORD 1 value
  named by image under HKLM ExcludedApplications — actually suppresses WER crash reporting.

  Design:
    * Negative control first: crash a NOT-excluded process and confirm event 1001 appears,
      so the later "absence" result is meaningful (not a false negative from WER being off).
    * Positive: add the exact shipped value, crash again, confirm 1001 is GONE.
    * Uses a THROWAWAY image name (hpthermal-wertest.exe); the real hp-thermal.exe exclusion
      is never read or written. A finally-block guarantees cleanup.

  Prereqs: elevated PowerShell + `rustc` on PATH (the crasher is built on demand from
  crasher.rs next to this script; no binary is committed). Dev tool, not shipped, not CI.
#>
$ErrorActionPreference = 'Continue'
Write-Host 'wer-abtest: starting (admin + rustc required)...'

$name   = 'hpthermal-wertest.exe'   # throwaway; NEVER the real exe
$werKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications'
$duiKey  = 'HKCU:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
if ($name -eq 'hp-thermal.exe') { throw 'refusing: would touch the real exclusion' }
if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) { Write-Host 'rustc not on PATH.' -ForegroundColor Red; exit 1 }

# Build the crasher into a fresh temp dir (nothing hardcoded, nothing left in the repo).
$src  = Join-Path $PSScriptRoot 'crasher.rs'
$work = Join-Path $env:TEMP ('wer-selftest-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$exe  = Join-Path $work $name
& rustc -O $src -o $exe 2>&1 | Out-Null
if (-not (Test-Path $exe)) { Write-Host "build failed: $exe" -ForegroundColor Red; exit 1 }

function Set-Excluded([bool]$on) {
  if ($on) {
    if (-not (Test-Path $werKey)) { New-Item -Path $werKey -Force | Out-Null }
    New-ItemProperty -Path $werKey -Name $name -Value 1 -PropertyType DWord -Force | Out-Null
  } else {
    Remove-ItemProperty -Path $werKey -Name $name -ErrorAction SilentlyContinue
  }
}
function Crash-And-Count {
  $t0 = Get-Date
  foreach ($m in 'av','fastfail') { Start-Process -FilePath $exe -ArgumentList $m -Wait; Start-Sleep 1 }
  Start-Sleep 7   # let WER flush events
  $e = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$t0; Id=1000,1001} -ErrorAction SilentlyContinue |
       Where-Object { $_.Message -like "*$($name.Replace('.exe',''))*" }
  [pscustomobject]@{
    E1000 = ($e | Where-Object Id -eq 1000 | Measure-Object).Count
    E1001 = ($e | Where-Object Id -eq 1001 | Measure-Object).Count
  }
}

# quiet: suppress the WerFault dialog (per-user; does NOT affect reporting / 1001)
$duiPrev = (Get-ItemProperty $duiKey -Name DontShowUI -ErrorAction SilentlyContinue).DontShowUI
New-ItemProperty -Path $duiKey -Name DontShowUI -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host "=== WER exclusion A/B ($name; real hp-thermal.exe untouched) ==="
try {
  Set-Excluded $false; $neg = Crash-And-Count
  Write-Host ("NEGATIVE (not excluded): 1000={0}  1001={1}" -f $neg.E1000, $neg.E1001)

  Set-Excluded $true;  $pos = Crash-And-Count
  Write-Host ("POSITIVE (excluded)    : 1000={0}  1001={1}" -f $pos.E1000, $pos.E1001)

  Write-Host ''
  if     ($neg.E1001 -ge 1 -and $pos.E1001 -eq 0) { Write-Host 'RESULT: PASS - 1001 present un-excluded, GONE when excluded. Exclusion works.' -ForegroundColor Green }
  elseif ($neg.E1001 -eq 0)                        { Write-Host 'RESULT: INCONCLUSIVE - negative control produced no 1001 (WER off/consent-gated).' -ForegroundColor Yellow }
  else                                             { Write-Host 'RESULT: FAIL - 1001 still present with exclusion set.' -ForegroundColor Red }
  Write-Host '(event 1000 persisting in both is expected - exclusion gates the WER report/1001, not the Application-Error notice.)'
}
finally {
  Set-Excluded $false                                   # remove throwaway exclusion
  if ($null -ne $duiPrev) { New-ItemProperty -Path $duiKey -Name DontShowUI -Value $duiPrev -PropertyType DWord -Force | Out-Null }
  else { Remove-ItemProperty -Path $duiKey -Name DontShowUI -ErrorAction SilentlyContinue }
  Remove-Item -Path $work -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host 'cleanup: throwaway exclusion + temp build removed; real hp-thermal.exe entry never touched.'
}
