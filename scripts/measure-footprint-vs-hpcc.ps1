# measure-footprint-vs-hpcc.ps1
#
# Reproduces the idle-footprint comparison in the project README: HP Command
# Center vs hp-thermal, measured over ONE shared window so CPU and every memory
# flavor are internally consistent (no stitched-together runs).
#
# What it measures, per process, in a single interval:
#   - CPU: cycles/s (QueryProcessCycleTime, bracketed around the window) and
#     % Processor Time (PerfMon), reported per-core and per-all-cores.
#   - Memory: RSS (Working Set), PRIVATE RSS (Working Set - Private, ~= Linux
#     USS), SHARED RSS (WS - private, derived), and Commit (Private Bytes).
#
# Groups: HP Command Center package | HP's broader stack (analytics + HSA/
# display services, separate packages) | hp-thermal (ours). Our own service is
# excluded from the HP group so it is only counted once, under "ours".
#
# ELEVATION: run from an elevated PowerShell. Cycle counts for SYSTEM-owned
# processes return DENIED without it (memory still reports fine either way).
#
# Windows PowerShell 5.1 (powershell.exe). ASCII only -- 5.1 reads scripts as
# ANSI, so non-ASCII corrupts string parsing.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\measure-footprint-vs-hpcc.ps1
#   ... -WindowSeconds 30 -OutFile footprint.txt
#
# The numbers in the README's "Measured footprint" table came from this script.

param(
  [int]$WindowSeconds = 30,
  [string]$OutFile
)

$ErrorActionPreference = 'Continue'
$window = $WindowSeconds
$ncores = [int]$env:NUMBER_OF_PROCESSORS
$L = New-Object System.Collections.Generic.List[string]

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Cyc {
  [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint a, bool i, uint p);
  [DllImport("kernel32.dll")] public static extern bool QueryProcessCycleTime(IntPtr h, out ulong c);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static ulong Get(uint pid){
    IntPtr h = OpenProcess(0x1000, false, pid);
    if (h == IntPtr.Zero) return ulong.MaxValue;
    ulong c; bool ok = QueryProcessCycleTime(h, out c); CloseHandle(h);
    return ok ? c : ulong.MaxValue;
  }
}
"@

# --- Groups (PID sets fixed up front) ---
$ccNames = @('HPCC.Bg.BackgroundApp','HPCC.Bg.BackgroundSys','HpSystemManagement')
$ccPids  = @(Get-Process | Where-Object { $ccNames -contains $_.Name } | Select-Object -Expand Id)
$svc = Get-CimInstance Win32_Service | Where-Object {
  ($_.Name -match '^HP' -or $_.DisplayName -match 'HP ') -and $_.State -eq 'Running' -and $_.Name -ne 'HpThermalService'
}
$svcPids = @($svc | Where-Object { $_.ProcessId -gt 0 } | Select-Object -Expand ProcessId | Sort-Object -Unique)
$ourPids = @(Get-Process | Where-Object { $_.Name -eq 'hp-thermal' } | Select-Object -Expand Id)
$allPids = @($ccPids + $svcPids + $ourPids) | Sort-Object -Unique

# HP Command Center is the comparison baseline. If none of its processes are
# running, the CC column is empty and the comparison is meaningless -- say so
# plainly (before the ${window}s wait), point at the Store, and keep going so
# the "ours" numbers are still measured. We do NOT auto-install or open a
# browser: a footprint tool shouldn't push a 168 MB app as a side effect.
$storeUrl = 'https://apps.microsoft.com/detail/9p92n00qv14j'
if ($ccPids.Count -eq 0) {
  Write-Warning "HP Command Center processes not found -- its column will be blank."
  $installed = $null
  try { $installed = Get-AppxPackage -Name 'AD2F1837.HPThermalControl' -ErrorAction SilentlyContinue } catch {}
  if ($installed) {
    Write-Warning "It appears installed but idle; launch HP Command Center once, then re-run."
  } else {
    Write-Warning "It does not appear installed. To reproduce the full comparison, install it: $storeUrl"
  }
  $L.Add("NOTE: HP Command Center not running -- CC column reflects absence, not a 0 MB footprint. $storeUrl")
}

# --- Single window: cycles before, perf counters ACROSS the window, cycles after ---
$cycB = @{}; foreach ($id in $allPids) { $cycB[$id] = [Cyc]::Get([uint32]$id) }
$counters = @(
  '\Process(*)\ID Process',
  '\Process(*)\% Processor Time',
  '\Process(*)\Working Set',
  '\Process(*)\Working Set - Private',
  '\Process(*)\Private Bytes'
)
$cs = (Get-Counter -Counter $counters -SampleInterval $window -MaxSamples 2)[-1].CounterSamples
$cycA = @{}; foreach ($id in $allPids) { $cycA[$id] = [Cyc]::Get([uint32]$id) }

# --- Index perf samples by instance, map instance->PID ---
$instByPid = @{}; $cpu = @{}; $ws = @{}; $wsp = @{}; $pb = @{}
foreach ($s in $cs) {
  $inst = $s.InstanceName; $p = $s.Path.ToLower()
  if     ($p -like '*\id process')          { $instByPid[[int]$s.CookedValue] = $inst }
  elseif ($p -like '*\% processor time')    { $cpu[$inst] = [double]$s.CookedValue }
  elseif ($p -like '*\working set - private'){ $wsp[$inst] = [double]$s.CookedValue }
  elseif ($p -like '*\working set')          { $ws[$inst]  = [double]$s.CookedValue }
  elseif ($p -like '*\private bytes')        { $pb[$inst]  = [double]$s.CookedValue }
}

$L.Add("=== FULL apples-to-apples audit (single ${window}s window, ${ncores} logical cores) ===")
$L.Add("time: $(Get-Date -Format o)")
$L.Add("cols: CPU%1c = % of one core | CPU%tot = % of all cores | cyc/s | RSS = working set | RSSpriv = private WS | RSSshared = WS-private | Commit = private bytes")
$L.Add("")

$totals = @{}
$groups = @(
  @{ t = 'HP Command Center package';               pids = $ccPids  },
  @{ t = 'HP services + analytics (separate pkgs)'; pids = $svcPids },
  @{ t = 'hp-thermal (ours)';                       pids = $ourPids }
)
foreach ($g in $groups) {
  $L.Add("--- $($g.t) ---")
  $L.Add(("  {0,-26} {1,5} {2,7} {3,7} {4,12}  {5,8} {6,8} {7,9} {8,8}" -f 'process','PID','CPU%1c','CPU%tot','cyc/s','RSS-MB','priv-MB','shared-MB','commit'))
  $sWS=0.0; $sWSP=0.0; $sPB=0.0; $sCyc=0.0; $sCpu=0.0
  foreach ($id in ($g.pids | Sort-Object -Unique)) {
    $proc = Get-Process -Id $id -ErrorAction SilentlyContinue
    $name = if ($proc) { $proc.Name } else { '(exited)' }
    $inst = $null
    foreach ($kv in $instByPid.GetEnumerator()) { if ($kv.Key -eq $id) { $inst = $kv.Value; break } }
    $c1 = if ($inst -and $cpu.ContainsKey($inst)) { $cpu[$inst] } else { 0 }
    $wsv = if ($inst -and $ws.ContainsKey($inst))  { $ws[$inst] }  else { if($proc){[double]$proc.WorkingSet64}else{0} }
    $wpv = if ($inst -and $wsp.ContainsKey($inst)) { $wsp[$inst] } else { 0 }
    $pbv = if ($inst -and $pb.ContainsKey($inst))  { $pb[$inst] }  else { 0 }
    $shared = $wsv - $wpv
    $b=$cycB[$id]; $a=$cycA[$id]
    $cyccell = if ($b -eq [uint64]::MaxValue -or $a -eq [uint64]::MaxValue) { 'DENIED' } else { $cps=($a-$b)/$window; $sCyc+=$cps; ('{0:N0}' -f $cps) }
    $sWS+=$wsv; $sWSP+=$wpv; $sPB+=$pbv; $sCpu+=$c1
    $L.Add(("  {0,-26} {1,5} {2,7:N2} {3,7:N2} {4,12}  {5,8:N1} {6,8:N1} {7,9:N1} {8,8:N1}" -f `
      $name,$id,$c1,($c1/$ncores),$cyccell,($wsv/1MB),($wpv/1MB),($shared/1MB),($pbv/1MB)))
  }
  $n = @($g.pids | Sort-Object -Unique).Count
  $L.Add(("  {0,-26} {1,5} {2,7:N2} {3,7:N2} {4,12:N0}  {5,8:N1} {6,8:N1} {7,9:N1} {8,8:N1}" -f `
    'SUBTOTAL',$n,$sCpu,($sCpu/$ncores),$sCyc,($sWS/1MB),($sWSP/1MB),(($sWS-$sWSP)/1MB),($sPB/1MB)))
  $L.Add("")
  $totals[$g.t] = @{ WS=$sWS; WSP=$sWSP; PB=$sPB; Cyc=$sCyc; Cpu=$sCpu; N=$n }
}

$cc=$totals['HP Command Center package']; $sv=$totals['HP services + analytics (separate pkgs)']; $our=$totals['hp-thermal (ours)']
$L.Add("=== TOTALS (same window) ===")
$L.Add(("CC package    : {0} proc  CPU {1:N2}%1c  {2,12:N0} cyc/s  RSS {3:N1} / priv {4:N1} / shared {5:N1} / commit {6:N1} MB" -f $cc.N,$cc.Cpu,$cc.Cyc,($cc.WS/1MB),($cc.WSP/1MB),(($cc.WS-$cc.WSP)/1MB),($cc.PB/1MB)))
$L.Add(("HP full stack : {0} proc  CPU {1:N2}%1c  {2,12:N0} cyc/s  RSS {3:N1} / priv {4:N1} / shared {5:N1} / commit {6:N1} MB" -f ($cc.N+$sv.N),($cc.Cpu+$sv.Cpu),($cc.Cyc+$sv.Cyc),(($cc.WS+$sv.WS)/1MB),(($cc.WSP+$sv.WSP)/1MB),((($cc.WS+$sv.WS)-($cc.WSP+$sv.WSP))/1MB),(($cc.PB+$sv.PB)/1MB)))
$L.Add(("ours          : {0} proc  CPU {1:N2}%1c  {2,12:N0} cyc/s  RSS {3:N1} / priv {4:N1} / shared {5:N1} / commit {6:N1} MB" -f $our.N,$our.Cpu,$our.Cyc,($our.WS/1MB),($our.WSP/1MB),(($our.WS-$our.WSP)/1MB),($our.PB/1MB)))
if ($our.WSP -gt 0) {
  $L.Add("")
  $L.Add(("PRIVATE-RSS ratio  CC / ours       : {0:N1}x" -f ($cc.WSP/$our.WSP)))
  $L.Add(("PRIVATE-RSS ratio  full stack / ours: {0:N1}x" -f (($cc.WSP+$sv.WSP)/$our.WSP)))
}
$L.Add("(one 3.5 GHz core = ~3.5e9 cyc/s)")
$L.Add("=== done ===")

$L | ForEach-Object { Write-Output $_ }
if ($OutFile) { $L | Out-File -FilePath $OutFile -Encoding UTF8 }
