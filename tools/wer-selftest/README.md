# WER opt-out self-test

Proves that hp-thermal's Windows Error Reporting opt-out (#38) actually works: the shipped
exclusion is a `REG_DWORD 1` value named by image under
`HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications`, and it should
suppress WER crash reporting so no dump ever leaves the machine.

The app writes that value directly (not via `WerAddExcludedApplication`) so the shipped binary
imports no `wer.dll`. This test confirms the direct write is functionally identical to the OS
API's own — WER reads the same registry value regardless of who wrote it.

## What it does

An A/B differential, so a "no report" result is meaningful rather than a false negative:

1. **Negative control** — crash a *not-excluded* process, confirm event **1001** ("Windows
   Error Reporting") appears. This validates the apparatus (WER is on and reporting).
2. **Positive** — add the exact shipped exclusion value, crash again, confirm event 1001 is
   **gone**. Event 1000 ("Application Error") persists in both phases; that's expected —
   exclusion gates the WER *report* (1001), not the crash *notice* (1000).

Faults are triggered two ways: a null-write access violation (`0xC0000005`) and a `__fastfail`
(`0xC0000409`), the path stack-cookie / CFG failures take.

## Safety

- Uses a **throwaway image name** (`hpthermal-wertest.exe`) and hard-refuses `hp-thermal.exe`,
  so the real exclusion is never read or written.
- A `finally` block removes the throwaway exclusion, restores `DontShowUI`, and deletes the
  temp build — even on error.

## Run

Elevated PowerShell (HKLM write needs admin), with `rustc` on `PATH` (the crasher is built on
demand from `crasher.rs`; no binary is committed):

```powershell
& .\wer-abtest.ps1
```

Expected: `RESULT: PASS`.

Dev tool only — not shipped, not part of CI (it requires elevation and deliberately crashes a
process).
