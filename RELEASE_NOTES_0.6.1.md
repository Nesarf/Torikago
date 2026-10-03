# Triage 0.6.1

A real Memz build was analysed statically, and it disproved the rule written for exactly that
kind of file. This release fixes the rule using the real sample's evidence.

## What went wrong

0.5.0 added destructive-capability detection keyed on `DeviceIoControl` + `WriteFile` — the
APIs an MBR overwriter needs. Against a **synthetic** sample it reported `critical`, and
against 260 benign binaries it reported nothing, so it looked calibrated.

Then a real sample was checked (MEMZ-Clean.exe, compiled **2016-07-10**, x86, five sections).
Its import table contains **neither** API:

```
KERNEL32.dll    Sleep, ExitProcess, FormatMessageW, GetCurrentThreadId, GlobalFree,
                GlobalAlloc, GetModuleHandleW, CreateThread, lstrlenW, GetCurrentProcessId
USER32.dll      SetWindowsHookExW, SendInput, SetCursorPos, SetDesktopWindow, EnumWindows, ...
GDI32.dll       CreateFontW, SelectObject, BitBlt, StretchBlt, ...
ADVAPI32.dll    CryptAcquireContextW, CryptGenRandom
SHELL32.dll     ShellExecuteA
WINMM.dll       PlaySoundA
```

The disk APIs are resolved at runtime through the export table, so they never appear as
imports at all. The rule was not merely noisy — **it was aimed at the wrong evidence**, and
against the real thing it reported nothing.

## What the real sample does import

An input hook, a screen grabber, a crypto RNG and a launcher, with **no write-to-disk import
anywhere**: a program busy with the machine while showing nothing on it, whose payload is
generated or fetched at runtime rather than read from disk. That is now reported as
**moderate**, and it requires both ingredients, so ordinary software using one of them stays
quiet.

## Calibrated on the real thing

| Input | Before | After |
|---|---|---|
| Real Memz import table | 0 findings | **1 finding (moderate)** |
| 260 real system and application binaries | 0 | **0** |

Three tests lock it in, and the third is the point of the exercise: **a hook alone, and a
crypto RNG alone, must each stay quiet.**

## How the sample was handled

Nothing was executed, and no complete sample was written to disk: only the two byte ranges
needed were fetched over HTTP (the PE header, then the import table). Microsoft Defender
detected the first partial download on arrival as `HackTool:Win32/Zmem!MSR` (severity 4) and
removed it — which is itself evidence that a real one-shot destroyer is what was under test,
and a reminder that a detector which only fires on samples it has seen before is no help on
the first encounter.

## Testing

90 tests (was 87), green on Python 3.9, 3.12, 3.13 and 3.14, on Linux and Windows.
