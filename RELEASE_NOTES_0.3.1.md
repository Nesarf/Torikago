# Triage 0.3.1

One fix, and it is the kind worth a release on its own.

## The injection triad was silent in the most common case

The `VirtualAlloc` + `WriteProcessMemory` + `CreateRemoteThread` check existed only in batch
scan mode. Pointing the tool at a *single* suspicious file — the most common way it is used
— reached a weaker import heuristic instead, so the strongest signal the tool has did not
fire where it mattered most.

It is now judged first, on the full import set, in both modes. `VirtualAlloc` on its own
still counts as an ordinary program's API rather than a third of a pattern, and both
directions are covered by tests.

## Testing

61 tests, green on Python 3.9, 3.12, 3.13 and 3.14, on Linux and Windows.
