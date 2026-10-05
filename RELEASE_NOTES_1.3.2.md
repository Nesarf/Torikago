# Torikago 1.3.2

Publishing moves to CI, and the project pages stop being dead ends.

## Releases are now made by pushing a tag

`.github/workflows/release.yml` fires on a `v*` tag and does the two useful things: puts the
package on PyPI, and attaches these notes to the GitHub release.

**PyPI publication uses Trusted Publishing, not a token.** The runner asks GitHub for an OIDC
token, PyPI verifies it came from this repository, this workflow file and the environment named
`pypi`, and issues a short-lived upload credential. **Nothing secret is stored anywhere** — which
is the point, after a token for this project ended up pasted into a chat window.

### Three guards, each for a mistake that is cheap to catch and unpleasant to find later

| guard | what it prevents |
|---|---|
| the tag must equal the version in `pyproject.toml` | a release whose tag disagrees is one nobody can find by version afterwards |
| the suite must pass before anything is published | shipping code whose tests are red |
| **the wheel's contents are printed and asserted** | see below |

That third one is not ceremony. **A release of this very package shipped without `unpack.py`** —
the entire implementation behind `--unpack` — and the build, `twine check` and the install all
reported success. The only thing that showed it was listing the files inside the wheel, from an
installed environment, which is why the file list is now part of the release. It asserts against an
expected set rather than merely printing, so the next omission **fails the release** instead of
reaching the index.

The environment name is pinned **in the workflow** rather than left to whatever the PyPI settings
page happens to say: a mismatch between the two is the most common way Trusted Publishing fails,
and it fails at the last step, after everything else has gone green.

## The project pages have links now

`[project.urls]` was never declared, so both PyPI pages were dead ends — no repository, no issue
tracker, no changelog. For a project whose purpose is to be useful to whoever just found it,
`pip install torikago` followed by nowhere to go is the wrong first impression.

## Version, in one place

`VERSION` now comes from the package metadata when the package is installed, falling back to a
`_SOURCE_VERSION` constant only when the module is loaded **by path** — which the sibling tool does
when it finds `nanodesu.py` on disk. Before this, the module reported `0.8.0` while `pyproject.toml`
said `1.3.0`: five releases of drift, caught by installing a built wheel and asking it. A test now
compares the constant against `pyproject.toml`.

## Testing

153 tests, green on Python 3.9, 3.12, 3.13 and 3.14.
