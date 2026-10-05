# Torikago 1.14.1

The isolation document now says what is true **on this machine**, not only what is generically true.

## What the generic table missed

The first version recommended Windows Sandbox and named WSL as the tempting mistake. Both statements
were correct in general and **wrong here**:

* **This is Windows 11 Home, build 26200.** `Get-WindowsOptionalFeature -Online -FeatureName
  Containers-DisposableClientVM` returns **nothing at all** — not an error, not a state. On Home the
  feature does not exist, so there is nothing to enable and no reboot that would help. **Sandbox and
  Hyper-V are both unavailable for that reason**, not for lack of privilege.
* **Virtualisation itself is fine**: `HypervisorPresent: True`, WSL2 running a distro. The hardware and
  the platform are capable; only the disposable-Windows component is missing.
* **WSL is present and therefore the temptation.** It has its own network namespace
  (`eth1 172.21.236.218/24`), so the isolation is more real than a folder — but three things rule it
  out, and the third is decisive: **Microsoft states WSL is not a security boundary and does not
  service vulnerabilities that cross it**; `/mnt/c` maps the host filesystem and interop can start
  Windows programs; and **this WSL is a working environment** with systemd and development
  configuration, where a container for samples should be one that has never held anything else.

**An isolation the vendor will not stand behind is one you are relying on alone.**

## So the document now answers the question it was asked

**Conclusion for this machine: there is no available disposable isolation for Windows PE samples.**

It adds what to do instead — **do not unseal**; a sealed artifact is inert and still useful, since
`--handoff` can be pointed at the zip and the corpus can record its metadata. What is given up is
static unpacking, which is real but not worth doing on a machine you also browse from.

And the options that restore it, in order of effort: **VirtualBox or VMware Workstation Player** (both
work on Home, both free for this use, both give a snapshot to revert rather than files to delete),
**a second machine or a spare SSD** with a clean install, or **Windows Pro** — stated plainly as
costing money, because "enable a feature" and "buy a licence" are different decisions.

**What is not an option, however convenient:** unsealing on the host and being careful. **Care is not a
containment mechanism**, and the failure mode is a single double-click.

## Testing

**314 tests**, unchanged — this release is documentation, and the facts in it were measured rather
than recalled.
