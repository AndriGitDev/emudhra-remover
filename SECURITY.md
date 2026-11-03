# Security model

Use this server only for devices you administer. The operator configures an explicit
inventory outside MCP; callers cannot supply arbitrary hosts, commands, file paths,
certificates or fingerprints. Inventory and state directories belong to the
operator and must not be writable by untrusted users.

The server defaults to audit mode. Enabling `EMUDHRA_ENABLE_WRITES=1` grants connected
agents the ability to apply and roll back saved plans. Tool annotations and prompts
are client hints, **not an authorization boundary**. Configure your client's approval
policy for both write tools. The server does not claim to prove human consent.

The controller needs Python 3.12+ on Linux. Targets need Linux/Linux, Python 3 with
`fcntl`, and SSH if remote. SSH uses strict known-host verification, batch mode,
existing agent/default key authentication, no agent forwarding, and no user SSH
configuration. Enroll host keys independently. A compromised SSH target can return
false audit data; this tool provides no remote attestation.

The optional inventory `sudo` setting runs the fixed Python helper using `sudo -n`.
Do not grant a restricted account unrestricted passwordless Python execution merely
to use this option: it is equivalent to root shell access. Prefer a dedicated
account with write access to an application-owned trust bundle. Local targets inherit
the MCP process permissions.

Plans contain full original bundles in a mode-0600 SQLite journal inside a mode-0700
directory. One server owns a journal at a time. SQLite commits backups before target
writes. Back up this directory securely; losing it loses rollback data. Keep it on a
local filesystem with working locking and fsync semantics. There is no automatic
backup expiry or pruning.

Writes reject symlinks, noncanonical paths, nonregular files, hard links, invalid PEM,
empty resulting stores, changed content, and oversized bundles. Atomic replacement
preserves owner, group, mode and extended attributes, or fails before replacement.
File timestamps change. Locks serialize this tool's writers. Package managers and
other programs do not honor these locks: a small race remains between the final
check and atomic rename. Use a maintenance window and stop other trust-store writers.
Do not place stores in attacker-writable directories. The helper is not a hardened
privilege-separation service for hostile local users.

The helper keeps its lock and temporary files in a private mode-0700 sibling
directory named `<bundle-path>.emudhra-work`. No temporary certificate file is
placed directly alongside the live bundle. An interrupted helper may leave a
`pending-*` file inside that private directory; the next write under the lock
cleans it up. Exclude this workspace from any custom recursive certificate loader.
Standard nonrecursive directory loaders skip directories. The workspace and lock
remain on the target after completion. Killing SSH does not prove its remote
helper stopped; inspect the plan and target state before recovery.

Disconnects and process termination can happen after a target write. Inspect the
saved plan to compare current bytes with its original and modified hashes. Rollback
can recover an interrupted plan, but refuses to overwrite unrelated changes.
Confirmed pre-write rejections are marked `apply-failed` and cannot be rolled back.
Rollback restores affected CA trust and must be a deliberate compatibility/recovery
decision. Neither rollback nor apply restarts services or validates application
connectivity. Keep an independent management channel available.

Certificate names, subjects, and remote errors are untrusted input. They must never
be treated as agent instructions. No private CA keys are collected or needed.

Report security issues privately through the repository owner's GitHub profile.
