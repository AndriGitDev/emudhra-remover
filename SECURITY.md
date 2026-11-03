# Security model

Use this server only for devices you administer. The operator configures an explicit
inventory outside MCP; callers cannot supply arbitrary hosts, commands, file paths,
certificates or fingerprints. Inventory and state directories belong to the
operator and must not be writable by untrusted users.

The server defaults to audit mode. Enabling `EMUDHRA_ENABLE_WRITES=1` grants connected
agents the ability to apply and roll back saved plans. Tool annotations and prompts
are client hints, **not an authorization boundary**. Configure your client's approval
policy for apply, resume and rollback tools. The server does not claim to prove human consent.

The controller needs Python 3.12+ on Linux. Linux targets need Python 3 with `fcntl` and SSH if remote. Windows targets
use the separate fixed Python/CryptoAPI helper over SSH. SSH uses strict known-host verification, batch mode,
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
empty resulting stores for deletion adapters, changed content, and oversized bundles.
Distrust adapters can deny every certificate while retaining explicit denial records. Atomic replacement
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

## Native Debian operations

The Debian adapter changes the configured ca-certificates.conf file and runs the fixed
system update-ca-certificates executable with explicit source and output directories.
It uses a separate operation lock around configuration replacement and regeneration;
package managers do not honor that lock. The underlying configuration replacement
retains the original file metadata. The native utility controls generated-file metadata.
Backups include the configuration and source content; rollback refuses changed sources.
Hooks are disabled so unrelated hook-managed stores are outside this adapter's scope.
Native utility failures may leave a partial derived store. They remain uncertain in
our journal, and inspect_plan reports verification separately from the configuration
hash. Keep an independent management connection and resolve partial states promptly.

## Java trust stores

The Java adapters operate on controller-side temporary copies using the bundled
Java source helper and a controller JDK. The process receives only selected runtime
environment values plus the configured store password. Java option injection
variables are not inherited. Passwords are not passed in arguments or journal data.
The helper rejects private/secret key entries; it must read the store to classify
it, so an accidentally configured identity store is still transferred and held
briefly in a private temporary directory before rejection. No plan is saved for it.
The original file backup retains its original integrity/encryption format. Temporary
files are normally cleaned on exit; a killed controller can leave its mode-0700
temporary directory. Protect the controller and its temporary storage accordingly.
Native Java parser exceptions are replaced by generic errors rather than copied
into MCP responses. Certificate subjects and aliases remain untrusted display data.

## NSS SQL scope and recovery

NSS snapshots include the certificate database and the companion key database's
metadata. The helper refuses nonempty nssPrivate tables before transferring the
companion bytes; supported databases contain no private-key records. Nonetheless,
protect backups as sensitive authentication metadata. Both cert9.db and key4.db are
replaced: native trust edits update authentication signatures in the companion.
Native operations run against private copies with a generated internal-module
configuration, never the target's potentially executable PKCS11 module configuration.
A change-to-same-empty-password operation on copies verifies the token's empty
password; those copies are immediately reset before transforming the store.
Unrelated companion metadata and private-key tables must remain unchanged. The two
replacements are individually atomic, but the pair is not. A half-written pair can
neutralize an existing partial denial until recovery. Keep applications closed and
use resume_plan to finish the saved distrust or rollback_plan to restore both exact
originals. Recovery refuses any member outside the saved before/after snapshots.

OFD byte-range locks protect snapshot/replace operations against cooperating SQLite
users, but locks attach to the old inodes. Keep applications stopped across the entire
workflow. Persistent profile-lock files and any database sidecars block all operations;
the server neither deletes locks nor attempts to repair/checkpoint live stores.
Built-in browser root modules and system enterprise trust sources remain outside scope.


## Persistent p11-kit operations

The p11-kit adapter reads only configured source trees and changes its owned policy
file plus six declared exports and one hash directory. Native module execution uses
an operator-selected binary/module on private source copies with user-only module
configuration and an empty isolation baseline. The native parser is part of the
trusted computing base. Controller/target certificate views must agree before a
plan can be applied. Source bytes and output metadata are bound to durable snapshots.

The policy file and output layout must pre-exist. Each regular replacement preserves
metadata through the common writer; hash-directory replacements require uniform
certificate and link metadata, copied exactly to the staged directory. Linux atomic
directory exchange replaces the hash tree. A private, fsynced record binds abandoned
staging names to inode identities for recovery cleanup. Per-file and whole-hash-tree
checks reject edits made after staging began, subject to the same noncooperating
writer race described above. Package managers must stay stopped.

The collection of replacements is not one transaction. Failure after the policy
write can leave exports using different source generations; inspect_plan reports
verification separately. Resume finishes the saved policy and rollback regenerates
the original policy. Recovery accepts only known source state and original/planned
export content, never arbitrary edits. Native comments and Java timestamps are not
part of semantic restoration. No arbitrary hooks, service restarts, or vendor module
updates run. Native purpose-specific denial does not cover every OpenSSL trust mode;
see the README for tested exceptions and platform validation limits.


## Native Windows store operations

The Windows adapter's only writable store is the configured location's physical
Disallowed store; logical Root/CA sources remain read-only. The fixed helper runs
under the SSH account, without sudo or arbitrary commands from MCP. The source and
existing denial entries must be certificate-only and free of private-key/provider
metadata. Backups preserve native certificate property values, with canonical order
and a checked derived SHA-1 property. Exact DER SHA-256 selects incident entries.
Native key material is neither acquired nor exported.

Named mutexes coordinate this tool's writers within a machine/principal scope.
Snapshots bind the security principal and store; native RESYNC checks run before
each mutation. Native certificate adds/deletes and registry flushes are followed by
full certificate/property checks. The operation is incremental, not a transaction.
Resume and rollback accept only denial entries from the saved before/after states.
Read-only source drift is preserved during recovery; fresh apply still pins the
complete source snapshot. Archived matching denials block planning instead of being
assumed effective. Verification explicitly reports that no chain validation ran. Rollback
removes only the plan's added plain denial entries and does not overwrite existing
ones. Registry ACLs are not rewritten or part of certificate-property verification.
Concurrent administrators and group-policy writers require a maintenance window.

Native tests use unique custom stores. Chain probes refuse to proceed when process
registry redirection does not isolate CryptoAPI. Store verification does not attest
to every Windows application's chain engine, CTL policy or cache behavior.


The Windows named mutex is predictable and uses the account's default DACL. A local
user can squat or hold its name and deny service; this cannot authorize a write.
The fixed bootstrap invokes `python` through the SSH account's native shell. That
account's working directory and executable search path must be trusted; cmd.exe may
search its current directory before PATH. No privilege boundary is crossed by the
helper, and it should never be exposed as a restricted-account privilege service.

## Apple certificate-profile artifacts

Only unsigned, public-certificate-only profile source files are accepted. The adapter
refuses mixed dependent payloads, identity containers and signed/encrypted envelopes.
It preserves surviving payload identities/values, reserializes the selected XML or
binary format, and uses the common file journal and atomic writer. Binary table and
object bounds are checked before decoding; XML rejects duplicate keys, entities,
unknown elements and noncanonical data encoding. No profile installation, global
Keychain/search-list changes, MDM calls or device trust-setting writes occur.

## JKS and JCEKS preflight

JKS/JCEKS inputs are parsed and checksum-verified before native Java loading. Only
trusted X.509 certificate entries are accepted; private, secret and unknown tags
never reach the Java loader. This avoids deserializing JCEKS secret-key objects.
Complete framing, canonical modified UTF-8, exact DER and unique aliases prevent
hidden or ambiguous records from disappearing in a native map. Independent output
parsing verifies surviving certificate, alias and creation-time values. The legacy
SHA-1 checksum is checked for format integrity, not claimed as modern authentication;
operator inventory, durable snapshots and content hashes remain the write boundary.

## Exported SST collection role

The operator must assert `sst_trust_anchors=true` in inventory. An SST cannot prove
its intended role; a plain exported Disallowed entry is indistinguishable from a
positive anchor. Denial feeds and live Windows store files are outside this adapter.
Only public certificates and a small allowlist of checked metadata are accepted.
Policy/identity/archive/unknown properties and CRLs/CTLs fail closed. Retained
certificate groups remain byte-identical, and normal journal/CAS rollback applies.
