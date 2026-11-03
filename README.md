# eMudhra Remover MCP

An MCP server that lets your agent audit configured devices and remove specific
incident-listed CA certificates from their configured certificate stores. It uses exact SHA-256
fingerprints, saved removal plans, durable backups, atomic writes and verified rollback.
It works with any MCP client supporting the stdio transport. No model API key is needed.

**Supported adapters: PEM, OpenSSL trusted PEM, unsigned PKCS#7/P7B, EDK2 HTTPS certificate collections, Apple certificate-only profile files, exported Windows SST anchor collections, Java JKS/JCEKS/PKCS12 trust stores, closed NSS SQL trust-only databases, persistent Debian/Ubuntu package-root deselection, and p11-kit source distrust with consolidated exports, on local or SSH-accessible Linux devices. Windows Root/CA-to-Disallowed remediation is available over SSH.**
It is an initial implementation, not a universal device updater. No real device has
been changed during development; testing uses temporary stores and synthetic certificates.

## Incident policy

The bundled policy is a reviewed snapshot of Microsoft's October 26, 2026 announcement:
[official announcement and fingerprints](https://github.com/TrustedRootProgram/Program-Requirements/blob/0fc6bfef5a36c073db756748e945b334bc87ba1f/Announcements.md).
It contains 16 intermediate certificate fingerprints and seven trust-list removals.
The root/trust-list entries are a broader distrust decision; they are not all
compromised private keys. One entry belongs to the Sectigo AAA hierarchy, so the
policy's scope is broader than an issuer-name search for eMudhra.

Read [Microsoft's response](https://www.microsoft.com/en-us/msrc/blog/2026/10/microsoft-response-to-compromised-emudhra-certificate-authority-keys)
before choosing a remediation policy. Each adapter covers only its configured store and declared outputs. It does not install an SPKI denylist, implement revocation
checking, find every alternate certificate using a compromised key, or prove that
every application on the device is protected. Updates from OS/browser vendors remain
necessary. No network feed can silently change the bundled removal policy.

## Quick start

Install [uv](https://docs.astral.sh/uv/), Python 3.12+, and OpenSSH on your Linux controller.
Remote targets require Python 3 and an existing SSH account (including Windows). Devices without Python,
SSH, or a supported editable store require another integration.

```bash
git clone https://github.com/AndriGitDev/emudhra-remover.git
cd emudhra-remover
uv sync --frozen
cp examples/inventory.json inventory.json
# Edit inventory.json to include only your own devices and actual bundle paths.
```

For a local store use `{"id":"app","transport":"local","path":"/absolute/path/roots.pem"}`.
Use the real canonical path; symlinked trust stores are rejected. Targets use the
`pem-bundle` adapter by default. Inventory is loaded at startup and cannot be edited
through MCP. Remote SSH uses default keys or an existing SSH agent; custom aliases,
ProxyCommand and ~/.ssh/config are intentionally ignored. Enroll and independently
verify each host's key in `known_hosts` before connecting.

Copy [examples/mcp.json](examples/mcp.json) into your client's MCP configuration,
replacing all absolute paths. Keep `EMUDHRA_ENABLE_WRITES` at `0` for the initial audit.
The private state directory is created with mode 0700. If you create it yourself,
set that mode explicitly. Keep one server process per state directory.

An equivalent server invocation is:

```bash
EMUDHRA_INVENTORY="$PWD/inventory.json" \
EMUDHRA_STATE_DIR="$HOME/.local/state/emudhra-remover" \
EMUDHRA_ENABLE_WRITES=0 \
uv run --frozen emudhra-remover
```

This is a stdio server: start it through an MCP client. It does not expose a public
HTTP endpoint. See [SECURITY.md](SECURITY.md) for permissions and recovery behavior.

## Agent workflow

Try: “List my configured devices, scan each trust bundle for the eMudhra incident
policy, and show me removal plans with the affected certificates and store hashes.”

| Tool | Behavior |
| --- | --- |
| `list_adapters` | List implemented formats and validation coverage |
| `list_targets` | List configured devices and store paths |
| `scan_target` | Read one store and report exact matches |
| `plan_removal` | Save original bytes and a plan; leave the target unchanged |
| `inspect_plan` | Report saved status and compare current bytes to the plan |
| `apply_plan` | Apply an unexpired plan and verify written bytes |
| `resume_plan` | Finish an interrupted NSS, p11-kit or Windows operation from saved snapshots |
| `rollback_plan` | Restore original bytes if no conflicting change occurred |

The `incident://emudhra/2026-10` MCP resource exposes the full policy and provenance.

To allow remediation, set `EMUDHRA_ENABLE_WRITES=1` in your client configuration and
restart the server. Review the plan and service dependencies, then authorize your
client to invoke `apply_plan`. Plans expire after 15 minutes and cannot be replayed.
The write setting allows both apply and rollback; it does not prove user approval.
Configure your MCP client's approval controls for those tools.

After a connection failure, use `inspect_plan`. `original` means the store equals
the backup; `modified` means it equals the planned replacement; `conflict` means
someone else changed it. A saved uncertain/interrupted plan can be rolled back,
including after a server restart. Rollback does not expire and restores the removed
trust. Conflicting edits are never overwritten. Preserve the state directory.
Confirmed pre-write rejections are recorded as `apply-failed` and cannot invoke
rollback. A private `<bundle-path>.emudhra-work` directory holds the target lock
and crash-isolated temporary files; exclude it from custom recursive CA loaders.

## Device and trust-store coverage

| Surface | v0.1 |
| --- | --- |
| Unsigned PKCS#7/P7B collection, DER or PEM | Audit, plan, remove, verify, rollback; only affects this collection |
| Application-owned PEM file on Linux | Audit, plan, remove, verify, rollback |
| OpenSSL trusted PEM (X509_AUX) bundle | Explicit anyExtendedKeyUsage rejection; preserves unrelated trust metadata |
| Linux appliance/media player over SSH with Python 3 | Same, if its trust store is an editable PEM file |
| Generated Linux system CA bundle | File operation only; regeneration can restore removed CAs |
| Debian/Ubuntu package CA configuration | Persistent deselection, native regeneration and verified rollback |
| p11-kit persistent source policy / Fedora-style consolidated outputs | Native distrust, regeneration and recovery; Ubuntu p11-kit and isolated Fedora 44 userspace fixtures |
| Exported Windows SST positive-anchor collection | Exact certificate-group removal and file rollback; no live-store import |
| Windows logical Root/CA and physical Disallowed | Exact-certificate denial additions, property verification, recovery; SSH from Linux controller |
| macOS Keychain / trust settings | Not implemented; isolation design still required |
| Apple unsigned certificate-only .mobileconfig source | Exact payload removal and file rollback; no profile installation or device update |
| Android, iOS, vendor APIs, immutable firmware | Vendor-specific adapter or firmware update required |
| Java JKS / JCEKS / PKCS12 certificate-only trust stores | Native Java API removal, verification, exact-byte rollback |
| EDK2 HTTPS X509 certificate collection file | Exact-match removal and rollback; no firmware-variable access |
| Closed NSS SQL trust-only database | Native certutil distrust; requires empty password and no private-key records |
| Firefox built-in roots, containers, other browser-managed stores | Separate adapters/stores required |

Removing a certificate from a generated file such as
`/etc/ssl/certs/ca-certificates.crt` is **not persistent OS distrust**. Prefer vendor
updates or native OS mechanisms. The `pem-bundle` adapter does not run native regeneration or change source anchors.
The separate `debian` adapter updates the persistent configuration and runs
`update-ca-certificates`. No adapter restarts applications.
Reaudit after package updates, store regeneration and application restarts. Never
interpret “no matches” as complete device compliance.

## Development

```bash
uv sync --frozen
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv build
```

Tests exercise the actual local helper, temporary files, process-death recovery,
mode/owner/group/xattr/ACL preservation, optimistic concurrency, input validation, and MCP tools over
both in-memory and real stdio connections. SSH command construction is tested without
connecting to a live device. CI runs on Linux with Python 3.12 and 3.13.

To update policy, retrieve the official announcement at the revision in
`tools/import_incident.py`, save it locally, and run:

```bash
uv run python tools/import_incident.py /path/to/Announcements.md
```

Review the manifest diff and source before committing. The importer rejects an
unexpected table size, category counts, and input bytes differing from the pinned
content hash. To track a new advisory revision, deliberately update its pinned
revision, content hash, importer expectations, tests, and reviewed date together.

Certificate parsing deliberately fails closed for malformed bundles. Cryptography
is bounded to the tested major-version range because future stricter X.509 parsing
may reject legacy certificates in system bundles; review compatibility before
raising that bound. The committed lockfile fixes the development/CI environment.

Future adapters should retain the same flow: explicit inventory, inspect, persist
backup, bind a plan to current state, apply a narrow change, verify, and recover.
Native OS adapters must make persistent distrust changes rather than editing their
generated bundles. Contributions should include realistic platform fixtures.

## License

MIT. The project is independent of eMudhra, Microsoft, and MCP client vendors.

### PKCS#7 collections

Set `"adapter": "pkcs7"` and an absolute `.p7b` path in inventory. DER and PEM
encodings are detected from the file. Only unsigned certificates-only SignedData
containers are editable. Signed messages, embedded content, CRLs, and attribute
certificates are rejected rather than discarded. Removing from an import/export
collection does not remove certificates previously imported into an OS store.
Tests generate collections with cryptography and verify removal and exact rollback
through the real local helper. No live appliance was modified.

### Debian/Ubuntu persistent package-root distrust

Use `"adapter": "debian"`, with `path` pointing to `/etc/ca-certificates.conf`.
[examples/inventory.debian.json](examples/inventory.debian.json) shows SSH settings.
The `debian` paths default to the standard package, local-anchor and output directories;
explicit overrides support isolated installations and test fixtures. All must exist,
be canonical absolute paths, and be administered by the operator. The native
`/usr/sbin/update-ca-certificates` utility and OpenSSL must be installed on the target.

The adapter snapshots configuration plus source certificates, matches active roots by
fingerprint, prefixes selected package entries with `!`, and invokes native regeneration.
It verifies the resulting bundle and CApath entries, including `.pem`, `.crt`, `.cer`
and hash-named files, against the selected sources. Unmanaged CApath anchors appear
in scan verification and matching ones are reported as non-removable. Plans block
unresolved verification issues; audits still return their certificate findings.
This preserves deselection across ordinary regeneration; package reconfiguration may
still override an administrator's selections, so re-audit after maintenance.

Local anchors under `/usr/local/share/ca-certificates` are included in the audit.
If any match the incident policy, planning is blocked and the scan identifies them
for separate removal. The adapter never claims those copies were distrusted by
changing the package configuration. Each source must contain one certificate; duplicate
configuration entries, source symlinks and unsupported path syntax fail closed.

**Regeneration hooks are deliberately disabled.** Java, browser and application
stores maintained by hooks require separate audits/adapters. Native regeneration
updates the managed bundle, PEM aliases and OpenSSL hash links. It may remove obsolete
managed symlinks, as the native `--fresh` operation normally does. Unknown extra PEM
anchors prevent successful verification. Use a maintenance window without package
updates or other trust-store writers.

The plan's before/after hashes identify the configuration-and-source snapshot.
`inspect_plan.verification` separately reports derived-store consistency. Rollback
restores the exact configuration and regenerates its selected trust; generated files
are reconstructed rather than restored byte-for-byte. An interrupted rollback can
regenerate even if its configuration has already been restored. Changes to source
certificates or local anchors cause a conflict and require operator reconciliation.

Debian scans and verification now take a shared lock on the configuration's parent
directory; mutations take an exclusive lock there through regeneration. This
coordinates this tool's processes without creating files for read-only scans.
Concurrent operations report busy, and package managers still require the
operator's maintenance window because they do not honor these advisory locks.

Tests run the real installed Debian utility against temporary directories, covering
persistent removal, rollback, source conflicts, local-anchor overlap, symlink rejection,
and interrupted regeneration. No real system trust store is modified by the tests.

### Java JKS, JCEKS and PKCS12 trust stores

Use `"adapter": "java-jks"`, `"adapter": "java-jceks"` or `"adapter": "java-pkcs12"`
and the absolute store path.
[examples/inventory.java.json](examples/inventory.java.json) demonstrates SSH access.
The controller requires a **JDK 17+**, not a JRE-only installation, because it runs a
bundled Java source helper. Java need not be installed on the remote target.
`EMUDHRA_JAVA` may name the absolute controller `java` executable; otherwise PATH
is used. Native interoperability fixtures pass on JDK 17, 21 and 25.

Set `password_env` to the name of an environment variable supplied to the MCP server
by the operator's secret manager/client environment. Its value is the store password;
there is no implicit password or default. The name is visible in inventory, but the
value is never supplied as an MCP argument, recorded in the plan, passed in command
arguments, or sent to the remote helper. The native Java helper receives bounded
UTF-8 bytes through stdin, avoiding locale-dependent environment decoding. Its
source runs from the same private temporary directory as the store copies. An
incorrect password aborts planning.

Only Java **trusted-certificate entries** are supported. Any private or secret key
entry aborts the operation before a plan is saved. Each certificate is matched by
its DER SHA-256 hash, so all matching aliases are removed. Remaining aliases,
certificates and Java-visible entry attributes are checked after reloading the
candidate with Java. Aliases are encoded in the helper protocol to support Unicode
and newlines without command/text parsing ambiguity.

Processing happens on copies inside a private temporary controller directory.
Only after successful transformation and plan review does the shared transport
replace the target using its current-content check. No-match transformations retain
exact original bytes; rollback always uses the original saved bytes. Changes to a
PKCS12 candidate may re-encode/re-encrypt its contents using the controller JDK's
security defaults. Test that JDK's output against your application's Java version
before deployment. These adapters cover Java trust stores, not arbitrary PKCS12
identity archives or vendor-specific bag formats. BKS is unsupported.

Stop the consuming application or arrange an application-specific reload: replacing
a file does not update trust already cached by a JVM. This tool does not restart it.

JKS and JCEKS versions 1 and 2 undergo independent certificate-only parsing before
Java starts. Exact format magic, the password checksum, entry framing, canonical
modified UTF-8, unique aliases, complete DER and complete file consumption are
required. JKS/JCEKS aliases must already be lowercase: native Java preserves
uppercase aliases on load but cannot reliably look them up. Unsupported aliases
receive an explicit preflight error. Private/secret-key entry tags are rejected before Java can deserialize
JCEKS key objects. Independent input and output maps verify every surviving alias,
certificate and creation timestamp; duplicate aliases cannot silently hide a
certificate in Java's map. Version 1 candidates are upgraded to version 2 by Java
when changed. No-match and rollback bytes remain exact. Native fixtures exercise
both versions, Unicode/NUL/supplementary aliases, Unicode passwords, key rejection,
and the duplicate-alias loss that preflight prevents.

### Strict Java PKCS12 format boundary

PKCS12 inputs must have a password MAC. The complete PFX structure is inspected,
including encrypted safe contents, before invoking Java. Supported encryption is
PBES2/PBKDF2 with AES-CBC and SHA-1/256/384/512 PRFs within bounded KDF iteration
counts. Only named X.509 certificate bags bearing Java's trust attribute are
accepted. Unknown/nested/key bags, unexpected attributes, duplicate or case-colliding
aliases, and missing MACs fail closed. Older PKCS12 PBE algorithms are unsupported.
A separate cryptography parser and Java must agree on the complete certificate
multiset, preventing Java-invisible certificates from being silently discarded.

On Debian, native hooks are disabled, so `/etc/ssl/certs/java/cacerts` needs its own
Java-adapter plan. Deselect the package roots with the Debian adapter first, then
remediate the Java store. Otherwise a later Debian hook can repopulate the Java roots.

### Closed NSS SQL trust-only databases

Use `"adapter": "nss-sql"`, the absolute `cert9.db` path, and `"nss_offline": true`
after closing the consuming application. See
[examples/inventory.nss.json](examples/inventory.nss.json). The controller requires
Mozilla NSS `certutil` (`libnss3-tools` on Debian/Ubuntu); `EMUDHRA_CERTUTIL` can select
its executable. The target needs 64-bit Linux, Python's sqlite3 module, and Linux
open-file-description locks. NSS tools need not be installed on the target.

The companion `key4.db` must exist, contain no private-key records, and accept an
empty password. Protected tokens, identity stores, prefixed/legacy DBM databases,
and HSM/external-module stores are unsupported. Most personal Firefox profiles may
contain private-key records and therefore fail this deliberately narrow check.
Built-in Firefox/NSS root modules are **not covered** by editing cert9.db. A database
with no incident matches does not prove the browser's built-in trust is protected.

Snapshots bind both cert9.db and key4.db. Matching certificates remain in the database
with native `p,p,p` distrust for SSL, email and object signing. Already distrusted
matches remain untouched. Scan matches describe entries needing stronger distrust;
already denied entries are not listed as pending changes. This preserves the denial when a server supplies the same
certificate as an intermediate, or another module supplies trust for that certificate.
The adapter does not discover incident certificates present only in external modules.

Native changes run on private controller copies. Every unrelated certificate/trust
row, trust flag, password record and companion metadata entry must stay unchanged.
Only the selected trust attributes and their authentication signatures may change.
Both database files are backed up before either replacement, and rollback restores
both exact originals. The two file replacements are individually atomic; the pair
is not. `inspect_plan` reports `partially-modified` for an interrupted pair update,
and rollback accepts only members equal to the saved before/after bytes. Any other
change blocks recovery. Keep the application closed until both files are verified
or recovery completes. A mixed pair can temporarily read selected trust records as
neutral (`,,`), including certificates that previously had a partial denial. Use
`resume_plan` to finish an interrupted apply and establish the planned distrust, or
`rollback_plan` to restore the original pair. Recovery does not expire, but refuses
any bytes outside the saved snapshots. Apps without profile lock files, and idle
apps holding database handles open, cannot reliably be detected by these guards.
Plans made by the former deletion implementation are rejected
on apply; their backups remain eligible for rollback.
Target `pkcs11.txt` is never loaded or changed; native processing uses a freshly
initialized internal-module configuration to avoid executing target-provided modules.

Profile lock markers and SQLite WAL/SHM/journal files block reads and writes. During
replacement, OFD locks conflict with SQLite's database locks on both old files.
The application must remain closed throughout: atomic file replacement introduces
new inodes, and no file lock can prevent an application from subsequently opening
them. The server never deletes profile locks or checkpoints a live database.
Native tests verify supplied-intermediate chain rejection with `vfychain`, surviving
trust flags, exact pair rollback, interrupted writes, sidecar/profile guards,
private-key rejection, password rejection, and an active SQLite transaction conflict.

### OpenSSL trusted PEM bundles

Use `adapter: "openssl-trusted-bundle"` for an application-owned file containing
ordinary `CERTIFICATE` and/or OpenSSL `TRUSTED CERTIFICATE` objects. Exact incident
fingerprints receive an explicit `anyExtendedKeyUsage` rejection in X509_AUX.
The certificate stays present as a denial entry. This avoids removing an existing
rejection and potentially exposing trust from another source.

Matching entries lose their positive auxiliary trust list and gain the
`anyExtendedKeyUsage` rejection; existing rejection OIDs, aliases, key IDs and algorithm metadata remain.
Unrelated objects and surrounding comments retain their exact bytes. Already
`anyExtendedKeyUsage`-rejected matches need no change. Unknown/malformed PEM objects,
malformed auxiliary structures, non-DER auxiliary encodings and trailing data
inside a certificate object fail the operation. Exact backups, conflict checks
and rollback use the shared file transport.

```json
{
  "id": "openssl-application",
  "transport": "local",
  "adapter": "openssl-trusted-bundle",
  "path": "/opt/application/ca-bundle.trust.crt"
}
```

Coverage is this configured file and applications that honor OpenSSL X509_AUX.
**OpenSSL's `ocsphelper` and `crlsign` verification purposes ignore these auxiliary
rejections in the tested OpenSSL 3.0 implementation.** This adapter does not block
those OCSP/CRL verification paths. The native tests explicitly record that limit;
`anyExtendedKeyUsage` is the name of the rejection OID, not a guarantee that every
OpenSSL trust-checking mode enforces it.
A consumer that strips auxiliary trust data can still trust the certificate.
This adapter does not regenerate Fedora/RHEL outputs or establish persistent OS
policy. Do not treat editing a generated bundle as a replacement for a native
source-policy change. Native OpenSSL fixture tests check rejection for server,
client, email and `any` purposes, retained survivor trust/reject flags, and exact
rollback. The format follows [OpenSSL's X509_AUX schema](https://github.com/openssl/openssl/blob/openssl-3.0/crypto/x509/x_x509a.c).

### EDK2 HTTPS certificate collection files

`adapter: "edk2-cacerts"` handles the X509-only EFI_SIGNATURE_LIST file format
emitted by `trust extract --format=edk2-cacerts`, such as a staged `cacerts.bin`
for an EDK2 HTTPS consumer. Select a canonical regular file on a local or SSH Linux
target. This is file remediation; it does not deploy firmware or update UEFI/Secure
Boot variables. Generated files can be repopulated from their source policy.

Each signature entry contains an owner GUID and a DER certificate. Matching uses
only exact DER SHA-256. The adapter removes every matching entry, keeps unrelated
owner GUIDs and certificate bytes, updates partially retained list lengths, and
preserves wholly untouched lists verbatim. It rejects non-X509 list types,
authentication envelopes, signature headers, malformed lengths, trailing data and
invalid certificates. Plans cannot empty the collection. The common durable journal,
conflict checks, metadata preservation and exact rollback apply.

Native p11-kit fixtures supply actual EDK2 exports; tests independently parse the
contained X509 certificates and check survivor bytes, owner identities, partial lists
and rollback. No EDK2 firmware or hardware has been exercised. The layout follows
[p11-kit's native EDK2 exporter](https://github.com/p11-glue/p11-kit/blob/0.25.3/trust/extract-edk2.c).


### Persistent p11-kit source distrust and consolidated exports

Use `"adapter": "p11-kit"` for an operator-managed p11-kit source tree and its
existing Fedora-style export layout. See
[examples/inventory.p11.json](examples/inventory.p11.json). This adapter appends
exact-certificate `trusted: false` / `x-distrusted: true` objects to one owned
`emudhra-remover.p11-kit` file in the first configured source directory. Existing
anchors stay intact; the native module resolves the explicit denial. Already denied
certificates are not reported as pending changes.

The owned policy file must already exist, even if empty, with the intended owner,
permissions, ACLs and security labels. Create it only if absent; never truncate an
existing policy to initialize the adapter. Source directories and the existing
output layout must also exist. This prerequisite lets every replacement preserve
known metadata. Source directories and writable paths cannot be symlinked. Read-only
source-file symlinks require an explicit `p11.source_symlinks` map from each absolute
link path to its exact canonical regular-file destination. The example inventory
includes Fedora's default legacy-bundle link; adjust it to the actual host, or omit
the map where that link does not exist. Link text and destination contents are bound
to the plan. Retargeting, chained links, missing mapped links and target changes
block writes or recovery. Private staging uses regular copies; source links and
their targets are never modified. The adapter also refuses overlapping source
and output trees, unsupported source nesting, and nonuniform per-certificate hash
metadata. Hash certificates must share the TLS bundle's metadata; hash links must
share the compatibility link's metadata when those aliases exist. Layouts without
compatibility aliases, including Fedora 44, require link ownership and xattrs to
match the hash directory, with symlink mode 0777. This remains reconstructible even
when every anchor is distrusted. These restrictions avoid losing custom permissions
or security labels during removal and restoration.

Both controller and target need native `trust` and `p11-kit-trust.so` supporting all
declared export formats. Set controller `EMUDHRA_TRUST` and `EMUDHRA_P11_MODULE` when
not found automatically; target paths belong in the inventory's `p11` options.
The target requires Linux `renameat2` directory exchange, procfs and Python 3.
The hash output directory must share the staging filesystem and cannot be a mount.
Native processing uses private source copies, an explicit module and a fresh
user-only module configuration. An empty baseline checks isolation. Controller and
target native certificate/distrust views must agree, including auxiliary trust data.
Neither target-provided module configuration nor arbitrary regeneration hooks run.

Before mutation, the native tools stage and check all these outputs:

- `openssl/ca-bundle.trust.crt`, retaining native rejection metadata.
- `pem/tls-ca-bundle.pem`, `pem/email-ca-bundle.pem` and `pem/objsign-ca-bundle.pem`.
- `java/cacerts` and `edk2/cacerts.bin`, retaining surviving aliases and owner GUIDs.
- `pem/directory-hash`, including hash links and any existing compatibility aliases.

Existing denials must survive native export, unrelated trust metadata must remain,
and selected certificates must disappear from the applicable anchor collections.
The policy survives ordinary native regeneration from those same sources. This
covers only the configured module sources and declared outputs; vendor extensions,
other modules, hooks and application caches require separate handling. External
compatibility aliases such as `/etc/pki/tls/certs` are outside the write scope:
removed anchors can leave dangling aliases there. Surviving hash certificate
filenames must remain stable; native filename collisions that would rename an
unrelated survivor block planning. Native
p11-kit exports purpose-specific rejections: the tested OpenSSL `any`, `ocsphelper`
and `crlsign` modes do not provide the same denial as TLS server verification. Do
not infer universal rejection from an OpenSSL bundle's presence.

The journal backs up the exact policy and source snapshot plus output metadata.
Source changes, native interpretation changes and conflicting generated content
block mutation or recovery. Each regular output replacement is atomic, and the
whole hash directory is exchanged atomically. The complete multi-output update is
not atomic: use a maintenance window without applications or package writers.
Advisory locks coordinate this tool's processes only. `inspect_plan.verification`
reports derived-output consistency separately from the policy snapshot. After an
interrupted apply, `resume_plan` completes the saved distrust; `rollback_plan`
restores the original policy and regenerates its outputs. Both refuse external
edits. Generated files are restored semantically, including trust attributes,
aliases and owner GUIDs; native comments and JKS timestamps can differ. Owned policy
bytes and output metadata are restored exactly. Private staging directories and
identity-checked crash records support cleanup after interruption.

Tests execute p11-kit 0.25.3 from extracted Ubuntu packages on temporary source and
output trees, including real OpenSSL chain checks, native Java/EDK2 exports,
all-certificates-denied stores, interrupted regeneration, roll-forward/rollback,
xattrs, metadata restrictions and competing edits. A copied public-root bundle also
passed a separate fixture smoke test. An isolated Fedora 44 userspace with p11-kit
0.26.5 and OpenSSL 3.5.9 also passed the service workflow using copied packaged
sources (399 certificates including the synthetic target). Its genuine
`update-ca-trust` preserved the owned denial; native OpenSSL rejection, exact policy
rollback, and interrupted-apply resume/rollback passed. The fixture exercises the
stock legacy source link and a hash directory without compatibility aliases.
[tools/probe_fedora.py](tools/probe_fedora.py) reproduces this against an explicitly
marked disposable rootfs; it never installs packages or changes host trust stores.
**SELinux enforcement, RHEL, kernel/filesystem differences and real-device deployment
remain unvalidated.** Validate the declared layout and native semantics on an
isolated copy of your deployment before using it on a device.


### Windows Certificate Store / Disallowed

Use `"adapter": "windows-store"` and `cert://LocalMachine/Root` or
`cert://LocalMachine/CA`. `CurrentUser` is also supported and means the **SSH account's
security principal**, not the desktop user. See
[examples/inventory.windows.json](examples/inventory.windows.json). The controller
remains Linux; Windows targets need OpenSSH Server and `python` on the SSH command
PATH. Both Windows cmd.exe and PowerShell bootstrap syntax is fixed; helper code and
all paths/data travel as JSON stdin rather than a large shell command. `sudo` and
local Windows-controller operation are unsupported. The account needs permission
to update the selected location's Disallowed store, which must already exist.

The logical source Root or CA store is read-only. Its native physical siblings are
enumerated, including archived entries. For each exact DER SHA-256 incident match,
the adapter adds a plain certificate to the same location's **physical Disallowed**
store. Existing denial records and source entries stay intact. Scope is certificates
already present in that configured source; it does not download missing intermediate
certificates, update the Microsoft CTL, or cover every store/application. Existing
non-archived Disallowed matches are not pending additions. An archived matching
denial is reported as requiring manual remediation and blocks planning because its
effectiveness has not been established. Duplicate certificates across logical
source siblings, CRL/CTL-bearing stores and private-key/provider metadata fail closed.

Snapshots bind the Windows security principal, selected source, all source and
denial certificates, and their native serialized property values. Native previews
include the derived SHA-1 property Windows materializes when persisting a certificate;
SHA-256 over DER remains the incident selector. Property ordering is canonicalized,
while property IDs and value bytes are preserved. Native serialization/deserialization
checks each prospective entry. Registry writes are explicitly flushed and re-read.
No registry ACL or store configuration is rewritten; ACL management is outside scope.

A machine- or principal-scoped named mutex coordinates this tool's operations, and
fresh store synchronization checks precede each addition/removal. Other Windows
administrative tools do not honor that mutex: use a maintenance window without
other trust-store writers. Denial additions are incremental; a failed multi-entry
apply may leave some planned certificates still undenied. `inspect_plan` reports
that partial state. `resume_plan` finishes the saved additions, and rollback removes
only the exact entries this plan added. Existing denials never get removed. External
Disallowed certificate/property changes block recovery. Recovery preserves changes
confined to the read-only source store, using saved certificates for exact denial
operations; fresh apply still requires the original source snapshot. Status exposes
`read_only_source_changed` separately from the observed denial state. Rollback restores prior trust by
removing those added denials. Root and CA targets share Disallowed, so plan/apply
one target before planning the other.

Windows CI uses unique temporary custom stores to test real CryptoAPI persistence,
property retention, exact-entry recovery and mutex identity. The Linux suite tests
journal and MCP integration separately. **Native chain-engine rejection has not been
validated:** a process-private registry probe found that CryptoAPI bypassed HKCU
redirection, so its isolation guard stopped before any real Root/Disallowed write.
Those two chain probes are explicitly skipped. No real Windows trust store has
been changed during development. Disallowed behavior is the native Windows mechanism;
verification returns `snapshot_verified` and `chain_validation: "not-performed"`;
it establishes exact store entries/properties, not application-wide
protection, group-policy behavior, or revocation checking. Microsoft/vendor updates
and application-specific verification remain necessary.


### Apple certificate-profile source files

Use `"adapter": "apple-profile"` with a canonical `.mobileconfig` source-file path on
an existing Linux local/SSH target, such as an operator's deployment repository.
This edits an **unsigned certificate-only profile artifact**. It does not connect to
an Apple device, install or replace an installed profile, update MDM, or modify a
Keychain or global trust settings. Removing a certificate payload from a source file
has no effect on devices until an independently reviewed deployment replaces their
installed configuration. Deployment tooling may impose additional UUID/version rules;
this source-file adapter preserves existing identities and does not validate deployment.

Supported payloads are `com.apple.security.root`, `com.apple.security.pkcs1` (DER
public certificates) and `com.apple.security.pem` (one ordinary public certificate).
XML and binary plist encodings retain their format. Exact DER SHA-256 matches remove
whole matching payloads, with the profile identity and every surviving payload UUID,
identifier, certificate and supported metadata preserved. No-match files stay
byte-identical. Changed profiles are reserialized; original bytes remain in the
journal for exact rollback. Plans cannot remove every certificate payload.

The format boundary is deliberately strict: valid unique UUIDs/identifiers, version
1, known profile/certificate metadata, public certificates only, and no dependent
WiFi/VPN/MDM payloads. Signed or encrypted CMS profiles, PKCS12 identity payloads,
unknown fields, duplicate dictionary keys, XML entities/ignored tags, noncanonical
base64, skipped/undeclared XML entities, noncanonical version integers, nonstandard
DTDs, malformed certificates and oversized binary object tables fail closed.
This prevents breaking signatures, discarding identities, or leaving dangling
references from other payload types. Supported metadata includes display/description/
organization fields, scope, removal restriction and localized consent text.

Linux tests cover XML/binary transformations, all three payload types, malformed
input, signed CMS refusal and the actual file plan/apply/rollback/conflict path.
A separate macOS CI job validates temporary inputs/outputs using native `plutil`;
it never installs a profile. Native profile deployment and Apple trust evaluation
are outside this adapter's validated scope. The payload definitions follow
[Apple's root certificate schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.root.yaml),
[DER certificate schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.pkcs1.yaml)
and [PEM certificate schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.pem.yaml).

### Exported Windows SST anchor collections

Use `"adapter": "windows-sst"` and `"sst_trust_anchors": true` for an exported
**positive-anchor collection file** on a Linux local/SSH target. This operator
assertion is required because SST files do not identify whether their certificates
are intended as trusted anchors or as denials. Never target a Disallowed export or
other denylist with this adapter. Use `windows-store` for live Windows distrust.
[Example inventory](examples/inventory.sst.json) shows the required role assertion.
No SST is imported into Windows, no CTL is changed, and editing an export does not
change an installed device store. Deployment/import is outside this file adapter.

The supported subset is version-zero serialized certificate collections with exact
X.509 DER and optional friendly-name/description or derived certificate-hash
properties (SHA-1, MD5, SHA-256 and combined SHA-1/SHA-256). Hash properties are
checked against DER; UTF-16 metadata must be well formed. These legacy hashes are
metadata only: incident matching always uses exact DER SHA-256. Every surviving
group, including property order and bytes, remains untouched. No-match files and
rollback retain exact original bytes; plans cannot remove all certificates.

Real Root/AuthRoot exports often contain additional policy/key-identifier/signature
properties and will be refused by this deliberately narrow subset.
Policy, archive, private-key/provider, CRL/CTL and unknown properties are refused,
as are duplicate certificates/properties, incomplete groups, hidden/trailing bytes,
bad end markers and malformed lengths. This prevents exporting a weakened denial
or silently discarding data outside the positive-anchor format boundary.

Linux tests exercise actual file apply/rollback/conflict and malformed collections.
Windows CI creates temporary **memory stores only**, exports with `CertSaveStore`,
filters the collection and reopens with `CERT_STORE_PROV_SERIALIZED` to check
surviving certificate/property values. It also probes rejection of native policy
and archive exports. No registry store is opened by these SST tests. All five SST native cases pass
on the Windows CI runner; installed-store and application trust remain outside
their scope. Format references are Microsoft's
[serialized-store specification](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/37d4b77d-a7d3-40fe-9c3b-cd327444f6ff)
and [CertSaveStore documentation](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsavestore).
