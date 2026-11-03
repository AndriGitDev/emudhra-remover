# Adapter expansion work log

User requested at least four hours of work adding as many adapters as possible.
Work started 2026-11-03 12:12:06 UTC. Local `.work-session.json` tracks cumulative
active seconds and the continuation schedule. Do not count idle scheduled intervals.
Do not stop just because four hours of wall time have elapsed. Disable the schedule
only after the active-work requirement and final verification are complete, or if
user cancels. The schedule is bound to the current thread.

## Completed in chunk 1

- Added a file-adapter registry separating format transformations from transport.
- Added `list_adapters` MCP tool with scope and actual validation coverage.
- Added unsigned certificates-only PKCS#7/P7B adapter, DER and PEM encodings.
- Rejects signed content, embedded payloads, CRLs, unsupported certificate variants,
  multiple PEM objects, malformed/trailing DER, and plans that empty the store.
- Preserves unrelated certificates and rolls back exact original bytes.
- 36 tests passed including real local helper round trips for both encodings.
- Added asn1crypto (pinned by lockfile) to inspect containers without silently
  discarding non-certificate content. cryptography independently validates certs.

## Next work

1. Debian adapter implemented in chunk 2. Consider expanded local-anchor removal only
   with an explicit design for multifile recovery; current behavior audits and blocks.
2. Fedora/RHEL p11-kit blacklist adapter with rollback of exact owned additions.
3. Java JKS/PKCS12 adapters implemented in chunk 3; broader PKCS12 bag formats and
   old-JVM compatibility remain outside validated scope.
4. Closed NSS SQL trust-only adapter implemented in chunk 4; built-in browser roots,
   identity/private-key stores and protected tokens remain unsupported.
5. Windows root/disallowed stores and macOS trust settings; platform execution and
   state locking need design beyond current Linux-only controller.
6. Useful appliance and OS variants only where real behavior can be verified.

## Environment and research

- certutil and update-ca-certificates are available; keytool and trust weren't on PATH.
- Debian official manual: https://manpages.debian.org/unstable/ca-certificates/update-ca-certificates.8.en.html
- keytool docs: https://docs.oracle.com/en/java/javase/25/docs/specs/man/keytool.html
- PKCS7 docs: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
- asn1crypto schema: https://github.com/wbond/asn1crypto/blob/master/asn1crypto/cms.py
- No implementation delegates authorized. User allowed Opus 5.5 for code review.
- Do not touch real system or network-device trust. Use isolated fixture directories,
  generated test certs, and native commands pointed at temporary stores.
- Existing recovery model stores byte snapshots in SQLite; native multifile adapters
  will need richer snapshots and verification, not arbitrary shell hooks.

## Completed in chunk 2

- Implemented Debian/Ubuntu persistent package CA deselection through a native helper.
- Snapshot binds config, all listed source files and local anchors; changes reject plans.
- Runs the fixed native update-ca-certificates executable with operator-configured
  directories and an empty hooks directory, avoiding untracked hook store mutations.
- Verifies generated bundle fingerprints and PEM aliases, including after rollback.
- Reports local-anchor matches and blocks incomplete plans.
- Added verification and reconcile transport operations; interrupted rollback can
  regenerate when the config is already original. inspect_plan includes verification.
- Added 8 tests using actual native regeneration in isolated temporary directories.
- 44 tests, lint, formatting pass. Build and push checked at chunk completion.
- Native helper composition currently appends debian_remote.py to remote.py; no target
  third-party Python dependencies are required. F821 lint is excluded for the appended
  module because it shares the fixed base helper namespace intentionally.
- Next priority is Fedora/RHEL or Java/NSS. Avoid introducing generic command hooks.

## Completed in chunk 3

- Added native Java JKS and PKCS12 trusted-certificate-only adapters using a bundled
  Java source helper (controller JDK 17+, tested with OpenJDK 21).
- No new Python keystore parsing dependency. Java checks entry kinds, deletes exact
  matching aliases, reloads output and compares retained cert/alias/entry attributes.
- Passwords come from operator-named environment variables. Values are not in MCP
  arguments, journal data or process arguments. No default password.
- Java work runs via asyncio.to_thread so native processing does not block MCP loop.
- Private/secret-key stores are rejected; alias protocol supports Unicode/newlines.
- CI now provisions Temurin 21; native tests create stores with keytool and inspect
  results independently. Original bytes are backed up/restored by common transport.
- Temporary OpenJDK extracted (not system-installed) from Ubuntu packages at:
  /tmp/emudhra-java-runtime/extracted/usr/lib/jvm/java-21-openjdk-amd64/bin/java
  Use EMUDHRA_JAVA pointing there for subsequent local test runs; no Java is on PATH.
- No real trust store changed. Runtime download used apt-get download + dpkg-deb -x,
  so no package post-install hooks or system certificate updates were run.
- Next: Fedora or NSS, then Windows/macOS; arrange an Opus review of accumulated
  native-adapter work. Java PKCS12 is scoped to Java trust stores, not arbitrary
  vendor PKCS12 bags; inspect whether stronger structure constraints are warranted.

Chunk 3 validation: 61 passed, 1 intentionally skipped (JKS cannot hold secret keys),
with native OpenJDK 21 enabled. Lint, formatting, wheel build and packaged Java source
check passed.

## Completed in chunk 4

- Implemented native NSS SQL trust-only adapter with fixture certutil integration.
  Binds cert9/key4 pair, rejects private-key records before companion transfer,
  verifies empty password on copies, deletes only cert9 certificate/trust objects,
  and preserves original key4 bytes and unrelated native trust flags.
- Added Linux OFD locks across SQLite byte ranges; ordinary POSIX locks were avoided
  because closing another descriptor releases a process's locks. Refuses profile
  locks and SQLite sidecars, and requires explicit nss_offline inventory assertion.
- Does not load target pkcs11.txt or claim built-in browser root coverage. Native
  initialized modules are used only in private temporary copies.
- Opus review of Debian/Java completed. Confirmed high CApath verification gap fixed:
  now checks crt/cer/hash-named files as well as PEM, identifies unmanaged anchors,
  returns audit findings despite verification errors, blocks plans on those errors.
- PKCS12 hidden-bag loss fixed with complete strict bag parsing, bounded PBES2/AES
  decryption, mandatory MAC, independent cryptography cert enumeration, and Java
  multiset comparison. Unknown attributes/bags and duplicate aliases rejected.
- Regression fixtures contain authenticated hidden/duplicate bags, using native
  OpenSSL PKCS12KDF to produce a valid MAC; no fake parser-only tests.
- Other review fixes: missing inactive Debian sources allowed (active missing still
  fail); ASCII/LF config boundary enforced in both parsers; glob-bearing paths
  rejected; docs explain Debian-first then Java ordering with hooks disabled.
- Review observation still to address: Debian read/verify does not share the mutation
  operation lock, so concurrent regeneration can yield a transient inconsistent audit.
  Mutations remain hash-bound and fail safely; plan/apply/recovery guards tested.
- Current chunk adds native NSS tests and expanded Debian/PFX regression coverage.
- Next priority: Fedora/RHEL, then Windows/macOS. Consider independent Opus review
  of NSS after accumulating further adapter work; do not claim it was already reviewed.

Chunk 4 validation: 88 passed, 1 intentionally skipped (JKS secret keys unsupported).
Native Java/NSS/Debian fixture integrations enabled. CI for the preceding Java and
Debian commits passed. Current lint/format/build checks pass; current push CI is new.
Opus review completed without modifying files; no delegate remains running. NSS was
implemented after that review and has not received independent review yet.

## Completed in chunk 5

- Added `openssl-trusted-bundle`, the seventh implemented adapter. It accepts mixed
  ordinary/X509_AUX PEM objects, matches certificate DER SHA-256, clears positive
  auxiliary trust on matches and adds anyExtendedKeyUsage rejection. Existing
  universal denial is idempotent. Unrelated blocks/comments remain byte-identical;
  matching aliases, key IDs, other algorithms and existing rejection OIDs survive.
- Added 12 tests including actual OpenSSL verification for server/client/email/any
  purposes, surviving trust/rejection behavior, exact rollback and concurrent edits.
  Malformed/trailing/unknown auxiliary structures fail closed. This adapter covers
  its configured file only; it is not advertised as persistent Fedora OS distrust.
- Closed the remaining Debian review concurrency issue. Shared parent-directory
  flock protects audits; exclusive flock spans mutations and native regeneration.
  No lock-file creation is required for read-only operations. Four native fixture
  tests cover busy reads/verification/regeneration and shared-read/write conflicts.
- Confirmed previous commit da9a5bb CI passed for Python 3.12/3.13.
- Researched Fedora/p11-kit using genuine Ubuntu 0.25.3 native binaries extracted
  under /tmp/emudhra-p11-runtime; no packages or trust configuration installed.
  Docker socket access and user namespaces are unavailable; no Fedora machine is
  available. The Fedora adapter remains planned, not advertised as implemented.
- Added tools/probe_p11.py and two native integration tests. Fresh user-only module
  configuration, explicit x-init-reserved paths, empty baseline and random synthetic
  certificate checks establish fixture isolation. Tests exercise separate-priority
  source trees and an anchor/blocklist collision in the same source tree. CI will
  extract p11-kit packages into RUNNER_TEMP to run these checks without installing
  a trust module into the system configuration.
- Observed with this native p11-kit build: `blocklist` is recognized, `blacklist` is
  ignored. A same-source collision exports a neutral selected certificate with
  `--filter=certificates`; `--filter=trust-policy` retains its server-auth denial.
  A higher-priority separate source preserves denial in both modes. TLS anchor
  extraction excludes the blocked certificate in both recognized layouts. Native
  rejection covers known purposes; `openssl verify -purpose any` still accepts
  this p11-kit-generated blocklist export (unlike our explicit universal rejection).
  Do not infer these behaviors from a successful trust command or label alone.
- Research references:
  https://p11-glue.github.io/p11-glue/p11-kit/manual/trust-module.html
  https://p11-glue.github.io/p11-glue/p11-kit/manual/pkcs11-conf.html
  https://github.com/p11-glue/p11-kit/blob/0.25.3/trust/token.c
  https://git.almalinux.org/rpms/ca-certificates/raw/branch/c9/SOURCES/update-ca-trust
  https://github.com/openssl/openssl/blob/openssl-3.0/crypto/x509/x_x509a.c

Next: build the persistent Fedora source-policy workflow with these native checks.
Prefer one owned policy file, source snapshot conflict binding, durable original
state including absence, explicit native regeneration and verified rollback. Account
for existing local anchors and the directory-name/version distinction. Do not claim
Java/EDK2/hashed-directory regeneration until each output is implemented and checked.
Then Windows/macOS native operations and useful appliance formats. NSS has still not
had independent review; an Opus review can assess it alongside the new OpenSSL adapter.

Chunk 5 validation: 106 passed, 1 intentionally skipped (JKS secret keys unsupported),
with native Java, NSS, Debian, OpenSSL and both p11-kit probe layouts enabled.
Lint, formatting, wheel/sdist builds and git diff checks passed. No native Windows,
macOS or complete Fedora update-ca-trust workflow has been executed yet.

## Chunk 6: review fixes and Fedora export groundwork

- Opus reviewed NSS/OpenSSL and reproduced a high-severity NSS bug: deleting an
  explicitly distrusted incident certificate removes its denial, allowing a supplied
  intermediate chain to validate again. Implemented native `certutil -M -t p,p,p`
  instead of deletion; already denied matches are left intact. Native vfychain
  regressions now exercise root -> incident intermediate -> leaf with the server
  supplying the intermediate, including before/after/rollback and existing denial.
- NSS trust attributes require matching authentication signatures in key4. A native
  experiment proved restoring old key4 after changing trust silently yields `,,`,
  so the adapter now backs up and replaces BOTH database files. Controller checks
  all unrelated cert/trust rows, trust flags, password metadata and signature rows;
  only selected trust attributes and associated signature metadata may change.
- Added stable parent-directory locking alongside SQLite OFD locks. Prospective
  databases receive integrity/private-key preflight before either write. A failure
  on the second replacement retains write-may-have-occurred status. Recovery accepts
  only per-file before/after bytes, reports partially-modified pairs, rejects other
  changes, and restores exact originals. Tests cover both mixed-pair orientations,
  actual second-file lock failure, invalid second-file rejection, and conflicts.
- Added adapter revision binding for apply. Previously saved NSS deletion plans are
  refused on apply; old backups can still roll back. Null nickname/value failures
  now produce clear errors rather than incidental Python attribute exceptions.
- Opus also confirmed OpenSSL ocsphelper/crlsign compatibility purposes ignore AUX
  rejection. Removed the blanket all-purposes claim; added four native chain tests
  recording this limitation for matched roots and intermediates. Existing tests
  cover rejection for server/client/email/any purposes. This is a scoped native
  trust mechanism, not a guarantee across every OpenSSL verification mode.
- Fedora work began with stdlib JKS/EDK2/native-PEM export readers and an EDK2 file
  transform. These files are still untracked work in progress until native tests
  and integration are complete; no new adapter is advertised yet.
- Commit 9e5161f CI passed. The completed Opus review changed no files and all its
  temporary fixtures were deleted. No review delegate is currently running.

Review-fix checkpoint validation: 119 passed, 1 intentionally skipped with all native
fixture tools enabled; lint/format/build checks passed. The NSS regression suite has
21 tests, including vfychain and two-file recovery. Fedora export tests are being
added separately after this checkpoint.

## Chunk 6 continued: EDK2 and native export verification

- Implemented and registered `edk2-cacerts`, now the eighth adapter. Strict X509-only
  EFI_SIGNATURE_LIST parsing, exact DER matching, owner/untouched-list preservation,
  length updates for partial lists, empty-store prevention and exact file rollback.
  This is an EDK2 HTTPS collection-file adapter; it never deploys firmware, accesses
  firmware variables or claims native firmware/hardware validation.
- Added stdlib p11_formats.py readers for native JKS, EDK2 and PEM exports. JKS validates
  magic/version/type, bounded entries, unique native ASCII aliases, complete input,
  and the native changeit SHA-1 checksum. Comparison ignores only entry timestamps.
  EDK2 preserves certificate and owner bytes and rejects unknown list/header types.
  These readers are groundwork for full Fedora derived-output verification.
- Added real p11-kit export fixtures for java-cacerts, edk2-cacerts, pem-bundle,
  openssl-bundle and pem-directory-hash. Native keytool independently reads the JKS;
  cryptography checks certs; OpenSSL verifies the hashed-directory anchors. New
  adapter tests cover native roundtrip, partial lists, duplicate owners, all-matching
  protection and malformed/trailing/unsupported binary input.
- The earlier untracked EDK2/readers are now implemented and tested, replacing the
  work-in-progress note above. Fedora persistent-source orchestration remains next.
  Design constraints: one owned policy file, source-tree snapshot binding, regenerate
  all declared exports, preserve surviving trust metadata, and recovery after source
  change but before export completion. Avoid a synthetic update-ca-trust wrapper:
  use real trust commands and report the absence of a Fedora runtime honestly.

Chunk 6 final validation: 137 passed, 1 intentionally skipped (JKS secret keys),
with native Java/NSS/vfychain/Debian/OpenSSL/p11-kit integrations enabled. Lint,
formatting, wheel/sdist builds and diff checks passed. All tests use temporary stores.
Native Fedora update-ca-trust, Windows Certificate Store and macOS trust settings
remain untested and unimplemented; do not advertise them as available adapters.

## Chunk 7 in progress

- Follow-up Opus review found no Critical/High NSS issues; confirmed the mixed-pair
  window can neutralize an existing partial denial. Added resume_plan for explicit
  roll-forward recovery, limited to interrupted NSS applies and exact saved member
  bytes. Rollback remains available; both recovery choices refuse external changes.
  Docs require applications to stay closed through recovery and state that idle
  handles / applications without profile lock files cannot be reliably detected.
- Fixed the deletion-only empty-store guard to allow explicit-distrust adapters
  (NSS and OpenSSL) to remediate stores containing only incident certificates.
  Added raw NSS trust-column checks alongside native p,p,p display for idempotency.
- Added p11_native.py: shared stdlib native staging for all six consolidated files,
  hashed-directory output and verification-only policy/blocklist exports. It uses
  private user-only module configuration and an empty baseline to prove isolation,
  creates fresh outputs only, bounds reads and refuses escaping links. Five native
  tests validate complete exports, blocked-cert removal across TLS/email/code/JKS/
  EDK2 outputs, existing-directory protection and module-config injection rejection.
- Native experiment: an explicit p11-kit object with trusted:false and
  x-distrusted:true in a top-level source .p11-kit file works without depending on
  the blocklist/blacklist directory name, and preserves denial in OpenSSL export
  even with a duplicate anchor in that source's anchors directory. This is the
  preferred format for the single owned persistent policy file.
- Fedora orchestration is still not advertised. Intended first scope: pre-existing
  owned emudhra-remover.p11-kit file (may be empty), two configured source trees,
  existing native export layout. Preserve policy metadata via common atomic writer;
  stage all outputs before mutation. Bind source bytes and output metadata. For
  hash-directory metadata, either preserve it completely or refuse nonuniform
  custom metadata; do not silently discard ACLs/SELinux labels. Reconcile derives
  outputs from the exact restored source snapshot after interruption.

Chunk 7 checkpoint validation: full suite 147 passed and 1 intentional JKS skip;
the subsequently added owned-policy collision regression also passed (six p11-native
checks total). Lint/format/build/diff checks passed. The regression confirms actual
OpenSSL server-auth rejection and survivor acceptance from native generated output,
and proves source anchor files remain unchanged. No real trust stores were modified.
The follow-up review is complete; no delegate remains running. Continue with the
persistent p11-kit target helper/controller integration, then Windows/macOS.

## Chunk 8: persistent p11-kit distrust and complete export recovery

- Implemented the ninth adapter, `p11-kit`, for one owned persistent policy file
  and configured Fedora-style source/output trees. Native distrust objects retain
  certificates as denials and work with same-source anchor collisions. Existing
  source anchors remain untouched. Default paths are Fedora-style, but no Fedora
  host/package integration or SELinux-enforcing deployment has been tested.
- Both controller and target stage real native exports using isolated module
  configuration. Snapshots bind raw sources, output metadata and the target's native
  certificate/auxiliary-trust/distrust view. Different controller/target native views
  fail before mutation. Every original denial must survive the OpenSSL export;
  unrelated purpose anchors, Java aliases, EDK2 owners and trust metadata are checked.
- Regenerates six consolidated files plus the TLS hash directory. TLS hash contents
  must equal the TLS bundle. All candidates are staged before policy replacement.
  Regular files use the common durable atomic writer; Linux renameat2 exchanges the
  complete hash directory. Per-file checks and an immediate directory-content/inode
  check catch edits made during staging. Noncooperating writers still require the
  documented maintenance window, as final check/rename is not a filesystem CAS.
- Hash metadata is preserved through a strict uniform-template rule. Existing
  owned policy and outputs must exist to supply owner/mode/ACL/security labels.
  Nonuniform hash metadata fails closed. Native read-only files needed temporary
  owner-write permission on private staged objects to restore user xattrs; the live
  hash directory's permissions are never relaxed. Same-parent exchange avoids the
  cross-parent read-only-directory rename failure found during fixture testing.
- Durable identity-bound staging records clean up a hash exchange interrupted at
  different points. Unknown inode identities refuse cleanup. Generated files may
  be in either saved generation during recovery, but unrelated edits block it.
  resume_plan now supports finishing p11-kit applies; rollback regenerates from the
  exact original policy, including when policy restoration already happened.
- Generated content is restored semantically, not byte-for-byte (native comments
  and JKS timestamps can change). Policy bytes and output metadata remain exact.
  No hooks, firmware writes, service restarts or real trust-store writes occurred.
- Added 21 native workflow tests covering complete apply/rollback, persistent
  regeneration, all roots denied, source/output conflicts, actual locked-output
  failure after policy write, both recovery paths, metadata/xattrs, abandoned staging,
  native-view mismatch, busy guards and edits injected during staging. Added native
  hash-content validation and a self-contained SSH-helper/argument-size check.
- Preserved old durable plans after adding optional inventory fields by normalizing
  defaults before comparison. Updated README, inventory example and stale NSS
  security documentation (both database files are required for signed distrust).
- Separate smoke test read a COPY of the host public-root bundle: native p11-kit
  enumerated 120 certificates and the production incident policy matched none.
  A second isolated copy used an explicitly synthetic policy selecting one root;
  apply and exact source-snapshot rollback succeeded. This is compatibility evidence,
  not evidence that any copied public root is part of the incident.

Next: independent authorized Opus review of the substantial p11-kit workflow, then
Windows/macOS native adapters. Native Windows/macOS CI fixtures should use custom
stores/keychains only; never change a real Root/System trust store. Keep actual
platform gaps explicit. No implementation delegates were used.

Chunk 8 validation: full suite passed 171 tests with one intentional JKS secret-key
skip. After the final hash-export consistency check, all 32 p11-kit workflow/native
and transport tests passed, including the new regression (172 tests now covered
across the full and focused runs). Lint, formatting, wheel/sdist packaging, packaged
helper/source checks and git diff checks pass. Prior commit 3f1850b CI passed.

Windows research starting points for the next chunk:
- https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certserializecertificatestoreelement
  serializes encoded certificates and their encoded properties, allowing a backup
  stronger than DER-only export. Use the returned actual byte count.
- https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certaddserializedelementtostore
  restores serialized elements; restrict accepted context type to certificates and
  use explicit add dispositions. Extended properties are Windows-specific.
- Investigate adding native Disallowed entries before removing trusted entries,
  preserving existing denials, named-store fixture isolation and exact state-bound
  recovery. A successful custom-store test alone does not prove chain-engine denial.

## Chunk 9 in progress: Windows native groundwork

- Building CryptoAPI support with native certificate/property serialization,
  archived-certificate enumeration, identity-key rejection and exact entry checks.
  No Windows adapter is registered or advertised yet.
- Added a Windows CI job using only unique EmudhraFixture-* custom CurrentUser
  stores, with explicit cleanup. It never writes Root or Disallowed. Initial native
  tests check serialized properties, persistence/reopen, exact deletion/restoration
  and mismatched serialized certificates. Local Linux collection correctly skips
  these three native tests; execution evidence must come from the Windows runner.
- Intended adapter leaves the configured source store intact and adds exact matches
  to the physical Disallowed store, preserving existing denials. Logical source
  enumeration covers its native physical siblings; duplicate records fail closed.
  Native source scope and actual chain-engine denial validation still need work.

### p11-kit review follow-up during chunk 9

Opus found no Critical/High issues and independently exercised native source
interpretation, mixed generations and four actual process-death points. All four
reproduced Low findings are now addressed:
- Hash staging records are fsynced before creating/moving the named directory;
  RENAME_NOREPLACE prevents replacing a colliding path. A real helper os._exit
  regression before the move verifies resume leaves no orphan hash directories.
- Reconcile skips semantically unchanged regular exports and unchanged hash trees,
  including native JKS timestamp-only differences. Inode-preservation regression added.
- Changed output parents/workspaces and staged metadata are checked before policy
  replacement. A locked output now fails preflight; unwritable Java output parent
  test confirms no policy write and apply-failed status.
- Verification reports unexpected generated certificate/trust records as extra
  anchors; scans surface incident matches with source paths and non-removable status.
  Stale outputs still block planning.

All 32 p11-kit workflow/native tests pass after these fixes. Review hypotheses remain
explicit limits: no Fedora/SELinux runtime, a reboot may change saved device identity
and require operator staging cleanup, and killed read-only helpers can leave public
certificate copies in temporary directories. No new review delegate is needed for
these narrow fixes.

### Windows implementation and native results

- Windows CI now passes the seven initial native CryptoAPI tests: actual custom-store
  add/delete/reopen, friendly-name property preservation, serialized mismatch refusal,
  both partial recovery directions, external conflict rejection and SID/mutex use.
  Two chain probes are explicitly skipped. CryptoAPI bypassed process HKCU registry
  redirection, so the sentinel isolation guard aborted before any Root/Disallowed
  write. Random custom sentinel stores are cleaned up. Do not claim chain validation.
- Native CI exposed signed error codes and automatic SHA-1 property materialization.
  Both are handled explicitly. Serialization property order also changes natively;
  strict bounded property framing now canonicalizes order without losing values.
  Exact incident matching remains DER SHA-256. Property schema reference:
  https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-oshared/462654f1-9be3-47f5-9c1e-a6d328ac52e0
- Implemented `windows-store` targeting logical Root/CA sources, adding plain exact
  matching certificates to the same location's physical Disallowed store. It leaves
  source entries/existing denials intact, binds snapshots to principal/store identity,
  includes archived certs, rejects key/provider metadata and CRL/CTL-containing stores,
  verifies serialized properties and explicitly flushes registry writes.
- Incremental writes use a native named mutex plus RESYNC/full-state checks before
  each entry. Saved before/after entry sets allow partial resume/rollback and block
  external changes. Linux journal integration tests exercise recovery and state
  classification using the same operation class with a fixture API; this is separate
  from the genuine Windows native tests.
- Added a fixed small Windows SSH bootstrap with all helper code/data in JSON stdin,
  avoiding Windows shell argument-size limits. Linux remains the controller platform.
  Operator inventory allows only cert://CurrentUser|LocalMachine/Root|CA, SSH only,
  without sudo. The physical Disallowed store must pre-exist. Principal and store
  snapshots protect against identity drift. Native registry ACL management is out
  of scope; certificate/property changes are the conflict boundary.
- Additional Windows tests now queued for archived entry visibility, fake key-provider
  metadata rejection (no actual keys acquired), and the packaged helper's full JSON
  stdin apply/read/rollback round trip against two custom stores. Record their actual
  CI outcome before claiming they passed.

Next priority: macOS native fixtures and adapter integration. Keep custom keychains
separate from global user/admin/system trust settings; do not write real device stores.
No implementation delegates used. Opus review of Windows may be requested after its
full integration validation, while the p11-kit reviewer is already complete.

Chunk 9 integration checkpoint: Linux full suite 189 passed, 13 skipped (12 native
Windows cases intentionally require Windows, plus the existing JKS secret-key skip).
Lint, formatting, build and diff checks pass. Windows initial native job at 1077900
passed seven tests and skipped two isolation-blocked chain probes; the next push
includes three additional native cases and the packaged-helper RPC integration.

Additional native results at 33aa52a: the packaged-helper JSON stdin round trip and
fake key-provider rejection passed. The archived fixture failed because its test
passed a DWORD instead of the documented empty CRYPT_DATA_BLOB; corrected the test
input. Native adapter enumeration logic was not the failure. The next run also tests
the fixed bootstrap through actual cmd.exe and PowerShell, not just Python directly.

Chunk 9 final Windows validation at 339fcd6: **12 passed, 2 skipped** on the native
Windows runner. Passed archived visibility, key-provider rejection and full packaged
helper apply/read/rollback under direct Python, cmd.exe and PowerShell. Only the two
chain-engine probes skip after the isolation guard; no real Root/Disallowed store
was written. Linux full integration remains 189 passed with its platform skips;
lint/format/build checks pass. Windows is now the tenth registered adapter.

Apple research for next work:
- Official schemas: https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.security.root.yaml
  and corresponding com.apple.security.pkcs1.yaml / com.apple.security.pem.yaml.
  Root aliases the DER public-certificate payload; PEM is public certificate data.
- A useful safe first Apple adapter is an unsigned certificate-only .mobileconfig
  source file (XML/binary plist), preserving UUIDs/identifiers/unrelated certificate
  payloads and rejecting signed/encrypted CMS, identity payloads, duplicate keys and
  profiles with dependent WiFi/VPN/MDM settings. It must be advertised as source-file
  remediation, never as deployment or a live global Keychain/trust-settings update.
  Native macOS plutil fixtures can validate serialization without installing profiles.
- Native Keychain/trust-settings support still needs an isolation design: creating a
  custom keychain or adding a trusted cert can affect the global search list or user
  trust settings. Do not casually run those commands on a real store or account.

## Chunk 10 in progress: Apple profile artifacts and Windows review fixes

- Implemented `apple-profile` for unsigned public-certificate-only .mobileconfig
  source artifacts, XML and binary plist. Exact DER selection removes whole matching
  root/pkcs1/PEM payloads, preserves profile/survivor UUIDs and metadata, retains
  encoding, backs up original bytes and refuses empty profiles at apply planning.
- Strict profile schema excludes identity and dependent WiFi/VPN/MDM payloads,
  signed/encrypted CMS, ambiguous duplicate keys/identifiers, XML parser differences
  and unbounded binary tables/objects. Real file workflow tests plus malformed and
  cryptography-signed CMS fixtures added. No profile is installed on any device.
- Added macOS plutil CI fixtures for all three payloads and both encodings. Native
  outcome is pending the next push; do not claim it has run yet. Keychain/global
  trust-setting mutation remains unimplemented because isolation is unresolved.
- Windows Opus review finished. Archived denial skip reproduced, while its effect on
  chain enforcement remains a hypothesis. Fixed conservatively: matching archived
  denials are non-removable findings and block plans. Added Linux and native archived
  fixtures; no existing denial is rewritten.
- Recovery now tolerates changes confined to read-only Windows sources, while keeping
  identity and all denial-entry conflict checks strict. Uses saved planned certs,
  preserves newly observed source entries, reports read_only_source_changed and
  checks for additional source changes during the operation. Fresh apply still pins
  the entire snapshot. Windows verification reports snapshot_verified separately and
  explicitly says chain_validation is not performed.
- Fixed malformed snapshot shape errors and preserved original exceptions if closing
  a native store also fails. Documented mutex-name denial-of-service and bare-python
  search-path assumptions. Review's add-disposition observation was incorrect: code
  already passes disposition 1 (ADD_NEW); the 2 is the certificate context-type mask.
  Added a native duplicate-add refusal regression and an explanatory code comment.

Chunk 10 local validation: **222 passed, 24 skipped** with native Java, NSS,
Debian, OpenSSL and isolated p11-kit enabled. Skips are 17 Windows-only cases,
six macOS-only cases and the unsupported JKS secret-key fixture. Lint, formatting,
wheel/sdist build and diff checks passed. Windows adapter revision is now 2 so
older plans cannot bypass the conservative archived-denial rule; rollback remains
available. New Windows/macOS native CI outcomes are pending the next push.

Chunk 10 changes pushed as 9d033d0. Native Windows/macOS jobs have not yet been
observed to finish. Request an independent Opus review of the strict Apple parser;
no implementation delegation.

Next expansion candidate: Java JCEKS trusted-certificate-only stores. OpenJDK's
JceKeyStore loads serialized secret-key objects and accepts JKS magic as compatibility
input, so do not simply add JCEKS to the native helper allowlist. First implement a
bounded independent certificate-only parser that checks exact magic/version, all
entry tags, modified UTF-8 aliases, complete DER, duplicate aliases and the keyed
SHA-1 checksum before Java runs. Apply it to JKS too: both native loaders insert
entries into a map and can hide duplicate aliases. Compare independent input and
output entries, including timestamps, with Java-visible certificates; reject private
and secret entries before deserialization. Keep password values out of diagnostics.
Research: https://github.com/openjdk/jdk21u/blob/master/src/java.base/share/classes/com/sun/crypto/provider/JceKeyStore.java
and https://github.com/openjdk/jdk21u/blob/master/src/java.base/share/classes/sun/security/provider/JavaKeyStore.java
Native keytool fixture expansion is available; no JCEKS adapter is advertised yet.

## Chunk 11 in progress: JCEKS and Apple review fixes

- Native CI for 7780435 confirmed **15 Windows tests passed, 2 chain probes skipped**
  and **6 macOS plutil tests passed**. No actual profile or device trust was changed.
- Added JCEKS trusted-certificate-only adapter with independent JKS/JCEKS preflight
  before Java loads anything. Exact magic, bounded framing, keyed checksum, modified
  UTF-8, aliases and DER are checked. Secret/private/unknown entry tags fail before
  JCEKS deserialization. Input/output alias/certificate/timestamp maps must agree.
- Applied the same parser to existing JKS; native loaders silently overwrite duplicate
  aliases, so native-only survivor verification was insufficient. JKS revision 2
  invalidates older apply plans, while preserving rollback. Native fixtures prove the
  duplicate alias behavior and strict rejection, versions 1/2, unusual aliases and
  Unicode passwords. Expanded existing native workflow tests to JCEKS.
- Opus Apple review reproduced two strict-XML gaps: skipped undeclared entities with
  a standard external DOCTYPE and Python's permissive integer parsing. Both fixed:
  skipped entities fail, only the canonical Apple DOCTYPE without internal subsets
  is accepted, and version integers must be literal 1. Apple adapter revision 2
  refuses older apply plans. Added Linux regressions and native plutil differential
  diagnostics without assuming native rejection. Other reviewed Apple paths passed.
- JCEKS native workflow suite: 26 passed, one unsupported JKS secret-key skip.
  Initial independent preflight suite: 32 passed; further native duplicate tests and
  Apple review regression tests are being validated before final full-suite results.

Chunk 11 JCEKS/Apple checkpoint: **274 passed, 28 skipped** in the full Linux suite
with all available native fixture tools. Skips comprise 17 Windows, 10 macOS and
one unsupported JKS secret-key test. Lint/format/build/diff checks passed. Native
CI for prior 7780435 is green on Linux, Windows and macOS. New macOS differential
cases are pending the next push. JCEKS is the twelfth implemented adapter.

Chunk 11 continued: Windows SST collection files

- Added `windows-sst` for explicit positive-anchor exports, requiring the operator's
  sst_trust_anchors inventory assertion. SST itself cannot distinguish an anchor
  export from a plain Disallowed export; denylist inputs are explicitly unsupported.
  This edits a Linux-hosted deployment artifact, never imports or changes a live store.
- Strict bounded MS-OSHARED framing, complete DER, end marker, unique certificates
  and property IDs. Only validated hash properties and well-formed name/description
  metadata are accepted; archive/policy/private-key/CRL/CTL/unknown properties fail.
  Retained complete groups, including property order, stay byte-identical.
- Added 28 SST tests covering exact removal, file apply/rollback/conflict, empty-store
  prevention, role configuration and malformed/unsupported input. Added five genuine
  Windows memory-store native cases for CertSaveStore/filter/serialized reopen and
  archive/policy rejection. Native outcome is pending the next push.
- Added JDK 17 and 25 native Java-only CI fixtures to check the declared JDK 17+
  controller boundary in addition to the existing JDK 21 full-suite runs. Results
  are pending; do not claim those JVMs validated until jobs complete.

SST integration checkpoint: **302 passed, 33 skipped** with all local native tools.
Skips are 22 Windows-only cases, 10 macOS-only cases and the JKS secret-key case.
Lint/format/build/diff checks pass. SST is the thirteenth adapter; its new native
memory-store tests await the next push.

Apple native differential results at ccac41c: plutil rejects undeclared entities,
underscore integers and full-width integers; it accepts hexadecimal integers. Our
format deliberately refuses all four, requiring literal version 1. All 10 macOS
cases passed; Linux and Windows CI for ccac41c also passed.

Fedora coverage exploration: extracted Ubuntu proot/libtalloc packages under
/tmp/emudhra-fedora-runtime/proot, without installing anything. ptrace-based proot
runs on this host (unlike Docker/unshare). Retrieved the official Fedora OCI latest
manifest, amd64 digest sha256:5b3a1aeece15ae01e3d04541e9269226d40e832566f3ce183856a12951dddb1e.
An isolated temporary Fedora userspace may now be feasible. Do not bind real /etc,
/usr, home directories or trust paths into a writable guest. No Fedora runtime test
has run yet; retain the Fedora/SELinux validation gap until actual evidence exists.

Chunk 11 native checkpoint at 0c30ce3: Linux CI green; **20 Windows tests passed,
2 chain probes skipped**, including all five SST memory-store cases; **10 macOS
tests passed**; Java compatibility jobs each report **65 passed, 1 skipped** on
JDK 17 and 25. Local full suite remains 302 passed, 33 platform/unsupported skips.
The Java and SST implementation is ready for an independent Opus review.

Fedora fixture exploration continued:
- Official Fedora 44 container layer SHA-256 verified, then extracted under
  /tmp/emudhra-fedora-runtime/rootfs using tarfile.data_filter. Absolute symlinks
  were converted to equivalent relative links confined inside the fixture tree;
  special nodes are skipped. No host root, trust directory or home was bound in.
- Guest rpm reports p11-kit/p11-kit-trust 0.26.5-1.fc44 and ca-certificates
  2026.2.92_v9.0.319-2.fc44. Python and openssl CLI were not initially installed.
- Stock Fedora local sources include ca-bundle.legacy.crt ->
  /usr/share/pki/ca-trust-legacy/ca-bundle.legacy.default.crt (empty default).
  Current strict source walker refuses this symlink, so the adapter cannot use
  the default Fedora sources yet. A useful next fix is an explicit operator map
  of permitted source symlinks to exact canonical read-only files. Bind link text,
  resolution and target bytes into the snapshot; materialize regular private copies;
  refuse retargeting and all changes during apply/recovery. Keep the owned policy
  and directory paths non-symlinked. Add source_links snapshot fields only when
  present to preserve existing no-link rollback snapshots, and compare these fields
  in replace/reconcile validation. No such implementation is committed yet.
- Fedora update-ca-trust also manages compatibility hash links under /etc/pki/tls/certs.
  Existing adapter scope is the declared extracted tree; investigate these external
  aliases before claiming complete native update-ca-trust parity.
- Ubuntu's old proot 5.1 ran rpm but dnf exited without completing installation;
  no packages were installed. Retrying with current upstream static proot from its
  official project download, PROOT_NO_SECCOMP=1, disabled glibc rseq and a /proc bind.
  The guest has its own copied resolv.conf; only /dev/{null,random,urandom} and /proc
  are bound, not host certificate stores. Check dnf-current.log and rpm availability
  before further testing. SELinux enforcement remains unavailable in this userspace.

## Chunk 12: Fedora native integration and Java/SST review fixes

- Added explicit operator-bound p11 source-file symlinks, needed for Fedora's
  stock ca-bundle.legacy.crt. Link text, canonical destination and target bytes
  enter the snapshot; missing/retargeted/chained links and hardlinked targets
  fail closed. Staging materializes copies and never writes links or destinations.
  No-link snapshots retain their previous representation for recovery compatibility.
- Native Fedora 44 has no compatibility aliases inside pem/directory-hash. Added
  zero/one/two-alias layouts, preserving existing aliases and reconstructible link
  metadata even when every certificate is denied. Refuse native filename collision
  changes that would rename unrelated survivors and break external CApath aliases.
  External /etc/pki/tls/certs aliases remain outside the adapter's write scope.
- New reusable tools/probe_fedora.py confines native commands to an explicitly
  marked disposable rootfs and copies all packaged sources into a fresh fixture.
  Actual Fedora update-ca-trust output initializes the layout; service apply,
  native regeneration persistence, OpenSSL rejection, rollback, resume and partial
  rollback pass. The fixture scans 399 certificates including its synthetic root.
  Ubuntu controller p11-kit 0.25.3 and Fedora target 0.26.5 agree on native policy.
- Fedora package versions: python3 3.14.8-1.fc44, OpenSSL 3.5.9-1.fc44, p11-kit and
  p11-kit-trust 0.26.5-1.fc44, ca-certificates 2026.2.92_v9.0.319-2.fc44. Uses the
  digest-pinned Fedora 44 OCI userspace recorded above through current PRoot.
  No host trust directory is bound into it. SELinux enforcement, RHEL, native
  kernel/filesystem differences and real device trust remain unvalidated.
- Added Fedora container CI for isolated p11/EDK2 fixtures, run as an unprivileged
  fixture user. New CI outcome is pending push; local userspace probe passed.
- Opus reviewed JKS/JCEKS and SST at 9e768c9: no confirmed data loss, secret-key
  deserialization bypass or SST ambiguity. Fixed misleading uppercase-alias failures
  with explicit preflight rejection. Passwords now travel as bounded UTF-8 stdin
  bytes to Java, independent of locale, instead of environment decoding. Minimal
  C-locale Unicode-password regressions pass. Helper source is copied to its own
  private directory before launch, avoiding Java 22+ adjacent-source compilation.
- SST metadata hash calculations use usedforsecurity=False. Verified property 129
  against Microsoft's current WinSDK wincrypt.h: CERT_SHA1_SHA256_HASH_PROP_ID;
  the reserved range starts at 130. Added native CryptoAPI evidence test, pending
  Windows CI. Docs explain that real-world exports with policy metadata are refused.
- Full local suite: 324 passed, 34 skipped (Windows/macOS platform cases plus the
  unsupported JKS secret-key fixture). Native JDK21, NSS, Debian, OpenSSL and p11-kit
  enabled. Lint, formatting, wheel/sdist builds and diff checks passed.

Next: observe new Fedora/Windows/Java CI and address failures; independent review
of source-link and aliasless-layout changes is useful. Continue substantive adapter
work until the cumulative active-time requirement is met. Candidate expansion:
Alpine's persistent CA configuration, researched and tested only in disposable
userspace, or a strictly scoped OpenSSL CApath adapter with directory recovery.
Do not advertise either until implemented and natively verified.

Final chunk-12 checks: the Fedora probe was rerun with an explicit OpenSSL exit-code
and error-18 assertion, and passed again. Added a regression for distinct subject
labels that collide only after native filename sanitization: new plans refuse the
survivor rename, while an older applied plan still rolls back safely. The focused
native recovery test passed; the preceding complete suite was 324 passed/34 skipped.
Rollback skips only the new filename guard, retaining all certificate, trust,
Java alias, EDK2 owner and generated-output conflict checks.

Alpine expansion research: its update-ca.c uses compile-time source/output paths
and always invokes run-parts; it does not offer Debian's isolated-directory/hook
options. Do not reuse the Debian native invocation or advertise Alpine support.
Primary source: https://github.com/alpinelinux/ca-certificates/blob/master/update-ca.c

## Chunk 13: BKS v2 and Fedora review hardening

- Added the fourteenth adapter, `bks`, for certificate-only Bouncy Castle BKS v2
  application files. Independent bounded parser verifies the PKCS#12/SHA-1-derived
  HMAC before entries; exact DER matching removes complete raw entry slices. Header,
  salt, iterations, survivor order, case-sensitive aliases and timestamps survive.
  No JVM/provider is loaded at runtime; passwords remain controller-only environment
  values, and remote helpers see only the public store and integrity MAC.
- Rejects v0/v1/UBER, keys/sealed entries, attached chains (which BC silently drops
  on certificate entries), duplicate aliases, malformed MUTF/DER, trailing content,
  invalid MACs and unbounded salt/iterations/entries. Empty-password MACs are still
  checked even though native BC skips their verification. Normal journal, CAS,
  empty-store guard, byte-exact no-match and rollback apply.
- Native tests use Bouncy Castle 1.83 with JDK21 keytool, creating stores, reading
  transformed stores, exporting exact survivor DER and rejecting an actual key
  entry. Unicode/empty/multi-block passwords tested. Independent OpenSSL PKCS12KDF
  fixtures verify MAC derivation. Test-only provider SHA-256 is pinned to
  82cf3a2af766c3bc874f6d36b9f20a8b99a8f09762dc776e8a227a45d8daaafb.
  Java17/25 and Linux full CI now include BKS native fixtures; pending next push.
- BKS format primary reference:
  https://github.com/bcgit/bc-java/blob/r1rv83/prov/src/main/java/org/bouncycastle/jcajce/provider/keystore/bc/BcKeyStoreSpi.java
- Fedora CI initially lacked `su`. Added util-linux and a writable user cache;
  commit 525150b now passes all CI jobs. Fedora native fixtures: 69 passed, one
  skipped (independent Java tool unavailable there). Windows: 21 passed/two chain
  probes skipped, including the actual combined SHA1/SHA256 property. Java17/25:
  69 passed/one unsupported JKS key fixture each. macOS remains 10 passing fixtures.
- Opus review of c5b2245 found no trust bypass, data loss or native mismatch. Fixed
  its two fail-closed availability issues: aliasless hash directories no longer
  require directory-only user xattrs or POSIX ACLs on symlinks; security labels
  still must match. Directory ACLs/xattrs are preserved exactly. Native regressions
  cover access/default ACLs, user attributes, one/no alias and all anchors denied.
- Bumped p11 adapter revision to 2. Older plans cannot apply/resume under the new
  filename guard and receive an explicit rollback-only message. Both fully applied
  and policy-only interrupted older collision plans retain successful rollback.
  Focused native review-regression suite: 18 passed. No SELinux enforcement tested.
- Pre-review-fix full suite with BKS: 351 passed/34 skipped. Final full-suite run
  is in progress after the added ACL/revision and independent-KDF coverage.

Next: inspect the final test log, commit/push the BKS and review fixes, then observe
native CI. A review of the new bounded BKS parser is appropriate; do not delegate
implementation. A possible further adapter is a strict OpenSSL CApath directory
whose individual certificates gain explicit AUX denial while all hash aliases
remain unchanged. It needs atomic directory exchange, exact metadata backups,
conflict/recovery fixtures and native OpenSSL chain tests before registration.

Chunk 13 final validation: 369 passed/34 skipped in the complete local suite, with
JDK21, native BC1.83, NSS, Debian, OpenSSL and Ubuntu p11-kit enabled. BKS-specific
suite: 32 passed. Build, lint, formatting and example inventory validation passed.

CApath follow-up: a separate directory adapter is unnecessary for explicitly
configured backing files. The existing openssl-trusted-bundle adapter updates a
single regular CApath certificate's AUX data without changing its DER or any hash
alias. Added eight native full-service fixtures covering root/intermediate target,
default/TLS-server/TLS-client/any purpose, supplied untrusted chain, alias inodes,
permissions and byte-exact rollback. All 25 OpenSSL tests pass. This is documented
as per-file scope, with no directory discovery or alias conflict protection and no
persistence across source regeneration. No unimplemented directory adapter is
registered or advertised.

## Chunk 14: native trust validation, real SSH and installed artifact

- Opus BKS review found no confirmed defects. Native BC 1.83 disassembly and
  differential fixtures agree with the MAC derivation and strict entry parser.
  Native ambiguities (hidden duplicate aliases, overlong MUTF, trailing content,
  discarded attached chains) are refused. Review reran 32 BKS tests successfully.
- Applied its diagnostic hardening suggestion: invalid-Unicode passwords in BKS
  and Java no longer chain the encoding exception containing the password object.
  Three preflight regressions pass and values remain absent from tool diagnostics.
- Added native Java PKIX chain validation across JKS, JCEKS, PKCS12 and BKS. Each
  synthetic store has two independently generated roots/chains. Removing the
  incident root rejects only its chain; the other stays valid; byte-exact rollback
  restores both. Four JDK21 cases pass; added to Java17/25 CI for the next push.
  Revocation is disabled and anchors are exclusively the temporary keystore;
  these tests never use system roots or fetch chain data from the network.
- Added genuine localhost OpenSSH transport fixtures for a PEM file and persistent
  p11-kit. Temporary host/client keys, private authorized_keys and pinned known_hosts,
  loopback-only high port, no system SSH configuration changes. Native apply,
  rollback, source-conflict refusal and wrong-host-key refusal all pass. Server
  StrictModes is disabled only inside the disposable config because /tmp ancestry
  fails its ownership check; client strict host-key verification remains enabled.
  Enable with EMUDHRA_TEST_SSHD; CI enables this when sshd is present.
- list_adapters now reports adapter-specific native evidence and limits, including
  untested Windows chain enforcement, Apple deployment and SELinux enforcement.
  Fixed the older Java section's stale blanket BKS-unsupported statement.
- CI at 8ed5060 passed on Linux, macOS, Windows, Fedora and Java17/25. Fedora:
  82 passed/one Java-tool skip, including the ACL/aliasless recovery regressions.
  Java17 and Java25 each: 101 passed/one unsupported JKS secret-key fixture,
  including BKS native round trips and independent KDF checks. Windows remains
  21 passed/two isolated-chain probes skipped; macOS remains 10 passed.
- Built wheel installed into a fresh /tmp virtual environment using exported locked
  production dependencies. An isolated Python process loads the installed package,
  packaged Java source and 23-cert incident policy; real stdio MCP scan reports the
  synthetic fixture accurately and refuses writes by default. No checkout import
  is available to that subprocess. Result log is under
  /tmp/emudhra-release-validation/result.log.

Final full suite with all local native tools, SSH and PKIX fixtures is running;
record its actual result below. Continue active work until >=14400 seconds, then
final artifact/check/CI verification and push, disable only the existing schedule.
Remaining deployment limits are documented; no real device trust store was changed.

## Final implementation evidence

- Final local suite with all available native tools and loopback SSH enabled:
  **386 passed, 34 skipped**. Skips are Windows/macOS-only fixtures on Linux and
  the unsupported JKS secret-key fixture, not failed adapter implementations.
- Implementation commit 3d015e9 passes every CI workflow. Linux Python3.12 and
  Python3.13 each report 386 passed/34 skipped, including real loopback SSH.
  Java17 and Java25 each report 108 passed/one JKS secret-key skip. Fedora reports
  82 passed/one unavailable Java-reader skip. Windows reports 21 passed/two
  chain-isolation probes skipped. macOS reports 10 passed.
- A separate upstream Bouncy Castle 1.70 compatibility run reports 34 passed,
  three non-BKS PKIX cases deselected. Provider SHA-256:
  8f3c20e3e2d565d26f33e8d4857a37d0d7f8ac39b62a7026496fcab1bdac30d4.
  This is upstream BKSv2 compatibility evidence, not Android/vendor-fork validation.
- Wheel's 36 packaged source/resource files match the checkout byte-for-byte.
  BKS module, Java helper and pinned incident manifest are present; private work
  session and virtual environments are excluded from the source distribution.
  Fresh-environment installed-wheel stdio smoke test passed, with writes disabled.
- Fourteen registered adapters: pem-bundle, pkcs7, debian, java-jks, java-jceks,
  java-pkcs12, nss-sql, openssl-trusted-bundle, edk2-cacerts, p11-kit,
  windows-store, windows-sst, apple-profile and bks. No placeholders registered.
- Native Windows chain enforcement, macOS Keychain/live profile installation,
  SELinux enforcement, real firmware/mobile devices, built-in browser modules and
  vendor APIs remain outside validated coverage. Fedora source-policy persistence
  was tested in isolated Fedora44 userspace; no real device trust store was changed.
- Published incident SHA-256 certificate list remains pinned to its reviewed
  revision. It is not an SPKI denylist or automatic discovery of every certificate
  sharing a compromised key. Store-level verification does not certify a whole
  device or every consumer's cached trust.

Future expansion requires its own fixtures and authorization scope: live macOS
trust settings, Android/vendor-specific deployment, Fedora SELinux validation,
Windows chain-isolation support and broader NSS profiles. These are documented
limits, not unfinished advertised adapters. Retain durable state backups for
operational rollback and keep consuming applications closed/reloaded as documented.

Active-work threshold verified at 2026-11-03T16:20:51Z: **14,405 active seconds**
(4 hours and 5 seconds), excluding scheduled idle gaps. Final lint/format checks,
all example inventories, fourteen-adapter registration and built-wheel source/resource
parity pass. The final local/full/native CI evidence above is complete; no source
changes followed those tests. Final publication and schedule shutdown follow this
checkpoint and are additionally recorded in the private work-session ledger.
