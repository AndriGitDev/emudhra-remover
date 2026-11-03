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
