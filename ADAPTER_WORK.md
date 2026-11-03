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
4. NSS SQL databases with native certutil; Firefox must be closed, preserve all
   unrelated records and trust flags, handle database sidecars and concurrency.
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
