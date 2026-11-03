import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

// Source-launched on the controller with JDK 17+. Only temporary copies are opened.
class TrustStore {
    static Map<String, String> inspect(KeyStore store) throws Exception {
        Map<String, String> entries = new TreeMap<>();
        for (String alias : Collections.list(store.aliases())) {
            if (!store.isCertificateEntry(alias) || store.isKeyEntry(alias)) {
                throw new IllegalArgumentException("KEY_ENTRIES_UNSUPPORTED");
            }
            KeyStore.TrustedCertificateEntry entry =
                (KeyStore.TrustedCertificateEntry) store.getEntry(alias, null);
            String certificate = Base64.getEncoder().encodeToString(entry.getTrustedCertificate().getEncoded());
            List<String> attributes = new ArrayList<>();
            for (KeyStore.Entry.Attribute attribute : entry.getAttributes()) {
                attributes.add(Base64.getEncoder().encodeToString(attribute.getName().getBytes(StandardCharsets.UTF_8))
                    + ":" + Base64.getEncoder().encodeToString(attribute.getValue().getBytes(StandardCharsets.UTF_8)));
            }
            Collections.sort(attributes);
            entries.put(alias, certificate + "\n" + attributes.toString());
        }
        return entries;
    }
    static KeyStore load(String format, String path, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance(format);
        try (InputStream stream = Files.newInputStream(Path.of(path))) {
            store.load(stream, password);
            if (stream.read() != -1) throw new IllegalArgumentException("TRAILING_DATA");
        }
        return store;
    }
    static void run(String[] args, char[] password) throws Exception {
        if (args.length != 4 || !(args[0].equals("JKS") || args[0].equals("PKCS12"))) {
            throw new IllegalArgumentException("UNSUPPORTED_FORMAT");
        }
        Security.setProperty("keystore.type.compat", "false");
        KeyStore store = load(args[0], args[1], password);
        Map<String, String> before = inspect(store);
        if (before.isEmpty()) throw new IllegalArgumentException("EMPTY_STORE");
        Set<String> denied = new HashSet<>(Files.readAllLines(Path.of(args[3])));
        for (String fingerprint : denied) {
            if (!fingerprint.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("BAD_POLICY");
        }
        Map<String, String> remaining = new TreeMap<>(before);
        for (String alias : before.keySet()) {
            byte[] certificate = store.getCertificate(alias).getEncoded();
            String fingerprint = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate));
            System.out.println("ENTRY\t" + Base64.getEncoder().encodeToString(alias.getBytes(StandardCharsets.UTF_8))
                + "\t" + Base64.getEncoder().encodeToString(certificate));
            if (denied.contains(fingerprint)) {
                store.deleteEntry(alias);
                remaining.remove(alias);
            }
        }
        if (remaining.size() == before.size()) {
            Files.copy(Path.of(args[1]), Path.of(args[2]));
        } else {
            // An empty candidate may be inspected, but the service refuses to apply it.
            try (OutputStream stream = Files.newOutputStream(Path.of(args[2]), StandardOpenOption.CREATE_NEW)) {
                store.store(stream, password);
            }
            if (!inspect(load(args[0], args[2], password)).equals(remaining)) {
                throw new IllegalArgumentException("SURVIVOR_VERIFICATION_FAILED");
            }
        }
        System.out.println("OK");
    }
    public static void main(String[] args) {
        String secret = System.getenv("EMUDHRA_JAVA_STORE_PASSWORD");
        if (secret == null) { System.err.println("PASSWORD_NOT_SET"); System.exit(2); }
        char[] password = secret.toCharArray();
        try { run(args, password); }
        catch (Exception error) {
            // Never print paths, aliases, passwords, provider exceptions or stack traces.
            String message = error instanceof IllegalArgumentException ? error.getMessage() : "STORE_OPERATION_FAILED";
            System.err.println(message);
            System.exit(2);
        } finally { Arrays.fill(password, '\0'); }
    }
}
