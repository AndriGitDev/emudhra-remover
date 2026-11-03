"""Fail-closed validation of the complete supported Java PKCS12 bag layout."""

from collections import Counter

from asn1crypto import pkcs12
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import pkcs12 as crypto_pkcs12

FRIENDLY_NAME = "1.2.840.113549.1.9.20"
JAVA_TRUST = "2.16.840.1.113894.746875.1.1"


def safe_contents(item, password: bytes) -> bytes:
    if item["content_type"].native == "data":
        return item["content"].native
    if item["content_type"].native != "encrypted_data":
        raise ValueError("Unsupported PKCS12 authenticated-safe content")
    encrypted = item["content"]
    if encrypted["unprotected_attrs"].native is not None:
        raise ValueError("Unsupported PKCS12 unprotected attributes")
    info = encrypted["encrypted_content_info"]
    algorithm = info["content_encryption_algorithm"]
    if info["content_type"].native != "data" or algorithm["algorithm"].native != "pbes2":
        raise ValueError("PKCS12 adapter requires PBES2 encryption or plaintext safe contents")
    parameters = algorithm["parameters"]
    derivation = parameters["key_derivation_func"]
    if derivation["algorithm"].native != "pbkdf2":
        raise ValueError("Unsupported PKCS12 key derivation")
    kdf = derivation["parameters"]
    salt, iterations = kdf["salt"].native, kdf["iteration_count"].native
    scheme = parameters["encryption_scheme"]
    length = {"aes128_cbc": 16, "aes192_cbc": 24, "aes256_cbc": 32}.get(scheme["algorithm"].native)
    hash_class = {
        "sha1": hashes.SHA1,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }.get(kdf["prf"]["algorithm"].native)
    if (
        length is None
        or hash_class is None
        or not isinstance(salt, bytes)
        or not 8 <= len(salt) <= 128
        or not 1 <= iterations <= 1_000_000
        or kdf["key_length"].native not in (None, length)
    ):
        raise ValueError("Unsupported PKCS12 encryption parameters")
    iv = scheme["parameters"].native
    if not isinstance(iv, bytes) or len(iv) != 16:
        raise ValueError("Invalid PKCS12 AES IV")
    key = PBKDF2HMAC(
        algorithm=hash_class(), length=length, salt=salt, iterations=iterations
    ).derive(password)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(info["encrypted_content"].native) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def validate_java_pfx(data: bytes, password: bytes) -> Counter:
    container = pkcs12.Pfx.load(data, strict=True)
    if (
        container["version"].native != "v3"
        or container["auth_safe"]["content_type"].native != "data"
        or container["mac_data"].native is None
    ):
        raise ValueError("Java PKCS12 requires a version-3 password-authenticated PFX")
    if not 1 <= container["mac_data"]["iterations"].native <= 1_000_000:
        raise ValueError("Unsupported PKCS12 MAC iteration count")
    certificates, aliases = [], set()
    authenticated = pkcs12.AuthenticatedSafe.load(
        container["auth_safe"]["content"].native, strict=True
    )
    for item in authenticated:
        for bag in pkcs12.SafeContents.load(safe_contents(item, password), strict=True):
            if bag["bag_id"].native != "cert_bag" or bag["bag_value"]["cert_id"].native != "x509":
                raise ValueError("PKCS12 contains unsupported non-certificate bags")
            attributes = {}
            for attribute in bag["bag_attributes"]:
                oid = attribute["type"].dotted
                if oid in attributes or oid not in (FRIENDLY_NAME, JAVA_TRUST):
                    raise ValueError("Unsupported or duplicate PKCS12 bag attribute")
                attributes[oid] = attribute["values"].native
            if (
                set(attributes) != {FRIENDLY_NAME, JAVA_TRUST}
                or len(attributes[FRIENDLY_NAME]) != 1
                or not attributes[JAVA_TRUST]
            ):
                raise ValueError("Every PKCS12 certificate must be a named Java trusted entry")
            alias = attributes[FRIENDLY_NAME][0].casefold()
            if alias in aliases:
                raise ValueError("Duplicate or case-colliding PKCS12 aliases")
            aliases.add(alias)
            certificates.append(bag["bag_value"]["cert_value"].parsed.dump())
    # Bag/encryption constraints are checked before the second parser performs
    # password work, so unsupported key bags and extreme KDF costs fail early.
    loaded = crypto_pkcs12.load_pkcs12(data, password)
    if loaded.key is not None:
        raise ValueError("PKCS12 identity/key stores are unsupported")
    independently_loaded = (
        [loaded.cert] if loaded.cert is not None else []
    ) + loaded.additional_certs
    actual = Counter(
        c.certificate.public_bytes(serialization.Encoding.DER) for c in independently_loaded
    )
    if actual != Counter(certificates):
        raise ValueError("PKCS12 certificate enumeration differs between parsers")
    return actual
