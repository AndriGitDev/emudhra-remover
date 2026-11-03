"""Unsigned certificate-only Apple configuration-profile source files.

This edits a deployment artifact; it never installs a profile or changes Keychains.
"""

import base64
import binascii
import plistlib
import re
import struct
from xml.parsers import expat

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ..certificates import digest

COMMON = {
    "PayloadType",
    "PayloadVersion",
    "PayloadUUID",
    "PayloadIdentifier",
    "PayloadDisplayName",
    "PayloadDescription",
    "PayloadOrganization",
}
TOP = COMMON | {"PayloadContent", "PayloadScope", "PayloadRemovalDisallowed", "ConsentText"}
CERTIFICATE = COMMON | {"PayloadContent", "PayloadCertificateFileName"}
KINDS = {"com.apple.security.root", "com.apple.security.pkcs1", "com.apple.security.pem"}
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
PEM = re.compile(
    rb"\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----\s*\Z"
)


class UniqueDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise ValueError("Duplicate Apple profile dictionary key")
        super().__setitem__(key, value)


def validate_xml(data):
    """Reject XML that plistlib may otherwise silently ignore or reinterpret."""
    parser = expat.ParserCreate()
    stack, count = [], 0
    allowed = {"plist", "dict", "array", "key", "string", "integer", "data", "true", "false"}

    def start(name, attrs):
        nonlocal count
        count += 1
        if len(stack) >= 16 or count > 50000:
            raise ValueError("Apple profile XML exceeds structure limits")
        if name not in allowed or (not stack and name != "plist") or (stack and name == "plist"):
            raise ValueError("Unsupported Apple profile XML element")
        if attrs and (name != "plist" or attrs != {"version": "1.0"}):
            raise ValueError("Unsupported Apple profile XML attributes")
        if stack:
            parent = stack[-1]
            if parent[0] == "plist":
                valid = name == "dict" and parent[1] == 0
            elif parent[0] == "dict":
                valid = (name == "key") == (parent[1] % 2 == 0)
            else:
                valid = parent[0] == "array" and name != "key"
            if not valid:
                raise ValueError("Invalid Apple profile XML nesting")
            parent[1] += 1
        stack.append([name, 0, []])

    def characters(text):
        if stack:
            if stack[-1][0] in ("plist", "dict", "array", "true", "false") and text.strip():
                raise ValueError("Unexpected text in Apple profile XML")
            if stack[-1][0] in ("data", "integer"):
                stack[-1][2].append(text)

    def end(_):
        name, children, text = stack.pop()
        if (name == "plist" and children != 1) or (name == "dict" and children % 2):
            raise ValueError("Incomplete Apple profile XML container")
        if name == "integer" and "".join(text) != "1":
            raise ValueError("Apple profile XML integers must be canonical version 1")
        if name == "data":
            try:
                encoded = re.sub(rb"\s", b"", "".join(text).encode("ascii"))
                raw = base64.b64decode(encoded, validate=True)
                if base64.b64encode(raw) != encoded:
                    raise ValueError("Noncanonical Apple profile data encoding")
            except (UnicodeEncodeError, binascii.Error) as error:
                raise ValueError("Invalid Apple profile data encoding") from error

    def entity(*_):
        raise ValueError("Apple profile XML entities are unsupported")

    def doctype(name, system, public, internal):
        if (name, system, public, internal) != (
            "plist",
            "http://www.apple.com/DTDs/PropertyList-1.0.dtd",
            "-//Apple//DTD PLIST 1.0//EN",
            0,
        ):
            raise ValueError("Unsupported Apple profile XML document type")

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CharacterDataHandler = characters
    parser.EntityDeclHandler = entity
    parser.ExternalEntityRefHandler = entity
    parser.SkippedEntityHandler = entity
    parser.StartDoctypeDeclHandler = doctype
    try:
        parser.Parse(data, True)
    except expat.ExpatError as error:
        raise ValueError("Invalid Apple profile XML") from error


def validate_binary(data):
    """Bound plistlib's allocations before it follows binary object references."""
    if len(data) < 40:
        raise ValueError("Truncated Apple binary profile")
    offset_size, ref_size, count, root, table = struct.unpack(">6xBBQQQ", data[-32:])
    if (
        offset_size not in (1, 2, 4, 8)
        or ref_size not in (1, 2, 4, 8)
        or not 1 <= count <= 50000
        or root >= count
        or table < 8
        or table + count * offset_size != len(data) - 32
    ):
        raise ValueError("Invalid or oversized Apple binary profile table")
    offsets = [
        int.from_bytes(data[i : i + offset_size], "big")
        for i in range(table, len(data) - 32, offset_size)
    ]
    if len(set(offsets)) != count or any(not 8 <= offset < table for offset in offsets):
        raise ValueError("Invalid Apple binary profile object offsets")
    ordered = sorted(offsets)
    references = 0
    for position, boundary in zip(ordered, ordered[1:] + [table], strict=True):
        marker = data[position]
        position += 1
        kind, size = marker & 0xF0, marker & 0x0F
        if marker in (0x08, 0x09):
            continue
        if kind == 0x10:
            size = 1 << size
            if size > 16 or position + size > boundary:
                raise ValueError("Invalid Apple binary integer")
            continue
        if kind not in (0x40, 0x50, 0x60, 0xA0, 0xD0):
            raise ValueError("Unsupported Apple binary profile object")
        if size == 15:
            if position >= boundary or data[position] & 0xF0 != 0x10:
                raise ValueError("Invalid Apple binary object size")
            length_bytes = 1 << (data[position] & 0x0F)
            position += 1
            if length_bytes > 8 or position + length_bytes > boundary:
                raise ValueError("Oversized Apple binary object size")
            size = int.from_bytes(data[position : position + length_bytes], "big")
            position += length_bytes
        multiplier = (
            ref_size * (2 if kind == 0xD0 else 1)
            if kind in (0xA0, 0xD0)
            else (2 if kind == 0x60 else 1)
        )
        if position + size * multiplier > boundary:
            raise ValueError("Apple binary object exceeds its bounds")
        if kind in (0xA0, 0xD0):
            references += size * (2 if kind == 0xD0 else 1)
            if references > 500000:
                raise ValueError("Apple binary profile has excessive references")
            for i in range(position, position + size * multiplier, ref_size):
                if int.from_bytes(data[i : i + ref_size], "big") >= count:
                    raise ValueError("Invalid Apple binary object reference")


def common_fields(payload, allowed, identifiers, uuids):
    if not isinstance(payload, dict) or payload.keys() - allowed:
        raise ValueError("Unsupported Apple profile fields or payload structure")
    if type(payload.get("PayloadVersion")) is not int or payload["PayloadVersion"] != 1:
        raise ValueError("Apple profile requires PayloadVersion 1")
    for key in COMMON - {"PayloadVersion"}:
        value = payload.get(key)
        if key in ("PayloadType", "PayloadIdentifier", "PayloadUUID") or key in payload:
            if not isinstance(value, str) or not value or len(value) > 8192:
                raise ValueError("Invalid Apple profile identity/metadata field")
    identifier, uuid = payload["PayloadIdentifier"], payload["PayloadUUID"]
    if not UUID.fullmatch(uuid) or uuid.lower() in uuids or identifier in identifiers:
        raise ValueError("Invalid or duplicate Apple profile UUID/identifier")
    identifiers.add(identifier)
    uuids.add(uuid.lower())


def certificate(payload):
    data = payload.get("PayloadContent")
    if not isinstance(data, bytes) or not data:
        raise ValueError("Apple certificate payload requires binary data")
    if "PayloadCertificateFileName" in payload and not isinstance(
        payload["PayloadCertificateFileName"], str
    ):
        raise ValueError("Invalid Apple certificate filename metadata")
    if payload["PayloadType"] == "com.apple.security.pem":
        match = PEM.fullmatch(data)
        if match is None:
            raise ValueError("Apple PEM payload must contain exactly one public certificate")
        encoded = re.sub(rb"\s", b"", match[1])
        try:
            der = base64.b64decode(encoded, validate=True)
        except binascii.Error as error:
            raise ValueError("Invalid Apple PEM certificate encoding") from error
        if base64.b64encode(der) != encoded:
            raise ValueError("Noncanonical Apple PEM certificate encoding")
    else:
        der = data
    cert = x509.load_der_x509_certificate(der)
    if cert.public_bytes(Encoding.DER) != der:
        raise ValueError("Apple payload must contain exactly one DER certificate")
    return cert, der


def load_profile(data):
    if not data or len(data) > 16 * 1024 * 1024:
        raise ValueError("Apple profile exceeds size limits")
    binary = data.startswith(b"bplist00")
    if binary:
        validate_binary(data)
    else:
        if not data.lstrip().startswith((b"<?xml", b"<plist")):
            raise ValueError("Expected unsigned XML/binary Apple profile; CMS is unsupported")
        validate_xml(data)
    try:
        profile = plistlib.loads(data, dict_type=UniqueDict)
    except (plistlib.InvalidFileException, OverflowError, RecursionError) as error:
        raise ValueError("Invalid Apple configuration profile") from error
    identifiers, uuids = set(), set()
    common_fields(profile, TOP, identifiers, uuids)
    if profile["PayloadType"] != "Configuration":
        raise ValueError("Expected an Apple Configuration profile")
    payloads = profile.get("PayloadContent")
    if not isinstance(payloads, list) or not 1 <= len(payloads) <= 4096:
        raise ValueError("Apple profile requires a bounded certificate payload list")
    if "PayloadScope" in profile and profile["PayloadScope"] not in ("User", "System"):
        raise ValueError("Unsupported Apple profile scope")
    if (
        "PayloadRemovalDisallowed" in profile
        and type(profile["PayloadRemovalDisallowed"]) is not bool
    ):
        raise ValueError("Invalid Apple profile removal metadata")
    if "ConsentText" in profile:
        consent = profile["ConsentText"]
        if not isinstance(consent, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in consent.items()
        ):
            raise ValueError("Invalid Apple profile consent metadata")
    certificates = []
    for payload in payloads:
        common_fields(payload, CERTIFICATE, identifiers, uuids)
        if payload["PayloadType"] not in KINDS:
            raise ValueError(
                "Only public certificate payloads are supported; dependencies/identities refused"
            )
        certificates.append(certificate(payload))
    return profile, certificates, plistlib.FMT_BINARY if binary else plistlib.FMT_XML


def filter_apple_profile(data: bytes, incident: dict):
    profile, certificates, format = load_profile(data)
    policy = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    matches, retained = [], []
    for payload, (cert, der) in zip(profile["PayloadContent"], certificates, strict=True):
        entry = policy.get(digest(der))
        if entry:
            matches.append(
                {
                    **entry,
                    "subject": cert.subject.rfc4514_string(),
                    "payload_uuid": payload["PayloadUUID"],
                    "payload_identifier": payload["PayloadIdentifier"],
                }
            )
        else:
            retained.append(payload)
    if not matches:
        return [], data, len(certificates)
    profile = {**profile, "PayloadContent": retained}
    output = plistlib.dumps(profile, fmt=format, sort_keys=False)
    if plistlib.loads(output) != profile:
        raise ValueError("Apple profile survivor verification failed")
    # Service prevents applying an all-matching plan. Keep it auditable here.
    if retained:
        load_profile(output)
    return matches, output, len(certificates)
