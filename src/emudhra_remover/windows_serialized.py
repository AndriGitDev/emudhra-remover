"""Strict native serialized certificate-element framing, with stable property order.

MS-OSHARED CertStoreCertificateGroup: property entries followed by certificate ID 32.
Only property ordering is normalized; IDs, encoding and every value byte survive.
"""

import struct


def canonical_element(data):
    position, properties = 0, {}
    if not data or len(data) > 16 * 1024 * 1024:
        raise ValueError("Invalid serialized Windows certificate size")
    while position < len(data):
        if len(data) - position < 12:
            raise ValueError("Truncated Windows certificate property")
        identifier, encoding, size = struct.unpack_from("<III", data, position)
        end = position + 12 + size
        if encoding != 1 or not 0 < identifier <= 65535 or end > len(data):
            raise ValueError("Invalid Windows certificate property header")
        block = data[position:end]
        position = end
        if identifier == 32:
            if position != len(data) or not size:
                raise ValueError("Trailing or empty Windows certificate element")
            return b"".join(properties[key] for key in sorted(properties)) + block
        if identifier in properties or len(properties) >= 256:
            raise ValueError("Duplicate or excessive Windows certificate properties")
        properties[identifier] = block
    raise ValueError("Serialized Windows element contains no certificate")


def property_ids(data):
    data = canonical_element(data)
    result, position = set(), 0
    while position < len(data):
        identifier, _, size = struct.unpack_from("<III", data, position)
        if identifier == 32:
            return result
        result.add(identifier)
        position += 12 + size
    raise ValueError("Missing Windows certificate element")
