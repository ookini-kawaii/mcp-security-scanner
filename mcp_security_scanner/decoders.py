"""Bounded decoding of suspicious text payloads."""

import base64
import binascii
import re


BASE64_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_+/-])(?P<value>[A-Za-z0-9_+/-]{24,}={0,2})(?![A-Za-z0-9_+/-])"
)
MAX_DECODED_BYTES = 64 * 1024
MAX_ITEMS = 100


def extract_base64(text: str, depth: int = 0):
    if depth >= 2:
        return []
    results = []
    for match in BASE64_PATTERN.finditer(text):
        encoded = match.group("value")
        normalized = encoded.replace("-", "+").replace("_", "/")
        normalized += "=" * (-len(normalized) % 4)
        try:
            decoded_bytes = base64.b64decode(normalized, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not decoded_bytes or len(decoded_bytes) > MAX_DECODED_BYTES:
            continue
        decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
        if not decoded_text or len(decoded_text) < 5:
            continue
        printable_ratio = sum(char.isprintable() for char in decoded_text) / len(decoded_text)
        if printable_ratio < 0.7:
            continue
        result = {
            "encoded": encoded[:120],
            "decoded": decoded_text,
            "position": match.start("value"),
            "depth": depth + 1,
        }
        results.append(result)
        if len(results) >= MAX_ITEMS:
            break
    return results
