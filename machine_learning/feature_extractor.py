"""
ThreatOps 18-Feature Lexical & Shannon Entropy Extractor (`machine_learning/feature_extractor.py`)
--------------------------------------------------------------------------------------------------
Extracts an 18-dimensional numeric feature vector from any URL, IPv4, or Domain IOC
for the separated models inside `machine_learning/models/`.
"""

import math
import re
import sys
from typing import Dict, List

sys.dont_write_bytecode = True

FEATURE_NAMES: List[str] = [
    "length",
    "host_length",
    "path_length",
    "query_length",
    "shannon_entropy",
    "host_entropy",
    "consonant_vowel_ratio",
    "digit_ratio",
    "special_char_count",
    "dot_count",
    "hyphen_count",
    "slash_count",
    "max_token_length",
    "uses_ip_host",
    "has_non_standard_port",
    "has_suspicious_tld",
    "suspicious_keyword_count",
    "hex_encoding_ratio",
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "work", "click", "gq", "tk", "ml", "cf", "ga",
    "ru", "cn", "su", "pw", "cc", "biz", "info", "icu", "buzz", "monster",
}

SUSPICIOUS_KEYWORDS = [
    "mozi", "mirai", "gafgyt", "qbot", "emotet", "cobalt", "beacon",
    "bin.sh", "wget", "curl", "chmod", "payload", "dropper", "loader",
    "gate.php", "panel", "login", "verify", "secure", "update", "account",
    "banking", "wallet", "auth", "cmd", "powershell", "elf", "mips", "arm7",
]

IPV4_HOST_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HEX_CHAR_RE = re.compile(r"[0-9a-fA-F]")


def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    length = len(text)
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_ioc_features(ioc_value: str) -> Dict[str, float]:
    raw = str(ioc_value or "").strip()
    lower = raw.lower()
    total_len = max(len(raw), 1)

    without_proto = re.sub(r"^[a-zA-Z0-9+.-]+://", "", lower)
    query_part = ""
    if "?" in without_proto:
        without_proto, query_part = without_proto.split("?", 1)

    slash_idx = without_proto.find("/")
    if slash_idx >= 0:
        host_port = without_proto[:slash_idx]
        path_part = without_proto[slash_idx:]
    else:
        host_port = without_proto
        path_part = ""

    host_only = host_port
    port_num = None
    if ":" in host_port:
        h_part, p_part = host_port.rsplit(":", 1)
        if p_part.isdigit():
            host_only = h_part
            port_num = int(p_part)

    uses_ip_host = 1.0 if IPV4_HOST_RE.match(host_only) else 0.0
    has_non_standard_port = (
        1.0 if (port_num is not None and port_num not in (80, 443, 8080, 8443)) else 0.0
    )

    tld = host_only.rsplit(".", 1)[-1] if "." in host_only and not uses_ip_host else ""
    has_suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    vowels = sum(1 for c in lower if c in "aeiou")
    consonants = sum(1 for c in lower if c.isalpha() and c not in "aeiou")
    cv_ratio = round(consonants / max(vowels, 1), 4)

    digits = sum(1 for c in raw if c.isdigit())
    digit_ratio = round(digits / total_len, 4)

    special_chars = sum(1 for c in raw if not c.isalnum() and c not in ".:/-_")
    dot_count = float(raw.count("."))
    hyphen_count = float(raw.count("-"))
    slash_count = float(raw.count("/"))

    tokens = [t for t in re.split(r"[^a-zA-Z0-9]+", lower) if t]
    max_token_length = float(max((len(t) for t in tokens), default=0))

    suspicious_kw_count = float(sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower))

    hex_chars = len(HEX_CHAR_RE.findall(lower))
    hex_encoding_ratio = round((hex_chars / total_len) if ("%2" in lower or digits > 6) else 0.0, 4)

    return {
        "length": float(len(raw)),
        "host_length": float(len(host_only)),
        "path_length": float(len(path_part)),
        "query_length": float(len(query_part)),
        "shannon_entropy": calculate_shannon_entropy(raw),
        "host_entropy": calculate_shannon_entropy(host_only),
        "consonant_vowel_ratio": cv_ratio,
        "digit_ratio": digit_ratio,
        "special_char_count": float(special_chars),
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "slash_count": slash_count,
        "max_token_length": max_token_length,
        "uses_ip_host": uses_ip_host,
        "has_non_standard_port": has_non_standard_port,
        "has_suspicious_tld": has_suspicious_tld,
        "suspicious_keyword_count": suspicious_kw_count,
        "hex_encoding_ratio": hex_encoding_ratio,
    }


def feature_map_to_vector(feature_map: Dict[str, float]) -> List[float]:
    return [float(feature_map.get(name, 0.0)) for name in FEATURE_NAMES]
