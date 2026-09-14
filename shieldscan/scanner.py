import re
from typing import List, Dict, Any
from shieldscan.entropy import calculate_shannon_entropy

# High-risk token regex patterns
DEFAULT_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
    "Generic API Token": r"(?i)(api_key|apikey|secret|password)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"
}

class SecretScanner: