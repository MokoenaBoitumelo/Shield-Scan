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
    def __init__(self, entropy_threshold: float = 4.5):
        self.entropy_threshold = entropy_threshold

    def scan_text(self, content: str) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            # 1. Pattern Matching
            for secret_type, pattern in DEFAULT_PATTERNS.items():
                if re.search(pattern, line):
                    findings.append({
                        "line": line_num,
                        "type": secret_type,
                        "match": line.strip(),
                        "reason": "Pattern Match"
                    })

            # 2. High Entropy Analysis on Individual Tokens
            tokens = line.split()
            for token in tokens:
                clean_token = token.strip("'\",;")
                if len(clean_token) >= 20:  # Minimum threshold for entropy evaluation
                    entropy = calculate_shannon_entropy(clean_token)
                    if entropy >= self.entropy_threshold:
                        findings.append({
                            "line": line_num,
                            "type": "High Entropy String",
                            "match": clean_token,
                            "entropy": entropy,
                            "reason": f"Entropy ({entropy}) exceeds threshold ({self.entropy_threshold})"
                        })

        return findings