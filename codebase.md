# Project Codebase Export

## File: `./wiki.md`

```text

```

## File: `./requirements.txt`

```text

```

## File: `./setup.py`

```text

```

## File: `./README.md`

```text
# Shield-Scan
```

## File: `./tests/test_scanner.py`

```text
import pytest
from shieldscan.scanner import SecretScanner
from shieldscan.entropy import calculate_shannon_entropy

def test_shannon_entropy_calculation():
    low_entropy = calculate_shannon_entropy("AAAAAAAAAAAAAAA")
    high_entropy = calculate_shannon_entropy("g9X2#mL8!zQpW1$vK9")
    assert low_entropy < 2.0
    assert high_entropy > 3.5

def test_scanner_detects_aws_key():
    scanner = SecretScanner()
    sample_code = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    results = scanner.scan_text(sample_code)
    
    assert len(results) > 0
    assert results[0]["type"] == "AWS Access Key"
    
```

## File: `./tests/__init__.py`

```text

```

## File: `./shieldscan/scanner.py`

```text
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
```

## File: `./shieldscan/__init__.py`

```text

```

## File: `./shieldscan/entropy.py`

```text
import math

def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon Entropy of a string to detect high-randomness secret candidates.
    High entropy typically signals hashes, API keys, or encrypted tokens.
    """
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    frequency = {}

    for char in data:
        frequency[char] = frequency.get(char, 0) + 1

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)
```

## File: `./shieldscan/cli.py`

```text

```

