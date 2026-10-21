import os
import re
from typing import List, Dict, Any, Set
from shieldscan.entropy import calculate_shannon_entropy

# High-risk token regex patterns
DEFAULT_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Generic Private Key": r"-----BEGIN PRIVATE KEY-----",
    "Generic API Token": r"(?i)(api_key|apikey|secret|password)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"
}

# Default directories and file extensions to skip
DEFAULT_IGNORED_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules", ".idea", ".vscode"}
DEFAULT_IGNORED_EXTENSIONS = {".md", ".txt", ".png", ".jpg", ".pdf"}


class SecretScanner:
    """
    Scans text, files, and directories for exposed secrets and high-entropy strings.
    """
    def __init__(self, entropy_threshold: float = 4.5):
        self.entropy_threshold = entropy_threshold

    def scan_text(self, content: str, source_label: str = "inline") -> List[Dict[str, Any]]:
        """
        Scans multi-line text line by line for secret patterns and high entropy tokens.
        """
        findings = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, start=1):
            stripped_line = line.strip()

            # Skip comment lines or raw regex pattern assignments to avoid false positives
            if stripped_line.startswith("#") or "r\"" in stripped_line or "r'" in stripped_line:
                continue

            # 1. Pattern Matching
            for secret_type, pattern in DEFAULT_PATTERNS.items():
                if re.search(pattern, line):
                    findings.append({
                        "source": source_label,
                        "line": line_num,
                        "type": secret_type,
                        "match": line.strip(),
                        "reason": "Pattern Match"
                    })

            # 2. High Entropy Analysis on Individual Tokens
            tokens = line.split()
            for token in tokens:
                clean_token = token.strip("'\",;()")
                if len(clean_token) >= 20:
                    entropy = calculate_shannon_entropy(clean_token)
                    if entropy >= self.entropy_threshold:
                        findings.append({
                            "source": source_label,
                            "line": line_num,
                            "type": "High Entropy String",
                            "match": clean_token,
                            "entropy": entropy,
                            "reason": f"Entropy ({entropy}) exceeds threshold ({self.entropy_threshold})"
                        })

        return findings

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Safely opens and scans a single text file.
        """
        if not os.path.isfile(file_path):
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_text(content, source_label=file_path)
        except Exception as e:
            return [{
                "source": file_path,
                "line": 0,
                "type": "Read Error",
                "match": "",
                "reason": f"Could not read file: {str(e)}"
            }]

    def scan_directory(self, root_dir: str, ignore_dirs: Set[str] = None, ignore_exts: Set[str] = None) -> List[Dict[str, Any]]:
        """
        Recursively scans all non-ignored directories and files under root_dir.
        """
        if ignore_dirs is None:
            ignore_dirs = DEFAULT_IGNORED_DIRS
        if ignore_exts is None:
            ignore_exts = DEFAULT_IGNORED_EXTENSIONS

        all_findings = []
        for current_root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]
            for file_name in files:
                _, ext = os.path.splitext(file_name)
                if ext.lower() in ignore_exts:
                    continue

                full_path = os.path.join(current_root, file_name)
                findings = self.scan_file(full_path)
                all_findings.extend(findings)

        return all_findings