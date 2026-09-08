import math

def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon Entropy of a string to detect high-randomness secret candidates.
    High entropy typically signals hashes, API keys, or encrypted tokens.
    """