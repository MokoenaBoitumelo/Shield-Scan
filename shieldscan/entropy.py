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