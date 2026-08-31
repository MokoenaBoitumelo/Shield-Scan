import pytest
from shieldscan.scanner import SecretScanner
from shieldscan.entropy import calculate_shannon_entropy

def test_shannon_entropy_calculation():
    low_entropy = calculate_shannon_entropy("AAAAAAAAAAAAAAA")
    high_entropy = calculate_shannon_entropy("g9X2#mL8!zQpW1$vK9")
    assert low_entropy < 2.0
    assert high_entropy > 3.5

