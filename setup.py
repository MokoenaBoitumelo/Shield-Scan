from setuptools import setup, find_packages

setup(
    name="shieldscan",
    version="0.1.0",
    description="Shield Scan: Security scanner for detecting hardcoded secrets and high-entropy strings.",
    author="Boitumelo Mokoena",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "shieldscan=shieldscan.cli:main",
        ],
    },
    python_requires=">=3.8",
)