# Shield-Scan
# Shield Scan 🛡️

**Shield Scan** is an open-source static application security testing (SAST) tool built in Python. It detects accidentally exposed secrets, private keys, API tokens, and high-entropy cryptographic strings within local source code repositories and project files.

---

## 🎯 Purpose of the Project

Hardcoded secrets in version control are one of the most common vectors for cloud account takeovers and infrastructure breaches. Shield Scan provides developers and security teams with an automated tool to identify sensitive credentials before code is committed or deployed to production environments.

By combining **Regex Pattern Matching** with **Shannon Entropy Analysis**, Shield Scan flags both known key structures (e.g., AWS access keys) and arbitrary randomized secrets (e.g., database passwords, tokens).

---

## 🔒 Cyber Security Applications

In real-world DevSecOps environments, Shield Scan serves key security functions:

1. **Pre-Commit Defense**: Runs locally as a git pre-commit hook to block developers from committing credentials.
2. **CI/CD Pipeline Gatekeeper**: Integrates into build pipelines (e.g., GitHub Actions, GitLab CI) to break builds if secrets are detected.
3. **Repository Auditing**: Conducts security reviews across legacy codebases to remediate hardcoded credentials.
4. **Credential Leak Prevention**: Lowers corporate risk by preventing credential exposure on public code platforms like GitHub.

---

## 🚀 Getting Started

### Prerequisites

* Python 3.8 or higher
* `pip` package manager

### Installation

1. **Clone the Repository**:
   ```bash
   git clone [https://github.com/your-username/Shield-Scan.git](https://github.com/your-username/Shield-Scan.git)
   cd Shield-Scan
   


# To Have Me Working On Your Local Machine

Create and Activate a Virtual Environment:

    Bash
    python3 -m venv venv
    source venv/bin/activate
Install Dependencies and Editable CLI:

    Bash
    pip install -r requirements.txt
    pip install -e .



## 💻 Running the Project
Once installed, use the shieldscan command directly in your terminal:

Basic Directory Scan
Scan your current working directory:

    Bash
    shieldscan .
Scan a Specific File
Target a single configuration file or script:

    Bash
    shieldscan path/to/config.py
Custom Entropy Threshold
Lower the Shannon entropy threshold (default is 4.5) to catch lower-randomness strings:

    Bash
    shieldscan . --entropy 4.0
Output Findings in JSON Format
Export structured results for integration into security dashboards or scripts:

    Bash
    shieldscan . --format json



## 🧪 Running Unit Tests
Shield Scan uses pytest for unit testing.

Ensure your virtual environment is active:

    Bash
    source venv/bin/activate
Run the full test suite:

    Bash
    pytest
Run tests with detailed verbose output:
        
    Bash
    pytest -v



## 🔬 How Detection Works
Shield Scan uses a dual-layer strategy to identify high-risk strings:

1. Pattern Matching: Matches strings against predefined regular expressions targeting known formats like AWS Access Keys (AKIA...) and Private Key headers (-----BEGIN PRIVATE KEY-----).   

2. Shannon Entropy Analysis: Evaluates string randomness using Shannon entropy math[cite: 1]:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
Tokens exceeding the set entropy threshold (e.g., 4.5) are flagged as potential cryptographic keys or secret tokens[cite: 1].




## 🛠️ Project Structure
Plaintext
Shield-Scan/
├── shieldscan/
│   ├── __init__.py
│   ├── cli.py          # Command Line Interface logic
│   ├── entropy.py      # Shannon Entropy calculation engine
│   └── scanner.py      # Core secret scanning implementation
├── tests/
│   ├── __init__.py
│   └── test_scanner.py # Unit tests for scanner and entropy functions
├── codebase.md         # Reference export of project code
├── README.md           # Project documentation
├── requirements.txt    # Python dependencies
└── setup.py            # Package packaging configuration


---

Verification Code: WTC-QS638A6D

### Step-by-Step Implementation Instructions

1. Open VS Code and locate `README.md` at the root of the project[cite: 1].
2. Replace its existing contents with the code snippet above[cite: 1].
3. Save the file.
4. Preview the formatted Markdown file in VS Code by pressing `Ctrl + K`, then `V` (or `Cmd + K`, `V` on macOS).



Verification Code: WTC-QS638A6D