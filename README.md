# Prototype Pollution Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Static Analysis](https://img.shields.io/badge/security-static_analysis-orange)](https://owasp.org/www-community/vulnerabilities/Prototype_Pollution)

A sophisticated static analysis tool for detecting **Prototype Pollution vulnerabilities** in JavaScript/TypeScript codebases and identifying vulnerable dependencies in Node.js projects.

> ⚠️ **Security Notice**: This tool performs *static analysis only* and may produce false positives/negatives. Always combine with manual code review and dynamic testing for comprehensive security auditing.

## 🔍 Key Features

- **Multi-layer Detection**:
  - Direct `__proto__`/`constructor.prototype` assignments
  - Unsafe merge/extend operations with user input
  - Vulnerable dependency identification (lodash, minimist, yargs-parser, etc.)
  - Unsafe `JSON.parse()` reviver functions
  - Custom recursive merge functions without safeguards
  - VM context pollution vectors

- **Intelligent Analysis**:
  - Confidence scoring (0-100%) for each finding
  - Context-aware pattern matching with regex heuristics
  - Safe pattern recognition (`Object.create(null)`, `Map`, `hasOwnProperty`)
  - Semantic version comparison for dependency vulnerability checks

- **Professional Reporting**:
  - Colorized console output with severity-based highlighting
  - JSON export for CI/CD integration
  - HTML reports with interactive styling
  - Detailed mitigation recommendations per finding
  - CVE references for vulnerable dependencies

- **Production Ready**:
  - Configurable ignore patterns
  - Deep scanning capabilities
  - Node.js ecosystem aware (respects `node_modules` by default)
  - Comprehensive logging with file output
  - Progress tracking for large codebases

## 🚀 Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup
```bash
# Clone the repository
git clone https://github.com/arkanzasfeziii/prototype-pollution-scanner.git
cd prototype-pollution-scanner

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Linux/MacOS
# OR
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```
#🛠️ Usage
```bash
Basic Scan
python prototypepollutionscan.py /path/to/project

Advanced Options
# Deep scan including node_modules
python prototypepollutionscan.py . --deep --include-node-modules

# Generate JSON report for CI/CD pipelines
python prototypepollutionscan.py . --output report.json

# Generate HTML report for auditors
python prototypepollutionscan.py . --output report.html

# Custom ignore patterns
python prototypepollutionscan.py . --ignore 'test/**' --ignore '*.spec.js'

# Verbose logging for debugging
python prototypepollutionscan.py . --verbose
```
#Full Command Reference
```bash
usage: prototypepollutionscan.py [-h] [--deep] [--include-node-modules]
                                 [--ignore IGNORE] [--output OUTPUT]
                                 [--verbose] [--examples] [--version]
                                 [--no-banner]
                                 [path]

Prototype Pollution Scanner - Static analysis for Prototype Pollution in Node.js

positional arguments:
  path                  Path to scan (file or directory)

options:
  -h, --help            show this help message and exit
  --deep                Enable deep scanning
  --include-node-modules
                        Include node_modules in scan
  --ignore IGNORE       Additional ignore patterns (can be used multiple times)
  --output OUTPUT       Output file (.json or .html)
  --verbose             Verbose logging
  --examples            Show detailed usage examples
  --version             show program's version number and exit
  --no-banner           Skip banner
```
