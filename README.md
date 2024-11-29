# Enterprise Cybersecurity System

## Overview
This project is a comprehensive cybersecurity solution designed to protect enterprise-level file systems. It integrates custom threat detection, dynamic encryption, and adaptive defense mechanisms to provide robust security against a wide range of cyber threats.

## ⚠️ Important Warning
**This system should only be used in a controlled, isolated environment.** 
It contains powerful tools that could potentially disrupt live systems if not used carefully. Never deploy on production systems without thorough testing and proper authorization. The creators are not responsible for any damage caused by improper use of this software.

## Key Features
1. **Custom Yara Engine**
   - Advanced threat detection for malware, hidden files, and malicious scripts
   - Custom signature detection system
   - Integration with VirusTotal for multi-engine malware analysis

2. **Dynamic Encryption System**
   - 50-character key length
   - Multiple cipher techniques (substitution, transposition, Vigenère)
   - Custom hashing algorithm for file integrity verification

3. **Moving Target Defense (MTD)**
   - Dynamic protection settings based on detected threats
   - Automatic encryption key rotation
   - Real-time file system monitoring

4. **Security Recommendations Engine**
   - Automated generation of actionable security recommendations
   - Logging and auditing features for compliance

## Technologies Used
- Python
- Yara
- Cryptography libraries
- VirusTotal API

## Setup and Installation
1. Clone the repository:
   ```
   git clone https://github.com/MahitGtg/Rapido-Bank-by-Pile-
   ```
2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Set up VirusTotal API key:
   - Obtain an API key from VirusTotal
   - Add your API key to the `config.py` file

## Usage
1. Ensure you are operating in a controlled, isolated environment.
2. Run the main script:
   ```
   python main.py
   ```
3. Follow the on-screen prompts to select specific features or run a full system scan.

## Configuration
- Modify `config.py` to adjust settings such as scan intervals, encryption parameters, and file paths.
- Custom Yara rules can be added or modified in the `rules` directory.

## File Structure
```
enterprise-cybersecurity-system/
│
├── main.py                 # Main execution script
├── config.py               # Configuration settings
├── requirements.txt        # List of project dependencies
│
├── yara_engine/
│   ├── rules/              # Custom Yara rules
│   └── scanner.py          # Yara scanning implementation
│
├── encryption/
│   ├── cipher.py           # Encryption algorithms
│   └── key_manager.py      # Key generation and management
│
├── mtd/
│   └── defense.py          # Moving Target Defense implementation
│
├── security_recommendations/
│   └── generator.py        # Security recommendation logic
│
└── utils/
    ├── file_monitor.py     # File system monitoring
    └── virus_total.py      # VirusTotal API integration
```

## Contributing
Contributions to enhance the system are welcome. Please follow these steps:
1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Make your changes and commit (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature-branch`)
5. Create a new Pull Request


## Disclaimer
This software is provided "as is", without warranty of any kind, express or implied. The authors are not responsible for any damages or liability arising from its use. Always use in a controlled environment and obtain necessary permissions before deploying in any production setting.

## Contact
1. Mahit Gupta - mahit.gupta64@gmail.com
2. Lucas De Melo Veloso
3. Will Vetter

Project Link: https://github.com/MahitGtg/Rapido-Bank-by-Pile-
