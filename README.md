# CTF Simple PCAP Analyzer

A comprehensive network capture analysis tool designed for CTF challenges and digital forensics. This tool automates the extraction and analysis of network traffic data from PCAP files, helping security researchers and CTF players quickly identify flags, credentials, and security indicators.

## Features

### Automated Extraction
- **Protocol Analysis**: Complete protocol hierarchy and conversation statistics
- **TCP Stream Extraction**: Automatic extraction of all TCP streams in both binary and text formats
- **HTTP Object Export**: Retrieves all files transferred via HTTP
- **FTP Data Recovery**: Extracts FTP commands and transferred files
- **Image Extraction**: Carves JPEG, PNG, and GIF images from packet data

### Pattern Searching
- **CTF Flag Detection**: Built-in support for CTF flag formats with customizable prefixes
- **Custom Regex Search**: Search for any pattern across all extracted data
- **Multi-source Search**: Searches across TCP streams, HTTP objects, DNS queries, ICMP data, and raw packets

### Security Analysis
- **Credential Detection**: Automatically identifies potential passwords, usernames, and API keys
- **Vulnerability Indicators**: Scans for SQL injection, command injection, and path traversal attempts
- **Private Key Detection**: Identifies exposed cryptographic keys
- **HTTP Authentication**: Extracts HTTP Basic Auth credentials

### Comprehensive Output
- Organized directory structure for all extracted artifacts
- Detailed text reports for findings
- JSON summary report for programmatic access
- Protocol hierarchy and conversation statistics

## Installation

### Prerequisites

This tool requires `tshark` (part of Wireshark) to be installed on your system.

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install tshark
```

#### Linux (Fedora/RHEL)
```bash
sudo dnf install wireshark-cli
```

#### macOS (with Homebrew)
```bash
brew install wireshark
```

#### Windows
Download and install Wireshark from [wireshark.org](https://www.wireshark.org/download.html). Ensure that the installation directory is added to your system PATH.

### Clone Repository
```bash
git clone https://github.com/reinharrt/ctf-simple-pcap-analyzer.git
cd ctf-simple-pcap-analyzer
```

### Verify Installation
```bash
tshark --version
```

## Usage

### Basic Analysis
Analyze a PCAP file with default settings:
```bash
python analyzer.py capture.pcap
```

### CTF Flag Search
Search for flags with a specific prefix format:
```bash
# Search for FLAG{...} format
python analyzer.py capture.pcap -c FLAG

# Search for picoCTF{...} format
python analyzer.py capture.pcap -f picoCTF

# Search for custom CTF format
python analyzer.py capture.pcap -c HTB
```

### Custom Pattern Search
Search for specific strings or regex patterns:
```bash
# Search for password mentions
python analyzer.py capture.pcap -s password

# Search for API keys
python analyzer.py capture.pcap -s 'api[_-]?key'

# Multiple search patterns
python analyzer.py capture.pcap -c CTF -s password -s token
```

### Combined Analysis
Combine CTF flag search with custom patterns:
```bash
python analyzer.py capture.pcap -f DUCTF -s 'secret' -s 'key='
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-c, --ctf-pattern PREFIX` | Search for CTF flags with format PREFIX{...} |
| `-f, --flag-format PREFIX` | Alias for --ctf-pattern |
| `-s, --search PATTERN` | Search for custom regex pattern |

## Output Structure

All analysis results are saved in the `analysis_output/` directory:

```
analysis_output/
├── tcp_streams/          # Extracted TCP streams (.bin and .txt files)
├── http_objects/         # Files transferred via HTTP
├── ftp_data/             # FTP transferred files
├── images/               # Carved images (JPEG, PNG, GIF)
├── protocol_hierarchy.txt    # Protocol distribution statistics
├── tcp_conversations.txt     # TCP conversation pairs
├── udp_conversations.txt     # UDP conversation pairs
├── ftp_commands.txt          # FTP command log
├── search_results.txt        # Custom pattern search results
├── security_findings.txt     # Security indicators found
├── credentials.txt           # Extracted credentials
└── report.json              # JSON summary report
```

## Security Indicators Detected

The tool automatically scans for the following security indicators:

- **Credentials**: password, passwd, pwd, user, username, login fields
- **API Keys**: api_key, apikey, token, secret patterns
- **Private Keys**: PEM-formatted private keys
- **SQL Injection**: Common SQL injection patterns
- **Command Injection**: Shell command injection attempts
- **Path Traversal**: Directory traversal patterns

## Examples

### Example 1: Basic CTF Challenge
```bash
python analyzer.py challenge.pcap -c FLAG
```
Output:
```
[*] Analyzing protocol hierarchy...
[*] Extracting TCP streams...
    Extracted 15 TCP streams
[*] Extracting HTTP objects...
    Found 3 HTTP objects
[*] Searching for 2 pattern(s)...
    Found 1 matches

  Complete matches:
    [tcp_streams/stream_4.txt] FLAG{n3tw0rk_f0r3ns1cs_ftw}
```

### Example 2: Network Forensics Investigation
```bash
python analyzer.py suspicious_traffic.pcap -s password -s admin
```
Output:
```
[*] Looking for credentials...
    Found 2 credentials
    
    FTP: admin:P@ssw0rd123
    HTTP Auth: Basic YWRtaW46c2VjcmV0
```

### Example 3: Data Exfiltration Analysis
```bash
python analyzer.py exfil.pcap
```
The tool will automatically extract all transferred files, images, and analyze DNS queries for potential data exfiltration channels.

## Permissions

On Linux systems, you may need to run the tool with elevated privileges to access network capture files:

```bash
sudo python analyzer.py capture.pcap
```

Alternatively, grant your user permission to capture packets:
```bash
sudo usermod -a -G wireshark $USER
```
Then log out and log back in for the changes to take effect.

## Troubleshooting

### tshark not found
If you receive an error about tshark not being found:
1. Verify Wireshark is installed: `tshark --version`
2. Check that tshark is in your PATH
3. On Windows, ensure Wireshark installation directory is added to system PATH
4. Restart your terminal after installation

### Permission Denied
If you encounter permission errors:
- Run with sudo: `sudo python analyzer.py capture.pcap`
- Add your user to the wireshark group (Linux)
- Run terminal as Administrator (Windows)

### No Output Generated
If no analysis output is produced:
- Verify the PCAP file is valid and not corrupted
- Check that the file contains actual packet data
- Ensure you have write permissions in the current directory

## Contributing

Contributions are welcome. Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary
- Free to use, modify, and distribute
- No warranty provided
- Author is not liable for any damages or misuse

## Author

Developed by [reinharrt](https://github.com/reinharrt) for CTF players and network forensics enthusiasts.

Repository: [github.com/reinharrt/ctf-simple-pcap-analyzer](https://github.com/reinharrt/ctf-simple-pcap-analyzer)

## Disclaimer and Liability

**IMPORTANT - READ CAREFULLY**

This tool is provided "AS IS" without warranty of any kind. The author assumes NO responsibility or liability for:

- Any misuse or illegal use of this tool
- Any damages, losses, or legal consequences resulting from use of this tool
- Unauthorized network traffic analysis or packet capture
- Any violation of local, state, national, or international laws

**User Responsibilities:**
- Users must ensure they have proper legal authorization before analyzing any network traffic
- This tool is intended ONLY for:
  - Educational purposes and learning
  - Authorized CTF (Capture The Flag) competitions
  - Security research with explicit permission
  - Analysis of networks you own or have written permission to test

**Legal Notice:**
Unauthorized interception or analysis of network communications may be illegal in your jurisdiction. Users are solely responsible for compliance with all applicable laws and regulations.

By using this tool, you acknowledge that you have read this disclaimer and agree to use the tool responsibly and legally.

## Acknowledgments

This tool utilizes tshark (Wireshark) for packet analysis. Special thanks to the Wireshark development team for their excellent network analysis tools.