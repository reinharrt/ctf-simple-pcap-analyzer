# CTF Simple PCAP Analyzer

Quick PCAP analysis tool for CTF challenges. Extracts streams, files, and searches for flags automatically.

## Quick Start

```bash
# Install tshark
sudo apt-get install tshark  # Linux
brew install wireshark       # macOS

# Run analysis
python analyzer.py capture.pcap

# Search for CTF flags
python analyzer.py capture.pcap -c FLAG
python analyzer.py capture.pcap -f picoCTF

# Custom search
python analyzer.py capture.pcap -s password -s token
```

## What It Does

- Extracts TCP streams, HTTP objects, FTP files, and images
- Searches for CTF flags with customizable prefixes
- Finds credentials, API keys, and security indicators
- Generates organized output in `analysis_output/` directory

## Options

```bash
-c, --ctf-pattern PREFIX    # Search for PREFIX{...} flags
-f, --flag-format PREFIX    # Same as above
-s, --search PATTERN        # Search custom regex pattern
```

## Output

```
analysis_output/
├── tcp_streams/
├── http_objects/
├── ftp_data/
├── images/
├── credentials.txt
├── security_findings.txt
└── report.json
```

## Examples

```bash
# Basic CTF
python analyzer.py chall.pcap -c FLAG

# Multiple patterns
python analyzer.py traffic.pcap -s admin -s secret

# Just extract everything
python analyzer.py capture.pcap
```

## License & Disclaimer

MIT License - free to use and modify.

**Use responsibly:** Only analyze traffic you're authorized to capture. This tool is for CTFs, education, and authorized testing only. No warranty provided, use at your own risk. 

By [@reinharrt](https://github.com/reinharrt)