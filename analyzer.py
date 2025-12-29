#!/usr/bin/env python3
"""
PCAP Forensics Tool - CTF Edition
Universal network capture analyzer for forensics challenges
"""

import os
import re
import sys
import json
import subprocess
import shutil
from collections import defaultdict
from pathlib import Path

class PCAPAnalyzer:
    def __init__(self, pcap_file, search_patterns=None):
        self.pcap_file = pcap_file
        self.output_dir = Path("analysis_output")
        self.output_dir.mkdir(exist_ok=True)
        
        # User-defined search patterns
        self.search_patterns = []
        if search_patterns:
            self.search_patterns = [p.encode() if isinstance(p, str) else p for p in search_patterns]
        
        # Security/vulnerability patterns (always checked)
        self.vuln_patterns = {
            'credentials': [
                rb'password[:\s=]+[^\s\r\n]{3,}',
                rb'passwd[:\s=]+[^\s\r\n]{3,}',
                rb'pwd[:\s=]+[^\s\r\n]{3,}',
                rb'user[:\s=]+[^\s\r\n]{3,}',
                rb'username[:\s=]+[^\s\r\n]{3,}',
                rb'login[:\s=]+[^\s\r\n]{3,}',
            ],
            'api_keys': [
                rb'api[_-]?key[:\s=]+[A-Za-z0-9_\-]{16,}',
                rb'apikey[:\s=]+[A-Za-z0-9_\-]{16,}',
                rb'token[:\s=]+[A-Za-z0-9_\-]{16,}',
                rb'secret[:\s=]+[A-Za-z0-9_\-]{16,}',
            ],
            'private_keys': [
                rb'-----BEGIN.*PRIVATE KEY-----',
                rb'-----BEGIN RSA PRIVATE KEY-----',
            ],
            'sql_injection': [
                rb"'[\s]*OR[\s]+'1'[\s]*=[\s]*'1",
                rb'UNION[\s]+SELECT',
                rb';[\s]*DROP[\s]+TABLE',
            ],
            'command_injection': [
                rb';\s*(?:cat|ls|pwd|whoami|id|uname)',
                rb'\|\s*(?:cat|ls|pwd|whoami|id|uname)',
                rb'`(?:cat|ls|pwd|whoami|id|uname)',
            ],
            'path_traversal': [
                rb'\.\./\.\.',
                rb'\.\.\\\.\.\\',
            ],
        }
    
    def check_tshark(self):
        """Check if tshark is installed"""
        if not shutil.which('tshark'):
            print("\n" + "="*60)
            print("ERROR: tshark not found on your device")
            print("="*60)
            print("\nTshark is part of Wireshark and is required for this tool.")
            print("\nInstallation instructions:")
            print("\n  Linux (Debian/Ubuntu):")
            print("    sudo apt-get update")
            print("    sudo apt-get install tshark")
            print("\n  Linux (Fedora/RHEL):")
            print("    sudo dnf install wireshark-cli")
            print("\n  macOS (with Homebrew):")
            print("    brew install wireshark")
            print("\n  Windows:")
            print("    Download from: https://www.wireshark.org/download.html")
            print("    Make sure to add Wireshark to PATH during installation")
            print("\nAfter installation, you may need to:")
            print("  - Restart your terminal")
            print("  - Add tshark to your PATH")
            print("  - Run with appropriate permissions (sudo on Linux)")
            print("\n" + "="*60)
            return False
        return True
    
    def run_tshark(self, args):
        """Execute tshark command with error handling"""
        cmd = ['tshark', '-r', self.pcap_file] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Check for permission errors
            if result.returncode != 0 and result.stderr:
                if 'permission denied' in result.stderr.lower():
                    print(f"    Warning: Permission denied. Try running with sudo")
                elif 'not found' in result.stderr.lower():
                    print(f"    Warning: Command failed - tshark may not be properly installed")
                elif result.stderr.strip():
                    print(f"    Warning: {result.stderr.strip()[:100]}")
            
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            print(f"    Warning: Command timeout after 60 seconds")
            return None, "Timeout"
        except FileNotFoundError:
            print(f"    Error: tshark executable not found")
            return None, "Not found"
        except Exception as e:
            print(f"    Warning: Command failed - {str(e)[:100]}")
            return None, str(e)
    
    def analyze_protocols(self):
        """Get protocol hierarchy and conversations"""
        print("[*] Analyzing protocol hierarchy...")
        
        stdout, stderr = self.run_tshark(['-q', '-z', 'io,phs'])
        if stdout:
            try:
                with open(self.output_dir / 'protocol_hierarchy.txt', 'w') as f:
                    f.write(stdout)
            except IOError as e:
                print(f"    Warning: Could not write protocol hierarchy - {e}")
        
        for proto in ['tcp', 'udp']:
            stdout, _ = self.run_tshark(['-q', '-z', f'conv,{proto}'])
            if stdout:
                try:
                    with open(self.output_dir / f'{proto}_conversations.txt', 'w') as f:
                        f.write(stdout)
                except IOError as e:
                    print(f"    Warning: Could not write {proto} conversations - {e}")
    
    def extract_http_objects(self):
        """Extract HTTP transferred files"""
        print("[*] Extracting HTTP objects...")
        http_dir = self.output_dir / 'http_objects'
        
        try:
            http_dir.mkdir(exist_ok=True)
        except OSError as e:
            print(f"    Warning: Could not create directory - {e}")
            return []
        
        self.run_tshark(['--export-objects', f'http,{http_dir}'])
        
        try:
            files = list(http_dir.glob('*'))
            if files:
                print(f"    Found {len(files)} HTTP objects")
            return files
        except Exception as e:
            print(f"    Warning: Could not list HTTP objects - {e}")
            return []
    
    def extract_ftp_data(self):
        """Extract FTP transferred files"""
        print("[*] Extracting FTP data...")
        ftp_dir = self.output_dir / 'ftp_data'
        
        try:
            ftp_dir.mkdir(exist_ok=True)
        except OSError as e:
            print(f"    Warning: Could not create directory - {e}")
            return []
        
        # Get FTP commands
        stdout, _ = self.run_tshark(['-Y', 'ftp', '-T', 'fields', 
                                      '-e', 'ftp.request.command', 
                                      '-e', 'ftp.request.arg'])
        if stdout:
            try:
                with open(self.output_dir / 'ftp_commands.txt', 'w') as f:
                    f.write(stdout)
            except IOError as e:
                print(f"    Warning: Could not write FTP commands - {e}")
        
        self.run_tshark(['--export-objects', f'ftp-data,{ftp_dir}'])
        
        try:
            files = list(ftp_dir.glob('*'))
            if files:
                print(f"    Found {len(files)} FTP files")
            return files
        except Exception as e:
            print(f"    Warning: Could not list FTP files - {e}")
            return []
    
    def extract_images(self):
        """Extract embedded images from capture"""
        print("[*] Extracting images...")
        img_dir = self.output_dir / 'images'
        
        try:
            img_dir.mkdir(exist_ok=True)
        except OSError as e:
            print(f"    Warning: Could not create directory - {e}")
            return 0
        
        try:
            with open(self.pcap_file, 'rb') as f:
                data = f.read()
        except IOError as e:
            print(f"    Error: Could not read PCAP file - {e}")
            return 0
        
        image_types = {
            'jpeg': (b'\xff\xd8\xff', b'\xff\xd9'),
            'png': (b'\x89PNG\r\n\x1a\n', b'IEND\xaeB`\x82'),
            'gif': (b'GIF89a', b'\x00;'),
        }
        
        total_images = 0
        for img_type, (start_sig, end_sig) in image_types.items():
            pos = 0
            img_count = 0
            
            while True:
                pos = data.find(start_sig, pos)
                if pos == -1:
                    break
                
                end_pos = data.find(end_sig, pos)
                if end_pos != -1:
                    if img_type == 'png':
                        end_pos += len(end_sig)
                    else:
                        end_pos += 2
                    
                    img_data = data[pos:end_pos]
                    filename = img_dir / f'{img_type}_{img_count}.{img_type if img_type != "jpeg" else "jpg"}'
                    
                    try:
                        with open(filename, 'wb') as f:
                            f.write(img_data)
                        img_count += 1
                        total_images += 1
                    except IOError as e:
                        print(f"    Warning: Could not write image - {e}")
                
                pos += 1
        
        if total_images > 0:
            print(f"    Extracted {total_images} images")
        
        return total_images
    
    def extract_streams(self):
        """Extract all TCP streams (binary + text)"""
        print("[*] Extracting TCP streams...")
        streams_dir = self.output_dir / 'tcp_streams'
        
        try:
            streams_dir.mkdir(exist_ok=True)
        except OSError as e:
            print(f"    Warning: Could not create directory - {e}")
            return 0
        
        stdout, _ = self.run_tshark(['-T', 'fields', '-e', 'tcp.stream'])
        if not stdout:
            return 0
        
        streams = set(line.strip() for line in stdout.split('\n') if line.strip())
        
        for stream_id in streams:
            stdout, _ = self.run_tshark([
                '-Y', f'tcp.stream eq {stream_id}',
                '-T', 'fields', '-e', 'data'
            ])
            
            if stdout:
                hex_data = stdout.replace('\n', '').replace(':', '')
                try:
                    binary_data = bytes.fromhex(hex_data)
                    
                    # Always save binary
                    try:
                        with open(streams_dir / f'stream_{stream_id}.bin', 'wb') as f:
                            f.write(binary_data)
                    except IOError:
                        pass
                    
                    # Save as text if mostly printable
                    try:
                        text = binary_data.decode('utf-8', errors='ignore')
                        printable_chars = sum(c.isprintable() or c in '\n\r\t' for c in text)
                        printable_ratio = printable_chars / len(text) if text else 0
                        
                        if printable_ratio > 0.7 and text.strip():
                            with open(streams_dir / f'stream_{stream_id}.txt', 'w', 
                                    encoding='utf-8', errors='ignore') as f:
                                f.write(text)
                    except:
                        pass
                except ValueError:
                    pass
                except Exception:
                    pass
        
        print(f"    Extracted {len(streams)} TCP streams")
        return len(streams)
    
    def search_user_patterns(self):
        """Search for user-defined patterns across all data"""
        if not self.search_patterns:
            return []
        
        print(f"[*] Searching for {len(self.search_patterns)} pattern(s)...")
        found = []
        
        search_locations = [
            ('tcp_streams', ['*.bin', '*.txt']),
            ('http_objects', ['*']),
            ('ftp_data', ['*']),
            ('images', ['*']),
        ]
        
        # Search in extracted files
        for location, patterns in search_locations:
            loc_dir = self.output_dir / location
            if not loc_dir.exists():
                continue
            
            for file_pattern in patterns:
                for file_path in loc_dir.glob(file_pattern):
                    try:
                        with open(file_path, 'rb') as f:
                            data = f.read()
                        
                        for pattern in self.search_patterns:
                            matches = re.findall(pattern, data, re.IGNORECASE)
                            for match in matches:
                                try:
                                    decoded = match.decode('utf-8', errors='ignore')
                                    printable = sum(c.isprintable() for c in decoded)
                                    ratio = printable / len(decoded) if decoded else 0
                                    
                                    if ratio > 0.6:
                                        if not any(decoded == f[0] for f in found):
                                            found.append((decoded, f'{location}/{file_path.name}'))
                                except:
                                    pass
                    except IOError:
                        pass
                    except Exception:
                        pass
        
        # Search in DNS traffic
        stdout, _ = self.run_tshark(['-Y', 'dns', '-T', 'fields', 
                                     '-e', 'dns.qry.name', '-e', 'dns.resp.name'])
        if stdout:
            for pattern in self.search_patterns:
                matches = re.findall(pattern, stdout.encode(), re.IGNORECASE)
                for match in matches:
                    try:
                        decoded = match.decode('utf-8', errors='ignore')
                        if not any(decoded == f[0] for f in found):
                            found.append((decoded, 'dns_traffic'))
                    except:
                        pass
        
        # Search in HTTP headers
        for field in ['http.request.uri', 'http.cookie', 'http.user_agent']:
            stdout, _ = self.run_tshark(['-Y', 'http', '-T', 'fields', '-e', field])
            if stdout:
                for pattern in self.search_patterns:
                    matches = re.findall(pattern, stdout.encode(), re.IGNORECASE)
                    for match in matches:
                        try:
                            decoded = match.decode('utf-8', errors='ignore')
                            if not any(decoded == f[0] for f in found):
                                found.append((decoded, f'http_header:{field}'))
                        except:
                            pass
        
        # Search in ICMP
        stdout, _ = self.run_tshark(['-Y', 'icmp', '-T', 'fields', '-e', 'data.data'])
        if stdout:
            for pattern in self.search_patterns:
                matches = re.findall(pattern, stdout.encode(), re.IGNORECASE)
                for match in matches:
                    try:
                        decoded = match.decode('utf-8', errors='ignore')
                        if not any(decoded == f[0] for f in found):
                            found.append((decoded, 'icmp_data'))
                    except:
                        pass
        
        # Search in UDP
        stdout, _ = self.run_tshark(['-Y', 'udp', '-T', 'fields', '-e', 'data.data'])
        if stdout:
            hex_data = stdout.replace('\n', '').replace(':', '')
            try:
                binary_data = bytes.fromhex(hex_data)
                for pattern in self.search_patterns:
                    matches = re.findall(pattern, binary_data, re.IGNORECASE)
                    for match in matches:
                        try:
                            decoded = match.decode('utf-8', errors='ignore')
                            if not any(decoded == f[0] for f in found):
                                found.append((decoded, 'udp_data'))
                        except:
                            pass
            except ValueError:
                pass
            except Exception:
                pass
        
        # Search raw PCAP
        try:
            with open(self.pcap_file, 'rb') as f:
                pcap_data = f.read()
            
            for pattern in self.search_patterns:
                matches = re.findall(pattern, pcap_data, re.IGNORECASE)
                for match in matches:
                    try:
                        decoded = match.decode('utf-8', errors='ignore')
                        printable = sum(c.isprintable() for c in decoded)
                        ratio = printable / len(decoded) if decoded else 0
                        
                        if ratio > 0.6:
                            if not any(decoded == f[0] for f in found):
                                found.append((decoded, 'raw_pcap'))
                    except:
                        pass
        except IOError as e:
            print(f"    Warning: Could not read PCAP file - {e}")
        except Exception:
            pass
        
        if found:
            print(f"    Found {len(found)} matches\n")
            try:
                with open(self.output_dir / 'search_results.txt', 'w', 
                         encoding='utf-8', errors='ignore') as f:
                    f.write("="*70 + "\n")
                    f.write("SEARCH RESULTS\n")
                    f.write("="*70 + "\n\n")
                    
                    complete = [(m, s) for m, s in found if m.count('{') == m.count('}') and '{' in m]
                    incomplete = [(m, s) for m, s in found if m not in [c[0] for c in complete]]
                    
                    if complete:
                        print("  Complete matches:")
                        f.write("COMPLETE MATCHES:\n")
                        f.write("-"*70 + "\n")
                        for match, source in complete:
                            clean = ''.join(c if c.isprintable() else '?' for c in match)
                            print(f"    [{source}] {clean}")
                            f.write(f"[{source}] {match}\n")
                        f.write("\n")
                    
                    if incomplete:
                        print("\n  Partial/incomplete matches:")
                        f.write("PARTIAL/INCOMPLETE MATCHES:\n")
                        f.write("-"*70 + "\n")
                        for match, source in incomplete:
                            clean = ''.join(c if c.isprintable() else '?' for c in match)
                            print(f"    [{source}] {clean}")
                            f.write(f"[{source}] {match}\n")
            except IOError as e:
                print(f"    Warning: Could not write search results - {e}")
        else:
            print("    No matches found")
        
        return found
    
    def check_security(self):
        """Check for security indicators"""
        print("[*] Checking for security indicators...")
        findings = defaultdict(list)
        
        try:
            with open(self.pcap_file, 'rb') as f:
                pcap_data = f.read()
        except IOError as e:
            print(f"    Error: Could not read PCAP file - {e}")
            return findings
        
        for category, patterns in self.vuln_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, pcap_data, re.IGNORECASE)
                for match in matches:
                    try:
                        decoded = match.decode('utf-8', errors='ignore')
                        if decoded not in findings[category]:
                            findings[category].append(decoded)
                    except:
                        pass
        
        streams_dir = self.output_dir / 'tcp_streams'
        if streams_dir.exists():
            for stream_file in streams_dir.glob('*.txt'):
                try:
                    with open(stream_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    for category, patterns in self.vuln_patterns.items():
                        for pattern in patterns:
                            matches = re.findall(pattern, content.encode(), re.IGNORECASE)
                            for match in matches:
                                try:
                                    decoded = match.decode('utf-8', errors='ignore')
                                    if decoded not in findings[category]:
                                        findings[category].append(decoded)
                                except:
                                    pass
                except IOError:
                    pass
        
        if findings:
            print("    Found security indicators\n")
            try:
                with open(self.output_dir / 'security_findings.txt', 'w', 
                         encoding='utf-8', errors='ignore') as f:
                    for category, items in findings.items():
                        print(f"  {category}: {len(items)} found")
                        f.write(f"\n{category.upper()}:\n")
                        f.write("="*70 + "\n")
                        for item in items[:10]:
                            clean = ''.join(c if c.isprintable() else '?' for c in item[:100])
                            f.write(f"{clean}\n")
            except IOError as e:
                print(f"    Warning: Could not write security findings - {e}")
        
        return findings
    
    def extract_credentials(self):
        """Extract potential credentials"""
        print("[*] Looking for credentials...")
        creds = []
        
        # FTP credentials
        stdout, _ = self.run_tshark([
            '-Y', 'ftp.request.command == "USER" or ftp.request.command == "PASS"',
            '-T', 'fields', '-e', 'ftp.request.command', '-e', 'ftp.request.arg'
        ])
        if stdout:
            lines = stdout.strip().split('\n')
            for i in range(0, len(lines)-1, 2):
                if 'USER' in lines[i]:
                    parts = lines[i].split('\t')
                    user = parts[1] if len(parts) > 1 else 'unknown'
                    parts = lines[i+1].split('\t')
                    pwd = parts[1] if len(parts) > 1 else 'unknown'
                    creds.append(f"FTP: {user}:{pwd}")
        
        # HTTP Basic Auth
        stdout, _ = self.run_tshark(['-Y', 'http.authorization', 
                                     '-T', 'fields', '-e', 'http.authorization'])
        if stdout:
            for line in stdout.strip().split('\n'):
                if line:
                    creds.append(f"HTTP Auth: {line}")
        
        if creds:
            print(f"    Found {len(creds)} credentials\n")
            try:
                with open(self.output_dir / 'credentials.txt', 'w', 
                         encoding='utf-8', errors='ignore') as f:
                    for cred in creds:
                        print(f"    {cred}")
                        f.write(cred + '\n')
            except IOError as e:
                print(f"    Warning: Could not write credentials - {e}")
        
        return creds
    
    def generate_report(self):
        """Generate analysis summary"""
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        
        report = {
            'pcap_file': self.pcap_file,
            'output_directory': str(self.output_dir),
            'extracted': {}
        }
        
        for subdir in ['tcp_streams', 'http_objects', 'ftp_data', 'images']:
            path = self.output_dir / subdir
            if path.exists():
                try:
                    count = len(list(path.glob('*')))
                    report['extracted'][subdir] = count
                    if count > 0:
                        print(f"  {subdir}: {count}")
                except Exception:
                    pass
        
        for result_file in ['search_results.txt', 'security_findings.txt', 'credentials.txt']:
            if (self.output_dir / result_file).exists():
                print(f"  {result_file}: available")
        
        try:
            with open(self.output_dir / 'report.json', 'w') as f:
                json.dump(report, f, indent=2)
        except IOError as e:
            print(f"  Warning: Could not write report - {e}")
        
        print(f"\n  Output: {self.output_dir}/")
        print("="*60)
    
    def run_analysis(self):
        """Execute full analysis"""
        # Check tshark availability first
        if not self.check_tshark():
            sys.exit(1)
        
        print(f"\nAnalyzing: {self.pcap_file}")
        print(f"Output: {self.output_dir}/\n")
        
        try:
            self.analyze_protocols()
            self.extract_streams()
            self.extract_http_objects()
            self.extract_ftp_data()
            self.extract_images()
            self.search_user_patterns()
            self.check_security()
            self.extract_credentials()
            self.generate_report()
            print("\nAnalysis complete.")
        except KeyboardInterrupt:
            print("\n\nAnalysis interrupted by user.")
            sys.exit(1)
        except Exception as e:
            print(f"\nError: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


def main():
    print("="*60)
    print("PCAP Forensics Analyzer")
    print("="*60)
    
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python analyzer.py <file.pcap>")
        print("  python analyzer.py <file.pcap> [options]")
        print("\nOptions:")
        print("  -s, --search PATTERN       Search for custom regex pattern")
        print("  -c, --ctf-pattern PREFIX   Search for CTF flag format (e.g., FLAG, CTF)")
        print("  -f, --flag-format PREFIX   Alias for --ctf-pattern")
        print("\nExamples:")
        print("  python analyzer.py capture.pcap")
        print("  python analyzer.py capture.pcap -s 'password'")
        print("  python analyzer.py capture.pcap -c FLAG")
        print("  python analyzer.py capture.pcap -f picoCTF -s 'api.key'")
        print("\nNote: CTF patterns automatically search for PREFIX{...} format (complete and incomplete)")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not os.path.exists(pcap_file):
        print(f"\nError: File '{pcap_file}' not found")
        print("Please check the file path and try again.")
        sys.exit(1)
    
    # Check if file is readable
    try:
        with open(pcap_file, 'rb') as f:
            f.read(1)
    except IOError as e:
        print(f"\nError: Cannot read file '{pcap_file}'")
        print(f"Reason: {e}")
        sys.exit(1)
    
    # Parse arguments
    patterns = []
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        
        # CTF pattern shortcuts
        if arg in ['-c', '--ctf-pattern', '-f', '--flag-format'] and i + 1 < len(sys.argv):
            prefix = sys.argv[i + 1]
            # Add both complete and incomplete patterns
            patterns.append(rf'{prefix}\{{[^\}}]+\}}')  # Complete: PREFIX{...}
            patterns.append(rf'{prefix}\{{[^\}}]{{8,}}')  # Incomplete: PREFIX{...
            i += 2
        # Custom search pattern
        elif arg in ['-s', '--search'] and i + 1 < len(sys.argv):
            patterns.append(sys.argv[i + 1])
            i += 2
        else:
            i += 1
    
    if patterns:
        print(f"\nSearch patterns ({len(patterns)}):")
        for p in patterns:
            print(f"  {p}")
    
    analyzer = PCAPAnalyzer(pcap_file, patterns if patterns else None)
    analyzer.run_analysis()


if __name__ == '__main__':
    main()