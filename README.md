# Hacking-tools
hahahahahahah(evil laughsss)
This repository contains two(for now more in futuree as i learn more hackingggggg ) Python scripts for working with devices on your local network:

1. **ver1.py** - Network Device Finder and File Writer
2. **ver2.py** - Enhanced Network Tool with Remote Command Execution

Both tools allow you to discover devices on your network and write files to them. The second version (ver2.py) adds powerful remote command execution capabilities.

## Prerequisites

### For ver1.py:
- Python 3.6+
- Standard Python libraries
- Optional: `nmap` for advanced network scanning
- Optional: `smbclient` for SMB share discovery on Linux/macOS

### For ver2.py (additional requirements):
- `paramiko` library for SSH connections
- For Windows targets: PowerShell remoting enabled on target
- For Linux/macOS targets: SSH server running on target

Install the required package for ver2.py:
```bash
pip install paramiko
```

## Usage

### Basic Device Discovery (Both Versions)

Discover all devices on your local network:
```bash
# Using ver1.py
python ver1.py --discover

# Using ver2.py
python ver2.py --discover
```

This will show:
- Your computer's hostname and IP address
- All devices found on your network
- Available SMB shares on discovered devices
- Example network paths for available shares

### Writing Files to Network Devices (Both Versions)

Write a file to a networked device:
```bash
# Using ver1.py
python ver1.py --path "//192.168.1.100/ShareName" --filename "hello.txt" --content "Hello World!"

# Using ver2.py
python ver2.py --path "//192.168.1.100/ShareName" --filename "hello.txt" --content "Hello World!"
```

### Remote Command Execution (ver2.py only)

Execute commands on remote Linux/macOS devices using SSH:
```bash
python ver2.py --exec "ls -la" --host "192.168.1.100" --user "username"
```

Execute commands on remote Windows devices using PowerShell remoting:
```bash
python ver2.py --exec "Get-Process" --host "192.168.1.100" --user "username" --windows
```

Additional options:
- `--port` - Specify custom SSH port (default: 22)
- `--password` - Provide password on command line (not recommended for security reasons)

## Examples

### Workflow Example with ver1.py

1. Discover devices on your network:
   ```bash
   python ver1.py --discover
   ```

2. Write a file to a discovered device:
   ```bash
   python ver1.py --path "//192.168.1.100/Documents" --filename "report.txt" --content "Quarterly Report"
   ```

### Advanced Workflow Example with ver2.py

1. Discover devices on your network:
   ```bash
   python ver2.py --discover
   ```

2. Execute a command on a Linux device:
   ```bash
   python ver2.py --exec "df -h" --host "192.168.1.100" --user "admin"
   ```

3. Execute a command on a Windows device:
   ```bash
   python ver2.py --exec "Get-ChildItem C:\" --host "192.168.1.200" --user "administrator" --windows
   ```

4. Write a file to a discovered device:
   ```bash
   python ver2.py --path "//192.168.1.100/Documents" --filename "report.txt" --content "Quarterly Report"
   ```

## Troubleshooting

### File Writing Issues
- Ensure the target device is accessible
- Verify you have write permissions to the shared folder
- For Windows shares, you may need to authenticate first:
  - Windows: `net use \\SERVER\share /user:username password`
  - Linux/Mac: Mount with appropriate credentials

### Command Execution Issues
- Ensure SSH server is running (Linux/macOS targets)
- Ensure PowerShell remoting is enabled (Windows targets)
- Verify firewall settings allow the connection
- Verify username and password are correct

## Security Notice

**Important:** These tools should only be used on networks and devices you own or have explicit permission to access. Unauthorized access to computer systems is illegal in most jurisdictions.

The remote command execution functionality in ver2.py is particularly powerful and should be used responsibly.
