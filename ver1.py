import os
import socket
import platform
import argparse
import subprocess
import re
import time
from threading import Thread
import ipaddress

def get_local_network_info():
    """Get local IP and determine network range"""
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    # Parse IP to determine network range
    ip_parts = local_ip.split('.')
    network_prefix = '.'.join(ip_parts[0:3])
    
    print(f"Your computer hostname: {hostname}")
    print(f"Your computer IP: {local_ip}")
    print(f"Network prefix: {network_prefix}.*")
    
    return local_ip, network_prefix

def ping_device(ip, active_devices):
    """Ping a specific IP address to check if it's active"""
    try:
        # Configure ping command based on OS
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", "1", "-w", "500", ip]
        else:  # Linux, macOS
            ping_cmd = ["ping", "-c", "1", "-W", "1", ip]
        
        result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            # Device responded to ping
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "Unknown"
            
            active_devices.append((ip, hostname))
            print(f"Found device: {ip} ({hostname})")
    except Exception as e:
        pass  # Silently ignore errors

def scan_network(network_prefix, max_devices=255):
    """Scan the network for active devices using parallel pings"""
    print(f"\nScanning network {network_prefix}.* for active devices...")
    print("This may take a few moments...\n")
    
    active_devices = []
    threads = []
    
    # Launch ping threads
    for i in range(1, max_devices + 1):
        ip = f"{network_prefix}.{i}"
        thread = Thread(target=ping_device, args=(ip, active_devices))
        thread.daemon = True
        threads.append(thread)
        thread.start()
        
        # Limit number of concurrent threads
        if len(threads) >= 20:
            for t in threads:
                t.join(0.05)
            threads = [t for t in threads if t.is_alive()]
    
    # Wait for remaining threads
    for t in threads:
        t.join()
    
    return sorted(active_devices, key=lambda x: [int(part) for part in x[0].split('.')])

def scan_network_with_nmap():
    """Alternative scan using nmap if installed"""
    try:
        result = subprocess.run(["nmap", "-sn", "-T4", "--min-parallelism", "100", f"192.168.1.0/24"], 
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            devices = []
            ip_pattern = r'Nmap scan report for (?:([^\s]+) )?(?:\()?(\d+\.\d+\.\d+\.\d+)(?:\))?'
            matches = re.finditer(ip_pattern, result.stdout)
            
            for match in matches:
                hostname = match.group(1) or "Unknown"
                ip = match.group(2)
                devices.append((ip, hostname))
            
            return devices
        return None
    except FileNotFoundError:
        return None

def scan_network_with_arp():
    """Use ARP table to find connected devices"""
    devices = []
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)'
        else:  # Linux, macOS
            result = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            pattern = r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)'
        
        if result.returncode == 0:
            matches = re.finditer(pattern, result.stdout.lower())
            for match in matches:
                ip = match.group(1)
                mac = match.group(2)
                
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    hostname = "Unknown"
                
                devices.append((ip, hostname))
        
        return devices
    except Exception:
        return []

def find_smb_shares(host):
    """Try to discover SMB shares on a host"""
    shares = []
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["net", "view", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode == 0:
                share_pattern = r'(\S+)\s+Disk'
                matches = re.finditer(share_pattern, result.stdout)
                for match in matches:
                    shares.append(match.group(1))
        else:
            # For Linux/Mac systems with smbclient
            try:
                result = subprocess.run(["smbclient", "-N", "-L", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if result.returncode == 0:
                    share_pattern = r'^\s+(\S+)\s+Disk'
                    for line in result.stdout.split('\n'):
                        match = re.search(share_pattern, line)
                        if match:
                            shares.append(match.group(1))
            except FileNotFoundError:
                pass
    except Exception:
        pass
    
    return shares

def discover_devices():
    """Find devices on the local network using multiple methods"""
    local_ip, network_prefix = get_local_network_info()
    
    # Try multiple discovery methods
    print("\nDiscovering network devices...")
    
    # Method 1: ARP table (fastest, but limited to recently connected devices)
    arp_devices = scan_network_with_arp()
    if arp_devices:
        print("\nDevices found in ARP cache:")
        for ip, hostname in arp_devices:
            print(f"IP: {ip} - Hostname: {hostname}")
    
    # Method 2: Try nmap if available (most comprehensive)
    nmap_devices = scan_network_with_nmap()
    if nmap_devices:
        print("\nDevices found with nmap scan:")
        for ip, hostname in nmap_devices:
            print(f"IP: {ip} - Hostname: {hostname}")
            # Try to find shares
            shares = find_smb_shares(ip)
            if shares:
                print(f"  Available shares: {', '.join(shares)}")
                print(f"  Network path example: //{ip}/{shares[0]}")
    
    # Method 3: Ping scan (fallback)
    if not nmap_devices and len(arp_devices) < 3:
        print("\nPerforming ping scan (this will take longer)...")
        ping_devices = scan_network(network_prefix)
        print("\nDevices found with ping scan:")
        for ip, hostname in ping_devices:
            print(f"IP: {ip} - Hostname: {hostname}")
            # Try to find shares
            shares = find_smb_shares(ip)
            if shares:
                print(f"  Available shares: {', '.join(shares)}")
                print(f"  Network path example: //{ip}/{shares[0]}")
    
    # Combine all unique devices
    all_devices = {}
    for devices in [arp_devices, nmap_devices or []]:
        for ip, hostname in devices:
            all_devices[ip] = hostname
    
    return all_devices

def write_file_to_network(network_path, filename, content):
    """Write content to a file on a network location"""
    try:
        # Create full path
        full_path = os.path.join(network_path, filename)
        
        # Ensure the directory exists
        os.makedirs(os.path.dirname(os.path.abspath(full_path)), exist_ok=True)
        
        # Write the file
        with open(full_path, 'w') as file:
            file.write(content)
        
        print(f"Successfully wrote to {full_path}")
        return True
    except Exception as e:
        print(f"Error writing file: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Write files to a networked device')
    parser.add_argument('--path', help='Network path (e.g., //SERVER/share or /mnt/share)')
    parser.add_argument('--filename', help='Name of the file to create')
    parser.add_argument('--content', default='Test content', help='Content to write to the file')
    parser.add_argument('--discover', action='store_true', help='Discover devices on the network')
    
    args = parser.parse_args()
    
    # Always run discovery if no specific action is requested
    if args.discover or not (args.path and args.filename):
        discover_devices()
        print("\n")
    
    # If path and filename provided, write the file
    if args.path and args.filename:
        # Detect OS and provide guidance
        current_os = platform.system()
        if current_os == "Windows":
            print("Windows detected. Network paths typically use format: \\\\SERVER\\ShareName\\folder")
            print("For this script, use format: //SERVER/ShareName/folder")
        elif current_os == "Linux":
            print("Linux detected. Ensure the remote share is mounted (e.g., /mnt/share)")
        elif current_os == "Darwin":
            print("macOS detected. Ensure the remote share is mounted (e.g., /Volumes/share)")

        success = write_file_to_network(args.path, args.filename, args.content)
        
        if success:
            print("Operation completed successfully")
        else:
            print("\nTroubleshooting tips:")
            print("1. Verify the network device is accessible")
            print("2. Check permissions - you need write access to the shared folder")
            print("3. For Windows shares, you may need to provide credentials:")
            print("   - Windows: net use \\\\SERVER\\share /user:username password")
            print("   - Linux/Mac: mount with appropriate credentials")
            print("4. Ensure the network path format is correct for your OS")
    else:
        if not args.discover:
            print("\nNo file operation specified. Use --path and --filename to write a file.")
            print("Example: python network_file_writer.py --path '//SERVER/share' --filename 'test.txt'")

if __name__ == "__main__":
    main()
