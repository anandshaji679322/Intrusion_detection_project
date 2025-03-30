import subprocess
import os
import sys
import time
from datetime import datetime
import argparse
import shutil

# Parse command line arguments
parser = argparse.ArgumentParser(description='Capture network traffic using tshark')
parser.add_argument('--interface', type=str, default='WiFi', help='Network interface to capture traffic from')
parser.add_argument('--duration', type=int, default=30, help='Duration in seconds to capture traffic')
parser.add_argument('--filter', type=str, default='', help='Capture filter (e.g., "tcp")')
parser.add_argument('--list', action='store_true', help='List available interfaces and exit')
args = parser.parse_args()

# Define paths
project_dir = os.path.dirname(os.path.abspath(__file__))
output_dir = os.path.join(project_dir, 'realtime_data')
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# Find tshark executable
tshark_path = None

# Option 1: Use which/where command to find tshark in PATH
try:
    if os.name == 'nt':  # Windows
        result = subprocess.run(['where', 'tshark'], capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            tshark_path = result.stdout.strip().split('\n')[0]
    else:  # Unix/Linux/Mac
        result = subprocess.run(['which', 'tshark'], capture_output=True, text=True, check=False)
        if result.returncode == 0:
            tshark_path = result.stdout.strip()
except Exception:
    pass

# Option 2: Use shutil.which
if not tshark_path:
    tshark_path = shutil.which('tshark')

# Option 3: Check common installation locations
if not tshark_path:
    common_locations = [
        r'C:\Program Files\Wireshark\tshark.exe',
        r'C:\Program Files (x86)\Wireshark\tshark.exe',
        r'C:\Windows\System32\tshark.exe',
        r'C:\Windows\SysWOW64\tshark.exe',
        # Add more potential locations as needed
    ]
    for location in common_locations:
        if os.path.exists(location):
            tshark_path = location
            break

if not tshark_path:
    print("Error: Could not find tshark executable. Please make sure Wireshark is installed.")
    sys.exit(1)

print(f"Found tshark at: {tshark_path}")

# List available interfaces if requested
if args.list:
    try:
        print("Listing available network interfaces:")
        subprocess.run([tshark_path, '-D'], check=True)
        sys.exit(0)
    except Exception as e:
        print(f"Error listing interfaces: {str(e)}")
        sys.exit(1)

# Create timestamp for the capture file
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
capture_file_path = os.path.join(output_dir, f'capture_{timestamp}.pcapng')

print(f"Starting capture on interface '{args.interface}' for {args.duration} seconds...")
print(f"Output will be saved to: {capture_file_path}")

# Build the tshark command
cmd = [
    tshark_path,
    '-i', args.interface,
    '-w', capture_file_path
]

# Add filter if provided
if args.filter:
    cmd.extend(['-f', args.filter])

# Add duration
cmd.extend(['-a', f'duration:{args.duration}'])

# Print the command we're about to execute
print(f"Running command: {' '.join(cmd)}")

try:
    # Run the tshark command
    process = subprocess.Popen(cmd)
    
    # Display countdown
    for i in range(args.duration, 0, -1):
        sys.stdout.write(f"\rCapturing... {i} seconds remaining")
        sys.stdout.flush()
        time.sleep(1)
    
    # Wait for tshark to finish
    process.wait()
    
    # Wait to ensure file is fully written
    print("\nWaiting for file to be fully written...")
    time.sleep(2)
    
    # Verify the file exists and has content
    if os.path.exists(capture_file_path) and os.path.getsize(capture_file_path) > 0:
        print(f"Capture completed successfully!")
        print(f"PCAPNG file saved to: {capture_file_path} ({os.path.getsize(capture_file_path)} bytes)")
        
        # Now run the feature extraction script
        print("\nNow extracting features from the captured file...")
        extract_cmd = [
            'python', 
            os.path.join(project_dir, 'extract_features.py'),
            '--input_file', capture_file_path
        ]
        
        subprocess.run(extract_cmd)
    else:
        print(f"Error: Capture file was not created or is empty.")
        sys.exit(1)
    
except Exception as e:
    print(f"\nError during capture: {str(e)}")
    sys.exit(1) 