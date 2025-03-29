import pyshark
import pandas as pd
from collections import defaultdict
import numpy as np
from datetime import datetime
import os

# Dictionary to store flow information
flow_data = defaultdict(lambda: {
    'start_time': None,
    'packets': [],
    'state': 'INIT',
    'service': None,
    'bytes_forward': 0,
    'bytes_backward': 0,
    'packets_forward': 0,
    'packets_backward': 0
})

def calculate_features(flow_key, flow_info):
    packets = flow_info['packets']
    if not packets:
        return None
    
    # Convert timestamps to float and calculate duration
    try:
        start_time = float(packets[0].sniff_timestamp)
        end_time = float(packets[-1].sniff_timestamp)
        duration = end_time - start_time
    except (ValueError, AttributeError):
        duration = 0
    
    # Basic features
    proto = packets[0].transport_layer if hasattr(packets[0], 'transport_layer') else 'UNKNOWN'
    
    # Calculate packet counts and bytes
    spkts = flow_info['packets_forward']
    dpkts = flow_info['packets_backward']
    sbytes = flow_info['bytes_forward']
    dbytes = flow_info['bytes_backward']
    
    # Calculate rate
    rate = len(packets) / duration if duration > 0 else 0
    
    # Extract source and destination IP
    source_ip = packets[0].ip.src if hasattr(packets[0], 'ip') else None
    dest_ip = packets[0].ip.dst if hasattr(packets[0], 'ip') else None
    
    # Initialize all per-packet metric lists
    src_ttl_values = []
    dst_ttl_values = []
    forward_times = []
    backward_times = []
    swin_values = []
    dwin_values = []
    forward_pkt_sizes = []  # For smean calculation
    backward_pkt_sizes = []  # For dmean calculation
    
    # Track TCP sequence numbers for retransmission detection
    seq_nums_src = {}
    seq_nums_dst = {}
    
    # Track last packet timestamps for calculating interarrival times
    last_forward_time = None
    last_backward_time = None
    
    # Track packet sizes for mean calculations
    total_forward_size = 0
    total_backward_size = 0
    
    # Process each packet for detailed metrics
    for packet in packets:
        if not hasattr(packet, 'ip'):
            continue
            
        # Determine packet direction
        is_forward = packet.ip.src == source_ip
        
        # Get packet size
        try:
            pkt_size = int(packet.length)
            if is_forward:
                forward_pkt_sizes.append(pkt_size)
            else:
                backward_pkt_sizes.append(pkt_size)
        except (ValueError, AttributeError):
            pkt_size = 0
            
        # Extract TTL
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'ttl'):
            try:
                ttl_value = int(packet.ip.ttl)
                if is_forward:
                    src_ttl_values.append(ttl_value)
                else:
                    dst_ttl_values.append(ttl_value)
            except (ValueError, AttributeError):
                pass
                
        # Extract timestamp for interarrival times and jitter
        try:
            current_time = float(packet.sniff_timestamp)
            
            if is_forward:
                if last_forward_time is not None:
                    forward_times.append(current_time - last_forward_time)
                last_forward_time = current_time
            else:
                if last_backward_time is not None:
                    backward_times.append(current_time - last_backward_time)
                last_backward_time = current_time
        except (ValueError, AttributeError):
            pass
            
        # Extract window size for TCP packets
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'window_size'):
            try:
                win_size = int(packet.tcp.window_size)
                if is_forward:
                    swin_values.append(win_size)
                else:
                    dwin_values.append(win_size)
            except (ValueError, AttributeError):
                pass
                
        # Track TCP sequence numbers for retransmission detection
        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'seq'):
            try:
                seq_num = int(packet.tcp.seq)
                if is_forward:
                    if seq_num in seq_nums_src:
                        seq_nums_src[seq_num] += 1  # Count retransmissions
                    else:
                        seq_nums_src[seq_num] = 1
                else:
                    if seq_num in seq_nums_dst:
                        seq_nums_dst[seq_num] += 1  # Count retransmissions
                    else:
                        seq_nums_dst[seq_num] = 1
            except (ValueError, AttributeError):
                pass
    
    # Calculate TTL statistics
    sttl = np.mean(src_ttl_values) if src_ttl_values else 0
    dttl = np.mean(dst_ttl_values) if dst_ttl_values else 0
    
    # Calculate window size statistics
    swin = np.mean(swin_values) if swin_values else 0
    dwin = np.mean(dwin_values) if dwin_values else 0
    
    # Calculate mean packet sizes
    smean = np.mean(forward_pkt_sizes) if forward_pkt_sizes else 0
    dmean = np.mean(backward_pkt_sizes) if backward_pkt_sizes else 0
    
    # Calculate jitter (standard deviation of interarrival times)
    sjit = np.std(forward_times) if len(forward_times) > 1 else 0
    djit = np.std(backward_times) if len(backward_times) > 1 else 0
    
    # Calculate mean interpacket arrival time
    sinpkt = np.mean(forward_times) if forward_times else (duration/spkts if spkts > 0 else 0)
    dinpkt = np.mean(backward_times) if backward_times else (duration/dpkts if dpkts > 0 else 0)
    
    # Calculate packet loss based on retransmissions
    sloss = sum(1 for count in seq_nums_src.values() if count > 1) 
    dloss = sum(1 for count in seq_nums_dst.values() if count > 1)
    
    # Load calculations - bits per second
    sload = (sbytes * 8) / duration if duration > 0 else 0
    dload = (dbytes * 8) / duration if duration > 0 else 0
    
    # Initialize TCP-specific variables
    syn_time = None
    synack_time = None
    ack_time = None
    stcpb = 0
    dtcpb = 0
    
    # Track TCP handshake more accurately
    for packet in packets:
        if hasattr(packet, 'tcp'):
            try:
                tcp_flags = int(packet.tcp.flags, 16)
                
                # SYN packet (first handshake)
                if tcp_flags & 0x02 and not tcp_flags & 0x10:  # SYN but not ACK
                    if syn_time is None:  # Only capture first SYN
                        syn_time = float(packet.sniff_timestamp)
                        stcpb = int(packet.tcp.seq) if hasattr(packet.tcp, 'seq') else 0
                
                # SYN-ACK packet (second handshake)
                elif tcp_flags & 0x02 and tcp_flags & 0x10:  # Both SYN and ACK
                    if synack_time is None and syn_time is not None:  # Only capture first SYN-ACK after SYN
                        synack_time = float(packet.sniff_timestamp)
                        dtcpb = int(packet.tcp.seq) if hasattr(packet.tcp, 'seq') else 0
                
                # ACK packet (third handshake)
                elif tcp_flags & 0x10 and not tcp_flags & 0x02:  # ACK but not SYN
                    if ack_time is None and synack_time is not None:  # Only capture first ACK after SYN-ACK
                        ack_time = float(packet.sniff_timestamp)
                        break  # We have all three handshake packets
                        
            except Exception as e:
                continue  # Skip problematic packets
    
    # Calculate TCP metrics
    synack = synack_time - syn_time if syn_time is not None and synack_time is not None else 0
    ackdat = ack_time - synack_time if synack_time is not None and ack_time is not None else 0
    tcprtt = synack  # Round trip time is the time between SYN and SYN-ACK
    
    # Extract ports from flow key
    try:
        src_port = flow_key.split(':')[1].split('-')[0] if ':' in flow_key and '-' in flow_key.split(':')[1] else None
        dst_port = flow_key.split('-')[1].split(':')[0] if '-' in flow_key and ':' in flow_key.split('-')[1] else None
    except (IndexError, ValueError):
        src_port = None
        dst_port = None
    
    # Determine service
    service = flow_info['service'] or 'UNKNOWN'
    
    # Connection tracking features - placeholder implementation
    # In a complete implementation, these would track related connections over time
    ct_srv_src = 1  # Connections with same service and source
    ct_state_ttl = 1 if (sttl > 0 and dttl > 0) else 0
    ct_dst_ltm = 1  # Connections to same destination in last time window
    ct_src_dport_ltm = 1  # Connections from same source to same dest port
    ct_dst_sport_ltm = 1  # Connections to same dest from same source port
    ct_dst_src_ltm = 1  # Connections between same src and dst
    ct_src_ltm = 1  # Connections from same source
    ct_srv_dst = 1  # Connections with same service to same destination
    
    # HTTP and FTP specific features
    is_ftp_login = 1 if (dst_port == '21' or src_port == '21') else 0
    ct_ftp_cmd = 0
    ct_flw_http_mthd = 0
    
    # Check if source and destination ports are the same
    is_sm_ips_ports = 1 if src_port == dst_port else 0
    
    # Determine connection state based on TCP flags
    state = flow_info['state']
    if state == 'INIT' and synack > 0 and ackdat > 0:
        state = 'ESTABLISHED'
    
    # HTTP-specific metrics
    trans_depth = 0
    response_body_len = 0
    
    return {
        'dur': duration,
        'proto': proto,
        'service': service,
        'state': state,
        'spkts': spkts,
        'dpkts': dpkts,
        'sbytes': sbytes,
        'dbytes': dbytes,
        'rate': rate,
        'sttl': sttl,
        'dttl': dttl,
        'sload': sload,
        'dload': dload,
        'sloss': sloss,
        'dloss': dloss,
        'sinpkt': sinpkt,
        'dinpkt': dinpkt,
        'sjit': sjit,
        'djit': djit,
        'swin': swin,
        'dwin': dwin,
        'stcpb': stcpb,
        'dtcpb': dtcpb,
        'tcprtt': tcprtt,
        'synack': synack,
        'ackdat': ackdat,
        'smean': smean,
        'dmean': dmean,
        'trans_depth': trans_depth,
        'response_body_len': response_body_len,
        'ct_srv_src': ct_srv_src,
        'ct_state_ttl': ct_state_ttl,
        'ct_dst_ltm': ct_dst_ltm,
        'ct_src_dport_ltm': ct_src_dport_ltm,
        'ct_dst_sport_ltm': ct_dst_sport_ltm,
        'ct_dst_src_ltm': ct_dst_src_ltm,
        'is_ftp_login': is_ftp_login,
        'ct_ftp_cmd': ct_ftp_cmd,
        'ct_flw_http_mthd': ct_flw_http_mthd,
        'ct_src_ltm': ct_src_ltm,
        'ct_srv_dst': ct_srv_dst,
        'is_sm_ips_ports': is_sm_ips_ports,
        'attack_cat': 'BENIGN',
        'label': 0
    }

def process_packet(packet):
    try:
        if not hasattr(packet, 'ip'):
            return
        
        # Create flow key (5-tuple)
        if hasattr(packet, 'tcp'):
            proto = 'TCP'
            sport = packet.tcp.srcport
            dport = packet.tcp.dstport
            
            # Get TCP state information
            try:
                tcp_flags = int(packet.tcp.flags, 16)
                if tcp_flags & 0x02 and not tcp_flags & 0x10:  # SYN, no ACK
                    state = 'SYN'
                elif tcp_flags & 0x02 and tcp_flags & 0x10:  # SYN-ACK
                    state = 'SYN_ACK'
                elif tcp_flags & 0x01:  # FIN
                    state = 'FIN'
                elif tcp_flags & 0x04:  # RST
                    state = 'RST'
                elif tcp_flags & 0x10:  # ACK
                    state = 'ACK'
                else:
                    state = 'OTHER'
            except:
                state = 'UNKNOWN'
                
        elif hasattr(packet, 'udp'):
            proto = 'UDP'
            sport = packet.udp.srcport
            dport = packet.udp.dstport
            state = 'UDP'
        else:
            return

        forward_flow = f"{packet.ip.src}:{sport}-{packet.ip.dst}:{dport}-{proto}"
        backward_flow = f"{packet.ip.dst}:{dport}-{packet.ip.src}:{sport}-{proto}"
        
        # Determine flow direction and update statistics
        if forward_flow in flow_data or (backward_flow not in flow_data):
            flow_key = forward_flow
            is_forward = True
        else:
            flow_key = backward_flow
            is_forward = False
            
        # Initialize flow if new
        if flow_data[flow_key]['start_time'] is None:
            flow_data[flow_key]['start_time'] = float(packet.sniff_timestamp)
            flow_data[flow_key]['state'] = state
            
        # Update flow state if it's a more definitive state
        if state in ['SYN', 'SYN_ACK', 'FIN', 'RST']:
            flow_data[flow_key]['state'] = state
            
        # Update flow information
        flow_data[flow_key]['packets'].append(packet)
        
        # Update byte counts
        pkt_len = int(packet.length)
        if is_forward:
            flow_data[flow_key]['bytes_forward'] += pkt_len
            flow_data[flow_key]['packets_forward'] += 1
        else:
            flow_data[flow_key]['bytes_backward'] += pkt_len
            flow_data[flow_key]['packets_backward'] += 1
            
        # Try to determine service based on port numbers
        if not flow_data[flow_key]['service']:
            flow_data[flow_key]['service'] = get_service_name(sport, dport)
            
    except AttributeError as e:
        print(f"Error processing packet: {e}")

def get_service_name(sport, dport):
    common_ports = {
        80: 'HTTP',
        443: 'HTTPS',
        21: 'FTP',
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        53: 'DNS',
        110: 'POP3',
        143: 'IMAP',
        993: 'IMAPS',
        995: 'POP3S',
        20: 'FTP-DATA',
        194: 'IRC',
        5060: 'SIP',
        69: 'TFTP',
        123: 'NTP',
        161: 'SNMP',
        3389: 'RDP'
    }
    
    try:
        sport_int = int(sport)
        dport_int = int(dport)
        return (common_ports.get(sport_int) or 
                common_ports.get(dport_int) or 
                ('HTTP' if sport_int == 8080 or dport_int == 8080 else 'UNKNOWN'))
    except (ValueError, TypeError):
        return 'UNKNOWN'

# Load the PCAP file with TCP filter
print("Starting packet analysis...")
cap = pyshark.FileCapture(
    r'C:\Users\ANAND\OneDrive\Desktop\wire\data.pcapng',  # Changed to data.pcapng
    display_filter='tcp'  # Only capture TCP packets
)

# Process each packet
for packet in cap:
    process_packet(packet)

# Convert flow data to features
print("Converting flows to features...")
features_list = []
for flow_key, flow_info in flow_data.items():
    features = calculate_features(flow_key, flow_info)
    if features:
        features_list.append(features)

# Create DataFrame
df = pd.DataFrame(features_list)

# Ensure all required columns are present
required_columns = ['id', 'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 
                   'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 
                   'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 
                   'tcprtt', 'synack', 'ackdat', 'smean', 'dmean', 'trans_depth', 
                   'response_body_len', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 
                   'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login', 
                   'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 
                   'is_sm_ips_ports', 'attack_cat', 'label']

# Add missing columns with default values
for col in required_columns:
    if col not in df.columns:
        df[col] = 0
    
# Add ID column
df['id'] = range(len(df))

# Reorder columns to match required format
df = df[required_columns]

# Modify the file saving part
try:
    # Add timestamp to filename to make it unique
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Define the output directory and create it if it doesn't exist
    output_dir = r'C:\Users\ANAND\OneDrive\Desktop\Intrusion_detection_project\realtime_data'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Save the file to real-time data location
    output_path = os.path.join(output_dir, 'data.csv')
    
    # Save to CSV with error handling
    df.to_csv(output_path, index=False)
    print(f"Feature extraction complete. Saved to {output_path}")
except PermissionError:
    # Try alternative location if permission denied
    alt_dir = r'C:\Users\ANAND\OneDrive\Desktop\Intrusion_detection_project\realtime_data'
    if not os.path.exists(alt_dir):
        os.makedirs(alt_dir)
    alt_path = os.path.join(alt_dir, f'data_backup_{timestamp}.csv')
    df.to_csv(alt_path, index=False)
    print(f"Feature extraction complete. Saved to {alt_path}")

# For Excel format, uncomment these lines and install openpyxl if needed:
# pip install openpyxl
# excel_path = rf'C:\Users\ANAND\OneDrive\Desktop\wire\extracted_features_{timestamp}.xlsx'
# df.to_excel(excel_path, index=False, engine='openpyxl')
# print(f"Also saved as Excel file to {excel_path}")
