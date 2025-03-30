from flask import Flask, request, render_template, jsonify
from flask_cors import CORS, cross_origin
import pandas as pd
from threading import Thread
import time
import pyshark  # Add this import for pcap processing
from src.pipeline.predict_pipeline import PredictPipeline  # Your existing PredictPipeline class
import subprocess  # For running the send_data.py script
from twilio.rest import Client
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta  # For timestamp handling

app = Flask(__name__)
CORS(app)

# Global variable to store live results for the dashboard
predicted_results = []
sending_data = True  # Flag to control data transmission
data_process = None  # Global variable to track the subprocess
packet_capture_process = None  # New variable to track packet capture subprocess

# Twilio WhatsApp configuration
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")  # Replace with your Twilio SID
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")     # Replace with your Twilio token
TWILIO_WHATSAPP_NUMBER = os.getenv("TWILIO_WHATSAPP_NUMBER")  # Twilio's WhatsApp sandbox number
RECIPIENT_WHATSAPP_NUMBER = os.getenv("RECIPIENT_WHATSAPP_NUMBER") # Your WhatsApp number (with country code)

@app.route('/')
@cross_origin()
def index_page():
    return render_template('index.html')

@app.route('/login')
@cross_origin()
def login_page():
    return render_template('login.html')

@app.route('/home')
@cross_origin()
def home_page():
    return render_template('home.html')

@app.route('/register')
@cross_origin()
def register_page():
    return render_template('register.html')

@app.route('/upload_dataset', methods=['GET', 'POST'])
@cross_origin()
def upload_dataset():
    if request.method == 'POST':
        # Handle dataset upload
        if 'dataset' not in request.files:
            return render_template('upload.html', results='Error: No file uploaded')

        file = request.files['dataset']
        if file.filename == '':
            return render_template('upload.html', results='Error: No file selected')

        try:
            # Read the dataset based on file type directly from the uploaded file
            if file.filename.endswith('.csv'):
                dataset = pd.read_csv(file)
            elif file.filename.endswith('.xlsx'):
                dataset = pd.read_excel(file)
            elif file.filename.endswith('.json'):
                dataset = pd.read_json(file)
            else:
                return render_template('upload.html', results='Error: Unsupported file type')

            # Initialize the prediction pipeline for intrusion detection
            predict_pipeline = PredictPipeline()
            predicted_attacks = predict_pipeline.predict(dataset)

            # Add predictions to dataset
            dataset['Predicted_Attack'] = predicted_attacks

            # Convert the results to HTML table to display
            table_html = dataset[['Predicted_Attack']].to_html(classes='table table-striped', index=False)

            return render_template('upload.html', results=table_html)

        except Exception as e:
            return render_template('upload.html', results=f"Error: {str(e)}")

    return render_template('upload.html')  # Show the upload form

@app.route('/real_time_prediction', methods=['GET'])
@cross_origin()
def real_time_prediction():
    return render_template('real_time.html')  # A separate HTML page for real-time predictions

# Function to extract IP addresses from pcapng files based on timestamp
def extract_attack_source_ip(timestamp_str):
    try:
        # Convert the timestamp string to datetime
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        
        # Define time window (look at packets within 10 seconds of the timestamp)
        time_window = 10
        start_time = timestamp - timedelta(seconds=time_window)
        end_time = timestamp + timedelta(seconds=time_window)
        
        # Find the relevant pcapng file (most recent file created before the timestamp)
        import os
        import shutil
        
        # Find tshark executable
        tshark_path = None
        if os.name == 'nt':  # Windows
            common_locations = [
                r'C:\Program Files\Wireshark\tshark.exe',
                r'C:\Program Files (x86)\Wireshark\tshark.exe',
            ]
            for location in common_locations:
                if os.path.exists(location):
                    tshark_path = location
                    break
            if not tshark_path:
                tshark_path = shutil.which('tshark')
        else:  # Unix/Linux
            tshark_path = shutil.which('tshark')
            
        if not tshark_path:
            print("Could not find tshark. Cannot extract IP addresses.")
            return "IP extraction failed (tshark not found)"
        
        realtime_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'realtime_data')
        pcap_files = [f for f in os.listdir(realtime_data_dir) if f.endswith('.pcapng')]
        
        if not pcap_files:
            return "Unknown IP (no pcap files found)"
        
        # Sort by modification time (most recent first)
        pcap_files.sort(key=lambda x: os.path.getmtime(os.path.join(realtime_data_dir, x)), reverse=True)
        
        # Get the most recent pcap file
        pcap_file = os.path.join(realtime_data_dir, pcap_files[0])
        
        print(f"Analyzing pcap file: {pcap_file} to find attack source")
        
        # Format timestamp for tshark - use epoch seconds which are more reliable
        start_epoch = int(start_time.timestamp())
        end_epoch = int(end_time.timestamp())
        
        # First try: Use tshark with time constraints
        cmd = [
            tshark_path,
            '-r', pcap_file,
            '-T', 'fields',
            '-e', 'ip.src',
            '-Y', f'frame.time_epoch >= {start_epoch} and frame.time_epoch <= {end_epoch}'
        ]
        
        print(f"Running tshark command with time filter: {' '.join(cmd)}")
        
        # Run tshark process
        result = subprocess.run(cmd, capture_output=True, text=True)
        ips = [ip.strip() for ip in result.stdout.split('\n') if ip.strip()]
        
        # If no results with time filter, try without time constraints
        if not ips or result.returncode != 0:
            print("No results with time filter, trying without time constraints")
            # Second try: Just get all source IPs from the file
            cmd = [
                tshark_path,
                '-r', pcap_file,
                '-T', 'fields',
                '-e', 'ip.src'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                print(f"Error running tshark without filter: {result.stderr}")
                return "IP extraction failed (tshark error)"
            
            ips = [ip.strip() for ip in result.stdout.split('\n') if ip.strip()]
        
        # Count occurrences of each IP
        ip_counts = {}
        for ip in ips:
            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] = 1
        
        print(f"Found {len(ips)} packets with IPs, {len(ip_counts)} unique IPs")
        
        # Return most frequent IP (or IPs if there's a tie)
        if not ip_counts:
            return "Unknown IP (no matching packets)"
            
        # Find most frequent IP
        max_count = max(ip_counts.values())
        most_frequent_ips = [ip for ip, count in ip_counts.items() if count == max_count]
        
        if len(most_frequent_ips) == 1:
            return most_frequent_ips[0]
        else:
            return ", ".join(most_frequent_ips[:3]) + f" (and {len(most_frequent_ips)-3} more)" if len(most_frequent_ips) > 3 else ", ".join(most_frequent_ips)
            
    except Exception as e:
        print(f"Error extracting IP address: {str(e)}")
        import traceback
        traceback.print_exc()
        return "IP extraction failed"

# Function to send WhatsApp notification
def send_whatsapp_alert(attack_type, timestamp):
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        
        # Create message content - if attack_type is already a full message, use it directly
        if "Attack detected" in attack_type:
            message_body = f"🚨 SECURITY ALERT: {attack_type}! Immediate action required."
        else:
        message_body = f"🚨 SECURITY ALERT: {attack_type} attack detected at {timestamp}! Immediate action required."
        
        # Send WhatsApp message
        message = client.messages.create(
            body=message_body,
            from_=TWILIO_WHATSAPP_NUMBER,
            to=RECIPIENT_WHATSAPP_NUMBER
        )
        
        print(f"WhatsApp notification sent! SID: {message.sid}")
        return True
    except Exception as e:
        print(f"Failed to send WhatsApp notification: {str(e)}")
        return False

# Function to process incoming data and make predictions
def process_real_time_data(single_row):
    global predicted_results, sending_data
    predict_pipeline = PredictPipeline()
    
    # Convert the incoming single-row dictionary to DataFrame
    single_row_df = pd.DataFrame([single_row])
    
    # Make prediction
    predicted_attack = predict_pipeline.predict(single_row_df)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Store the prediction result for the live dashboard
    result = {
        'timestamp': timestamp,
        'prediction': predicted_attack[0]
    }
    predicted_results.append(result)

    # If an attack is detected, send WhatsApp notification
    if result['prediction'] != "Normal":
        print(f"⚠️ Attack Detected: {result['prediction']} at {timestamp}")
        
        # Send WhatsApp notification about the attack
        send_whatsapp_alert(result['prediction'], timestamp)
        
        # You can choose to still stop data transmission or continue
        sending_data = False

# API endpoint to receive real-time data and make predictions
@app.route('/receive_data', methods=['POST'])
def receive_data():
    global predicted_results
    data = request.get_json()
    
    # Process data
    predict_pipeline = PredictPipeline()
    single_row_df = pd.DataFrame([data])
    predicted_attack = predict_pipeline.predict(single_row_df)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Create result
    result = {
        'timestamp': timestamp,
        'prediction': predicted_attack[0]
    }
    
    # If an attack is detected, extract IP address
    if result['prediction'] != "Normal":
        # Get source IP address
        result['source_ip'] = extract_attack_source_ip(timestamp)
        print(f"Attack detected: {result['prediction']} from IP {result['source_ip']} at {timestamp}")
        
        # Format for WhatsApp message
        attack_message = f"Attack detected: {result['prediction']} from IP {result['source_ip']} at {timestamp}"
        send_whatsapp_alert(attack_message, timestamp)
    
    predicted_results.append(result)
    
    # IMPORTANT: Always return success status, never error
    return jsonify({"status": "success"})

# Add a new endpoint that will be used instead of any alert-triggering endpoint
@app.route('/check_status', methods=['GET'])
def check_status():
    global sending_data
    # Always return "no attack" to prevent alerts, but include the stop flag
    return jsonify({
        "attack_detected": False,
        "stop_sending": not sending_data  # If sending_data is False, we want to stop
    })

# Endpoint to fetch live prediction results for dashboard updates
@app.route('/results', methods=['GET'])
@cross_origin()
def get_results():
    global predicted_results
    # Return only the prediction results without any alert messages
    return jsonify(predicted_results)

# Endpoint to start sending data
@app.route('/start_sending_data', methods=['GET'])
@cross_origin()
def start_sending_data():
    global sending_data, data_process
    sending_data = True  # Reset data transmission if it was stopped

    # First run packet capture and feature extraction
    run_packet_capture_and_processing()

    # Start the send_data.py script in a new thread
    thread = Thread(target=run_send_data_script)
    thread.start()
    return jsonify({'message': 'Started capturing packets and sending data for real-time predictions'})

# Function to run packet capture and feature extraction
def run_packet_capture_and_processing():
    global packet_capture_process
    # Run the extract_features.py script with --capture flag
    import os
    
    try:
        print("Starting packet capture and feature extraction...")
        # First, run packet capture separately with a longer timeout
        if os.name == 'nt':  # Windows
            # Run capture with --capture flag
            print("Step 1: Capturing packets (this may take about 60 seconds)...")
            result = subprocess.run(['python', 'extract_features.py', '--capture'], 
                          check=False, timeout=120)  # Increased timeout to 120 seconds
            
            # Check for success
            if result.returncode != 0:
                print(f"Warning: Packet capture may have encountered issues, return code: {result.returncode}")
            
            # After packet capture, check if the Excel file exists
            realtime_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'realtime_data')
            excel_file = os.path.join(realtime_data_dir, 'data.xlsx')
            
            if not os.path.exists(excel_file):
                print("Excel file not found after packet capture. Manually running feature extraction...")
                # Find the most recent pcapng file
                pcap_files = [f for f in os.listdir(realtime_data_dir) if f.endswith('.pcapng')]
                if pcap_files:
                    # Sort by modification time (most recent first)
                    pcap_files.sort(key=lambda x: os.path.getmtime(os.path.join(realtime_data_dir, x)), reverse=True)
                    most_recent_pcap = os.path.join(realtime_data_dir, pcap_files[0])
                    print(f"Found pcap file: {most_recent_pcap}")
                    
                    # Run feature extraction on the most recent pcap file
                    print("Step 2: Extracting features from the captured packets...")
                    subprocess.run(['python', 'extract_features.py', '--input_file', most_recent_pcap], 
                                 check=False, timeout=60)
                    
                    # Wait for file processing
                    print("Waiting for feature extraction to complete...")
                    time.sleep(5)
                else:
                    print("No pcap files found in realtime_data directory.")
            
            # Final check if the Excel file exists
            if os.path.exists(excel_file):
                print(f"Feature extraction complete. Excel file created: {excel_file}")
            else:
                print("Warning: Excel file still not found after feature extraction attempt.")
                
            print("Packet capture and feature extraction steps completed")
        else:  # Unix/Linux - similar process but with Unix-specific considerations
            # Run capture with --capture flag
            result = subprocess.run(['python', 'extract_features.py', '--capture'], 
                          check=False, timeout=120)
            
            # Similar post-processing as above
            realtime_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'realtime_data')
            excel_file = os.path.join(realtime_data_dir, 'data.xlsx')
            
            if not os.path.exists(excel_file):
                print("Excel file not found after packet capture. Manually running feature extraction...")
                pcap_files = [f for f in os.listdir(realtime_data_dir) if f.endswith('.pcapng')]
                if pcap_files:
                    pcap_files.sort(key=lambda x: os.path.getmtime(os.path.join(realtime_data_dir, x)), reverse=True)
                    most_recent_pcap = os.path.join(realtime_data_dir, pcap_files[0])
                    print(f"Found pcap file: {most_recent_pcap}")
                    
                    subprocess.run(['python', 'extract_features.py', '--input_file', most_recent_pcap], 
                                 check=False, timeout=60)
                    
                    time.sleep(5)
                else:
                    print("No pcap files found in realtime_data directory.")
                    
            if os.path.exists(excel_file):
                print(f"Feature extraction complete. Excel file created: {excel_file}")
            else:
                print("Warning: Excel file still not found after feature extraction attempt.")
                
            print("Packet capture and feature extraction steps completed")
    except subprocess.TimeoutExpired:
        print("One of the steps took too long, but continuing anyway")
        # Check if we can find a pcap file and run manual extraction
        try:
            realtime_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'realtime_data')
            pcap_files = [f for f in os.listdir(realtime_data_dir) if f.endswith('.pcapng')]
            if pcap_files:
                pcap_files.sort(key=lambda x: os.path.getmtime(os.path.join(realtime_data_dir, x)), reverse=True)
                most_recent_pcap = os.path.join(realtime_data_dir, pcap_files[0])
                print(f"Found pcap file after timeout: {most_recent_pcap}")
                subprocess.run(['python', 'extract_features.py', '--input_file', most_recent_pcap], 
                               check=False, timeout=60)
        except Exception as e:
            print(f"Error during recovery attempt: {str(e)}")
    except Exception as e:
        print(f"Error during packet capture: {str(e)}")
        # Continue anyway, as we might have a previous capture file to use
        try:
            realtime_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'realtime_data')
            pcap_files = [f for f in os.listdir(realtime_data_dir) if f.endswith('.pcapng')]
            if pcap_files:
                pcap_files.sort(key=lambda x: os.path.getmtime(os.path.join(realtime_data_dir, x)), reverse=True)
                most_recent_pcap = os.path.join(realtime_data_dir, pcap_files[0])
                print(f"Found pcap file after error: {most_recent_pcap}")
                subprocess.run(['python', 'extract_features.py', '--input_file', most_recent_pcap], 
                               check=False, timeout=60)
        except Exception as e:
            print(f"Error during recovery attempt: {str(e)}")

# Endpoint to stop sending data
@app.route('/stop_sending_data', methods=['GET'])
@cross_origin()
def stop_sending_data():
    global sending_data, data_process, packet_capture_process
    sending_data = False
    
    # Terminate the subprocess if it's running - use kill instead of terminate for more forceful termination
    if data_process:
        try:
            import signal
            import os
            
            # On Windows, we might need to use taskkill for more reliable termination
            if os.name == 'nt':  # Windows
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(data_process.pid)], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:  # Unix/Linux
                os.killpg(os.getpgid(data_process.pid), signal.SIGTERM)
            
            data_process = None
            print("Successfully terminated data sending process")
        except Exception as e:
            print(f"Error terminating process: {str(e)}")
    
    # Also terminate packet capture process if it's still running
    if packet_capture_process and packet_capture_process.poll() is None:
        try:
            if os.name == 'nt':  # Windows
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(packet_capture_process.pid)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            else:  # Unix/Linux
                os.killpg(os.getpgid(packet_capture_process.pid), signal.SIGTERM)
            
            packet_capture_process = None
            print("Successfully terminated packet capture process")
        except Exception as e:
            print(f"Error terminating packet capture process: {str(e)}")
    
    return jsonify({'message': 'Stopped sending data for real-time predictions'})

def run_send_data_script():
    global data_process
    # Import os at the beginning of the function
    import os
    
    # Make sure we wait a few seconds for the feature extraction process to complete
    time.sleep(5)
    
    # Check if the Excel file exists before running send_data.py
    realtime_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'realtime_data')
    excel_file = os.path.join(realtime_data_dir, 'data.xlsx')
    
    if not os.path.exists(excel_file):
        print(f"Warning: Excel file {excel_file} does not exist before running send_data.py")
        # Look for any Excel file in the directory
        excel_files = [f for f in os.listdir(realtime_data_dir) if f.endswith('.xlsx')]
        if not excel_files:
            print("No Excel files found in realtime_data directory. Looking for pcapng files to process...")
            # Try to process the most recent pcapng file
            pcap_files = [f for f in os.listdir(realtime_data_dir) if f.endswith('.pcapng')]
            if pcap_files:
                pcap_files.sort(key=lambda x: os.path.getmtime(os.path.join(realtime_data_dir, x)), reverse=True)
                most_recent_pcap = os.path.join(realtime_data_dir, pcap_files[0])
                print(f"Found pcap file: {most_recent_pcap}, attempting to extract features...")
                try:
                    # Run feature extraction on the most recent pcap file
                    subprocess.run(['python', 'extract_features.py', '--input_file', most_recent_pcap], 
                                 check=False, timeout=60)
                    # Wait for processing to complete
                    time.sleep(5)
                except Exception as e:
                    print(f"Error extracting features: {str(e)}")
            else:
                print("No pcapng files found either. send_data.py may fail to find input data.")
    
    # Run the send_data.py script as a subprocess with shell=True on Windows
    print("Starting send_data.py to process extracted features...")
    
    if os.name == 'nt':  # Windows
        data_process = subprocess.Popen(['python', 'send_data.py'], 
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    else:  # Unix/Linux
        data_process = subprocess.Popen(['python', 'send_data.py'], 
                                       preexec_fn=os.setsid)
    print("send_data.py started")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
