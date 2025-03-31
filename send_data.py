import requests
import pandas as pd
import time
import json
import sys
import os

# Get the absolute path to the project directory
project_dir = os.path.dirname(os.path.abspath(__file__))
# Path to the realtime data folder
realtime_data_dir = os.path.join(project_dir, 'realtime_data')
# Path to the dynamically generated data file
file_path = os.path.join(realtime_data_dir, 'data.xlsx')

# URL of the Flask server
url = 'http://localhost:8000'  # Base URL

def check_if_stopped():
    """Check if the data sending should be stopped"""
    try:
        # Make a GET request to check the status
        response = requests.get(f"{url}/check_status", timeout=2)
        status = response.json()
        
        # If the server explicitly tells us to stop
        if 'stop_sending' in status and status['stop_sending']:
            print("Received stop signal from server")
            return True
            
        return False
    except Exception as e:
        print(f"Error checking stop status: {str(e)}")
        # If we can't connect to the server, assume we should stop
        return True  

# Load the dataset when script starts
print("Loading dataset...")
# Check if the file exists
if not os.path.exists(file_path):
    print(f"Error: Data file {file_path} does not exist. Looking for alternatives.")
    # Look for any Excel file in the realtime_data directory
    excel_files = [f for f in os.listdir(realtime_data_dir) if f.endswith('.xlsx')]
    if excel_files:
        # Use the most recent Excel file
        excel_files.sort(key=lambda x: os.path.getmtime(os.path.join(realtime_data_dir, x)), reverse=True)
        file_path = os.path.join(realtime_data_dir, excel_files[0])
        print(f"Using alternative file: {file_path}")
    else:
        print("No Excel files found in realtime_data directory.")
        sys.exit(1)

if file_path.endswith('.xlsx'):
    dataset = pd.read_excel(file_path)
elif file_path.endswith('.csv'):
    dataset = pd.read_csv(file_path)
elif file_path.endswith('.json'):
    dataset = pd.read_json(file_path)
else:
    raise ValueError('Unsupported file format. Only .xlsx, .csv, and .json are supported.')

print(f"Dataset loaded. Ready to send {len(dataset)} rows.")

# Main function to send data
def main():
    # Send data row by row with a break between each row
    for index, row in dataset.iterrows():
        # Check if we should stop sending data
        if check_if_stopped():
            print("Stopping data transmission as requested")
            sys.exit(0)
        
        # Convert row to JSON
        row_json = row.to_json()
        data = json.loads(row_json)  # Convert string to Python dict
        
        # Send a POST request to the Flask server
        try:
            response = requests.post(f"{url}/receive_data", json=data, timeout=5)
            
            if response.status_code == 200:
                print(f'Successfully sent row {index + 1}')
            else:
                print(f'Failed to send row {index + 1}. Status code: {response.status_code}')
        except Exception as e:
            print(f"Error sending data: {str(e)}")
            # If connection fails, wait a bit and continue (don't exit)
            time.sleep(2)
            continue
        
        # Pause between rows to simulate real-time data streaming
        time.sleep(30)  # Adjust as needed

if __name__ == "__main__":
    main()

def send_row_data(row_data):
    try:
        response = requests.post(f"{url}/receive_data", json=row_data)
        result = response.json()
        
        # Don't check for error status or show alerts
        return True
    except Exception as e:
        print(f"Error sending data: {str(e)}")
        return False
