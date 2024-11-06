import requests
import pandas as pd
import time
import json

# Change this to the path of your Excel/CSV file
file_path = '/app/intrusion/test.xlsx'

# URL of the Flask server
url = 'http://localhost:8000/receive_data'  # Update if the server URL is different

# Load the dataset
if file_path.endswith('.xlsx'):
    dataset = pd.read_excel(file_path)
elif file_path.endswith('.csv'):
    dataset = pd.read_csv(file_path)
elif file_path.endswith('.json'):
    dataset = pd.read_json(file_path)
else:
    raise ValueError('Unsupported file format. Only .xlsx, .csv, and .json are supported.')

# Send data row by row with a break between each row
for index, row in dataset.iterrows():
    # Convert row to JSON
    row_json = row.to_json()
    data = json.loads(row_json)  # Convert string to Python dict
    
    # Send a POST request to the Flask server
    response = requests.post(url, json=data)
    
    if response.status_code == 200:
        print(f'Successfully sent row {index + 1}')
    else:
        print(f'Failed to send row {index + 1}. Status code: {response.status_code}')
    
    # Pause for a specified amount of time (e.g., 3 seconds) to simulate real-time data streaming
    time.sleep(15)  # Adjust the sleep time as necessary (e.g., 1 sec, 5 sec)
