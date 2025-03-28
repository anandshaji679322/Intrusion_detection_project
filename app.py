from flask import Flask, request, render_template, jsonify
from flask_cors import CORS, cross_origin
import pandas as pd
from threading import Thread
import time
from src.pipeline.predict_pipeline import PredictPipeline  # Your existing PredictPipeline class
import subprocess  # For running the send_data.py script
from twilio.rest import Client
import os
from dotenv import load_dotenv

app = Flask(__name__)
CORS(app)

# Global variable to store live results for the dashboard
predicted_results = []
sending_data = True  # Flag to control data transmission

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

# Function to send WhatsApp notification
def send_whatsapp_alert(attack_type, timestamp):
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        
        # Create message content
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
@cross_origin()
def receive_data():
    global predicted_results
    data = request.get_json()
    
    # Process data
    predict_pipeline = PredictPipeline()
    single_row_df = pd.DataFrame([data])
    predicted_attack = predict_pipeline.predict(single_row_df)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    result = {
        'timestamp': timestamp,
        'prediction': predicted_attack[0]
    }
    predicted_results.append(result)
    
    # Send WhatsApp notification for attacks
    if result['prediction'] != "Normal":
        print(f"Attack detected: {result['prediction']} at {timestamp}")
        send_whatsapp_alert(result['prediction'], timestamp)
    
    # ALWAYS return success (200 OK) to prevent 403 errors
    return jsonify({"status": "success"})

# Endpoint to fetch live prediction results for dashboard updates
@app.route('/results', methods=['GET'])
@cross_origin()
def get_results():
    global predicted_results, sending_data

    # If an attack is detected, include an alert message
    for result in predicted_results:
        if result["prediction"] != "Normal":
            return jsonify(predicted_results + [{"alert": "Attack Detected! Data Transmission Stopped."}])

    return jsonify(predicted_results)

# Endpoint to start sending data
@app.route('/start_sending_data', methods=['GET'])
@cross_origin()
def start_sending_data():
    global sending_data
    sending_data = True  # Reset data transmission if it was stopped

    # Start the send_data.py script in a new thread
    thread = Thread(target=run_send_data_script)
    thread.start()
    return jsonify({'message': 'Started sending data for real-time predictions'})

def run_send_data_script():
    # Replace 'send_data.py' with the actual path to your script
    subprocess.run(['python', 'send_data.py'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
