from flask import Flask, request, render_template, jsonify
from flask_cors import CORS, cross_origin
import pandas as pd
from threading import Thread
import time
from src.pipeline.predict_pipeline import PredictPipeline  # Your existing PredictPipeline class
import subprocess  # For running the send_data.py script

app = Flask(__name__)
CORS(app)

# Global variable to store live results for the dashboard
predicted_results = []

@app.route('/')
@cross_origin()
def home_page():
    return render_template('home.html')  # Home page with options

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

# Function to process incoming data and make predictions
def process_real_time_data(single_row):
    global predicted_results
    predict_pipeline = PredictPipeline()
    
    # Convert the incoming single-row dictionary to DataFrame
    single_row_df = pd.DataFrame([single_row])
    
    # Make prediction
    predicted_attack = predict_pipeline.predict(single_row_df)
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # Store the prediction result for the live dashboard
    predicted_results.append({
        'timestamp': timestamp,
        'prediction': predicted_attack[0]
    })

# API endpoint to receive real-time data and make predictions
@app.route('/receive_data', methods=['POST'])
@cross_origin()
def receive_data():
    data = request.get_json()
    
    # Check if the data is valid
    if not data:
        return jsonify({'error': 'No data received'}), 400

    # Process the incoming data in a background thread
    thread = Thread(target=process_real_time_data, args=(data,))
    thread.start()

    return jsonify({'message': 'Data received and prediction in progress'}), 200

# Endpoint to fetch live prediction results for dashboard updates
@app.route('/results', methods=['GET'])
@cross_origin()
def get_results():
    global predicted_results
    return jsonify(predicted_results)

# Endpoint to start sending data
@app.route('/start_sending_data', methods=['GET'])
@cross_origin()
def start_sending_data():
    # Start the send_data.py script in a new thread
    thread = Thread(target=run_send_data_script)
    thread.start()
    return jsonify({'message': 'Started sending data for real-time predictions'})

def run_send_data_script():
    # Replace 'send_data.py' with the actual path to your script
    subprocess.run(['python', 'send_data.py'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
