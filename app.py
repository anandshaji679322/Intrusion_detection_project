from flask import Flask, request, render_template, jsonify
from flask_cors import CORS, cross_origin
import pandas as pd
import time
from threading import Thread
from src.pipeline.predict_pipeline import PredictPipeline  # Your existing PredictPipeline class
import datetime
app = Flask(__name__)
CORS(app)

# Global variable to store live results for the dashboard
predicted_results = []

@app.route('/')
@cross_origin()
def home_page():
    return render_template('index.html')

# Function to process incoming data and make predictions
def process_real_time_data(single_row):
    global predicted_results
    predict_pipeline = PredictPipeline()
    
    # Convert the incoming single-row dictionary to DataFrame
    single_row_df = pd.DataFrame([single_row])
    
    # Make prediction
    predicted_attack = predict_pipeline.predict(single_row_df)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
