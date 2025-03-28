# Intrusion Detection System for Medical IoT Networks

The **Intrusion Detection System for Medical IoT (MIoT) Networks** is designed to enhance the cybersecurity of medical devices and IoT systems in healthcare environments. With the rapid adoption of IoT devices in healthcare, the need for robust security mechanisms has become crucial. These devices are often vulnerable to cyber-attacks, which can jeopardize patient safety and privacy.

This project leverages **machine learning techniques**, specifically an  **Random Forest model**, to identify potential intrusions in Medical IoT networks. The system is designed to run efficiently on constrained IoT devices, ensuring that it can be deployed in real-world healthcare settings without sacrificing performance.
## Table of Contents

- [Features](#features)
- [Installation and Running](#installation-and-running)
- [Requirements](#requirements)
- [Contributing](#contributing)
- [License](#license)

## Features
- **Intrusion Detection Model**: A lightweight enhanced random forest model designed to run efficiently on IoT devices, optimized to detect attacks on Medical IoT networks.
- **User Interface**: A web interface allows users to upload datasets, view detection results, and log in/out of the system.
- **Docker Support**: The Dockerfile enables easy setup and deployment of the application in any environment.
- **Logging**: Logs are stored with timestamps for easy tracking and monitoring of system activity.

## Installation and Running

To install and run the project, follow these steps:

1. **Clone the repository**:
   ```bash
   git clone <your-fork-url>
   cd .\Intrusion_detection_project\
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   - Run Locally:
     ```bash
     python app.py
     ```
   - Run in Docker:
     ```bash
      docker build -t intrusion-detection .
      docker run -p 5000:5000 intrusion-detection
     ```
4. Access the web interface at http://localhost:5000.
5. Upload a dataset to check for intrusions.
6. View results displayed in a table.

## Requirements

This project requires the following Python packages:

- numpy
- pandas
- matplotlib
- seaborn
- scikit-learn
- tensorflow
- dill
- flask
- flask-cors

These packages are listed in the `requirements.txt` file and can be installed using the command mentioned in the Installation section.

## Contributing

Contributions are welcome! To contribute to this project, please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Make your changes
4. Commit your changes (`git commit -m 'Add new feature'`)
5. Push to the branch (`git push origin feature-branch`)
6. Open a pull request

