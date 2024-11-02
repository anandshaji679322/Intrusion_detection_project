import os
import sys
import numpy as np 
import pandas as pd
import dill
import pickle
from src.logger import logging

from sklearn import metrics  # Importing metrics from sklearn
from src.exception import CustomException
from sklearn.metrics import accuracy_score


def save_object(file_path, obj):
    try:
        dir_path = os.path.dirname(file_path)

        os.makedirs(dir_path, exist_ok=True)

        with open(file_path, "wb") as file_obj:
            pickle.dump(obj, file_obj)

    except Exception as e:
        raise CustomException(e, sys)
    
    
def load_object(file_path):
    try:
        with open(file_path, "rb") as file_obj:
            return pickle.load(file_obj)

    except Exception as e:
        raise CustomException(e, sys)
    

def evaluate_models(X_train, y_train, X_test, y_test, models):
    model_report = {}
    for model_name, model in models.items():  # Loop through model names and objects
        model.fit(X_train, y_train)           # Train the model
        y_pred = model.predict(X_test)        # Predict on the test set
        accuracy = accuracy_score(y_test, y_pred)
        logging.info(f"Model: {model_name}, Accuracy: {accuracy:.4f}")  # Calculate accuracy
        model_report[model_name] = accuracy   # Store accuracy in the report
    return model_report
