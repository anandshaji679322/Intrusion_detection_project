import sys
import pandas as pd
import os
from src.exception import CustomException
from src.logger import logging
from src.utils import load_object
from sklearn.preprocessing import MinMaxScaler
import numpy as np

class PredictPipeline:
    def __init__(self):
        # Path to the model
        self.model_path = os.path.join('artifacts', 'best_model.pkl')

        try:
            # Check if the model file exists
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model file not found: {self.model_path}")

            # Load the trained model
            self.model = load_object(file_path=self.model_path)

        except Exception as e:
            logging.error("Error occurred while loading the model.")
            raise CustomException(e, sys)

    def preprocess(self, data):
        try:
            # Replace missing values and drop null entries
            data['service'].replace('-', np.nan, inplace=True)
            data.dropna(inplace=True)

            # Columns classification
            nominal_names = ['srcip', 'dstip', 'proto', 'state', 'service', 'attack_cat']
            integer_names = ['sport', 'dsport', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'ct_state_ttl', 'ct_flw_http_mthd', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm']
            binary_names = ['is_sm_ips_ports', 'is_ftp_login', 'Label']
            float_names = ['dur', 'Sload', 'Dload', 'Sjit', 'Djit', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat']
            cols = data.columns

            # Select only available columns
            nominal_names = cols.intersection(nominal_names)
            integer_names = cols.intersection(integer_names)
            binary_names = cols.intersection(binary_names)
            float_names = cols.intersection(float_names)

            # Convert integer, binary, and float columns to numeric
            for c in integer_names:
                data[c] = pd.to_numeric(data[c])
            for c in binary_names:
                data[c] = pd.to_numeric(data[c])
            for c in float_names:
                data[c] = pd.to_numeric(data[c])

            num_col = data.select_dtypes(include='number').columns

            # selecting categorical data attributes
            cat_col = data.columns.difference(num_col)
            cat_col = cat_col[1:]
            data_cat = data[cat_col].copy()
            data_cat = pd.get_dummies(data_cat,columns=cat_col)
            data = pd.concat([data, data_cat],axis=1)
            data.drop(columns=cat_col,inplace=True)
            # Normalize numerical columns
            
            minmax_scale = MinMaxScaler(feature_range=(0, 1))
            num_col = list(data.select_dtypes(include='number').columns)
            num_col.remove('id')
            num_col.remove('label')
            def normalization(df, col):
                for i in col:
                    arr = df[i]
                    arr = np.array(arr)
                    df[i] = minmax_scale.fit_transform(arr.reshape(len(arr), 1))
                return df

            multi_data = normalization(data.copy(), num_col)
            multi_label = pd.DataFrame(multi_data.attack_cat)



            required_columns =  ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'sttl', 'dttl',
       'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit',
       'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat', 'smean',
       'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src',
       'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
       'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd',
       'ct_src_ltm', 'ct_srv_dst']
            available_columns = [col for col in required_columns if col in multi_data.columns]

            return multi_data[available_columns] 

        except Exception as e:
            logging.error('Error occurred during preprocessing')
            raise CustomException(e, sys)

    def predict(self, dataset):
        try:
            # Ensure that the input dataset is a pandas DataFrame
            if not isinstance(dataset, pd.DataFrame):
                raise ValueError("Input data must be a pandas DataFrame.")

            # Log input dataset details
            logging.info(f"Input dataset columns: {dataset.columns.tolist()}")

            # Preprocess the input data
            preprocessed_data = self.preprocess(dataset)

            # Drop the 'id' column if it exists
            if 'id' in preprocessed_data.columns:
                preprocessed_data = preprocessed_data.drop(columns=['id'])
            
            X_train_file_path = os.path.join('artifacts', 'updated_X_train.csv')  # Define the path to save the file
            preprocessed_data.to_csv(X_train_file_path, index=False)  # Save X_train to CSV without the index

            # Make predictions using the loaded model
            predictions = self.model.predict(preprocessed_data)

            # Map the numerical prediction to attack names
            attack_map = {
                0: "Analysis",
                1: 'Backdoor',
                2: 'DoS',
                3: 'Exploits',
                4: 'Fuzzers',
                5: 'Generic',
                6: 'Normal',
                7: 'Reconnaissance',
                8: 'Worms',
            }
            predicted_attack = [attack_map.get(pred, 'Unknown') for pred in predictions]

            return predicted_attack

        except ValueError as e:
            logging.error(f"Value error occurred: {e}")
            raise CustomException(e, sys)
        except Exception as e:
            logging.error('Exception occurred in prediction pipeline')
            raise CustomException(e, sys)
