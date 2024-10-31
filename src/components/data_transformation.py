# importing required libraries
import numpy as np
import pandas as pd

from src.exception import CustomException
from src.logger import logging
import os
import sys
from sklearn.preprocessing import MinMaxScaler
from sklearn import preprocessing
from sklearn.model_selection import train_test_split

class DataTransformation:
    def transform(self, data):
        # Replace missing values and drop null entries
        data['service'].replace('-', np.nan, inplace=True)
        data.dropna(inplace=True)
        
        # Columns classification
        nominal_names = ['proto', 'service', 'state', 'attack_cat']
        integer_names = ['sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'swin', 'stcpb', 'dtcpb', 'dwin',
                         'trans_depth', 'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
                         'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_srv_dst']
        binary_names = ['is_ftp_login', 'is_sm_ips_ports']
        float_names = ['dur', 'tcprtt', 'synack', 'ackdat']
        cols = data.columns

        # Handle each type of columns (nominal, binary, float, etc.)
        nominal_names = cols.intersection(nominal_names)
        integer_names = cols.intersection(integer_names)
        binary_names = cols.intersection(binary_names)
        float_names = cols.intersection(float_names)

        # Convert integer, binary, float columns to numeric
        for c in integer_names:
            data[c] = pd.to_numeric(data[c])
        for c in binary_names:
            data[c] = pd.to_numeric(data[c])
        for c in float_names:
            data[c] = pd.to_numeric(data[c])

        # Handle categorical columns (one-hot encoding)
        num_col = data.select_dtypes(include='number').columns
        cat_col = data.columns.difference(num_col)
        cat_col = cat_col[1:]  # Assuming 'id' is the first column
        data_cat = data[cat_col].copy()
        data_cat = pd.get_dummies(data_cat, columns=cat_col)
        data = pd.concat([data, data_cat], axis=1)
        data.drop(columns=cat_col, inplace=True)

        # Normalize numerical columns
        num_col = list(data.select_dtypes(include='number').columns)
        num_col.remove('id')
        num_col.remove('label')
        minmax_scale = MinMaxScaler(feature_range=(0, 1))

        def normalization(df, col):
            for i in col:
                arr = df[i]
                arr = np.array(arr)
                df[i] = minmax_scale.fit_transform(arr.reshape(len(arr), 1))
            return df

        data = normalization(data.copy(), num_col)

        # Label encoding for target column
        multi_data = data.copy()
        multi_label = pd.DataFrame(multi_data.attack_cat)
        le2 = preprocessing.LabelEncoder()
        enc_label = multi_label.apply(le2.fit_transform)
        multi_data['label'] = enc_label

        num_col = list(multi_data.select_dtypes(include='number').columns)
        corr_multi = multi_data[num_col].corr()
        corr_ymulti = abs(corr_multi['label'])
        highest_corr_multi = corr_ymulti[corr_ymulti > 0.3]
        highest_corr_multi.sort_values(ascending=True)
        multi_cols = highest_corr_multi.index
        multi_data = multi_data[multi_cols].copy()
        
        return multi_data

    def initiate_data_transformation(self, df_path):
        # Load the dataset
        df = pd.read_csv(df_path)

        try:
            logging.info("Starting dataset transformation.")
            
            # Apply transformation
            transformed_data = self.transform(df)

            X = transformed_data.drop(columns=['label'], axis=1)
            Y = transformed_data['label']

            X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.20, random_state=50)

            logging.info("Train-test split completed successfully.")

            X_train_file_path = os.path.join('artifacts', 'X_train.csv')  # Define the path to save the file
            X_train.to_csv(X_train_file_path, index=False)  # Save X_train to CSV without the index

            logging.info(f"X_train saved successfully at {X_train_file_path}")

            return X_train, X_test, y_train, y_test

        except Exception as e:
            logging.exception("Error occurred in data transformation process.")
            raise CustomException(e, sys)
