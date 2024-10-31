import os
import sys
from dataclasses import dataclass
import numpy as np
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier

from src.exception import CustomException
from src.logger import logging
from src.utils import evaluate_models, save_object

@dataclass
class ModelTrainerConfig:
    trained_model_file_path = os.path.join("artifacts", "best_model.pkl")

class ModelTrainer:
    def __init__(self):
        self.model_trainer_config = ModelTrainerConfig()

    def initiate_model_trainer(self, X_train, X_test, y_train, y_test):
        try:
            models = {
                "Linear SVM": SVC(kernel='linear', gamma='auto'),
                "KNN": KNeighborsClassifier(n_neighbors=5),
                "Random Forest": RandomForestClassifier(random_state=50),
                "Decision Tree": DecisionTreeClassifier(random_state=123),
                "MLP": MLPClassifier(random_state=123, solver='adam', max_iter=8000),
            }

            model_report:dict=evaluate_models(X_train=X_train,y_train=y_train,X_test=X_test,y_test=y_test,
                                             models=models)
            ## To get best model score from dict
            best_model_score = max(model_report.values())


            ## To get best model name from dict

            best_model_name = list(model_report.keys())[
                list(model_report.values()).index(best_model_score)
            ]
            best_model = models[best_model_name]

            if best_model_score<0.6:
                raise CustomException("No best model found")
            logging.info(f"Best found model on both training and testing dataset")

            save_object(
                file_path=self.model_trainer_config.trained_model_file_path,
                obj=best_model
            )


            print(best_model_name,best_model_score)
            return best_model_name,best_model_score
        except Exception as e:
            raise CustomException(e,sys)