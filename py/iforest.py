import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os


def load_model(name: str) -> IsolationForest:
    if not name:
        raise FileNotFoundError(f"name is empty")
    print(f"loading model {name} ...")
    if not os.path.exists(name):
        raise FileNotFoundError(
            f"model {name} not found, returned a new model. cwd: {os.getcwd()}"
        )
    model: IsolationForest = pickle.load(open(name, "rb"))
    print("model loaded")
    return model


def save_model(model: IsolationForest, path: str, name: str):
    if not name or not path:
        raise FileNotFoundError("Warning: path or name is empty")
    if not os.path.exists(path):
        os.makedirs(path)
    print(f"saving model {name} ...")
    pickle.dump(model, open(os.path.join(path, name), "wb"))
    print("model saved")


# fit and predict one data with n-dimensional features
# data: 1 dimensional list
# return True if the data is normal
def predict(model: IsolationForest, data: list) -> float:
    print("predicting data: ", data)
    dataArray = np.array(data)
    if dataArray.shape != (1,):
        print("Warning: data.shape != (1,)")
    pred = model.decision_function(dataArray.reshape(1, -1))
    print("pred: ", pred)
    return pred[0]


def train():
    features = np.loadtxt("models/dns_features.csv", delimiter=",")
    clf = IsolationForest(max_samples=features.shape[0])
    print(clf.fit_predict(features))
    print(clf.decision_function(features))
    save_model(clf, "models", "model")
    pass


if __name__ == "__main__":
    train()
