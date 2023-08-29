import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os


def load_model(name: str) -> IsolationForest:
    if not name:
        print("Warning: name is empty")
        return IsolationForest()
    print(f"loading model {name} ...")
    if not os.path.exists(name):
        print(f"model {name} not found, returned a new model. cwd: ", os.getcwd())
        return IsolationForest()
    model: IsolationForest = pickle.load(open(name, "rb"))
    print("model loaded")
    return model


def save_model(model: IsolationForest, path: str, name: str):
    if not name or not path:
        print("Warning: path or name is empty")
        return
    if not os.path.exists(path):
        os.makedirs(path)
    print(f"saving model {name} ...")
    pickle.dump(model, open(name, "wb"))
    print("model saved")


# fit and predict one data with n-dimensional features
# data: 1 dimensional list
# return True if the data is normal
def fit_predict(model: IsolationForest, data: list) -> bool:
    print("predicting data: ", data)
    dataArray = np.array(data)
    if dataArray.ndim != 1:
        print("Warning: data.ndim != 1")
    pred = model.fit_predict(dataArray.reshape(1, -1))
    print("pred: ", pred)
    return (pred == 1).all()


if __name__ == "__main__":
    load_model("model")
