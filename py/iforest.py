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
        print("Warning: model not found. cwd: ", os.getcwd())
        return IsolationForest()
    model: IsolationForest = pickle.load(open(name, "rb"))
    return model


# predict one data with n-dimensional features
# data: 1 dimensional list
# return True if the data is normal
def predict(model: IsolationForest, data: list) -> bool:
    print("predicting ..., data: ", data)
    dataArray = np.array(data)
    if dataArray.ndim != 1:
        print("Warning: data.ndim != 1")
    pred = model.predict(dataArray.reshape(1, -1))
    return (pred == 1).all()


# if __name__ == "__main__":
#     load_model("model")
