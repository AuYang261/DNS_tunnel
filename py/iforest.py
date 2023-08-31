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
    features_normal_all = np.loadtxt("models/dns_features1.csv", delimiter=",")
    features_abnormal_all = np.loadtxt("models/dns_features.csv", delimiter=",")
    # select some samples from features_normal and features_abnormal randomly
    features_normal = features_normal_all[
        np.random.randint(0, features_normal_all.shape[0], 2000)
    ]
    features_abnormal = features_abnormal_all[
        np.random.randint(0, features_abnormal_all.shape[0], 20)
    ]
    features = np.concatenate((features_normal, features_abnormal), axis=0)
    clf = IsolationForest(max_samples=features.shape[0])
    print(clf.fit_predict(features))
    d = clf.decision_function(features)
    # separate d into two parts
    d_normal = d[: features_normal.shape[0]]
    d_abnormal = d[features_normal.shape[0] :]
    print("d_normal: ", d_normal)
    print("d_abnormal: ", d_abnormal)

    # calculate the threshold
    threshold = np.sort(d_normal)[int(d_normal.shape[0] * 0.01)]
    print("threshold: ", threshold)
    # calculate the accuracy
    accuracy = (
        np.sum(d_normal > threshold) + np.sum(d_abnormal < threshold)
    ) / d.shape[0]
    print("Train Set:")
    print("accuracy: {:.2f}%".format(accuracy * 100))
    # calculate the precision
    precision = np.sum(d_normal > threshold) / d_normal.shape[0]
    print("precision: {:.2f}%".format(precision * 100))
    # calculate the recall
    recall = np.sum(d_abnormal < threshold) / d_abnormal.shape[0]
    print("recall: {:.2f}%".format(recall * 100))

    print("Test Set:")
    # calculate the accuracy, precision and recall of all features
    d_normal_all = clf.decision_function(features_normal_all)
    d_abnormal_all = clf.decision_function(features_abnormal_all)
    accuracy_all = (
        np.sum(d_normal_all > threshold) + np.sum(d_abnormal_all < threshold)
    ) / (d_normal_all.shape[0] + d_abnormal_all.shape[0])
    precision_all = np.sum(d_normal_all > threshold) / d_normal_all.shape[0]
    recall_all = np.sum(d_abnormal_all < threshold) / d_abnormal_all.shape[0]
    print("accuracy_all: {:.2f}%".format(accuracy_all * 100))
    print("precision_all: {:.2f}%".format(precision_all * 100))
    print("recall_all: {:.2f}%".format(recall_all * 100))

    import matplotlib.pyplot as plt

    # plot d_normal and d_abnormal sored and save
    plt.figure()
    plt.subplot(211)
    plt.title("normal")
    plt.plot(np.sort(d_normal_all))
    plt.subplot(212)
    plt.title("abnormal")
    plt.plot(np.sort(d_abnormal_all))
    plt.savefig("models/d_normal_d_abnormal.png")

    save_model(clf, "models", "model")
    pass


if __name__ == "__main__":
    train()
