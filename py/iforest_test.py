import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import pickle

rng = np.random.RandomState(42)
n_sample = 256 * 10
# 模拟数据的生成
# X = 0.3 * rng.uniform(low=-4, high=4, size=(n_sample, 2))
X = 0.3 * rng.randn(n_sample, 2)
X_train = np.r_[X + 2, X - 2]
# 产生具有规律的样本
X = 0.3 * rng.randn(1000, 2)
X_test = np.r_[X + 2, X - 2]
# 产生没有规律的观察样本
X_outliers = rng.uniform(low=-4, high=4, size=(200, 2))

X_test_all = np.concatenate((X_test, X_outliers), axis=0)
# 训练模型
clf = IsolationForest(max_samples=n_sample, random_state=rng)
y_pred_train = clf.fit_predict(X_train)
# y_pred_train = clf.fit_predict(np.r_[X_train, X_outliers])
# 保存模型
with open("models/model", "wb") as f:
    pickle.dump(clf, f)
# print((y_pred_train == clf.predict(X_train)).all())  # 返回正常或者异常的标志，1是正常，-1是异常
y_pred_test = clf.predict(X_test)
y_pred_outliers = clf.predict(X_outliers)

# 预测
test_shape = X_test_all.shape[0]
batch = 256
all_pred = []
for i in range(int(test_shape / batch) + 1):
    start = i * batch
    end = min((i + 1) * batch, test_shape)
    test = X_test_all[start:end]
    # 预测
    pred = clf.predict(test)
    all_pred.extend(pred)

# 绘制等高线图，表示异常程度分布，异常程度越高，颜色越深
# plot the line, the samples, and the nearest vectors to the plane
xx, yy = np.meshgrid(np.linspace(-5, 5, 50), np.linspace(-5, 5, 50))
# 正常分数，为正则为正常，为负可以认为是异常
Z = clf.decision_function(np.c_[xx.ravel(), yy.ravel()])
Z = Z.reshape(xx.shape)

plt.title("IsolationForest")
contour = plt.contourf(xx, yy, Z, cmap=plt.cm.Blues_r)
plt.colorbar(contour)

# b1 = plt.scatter(X_train[:, 0], X_train[:, 1], c="white", s=20, edgecolor="k")
# b2 = plt.scatter(X_test[:, 0], X_test[:, 1], c="green", s=20, edgecolor="k")
# c = plt.scatter(X_outliers[:, 0], X_outliers[:, 1], c="red", s=20, edgecolor="k")
plt.axis("tight")
plt.xlim((-5, 5))
plt.ylim((-5, 5))
# plt.legend(
#     [b1, b2, c],
#     ["training observations", "new regular observations", "new abnormal observations"],
#     loc="upper left",
# )
plt.savefig("iforest.png")
