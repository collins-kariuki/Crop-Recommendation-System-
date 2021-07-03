import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn import metrics
from sklearn.metrics import classification_report

path = 'crop_model/data.csv'
dataset = pd.read_csv(path)

features = dataset[['N', 'P','K','temperature', 'humidity', 'ph', 'rainfall']]
target = dataset['label']
labels = dataset['label']
print(dataset.head())

X_train, X_test, y_train, y_test =train_test_split(features,target,test_size = 0.2,random_state =2)

acc = []
model = []
NaiveBayes = GaussianNB()

NaiveBayes.fit(X_train,y_train)

predicted_values = NaiveBayes.predict(X_test)
x = metrics.accuracy_score(y_test, predicted_values)
acc.append(x)
model.append('Naive Bayes')
print("Naive Bayes's Accuracy is: ", x)

print(classification_report(y_test,predicted_values))


NB_pkl_filename = 'model.pkl'

NB_Model_pkl = open(NB_pkl_filename, 'wb')
pickle.dump(NaiveBayes, NB_Model_pkl)

NB_Model_pkl.close()

#tests
model_path = 'model.pkl'
model = pickle.load(open(model_path, 'rb'))

data = np.array([[10,55,23,21.18853178,19.63438599,5.728233081,137.1948633]])
prediction = model.predict(data)
print(prediction)