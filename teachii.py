import ssl

# Отключаем проверку сертификатов для nltk (если есть проблемы с SSL)
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

import pandas as pd
import nltk
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle

# Загружаем стоп-слова, если ещё не загружены
nltk.download('stopwords')

# Загружаем датасет
data = pd.read_csv('dataset.csv')
texts = data['text']
labels = data['label']

# Получаем русский список стоп-слов
russian_stopwords = stopwords.words('russian')

# Создаём векторизатор с русскими стоп-словами
vectorizer = TfidfVectorizer(stop_words=russian_stopwords, max_features=10000)
X = vectorizer.fit_transform(texts)

# Разделяем на обучающую и тестовую выборку
X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)

# Обучаем модель
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Оцениваем модель
y_pred = clf.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# Сохраняем модель и векторизатор
with open('model.pkl', 'wb') as f:
    pickle.dump((vectorizer, clf), f)

print("Обучение завершено, модель сохранена в 'model.pkl'")
