import joblib

model = joblib.load("ml/text_model.pkl")
vectorizer = joblib.load("ml/vectorizer.pkl")

sample = ["URGENT! Your bank account will be blocked immediately"]

vec = vectorizer.transform(sample)
prediction = model.predict(vec)
probability = model.predict_proba(vec)

print("Prediction:", prediction)
print("Probability:", probability)