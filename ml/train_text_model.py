"""
ml/train_text_model.py
Run once to train and save the text classification model.
Usage: python ml/train_text_model.py
"""

import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ── TRAINING DATA ─────────────────────────────────────────
# Label 1 = Social Engineering / Phishing, 0 = Legitimate
SAMPLES = [
    # PHISHING / SOCIAL ENGINEERING (label=1)
    ("URGENT: Your bank account will be suspended. Verify immediately.", 1),
    ("Congratulations! You've won a $1000 Amazon gift card. Claim now!", 1),
    ("Your password has been compromised. Click here to reset immediately.", 1),
    ("ALERT: Unauthorized login detected on your account. Act now!", 1),
    ("Your package is on hold. Pay $2.99 customs fee to release it.", 1),
    ("Dear customer, your Netflix subscription has expired. Update payment.", 1),
    ("IRS Notice: You owe back taxes. Pay now to avoid arrest.", 1),
    ("Your Apple ID has been locked. Verify your information immediately.", 1),
    ("WINNER! You have been selected for a free iPhone. Click to claim.", 1),
    ("Security Alert: Someone accessed your Gmail. Confirm your identity.", 1),
    ("Final warning: Your account will be closed in 24 hours.", 1),
    ("Urgent: Verify your PayPal account or it will be permanently limited.", 1),
    ("Dear user, your Microsoft account is at risk. Update credentials now.", 1),
    ("You owe $500 in unpaid tolls. Pay within 24 hours to avoid penalty.", 1),
    ("Suspicious activity detected. Call us immediately at this number.", 1),
    ("Your Social Security Number has been suspended. Contact us now.", 1),
    ("Congratulations, you qualify for a government COVID relief grant.", 1),
    ("Action required: Confirm your email or lose access to your account.", 1),
    ("LAST CHANCE: Your subscription expires tonight. Renew to keep access.", 1),
    ("Warning: Your computer has a virus. Call Microsoft support now.", 1),
    ("Your bank transfer requires additional verification. Click here.", 1),
    ("Hi, I'm a Nigerian prince. I need your help transferring funds.", 1),
    ("You have unclaimed lottery winnings. Send ID to receive funds.", 1),
    ("Your Uber account has been hacked. Reset password immediately.", 1),
    ("ALERT: Your credit card was charged $499. Dispute at this link.", 1),
    ("Limited time offer: Work from home and earn $5000/week guaranteed.", 1),
    ("Your insurance claim needs review. Call now or lose your coverage.", 1),
    ("Verify your identity within 48 hours or your account will be deleted.", 1),
    ("Dear winner, claim your prize before it expires at midnight!", 1),
    ("Your loan has been approved. Send processing fee to receive funds.", 1),

    # LEGITIMATE (label=0)
    ("Hi! Just wanted to check in and see how you're doing.", 0),
    ("The meeting is scheduled for tomorrow at 3 PM.", 0),
    ("Please find attached the report you requested.", 0),
    ("Your order has shipped and will arrive in 3-5 business days.", 0),
    ("Thank you for your purchase. Your receipt is attached.", 0),
    ("Reminder: Team standup at 9 AM tomorrow.", 0),
    ("Here is the summary of our discussion from today.", 0),
    ("Happy birthday! Hope you have a wonderful day.", 0),
    ("The project deadline has been extended to next Friday.", 0),
    ("Please review the document and share your feedback.", 0),
    ("Your appointment is confirmed for Monday at 2 PM.", 0),
    ("Great job on the presentation! The client loved it.", 0),
    ("The quarterly report is ready for your review.", 0),
    ("Let's catch up over coffee sometime this week.", 0),
    ("Your subscription has been renewed successfully.", 0),
    ("Here are the minutes from our last team meeting.", 0),
    ("The new feature has been deployed to production.", 0),
    ("Thanks for joining us at the event yesterday.", 0),
    ("Your feedback has been submitted. We'll review it shortly.", 0),
    ("Lunch today at noon — are you free to join?", 0),
    ("I've updated the spreadsheet with the latest numbers.", 0),
    ("The library book you reserved is now available for pickup.", 0),
    ("Your flight has been confirmed. Check-in opens 24 hours before.", 0),
    ("We've received your application and will be in touch.", 0),
    ("Monthly newsletter: Updates from our team this month.", 0),
    ("The wifi password for the conference room is posted on the board.", 0),
    ("Your package from Amazon was delivered to your front door.", 0),
    ("Just a reminder to submit your timesheet by end of day Friday.", 0),
    ("The gym is closed for maintenance this Saturday.", 0),
    ("Here's the link to the shared Google Doc we discussed.", 0),
]

texts  = [s[0] for s in SAMPLES]
labels = [s[1] for s in SAMPLES]

# ── TRAIN ─────────────────────────────────────────────────
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=5000,
    stop_words='english'
)

X = vectorizer.fit_transform(texts)
y = np.array(labels)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = LogisticRegression(max_iter=1000, C=1.0)
model.fit(X_train, y_train)

# ── EVALUATE ──────────────────────────────────────────────
y_pred = model.predict(X_test)
print("\n── Text Model Evaluation ──")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Social Engineering"]))

# ── SAVE ──────────────────────────────────────────────────
with open("ml/text_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("ml/vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("✅ Saved: ml/text_model.pkl")
print("✅ Saved: ml/vectorizer.pkl")