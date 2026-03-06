"""
ml/train_text_model.py
Retrain the phishing text classifier.
Usage (from project root): python ml/train_text_model.py data/sms_spam.csv
"""
import re, pickle, sys, pathlib, pandas as pd, numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

HERE = pathlib.Path(__file__).parent

BANK_LEGIT = [
    "Dear Customer, Rs.99.00 has been debited from account 5350 to VPA paytmqr57z7b9@paytm ROLL ME. UPI ref 119584071212",
    "Rs.500 debited from HDFC Bank account XX1234 to VPA abc@okicici. UPI Ref 320012345678.",
    "INR 250.00 debited from A/c XX9876 to UPI SWIGGY. Avl Bal INR 12340.50",
    "Your OTP for HDFC Bank transaction is 482910. Valid 10 minutes. Do not share.",
    "OTP for SBI NetBanking login is 739021. Valid 5 mins. NEVER share OTP.",
    "148920 is your OTP for ICICI Bank transaction. Do not share.",
    "Your Paytm OTP is 562371. Valid for 10 mins.",
    "Your HDFC Bank A/c XX3421 balance is Rs.15430.20 as on 07-Mar-2026.",
    "HDFC Bank: Rs 2500 spent on Credit Card XX9812 at AMAZON. Avl limit Rs 87500.",
    "NEFT credit Rs 10000 to SBI account from RAHUL SHARMA on 06-Mar-26.",
    "NACH debit of Rs.2500 from HDFC A/c XX1234 for loan EMI.",
    "RTGS INR 50000 credited to account XX7654 from ACME CORP.",
    "Kotak Bank: INR 1500 debited via IMPS to PRIYA SHARMA.",
    "Axis Bank Credit Card ending 4321 charged Rs.1899 at FLIPKART.",
    "482761 is your one-time password for Amazon Pay. Valid 15 minutes.",
    "Airtel: Bill of Rs.599 for Mar 2026 due on 15-Mar-26.",
    "Your order has shipped. Expected delivery 3-5 days.",
    "Swiggy: Your order confirmed. Delivery in 35 mins.",
    "Dear Customer Rs.1200.00 credited from VPA john@ybl. UPI Ref 449912345.",
]
PHISHING_CURATED = [
    "URGENT: Your HDFC account will be blocked! Click here to verify KYC: http://hdfc-kyc-update.xyz",
    "SBI Alert: Account suspended. Update now: bit.ly/sbi-kyc-2026 or lose access",
    "Your UPI ID is compromised! Call 9876543210 immediately to block.",
    "PAYTM ALERT: Wallet suspended! Verify KYC click: paytm-verify.ml/kyc",
    "PhonePe selected you for Rs.10000 cashback. Claim: phonepe-reward.xyz/claim now",
    "CBI: FIR registered against your mobile number. Call immediately to avoid arrest.",
    "TRAI: Your mobile disconnected in 2 hours due to illegal use. Press 9.",
    "KYC incomplete. Account blocked. Update: bit.ly/kyc-update-2026",
    "Income Tax: Rs.45000 TDS refund pending. Submit bank details at incometax-refund.tk",
    "FREE RECHARGE! Won Rs.500 Jio recharge. Claim: jio-free.xyz/claim",
    "URGENT: Your bank account will be suspended. Verify immediately at this link.",
    "You have won a $1000 Amazon gift card. Claim now before it expires!",
    "Your password has been compromised. Click here to reset immediately.",
    "ALERT: Unauthorized login. Account will be closed in 2 hours. Act now.",
    "IRS Notice: You owe back taxes. Pay now to avoid arrest.",
    "WINNER! Selected for a free iPhone 15. Click to claim your prize now.",
    "Final warning: Account will be closed in 24 hours. Verify identity.",
    "Urgent: Verify PayPal account or it will be permanently limited.",
    "Warning: Computer has 3 viruses. Call Microsoft support 1800-123-4567 now.",
    "Loan approved Rs.5 lakhs. Send Rs.2000 processing fee to receive funds.",
    "Unclaimed lottery winnings Rs.2500000. Send ID to claim your prize.",
    "Your Aadhaar linked to illegal activity. Call 1800 to clear name.",
    "Account will be deleted. Verify: secure-bank-verify.ru/login",
    "Security breach. Reset password: banklogin.xyz/reset",
    "Government subsidy Rs.15000 for you. Claim at subsidy-india.ml today!",
]

def clean(t):
    t = str(t)
    t = re.sub(r'http\S+|www\.\S+|bit\.ly\S+', ' PHISHURL ', t)
    t = re.sub(r'\b\d{10,}\b', ' LONGNUM ', t)
    t = re.sub(r'Rs\.?\s*[\d,]+(\.\d{1,2})?|INR\s*[\d,]+', ' RUPEEAMT ', t)
    t = re.sub(r'\bXX\d{4}\b|\b[xX]{4}\d{4}\b', ' MASKEDACC ', t)
    t = re.sub(r'\b\d{4,8}\b', ' CODE ', t)
    t = re.sub(r'[^a-zA-Z\s]', ' ', t)
    return re.sub(r'\s+', ' ', t).lower().strip()

csv_path = sys.argv[1] if len(sys.argv)>1 else str(HERE.parent/'data'/'sms_spam.csv')
df = pd.read_csv(csv_path, sep='\t', header=None, names=['label','text'], encoding='latin-1', on_bad_lines='skip')
df['label'] = df['label'].map(lambda x: 1 if str(x).strip().lower()=='spam' else 0)
df = df[['text','label']].dropna()

bank_df  = pd.DataFrame({'text':BANK_LEGIT*6,  'label':[0]*len(BANK_LEGIT)*6})
phish_df = pd.DataFrame({'text':PHISHING_CURATED*6,'label':[1]*len(PHISHING_CURATED)*6})
df = pd.concat([df,bank_df,phish_df],ignore_index=True).drop_duplicates(subset=['text'])
df['clean'] = df['text'].apply(clean)
df = df[df['clean'].str.len()>5]
print(f"Dataset: {len(df)} | legit={(df['label']==0).sum()} | phishing={(df['label']==1).sum()}")

X,y = df['clean'].values, df['label'].values
vec = TfidfVectorizer(ngram_range=(1,3), max_features=25000, sublinear_tf=True, min_df=1)
Xv  = vec.fit_transform(X)
Xtr,Xte,ytr,yte = train_test_split(Xv,y,test_size=0.15,random_state=42,stratify=y)
clf = LogisticRegression(max_iter=2000,C=0.6,class_weight={0:1.0,1:0.85},solver='lbfgs',random_state=42)
clf.fit(Xtr,ytr)
yp = clf.predict(Xte)
print(classification_report(yte,yp,target_names=["Legit","Phishing"]))
cm = confusion_matrix(yte,yp)
print(f"Confusion: {cm}\nFalse Positives: {cm[0][1]}")

with open(HERE/'text_model.pkl','wb') as f: pickle.dump(clf,f)
with open(HERE/'vectorizer.pkl','wb') as f: pickle.dump(vec,f)
print(f"✅ Saved to {HERE}")
