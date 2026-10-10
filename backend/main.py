from fastapi import UploadFile, File
from PIL import Image
import pytesseract
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import os
import re
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
import warnings


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model", "spam_model.joblib")


# ---------------------------------------------------------
# Suppress BeautifulSoup warnings
# ---------------------------------------------------------

warnings.filterwarnings(
    "ignore",
    category=MarkupResemblesLocatorWarning
)


# ---------------------------------------------------------
# Load trained model
# ---------------------------------------------------------

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Model file not found: {MODEL_PATH}"
    )

artifact = joblib.load(MODEL_PATH)

model = artifact["model"]
vectorizer = artifact["vectorizer"]
metadata = artifact.get("metadata", {})


# ---------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------

app = FastAPI(
    title="Spam Email Checker API",
    description="AI-powered spam email detection API",
    version="1.0.0"
)


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# Request schema
# ---------------------------------------------------------

class EmailRequest(BaseModel):
    subject: str = ""
    body: str = ""


# ---------------------------------------------------------
# Text preprocessing
# ---------------------------------------------------------

def clean_email_text(text):
    """
    Clean email text using the same preprocessing
    used during model training in Google Colab.
    """

    text = "" if text is None else str(text)

    # Remove HTML
    text = BeautifulSoup(
        text,
        "html.parser"
    ).get_text(" ")

    # Lowercase
    text = text.lower()

    # Replace URLs
    text = re.sub(
        r"https?://\S+|www\.\S+",
        " URL ",
        text
    )

    # Replace email addresses
    text = re.sub(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        " EMAIL ",
        text
    )

    # Replace numbers
    text = re.sub(
        r"\b\d+\b",
        " NUMBER ",
        text
    )

    # Normalize whitespace
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ---------------------------------------------------------
# Create model input
# ---------------------------------------------------------

def prepare_email(subject, body):
    clean_subject = clean_email_text(subject)
    clean_body = clean_email_text(body)

    return (
        "subject " +
        clean_subject +
        " body " +
        clean_body
    )


# ---------------------------------------------------------
# Detection indicators
# ---------------------------------------------------------

def get_indicators(subject, body):
    """
    Detect common suspicious patterns.
    These indicators are supplementary explanations;
    the ML model remains responsible for the prediction.
    """

    combined_text = f"{subject} {body}".lower()

    indicators = []

    # Urgency
    urgency_words = [
        "urgent",
        "immediately",
        "action required",
        "act now",
        "verify now",
        "account suspended",
        "account will be closed",
        "limited time"
    ]

    if any(word in combined_text for word in urgency_words):
        indicators.append("Urgent or threatening language")

    # Financial / prize language
    financial_words = [
        "winner",
        "won",
        "prize",
        "lottery",
        "reward",
        "cash",
        "money",
        "million",
        "claim your"
    ]

    if any(word in combined_text for word in financial_words):
        indicators.append("Prize or financial-related language")

    # Credential requests
    credential_words = [
        "password",
        "login",
        "username",
        "verify your account",
        "confirm your account",
        "bank account",
        "credit card",
        "personal information"
    ]

    if any(word in combined_text for word in credential_words):
        indicators.append("Possible credential or personal-information request")

    # URLs
    if re.search(
        r"https?://\S+|www\.\S+",
        combined_text
    ):
        indicators.append("Contains a URL")

    # Email addresses
    if re.search(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        combined_text
    ):
        indicators.append("Contains an email address")

    # Excessive exclamation marks
    if combined_text.count("!") >= 3:
        indicators.append("Excessive exclamation marks")

    # Suspicious HTML
    if re.search(
        r"<\s*(a|form|iframe|script)\b",
        body,
        re.IGNORECASE
    ):
        indicators.append("Contains potentially suspicious HTML")

    return indicators


# ---------------------------------------------------------
# Health check
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "Spam Email Checker API",
        "version": "1.0.0"
    }


# ---------------------------------------------------------
# Model information
# ---------------------------------------------------------

@app.get("/model-info")
def model_info():
    return {
        "dataset": metadata.get("dataset", "CEAS_08"),
        "features": metadata.get(
            "features",
            "Word + Character TF-IDF"
        ),
        "classifier": metadata.get(
            "classifier",
            "Logistic Regression"
        ),
        "metrics": metadata.get("metrics", {}),
        "labels": metadata.get(
            "label_mapping",
            {
                0: "NOT SPAM",
                1: "SPAM"
            }
        )
    }


# ---------------------------------------------------------
# Spam prediction
# ---------------------------------------------------------

@app.post("/predict")
def predict_email(request: EmailRequest):

    subject = request.subject.strip()
    body = request.body.strip()

    if not subject and not body:
        raise HTTPException(
            status_code=400,
            detail="Please provide an email subject or body."
        )

    # Prepare text exactly like training
    email_text = prepare_email(
        subject,
        body
    )

    # Convert text into TF-IDF features
    features = vectorizer.transform(
        [email_text]
    )

    # Prediction
    prediction = model.predict(
        features
    )[0]

    # Probabilities
    probabilities = model.predict_proba(
        features
    )[0]

    not_spam_probability = float(
        probabilities[0]
    )

    spam_probability = float(
        probabilities[1]
    )

    # Final label
    label = (
        "SPAM"
        if prediction == 1
        else "NOT SPAM"
    )

    # Model confidence
    confidence = max(
        spam_probability,
        not_spam_probability
    )

    # Explanation indicators
    indicators = get_indicators(
        subject,
        body
    )

    return {
        "prediction": label,
        "spam_probability": round(
            spam_probability,
            4
        ),
        "not_spam_probability": round(
            not_spam_probability,
            4
        ),
        "confidence": round(
            confidence,
            4
        ),
        "indicators": indicators
    }

@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...)):
    image = Image.open(file.file)

    extracted_text = pytesseract.image_to_string(image)

    return {
        "extracted_text": extracted_text,
        "has_text": bool(extracted_text.strip())
    }