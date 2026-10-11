"""
Text classification with the trained TF-IDF + Logistic Regression
model, plus keyword indicators and word-level explanations.
"""

import os
import re
import warnings

import joblib
import numpy as np
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "model", "spam_model.joblib")

# Number of words shown per side in the explanation
TOP_TERMS_PER_SIDE = 5

URL_PATTERN = r"https?://\S+|www\.\S+"

CREDENTIAL_WORDS = [
    "password",
    "login",
    "username",
    "verify your account",
    "confirm your account",
    "bank account",
    "credit card",
    "personal information"
]

URGENCY_WORDS = [
    "urgent",
    "immediately",
    "action required",
    "act now",
    "verify now",
    "account suspended",
    "account will be closed",
    "limited time"
]

FINANCIAL_WORDS = [
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

# Feature names and weights, used to explain predictions.
# The vectorizer is a FeatureUnion of "word" and "char" TF-IDF.
# Only word features are shown, since character pieces are not
# readable, and terms containing the "subject"/"body" markers
# added by prepare_email() are skipped (they occur in every email).
feature_names = np.array([
    str(name).removeprefix("word__")
    for name in vectorizer.get_feature_names_out()
])
feature_weights = model.coef_[0]
word_feature_mask = np.array([
    str(name).startswith("word__")
    and not {"subject", "body"} & set(str(name)[6:].split())
    for name in vectorizer.get_feature_names_out()
])

# Placeholders produced by clean_email_text()
PLACEHOLDER_LABELS = {
    "url": "[link]",
    "number": "[number]"
}


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
        URL_PATTERN,
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

def contains_any_word(text, words):
    """
    Match whole words/phrases only, so "won" does not
    match "wonderful" and "cash" does not match "cashew".
    """

    pattern = r"\b(?:" + "|".join(map(re.escape, words)) + r")\b"

    return re.search(pattern, text) is not None


def get_indicators(subject, body):
    """
    Detect common suspicious patterns.
    These indicators are supplementary explanations;
    the ML model remains responsible for the prediction.
    """

    combined_text = f"{subject} {body}".lower()

    indicators = []

    # Urgency
    if contains_any_word(combined_text, URGENCY_WORDS):
        indicators.append("Urgent or threatening language")

    # Financial / prize language
    if contains_any_word(combined_text, FINANCIAL_WORDS):
        indicators.append("Prize or financial-related language")

    # Credential requests
    if contains_any_word(combined_text, CREDENTIAL_WORDS):
        indicators.append("Possible credential or personal-information request")

    # URLs
    if re.search(
        URL_PATTERN,
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
# Prediction explanation
# ---------------------------------------------------------

def get_top_terms(features):
    """
    Explain a prediction with the words that pushed it most.
    For a linear model, a word's contribution is its
    TF-IDF value multiplied by the model weight.
    Positive weight = towards SPAM, negative = towards NOT SPAM.
    """

    row = features.tocsr()
    indices = row.indices
    values = row.data

    keep = word_feature_mask[indices]
    indices = indices[keep]
    contributions = values[keep] * feature_weights[indices]

    order = np.argsort(contributions)

    spam_side = [
        i for i in order[::-1][:TOP_TERMS_PER_SIDE]
        if contributions[i] > 0
    ]
    safe_side = [
        i for i in order[:TOP_TERMS_PER_SIDE]
        if contributions[i] < 0
    ]

    return [
        {
            "term": " ".join(
                PLACEHOLDER_LABELS.get(word, word)
                for word in feature_names[indices[i]].split()
            ),
            "weight": round(float(contributions[i]), 4)
        }
        for i in spam_side + safe_side
    ]


# ---------------------------------------------------------
# Prediction
# ---------------------------------------------------------

def predict_text(subject, body):
    """
    Run the spam model. Returns the same fields as /predict.
    """

    # Prepare text exactly like training
    email_text = prepare_email(subject, body)

    # Convert text into TF-IDF features
    features = vectorizer.transform([email_text])

    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]

    not_spam_probability = float(probabilities[0])
    spam_probability = float(probabilities[1])

    return {
        "prediction": "SPAM" if prediction == 1 else "NOT SPAM",
        "spam_probability": round(spam_probability, 4),
        "not_spam_probability": round(not_spam_probability, 4),
        "confidence": round(max(spam_probability, not_spam_probability), 4),
        "indicators": get_indicators(subject, body),
        "top_terms": get_top_terms(features)
    }
