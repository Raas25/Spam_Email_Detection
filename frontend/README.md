# Spam Email Checker — Frontend

A standalone HTML/CSS/JavaScript frontend for the Spam Email Detection mini-project.

## Files

- `index.html` — page structure
- `style.css` — responsive styling
- `script.js` — API communication and result handling

## Backend contract

The frontend sends:

POST `http://127.0.0.1:8000/predict`

```json
{
  "subject": "Email subject",
  "body": "Email body"
}
```

Expected response:

```json
{
  "prediction": "SPAM",
  "spam_probability": 0.9765,
  "not_spam_probability": 0.0235,
  "confidence": 0.9765,
  "indicators": [
    "Urgent or threatening language",
    "Contains a URL"
  ]
}
```

## Running

Start your FastAPI backend on port 8000, then serve this folder with a local static server.

For example:

```bash
python -m http.server 5500
```

Open:

`http://127.0.0.1:5500`

If the backend uses another URL, change `API_URL` at the top of `script.js`.

## CORS

FastAPI must allow requests from the frontend origin. For local development, configure `CORSMiddleware` in the backend.
