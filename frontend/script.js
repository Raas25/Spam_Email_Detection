const API_URL = "http://127.0.0.1:8000/predict";

const form = document.getElementById("emailForm");
const subjectInput = document.getElementById("subject");
const bodyInput = document.getElementById("body");
const checkBtn = document.getElementById("checkBtn");
const buttonText = document.getElementById("buttonText");
const clearBtn = document.getElementById("clearBtn");
const spinner = document.getElementById("spinner");
const validationError = document.getElementById("validationError");
const apiError = document.getElementById("apiError");
const results = document.getElementById("results");
const charCount = document.getElementById("charCount");

const resultHeader = document.getElementById("resultHeader");
const resultIcon = document.getElementById("resultIcon");
const resultTitle = document.getElementById("resultTitle");
const resultDescription = document.getElementById("resultDescription");
const spamProbability = document.getElementById("spamProbability");
const notSpamProbability = document.getElementById("notSpamProbability");
const confidence = document.getElementById("confidence");
const spamBar = document.getElementById("spamBar");
const notSpamBar = document.getElementById("notSpamBar");
const indicatorsList = document.getElementById("indicatorsList");

bodyInput.addEventListener("input", () => {
  const count = bodyInput.value.length;
  charCount.textContent = `${count.toLocaleString()} character${count === 1 ? "" : "s"}`;
});

function setLoading(isLoading) {
  checkBtn.disabled = isLoading;
  buttonText.textContent = isLoading ? "Analyzing..." : "Check Email";
  checkBtn.classList.toggle("loading", isLoading);
  spinner.setAttribute("aria-hidden", String(!isLoading));
}

function formatPercent(value) {
  const number = Number(value) || 0;
  return `${(number * 100).toFixed(2)}%`;
}

function showIndicators(indicators) {
  indicatorsList.innerHTML = "";

  if (!Array.isArray(indicators) || indicators.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No obvious suspicious indicators detected.";
    indicatorsList.appendChild(li);
    return;
  }

  indicators.forEach((indicator) => {
    const li = document.createElement("li");
    li.textContent = String(indicator);
    indicatorsList.appendChild(li);
  });
}

function displayResult(data) {
  const isSpam = String(data.prediction || "").toUpperCase() === "SPAM";
  const spam = Number(data.spam_probability) || 0;
  const notSpam = Number(data.not_spam_probability) || 0;
  const conf = Number(data.confidence) || 0;

  resultHeader.className = `result-header ${isSpam ? "spam" : "safe"}`;
  resultIcon.textContent = isSpam ? "!" : "✓";
  resultTitle.textContent = isSpam ? "SPAM DETECTED" : "NOT SPAM";
  resultDescription.textContent = isSpam
    ? "This email appears to contain characteristics commonly associated with spam or phishing emails."
    : "This email does not appear to contain strong indicators of spam.";

  spamProbability.textContent = formatPercent(spam);
  notSpamProbability.textContent = formatPercent(notSpam);
  confidence.textContent = formatPercent(conf);

  requestAnimationFrame(() => {
    spamBar.style.width = `${Math.max(0, Math.min(100, spam * 100))}%`;
    notSpamBar.style.width = `${Math.max(0, Math.min(100, notSpam * 100))}%`;
  });

  showIndicators(data.indicators);
  results.classList.remove("hidden");
  results.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  validationError.textContent = "";
  apiError.classList.add("hidden");

  const subject = subjectInput.value.trim();
  const body = bodyInput.value.trim();

  if (!subject && !body) {
    validationError.textContent = "Please enter an email subject or email body.";
    subjectInput.focus();
    return;
  }

  setLoading(true);

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ subject, body })
    });

    let data;
    try {
      data = await response.json();
    } catch {
      throw new Error("The backend returned an invalid response.");
    }

    if (!response.ok) {
      throw new Error(data.detail || data.message || `Request failed (${response.status}).`);
    }

    displayResult(data);
  } catch (error) {
    apiError.textContent =
      `Could not analyze the email. ${error.message} Make sure the FastAPI backend is running at ${API_URL}.`;
    apiError.classList.remove("hidden");
  } finally {
    setLoading(false);
  }
});

clearBtn.addEventListener("click", () => {
  form.reset();
  charCount.textContent = "0 characters";
  validationError.textContent = "";
  apiError.classList.add("hidden");
  results.classList.add("hidden");
  spamBar.style.width = "0";
  notSpamBar.style.width = "0";
  subjectInput.focus();
});
