console.log("SPAM DETECTOR LOADED");

// Check Spam button
const button = document.createElement("button");

button.innerText = "🔍 Check Spam";
button.style.position = "fixed";
button.style.bottom = "20px";
button.style.right = "20px";
button.style.zIndex = "99999";
button.style.padding = "12px 18px";
button.style.background = "#d93025";
button.style.color = "white";
button.style.border = "none";
button.style.borderRadius = "8px";
button.style.cursor = "pointer";
button.style.fontSize = "14px";
button.style.fontWeight = "bold";

document.body.appendChild(button);


// When button is clicked
button.addEventListener("click", async () => {

    const subjectElement = document.querySelector("h2.hP");
    const bodyElement = document.querySelector(".a3s.aiL");

    const subject = subjectElement
        ? subjectElement.innerText
        : "";

    const body = bodyElement
        ? bodyElement.innerText
        : "";
    
    extractEmailImages();
    if (!body && !subject) {
        alert("Please open an email first.");
        return;
    }

    button.innerText = "⏳ Checking...";
    button.disabled = true;

    try {

        const response = await fetch(
            "http://127.0.0.1:8000/predict",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    subject: subject,
                    body: body
                })
            }
        );

        const result = await response.json();

        console.log("BACKEND RESULT:", result);

        showResult(result);

    } catch (error) {

        console.error(error);

        alert(
            "Could not connect to the Spam Detection Server."
        );

    }

    button.innerText = "🔍 Check Spam";
    button.disabled = false;
});


// Display result
function showResult(result) {

    // Remove previous result
    const oldBox = document.getElementById("spamResultBox");

    if (oldBox) {
        oldBox.remove();
    }

    const box = document.createElement("div");

    box.id = "spamResultBox";

    box.style.position = "fixed";
    box.style.top = "80px";
    box.style.right = "20px";
    box.style.width = "320px";
    box.style.background = "white";
    box.style.padding = "20px";
    box.style.borderRadius = "12px";
    box.style.boxShadow = "0 4px 20px rgba(0,0,0,0.25)";
    box.style.zIndex = "99999";
    box.style.fontFamily = "Arial, sans-serif";
    box.style.color = "#222";

    const isSpam = result.prediction === "SPAM";

    const probability =
        (result.spam_probability * 100).toFixed(2);

    let indicators = "";

    if (result.indicators && result.indicators.length > 0) {

        indicators = `
            <h4 style="margin-bottom:8px;">
                ⚠️ Suspicious Indicators
            </h4>

            <ul style="padding-left:20px;">
                ${result.indicators
                    .map(item => `<li>${item}</li>`)
                    .join("")}
            </ul>
        `;
    }

    box.innerHTML = `
        <div style="font-size:20px;font-weight:bold;margin-bottom:12px;">
            ${isSpam ? "🔴 SPAM EMAIL" : "🟢 NOT SPAM"}
        </div>

        <div style="font-size:16px;margin-bottom:8px;">
            Spam Probability:
            <strong>${probability}%</strong>
        </div>

        <div style="
            height:10px;
            background:#eee;
            border-radius:5px;
            overflow:hidden;
            margin-bottom:15px;
        ">
            <div style="
                width:${probability}%;
                height:100%;
                background:${isSpam ? "#d93025" : "#188038"};
            "></div>
        </div>

        ${indicators}

        <button id="closeSpamResult"
            style="
                margin-top:10px;
                padding:8px 14px;
                border:none;
                border-radius:6px;
                background:#eee;
                cursor:pointer;
            ">
            Close
        </button>
    `;

    document.body.appendChild(box);

    document
        .getElementById("closeSpamResult")
        .addEventListener("click", () => {
            box.remove();
        });
}

async function extractEmailImages() {
    let ocrText = "";
    const images = Array.from(
        document.querySelectorAll('img[src*="attid="]')
    );

    console.log("Email attachments found:", images.length);

    for (const img of images) {

        console.log("Analyzing attachment:", img.src);

        try {

            const fullImageUrl = img.src.replace(
    /&sz=.*$/,
    ""
);

console.log("Full image URL:", fullImageUrl);

const response = await fetch(fullImageUrl);

            const blob = await response.blob();
            console.log(
    "IMAGE RECEIVED:",
    blob.type,
    blob.size
);

            const formData = new FormData();

            formData.append(
                "file",
                blob,
                "email-attachment.png"
            );

            const result = await fetch(
                "http://127.0.0.1:8000/analyze-image",
                {
                    method: "POST",
                    body: formData
                }
            );

           const data = await result.json();

console.log("ATTACHMENT OCR:", data);

if (data.extracted_text) {
    ocrText += " " + data.extracted_text;
}

        } catch (error) {

            console.error(
                "ATTACHMENT ERROR:",
                error
            );
        }
    }
    return ocrText;
}