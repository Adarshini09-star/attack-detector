const suspiciousWords = [
    "urgent",
    "verify",
    "account suspended",
    "click here",
    "bank",
    "login",
    "password",
    "update account",
    "confirm identity",
    "security alert"
];

const phishingKeywords = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "paypal",
    "update"
];

const trustedDomains = [
    "github.com",
    "google.com",
    "gmail.com",
    "microsoft.com",
    "linkedin.com"
];

function showWarning(message){

    if(document.getElementById("ai-warning-banner")) return;

    const banner = document.createElement("div");

    banner.id = "ai-warning-banner";
    banner.innerText = "⚠ " + message;

    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.background = "red";
    banner.style.color = "white";
    banner.style.padding = "12px";
    banner.style.fontSize = "16px";
    banner.style.textAlign = "center";
    banner.style.zIndex = "999999";

    document.body.appendChild(banner);
}

function detectEmailContent(){

    const emailBody = document.querySelector(".a3s");

    if(!emailBody) return;

    const text = emailBody.innerText.toLowerCase();

    for(let word of suspiciousWords){
        if(text.includes(word)){
            showWarning("Possible Social Engineering Message Detected");
            return;
        }
    }
}

function detectEmailLinks(){

    const emailBody = document.querySelector(".a3s");

    if(!emailBody) return;

    const links = emailBody.querySelectorAll("a");

    links.forEach(link => {

        const url = link.href;

        let hostname;

        try{
            hostname = new URL(url).hostname.toLowerCase();
        } catch {
            return;
        }

        let score = 0;

        // suspicious: IP address instead of domain
        if(/\d+\.\d+\.\d+\.\d+/.test(hostname)) score++;

        // suspicious: too many subdomains
        if(hostname.split(".").length > 4) score++;

        // suspicious: extremely long url
        if(url.length > 120) score++;

        // suspicious: @ in url
        if(url.includes("@")) score++;

        // suspicious keywords
        const phishingKeywords = [
            "login",
            "verify",
            "secure",
            "update",
            "account",
            "bank",
            "paypal",
            "signin"
        ];

        phishingKeywords.forEach(keyword=>{
            if(hostname.includes(keyword)){
                score++;
            }
        });

        // trigger only if strongly suspicious
        if(score >= 3){

            link.style.border = "3px solid red";
            link.style.background = "#ffcccc";

            showWarning("Suspicious Phishing Link Detected");
        }

    });
}

function scanEmail(){

    detectEmailContent();

    detectEmailLinks();

}

setInterval(scanEmail,4000);