const API_URL = "http://127.0.0.1:8000";

// Screenshot analysis
const formData = new FormData();
formData.append("file", file);
const res = await fetch(`${API_URL}/analyze-screenshot`, { method: "POST", body: formData });
const data = await res.json();
// data.extracted_text → the OCR text
// data.analysis.risk_level → "High" / "Medium" / "Low"
// data.analysis.score → 0–100
// data.analysis.keywords → array of flagged words
function showTab(tab){

document.getElementById("textSection").classList.add("hidden");
document.getElementById("urlSection").classList.add("hidden");
document.getElementById("screenshotSection").classList.add("hidden");

if(tab==="text")
document.getElementById("textSection").classList.remove("hidden");

if(tab==="url")
document.getElementById("urlSection").classList.remove("hidden");

if(tab==="screenshot")
document.getElementById("screenshotSection").classList.remove("hidden");

}



async function analyzeText(){

let message=document.getElementById("messageInput").value;

let response=await fetch(API_URL+"/analyze-text",{

method:"POST",

headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({
message:message
})

});

let data=await response.json();

document.getElementById("textResult").innerHTML=`

<h3 class="${data.risk_level.toLowerCase()}">
${data.risk_level} Risk
</h3>

<p><b>Score:</b> ${data.score}</p>

<p><b>Prediction:</b> ${data.prediction}</p>

`;

}



async function analyzeURL(){

let url=document.getElementById("urlInput").value;

let response=await fetch(API_URL+"/analyze-url",{

method:"POST",

headers:{
"Content-Type":"application/json"
},

body:JSON.stringify({
url:url
})

});

let data=await response.json();

document.getElementById("urlResult").innerHTML=`

<h3 class="${data.risk_level.toLowerCase()}">
${data.risk_level} Risk
</h3>

<p><b>Score:</b> ${data.score}</p>

<p><b>Prediction:</b> ${data.prediction}</p>

`;

}



async function analyzeScreenshot(){

const fileInput=document.getElementById("screenshotInput");

const file=fileInput.files[0];

if(!file){
alert("Upload a screenshot first");
return;
}

const formData=new FormData();

formData.append("file",file);

const response=await fetch(API_URL+"/analyze-screenshot",{

method:"POST",

body:formData

});

const data=await response.json();

document.getElementById("screenshotResult").innerHTML=`

<h3>${data.analysis.risk_level} Risk</h3>

<p><b>Score:</b> ${data.analysis.score}</p>

<p><b>Extracted Text:</b></p>

<p>${data.ocr_text || data.extracted_text}</p>

`;

}