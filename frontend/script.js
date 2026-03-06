const API_URL = "http://127.0.0.1:8000";

let textChart;
let urlChart;

function showTab(tab){

document.getElementById("textSection").classList.add("hidden");
document.getElementById("urlSection").classList.add("hidden");

document.getElementById("textTab").classList.remove("active");
document.getElementById("urlTab").classList.remove("active");

if(tab === "text"){
document.getElementById("textSection").classList.remove("hidden");
document.getElementById("textTab").classList.add("active");
}
else{
document.getElementById("urlSection").classList.remove("hidden");
document.getElementById("urlTab").classList.add("active");
}

}



function drawChart(id,value){

return new Chart(document.getElementById(id),{

type:'doughnut',

data:{
datasets:[{

data:[value,100-value],

}]
},

options:{

cutout:'75%',

plugins:{
legend:{display:false}
}

}

});

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

let riskScore=data.score || 70;

if(textChart) textChart.destroy();

textChart=drawChart("textChart",riskScore);

let tactics=data.tactics.map(t=>"<li>"+t+"</li>").join("");

document.getElementById("textResult").innerHTML=`

<h3 class="${data.risk_level.toLowerCase()}">${data.risk_level} Risk</h3>

<p><b>Attack Type:</b> ${data.prediction}</p>

<ul>${tactics}</ul>

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

let riskScore=data.score || 70;

if(urlChart) urlChart.destroy();

urlChart=drawChart("urlChart",riskScore);

let issues=data.issues.map(i=>"<li>"+i+"</li>").join("");

document.getElementById("urlResult").innerHTML=`

<h3 class="${data.risk_level.toLowerCase()}">${data.risk_level} Risk</h3>

<p><b>Prediction:</b> ${data.prediction}</p>

<ul>${issues}</ul>

`;

}