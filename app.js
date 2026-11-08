(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const apiBase = (window.PHISHGUARD_API_BASE || "").replace(/\/+$/, "");
  const SAMPLE_SAFE = `From: alex@university.edu
Subject: Meeting notes

Hi,
Thanks for the meeting today. Please review the attached notes and give me your feedback by Friday.
Best,
Alex`;
  const SAMPLE_PHISH = `From: security@paypa1-secure.com
Reply-To: refunds@gmail.com
Subject: Urgent: Your account has been suspended

Dear Customer,
Your PayPal account has been suspended due to unusual activity. Verify your identity immediately to avoid permanent closure within 24 hours.
Click here to login and confirm: http://paypa1-login.com/verify
Enter your password and credit card number to reactivate. Act now before your account is locked forever.`;
  const URGENCY = ["act now","account suspended","verify your identity","verify your account","urgent","immediately","within 24 hours","final notice","reactivate","limited time","you have won","unusual activity","account locked","security alert","claim your","payment failed","update your","click here","confirm your","login now","expires today","password expired"];
  const SENSITIVE = ["password","credit card","card number","cvv","ssn","social security","bank account","routing number","gift card","bitcoin","atm pin","verify your identity","update payment","wire transfer","itunes card"];
  const SHORTENERS = ["bit.ly","tinyurl.com","goo.gl","t.co","is.gd","cutt.ly","rb.gy","ow.ly","buff.ly","tiny.cc","s.id","rebrand.ly"];
  const TRUSTED = ["paypal.com","google.com","apple.com","amazon.com","microsoft.com","facebook.com","netflix.com","chase.com","wellsfargo.com","citibank.com","hsbc.com","bankofamerica.com","linkedin.com","dropbox.com","instagram.com"];
  const MISSPELLINGS = ["verifiy","acount","recieve","securty","passwrod","responce","informatiion","enail","payemnt","loging","unsesual","attentiion","immediatley","confirmaton"];
  const ATTACH = [".exe",".scr",".bat",".js",".zip",".rar",".lnk",".vbs",".cmd"];
  let installPrompt = null;

  function escapeHtml(s) { return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
  function showToast(message) { const t=$("toast"); t.textContent=message; t.classList.add("show"); setTimeout(()=>t.classList.remove("show"),2400); }
  function localAnalyze(text) {
    const lines=text.split(/\r?\n/), subject=(text.match(/^Subject:\s*(.*)$/im)||[])[1]||"";
    const from=(text.match(/^From:\s*(.*)$/im)||[])[1]||"", reply=(text.match(/^Reply-To:\s*(.*)$/im)||[])[1]||"";
    const domain=s => ((s.match(/@([\w.-]+)/)||[])[1]||"").toLowerCase();
    const sender=domain(from), replyDomain=domain(reply), low=(subject+" "+text).toLowerCase();
    let score=0; const cats={}, reasons=[], urls=[];
    const add=(cat,pts,reason)=>{score+=pts;cats[cat]=(cats[cat]||0)+pts;reasons.push(reason);};
    if(sender&&replyDomain&&sender!==replyDomain)add("Header",3,`Sender (${sender}) and Reply-To (${replyDomain}) domains do not match`);
    const display=(from.match(/^([^<@]+?)\s*</)||[])[1]||"";
    if(display&&sender&&["paypal","google","apple","amazon","microsoft","facebook","netflix","chase","linkedin"].some(b=>display.toLowerCase().includes(b))&&["gmail.com","yahoo.com","hotmail.com","outlook.com","aol.com","icloud.com"].includes(sender))add("Spoof",3,"Display name claims a known brand but uses a free-mail domain");
    const foundUrls=text.match(/https?:\/\/[^\s<>"')]+/gi)||[]; let ip=0,short=0,look=0;
    for(const u of foundUrls){let host="";try{host=new URL(u).hostname.toLowerCase()}catch{}if(!host)continue;let flag="Seems normal";
      if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)||host==="localhost"){ip++;flag="IP address";}
      else if(SHORTENERS.includes(host)){short++;flag="Shortened link";}
      else {const brand=TRUSTED.find(d=>host.includes(d.split(".")[0])&&!host.endsWith(d));if(brand){look++;flag=`Lookalike domain (possible fake ${brand.split(".")[0]})`;}else if(!u.startsWith("https:")&&/(login|verify|signin|secure)/i.test(low))flag="Non-secure login/verify link";}
      urls.push({url:u,flag});
    }
    if(ip)add("URL",2,`IP-address URL (${ip})`);if(short)add("URL",1,`Shortened link (${short})`);if(look)add("URL",3,`Lookalike domain (${look})`);
    const urg=URGENCY.filter(k=>low.includes(k));if(urg.length)add("Urgency",1+Math.min(urg.length,3),`Pressure language: "${urg[0]}"${urg.length>1?` (+${urg.length-1} more)`:""}`);
    const sens=SENSITIVE.filter(k=>low.includes(k));if(sens.length)add("Sensitive",Math.min(sens.length,4),`Asks for sensitive data: ${sens.slice(0,3).join(", ")}`);
    const att=ATTACH.filter(k=>low.includes(k));if(att.length)add("Attachment",2,`Potentially dangerous attachment type mentioned: ${att.join(", ")}`);
    const miss=MISSPELLINGS.filter(k=>low.includes(k));if(miss.length)add("Spelling",Math.min(miss.length,3),`Possible misspellings: ${miss.slice(0,3).join(", ")}`);
    if(!reasons.length)reasons.push("No obvious phishing indicators found by the local checks");
    const verdict=score<=2?"SAFE":score<=5?"SUSPICIOUS":"DANGEROUS";
    return {subject,from,reply_to:reply,score,verdict,final_verdict:verdict,reasons,cats,urls,ai_prob:null,ai_ready:false,local_mode:true};
  }
  async function post(path,payload) {
    if(!apiBase) throw new Error("Backend URL is not configured.");
    const response=await fetch(apiBase+path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
    const data=await response.json().catch(()=>({error:"The server returned an unreadable response."}));
    if(!response.ok)throw new Error(data.error||`Server error (${response.status})`);
    return data;
  }
  async function analyzeText(text) {
    if(apiBase){try{return await post("/api/analyze",{text});}catch(e){setConnection(false,"AI backend unavailable");showToast("AI backend unavailable — using browser checks.");}}
    return localAnalyze(text);
  }
  function renderResult(d) {
    const verdict=d.final_verdict||d.verdict||"SUSPICIOUS", el=$("verdict");
    el.textContent=verdict;el.className="verdict "+verdict;
    $("verdictNote").textContent=verdict==="SAFE"?"No strong warning signs detected.":verdict==="SUSPICIOUS"?"Some indicators deserve a closer look.":"High-risk indicators detected. Do not interact with this email.";
    $("score").textContent=d.score??"—";$("meterFill").style.width=Math.min((Number(d.score)||0)/12*100,100)+"%";
    $("meterFill").style.background=verdict==="SAFE"?"var(--green)":verdict==="SUSPICIOUS"?"var(--amber)":"var(--red)";
    if(d.ai_ready&&d.ai_prob!==null&&d.ai_prob!==undefined){$("aiTitle").textContent="AI model active";$("aiText").textContent=`Uncalibrated model score: ${(d.ai_prob*100).toFixed(1)}%. Treat as one signal, not a reliable probability; a Dangerous verdict also requires rule-based evidence.`;$("modeTag").textContent="AI + rule analysis";}
    else{$("aiTitle").textContent=d.local_mode?"Browser checks active":"AI model unavailable";$("aiText").textContent=d.local_mode?"Offline-friendly local checks are active. Connect the backend to use the trained machine-learning model.":"Rule-based checks are active; the machine-learning model is not currently available.";$("modeTag").textContent=d.local_mode?"Local fallback":"Rules + backend";}
    const cats=d.cats||{}, keys=Object.entries(cats).sort((a,b)=>b[1]-a[1]);
    $("breakdown").innerHTML=keys.length?keys.map(([k,v])=>`<span class="chip">${escapeHtml(k)} · +${Number(v)}</span>`).join(""):'<span class="subtle">No risk categories triggered.</span>';
    $("reasons").innerHTML=(d.reasons||["No detailed reasons supplied."]).map(r=>`<li>${escapeHtml(r)}</li>`).join("");
    $("urls").innerHTML=(d.urls||[]).length?d.urls.map(u=>`<div class="url-entry"><span class="url-flag">[${escapeHtml(u.flag)}]</span>${escapeHtml(u.url)}</div>`).join(""):'<span class="subtle">No links found in this message.</span>';
    $("resultArea").hidden=false;
  }
  function setError(id,msg){$(id).textContent=msg;$(id).hidden=!msg;}
  document.querySelectorAll(".tab").forEach(btn=>btn.addEventListener("click",()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("active",x===btn));document.querySelectorAll(".view").forEach(x=>x.hidden=x.id!==btn.dataset.tab);}));
  $("emailInput").addEventListener("input",()=>{$("charCount").textContent=$("emailInput").value.length.toLocaleString()+" characters";});
  $("safeSample").addEventListener("click",()=>{$("emailInput").value=SAMPLE_SAFE;$("emailInput").dispatchEvent(new Event("input"));$("resultArea").hidden=true;setError("error","");});
  $("phishSample").addEventListener("click",()=>{$("emailInput").value=SAMPLE_PHISH;$("emailInput").dispatchEvent(new Event("input"));$("resultArea").hidden=true;setError("error","");});
  $("clearBtn").addEventListener("click",()=>{$("emailInput").value="";$("emailInput").dispatchEvent(new Event("input"));$("resultArea").hidden=true;setError("error","");});
  $("analyzeBtn").addEventListener("click",async()=>{const text=$("emailInput").value.trim();if(!text){setError("error","Paste an email before starting the scan.");return;}setError("error","");$("analyzeBtn").disabled=true;$("analyzeBtn").textContent="Analysing…";try{renderResult(await analyzeText(text));}catch(e){setError("error",e.message);}finally{$("analyzeBtn").disabled=false;$("analyzeBtn").innerHTML="<span>⌕</span> Analyse email";}});
  async function batchAnalyze(messages){const results=[];for(let i=0;i<messages.length;i++){const d=await analyzeText(messages[i]);results.push({index:i+1,score:d.score,verdict:d.final_verdict||d.verdict,ai_prob:d.ai_prob});}return {results,total:results.length};}
  function renderBatch(data){const rows=data.results||[];$("batchTotal").textContent=`${data.total??rows.length} EMAILS ANALYSED`;$("batchResults").innerHTML=rows.length?`<div class="table-wrap"><table><thead><tr><th>#</th><th>RISK SCORE</th><th>VERDICT</th><th>AI PROBABILITY</th></tr></thead><tbody>${rows.map(r=>`<tr><td>${r.index}</td><td>${r.score}</td><td class="v-${escapeHtml(r.verdict)}">${escapeHtml(r.verdict)}</td><td>${r.ai_prob==null?"—":(Number(r.ai_prob)*100).toFixed(1)+"%"}</td></tr>`).join("")}</tbody></table></div>`:'<div class="empty-state">No emails were found in the input.</div>';}
  $("batchBtn").addEventListener("click",async()=>{const raw=$("batchInput").value.trim();if(!raw){setError("batchError","Paste one or more emails first.");return;}const chunks=raw.split(/\n\s*={2,}\s*\n/).map(s=>s.trim()).filter(Boolean);setError("batchError","");$("batchBtn").disabled=true;$("batchBtn").textContent="Scanning…";try{renderBatch(await batchAnalyze(chunks));}catch(e){setError("batchError",e.message);}finally{$("batchBtn").disabled=false;$("batchBtn").textContent="Run batch scan";}});
  $("csvBtn").addEventListener("click",()=>$("csvInput").click());
  function parseCSV(text){const rows=[];let row=[],cell="",quoted=false;for(let i=0;i<text.length;i++){const c=text[i];if(c==='"'&&quoted&&text[i+1]==='"'){cell+='"';i++;}else if(c==='"'){quoted=!quoted;}else if(c===","&&!quoted){row.push(cell);cell="";}else if((c==="\n"||c==="\r")&&!quoted){if(c==="\r"&&text[i+1]==="\n")i++;row.push(cell);if(row.some(x=>x.trim()))rows.push(row);row=[];cell="";}else cell+=c;}row.push(cell);if(row.some(x=>x.trim()))rows.push(row);return rows;}
  $("csvInput").addEventListener("change",async e=>{const file=e.target.files[0];if(!file)return;setError("batchError","");try{const rows=parseCSV(await file.text());if(rows.length<2)throw new Error("CSV needs a header row and at least one data row.");const headers=rows[0].map(x=>x.toLowerCase().trim());const col=headers.findIndex(h=>["text","email","body","message","content"].some(k=>h.includes(k)));if(col<0)throw new Error("Could not find an email/text column in the CSV header.");const messages=rows.slice(1).map(r=>r[col]||"").filter(x=>x.trim());const data=await batchAnalyze(messages);renderBatch(data);showToast(`${data.total} CSV rows scanned`);}catch(err){setError("batchError",err.message);}finally{e.target.value="";}});
  const savedTheme=localStorage.getItem("phishguard-theme");if(savedTheme==="dark")document.body.classList.add("dark");
  $("themeToggle").addEventListener("click",()=>{document.body.classList.toggle("dark");localStorage.setItem("phishguard-theme",document.body.classList.contains("dark")?"dark":"light");$("themeToggle").textContent=document.body.classList.contains("dark")?"☀":"☾";});
  $("themeToggle").textContent=document.body.classList.contains("dark")?"☀":"☾";
  function setConnection(online,label){const el=$("connection");el.classList.toggle("online",online);el.querySelector("span").textContent=label;}
  async function connection(){
    if(!navigator.onLine){setConnection(false,"Offline");return;}
    if(!apiBase){setConnection(false,"AI backend not configured");return;}
    setConnection(false,"Checking AI backend");
    const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),15000);
    try{
      const response=await fetch(apiBase+"/health",{signal:controller.signal});
      if(!response.ok)throw new Error(`Health check failed (${response.status})`);
      const status=await response.json();
      if(status.status!=="ok")throw new Error("Backend health check failed");
      setConnection(true,"AI backend connected");
    }catch(_){setConnection(false,"AI backend unavailable");}
    finally{clearTimeout(timeout);}
  }
  window.addEventListener("online",connection);
  window.addEventListener("offline",()=>setConnection(false,"Offline"));
  connection();
  window.addEventListener("beforeinstallprompt",e=>{e.preventDefault();installPrompt=e;$("installBtn").hidden=false;});
  $("installBtn").addEventListener("click",async()=>{if(!installPrompt){showToast("Use your browser menu and choose Install app or Add to Home screen.");return;}installPrompt.prompt();await installPrompt.userChoice;installPrompt=null;$("installBtn").hidden=true;});
  window.addEventListener("appinstalled",()=>{showToast("PhishGuard AI installed.");$("installBtn").hidden=true;});
  if("serviceWorker" in navigator && location.protocol!=="file:"){window.addEventListener("load",()=>navigator.serviceWorker.register("./sw.js").catch(()=>{}));}
})();