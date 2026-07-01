package server

// dashboardHTML is the single-page dashboard, served at "/". Self-contained
// (inline CSS/JS, no external assets) and styled to match the report: a cool
// slate + "signal teal" design system with a persistent light/dark toggle.
const dashboardHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Observer — Dashboard</title>
<style>
  :root{
    --bg:#0d1117; --surface:#161b22; --surface2:#1c2430; --border:#2a3340;
    --text:#e6edf3; --muted:#9aa7b4; --accent:#2bb6c9; --accent-ink:#04222a; --track:#243040;
    --crit:#e5484d; --high:#f76808; --med:#d99700; --low:#7c8893; --ok:#2ea043;
    --shadow:0 1px 3px rgba(0,0,0,.4), 0 10px 30px rgba(0,0,0,.22);
    --font:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
    --mono:ui-monospace,"Cascadia Code","SF Mono","JetBrains Mono",Consolas,monospace;
  }
  [data-theme="light"]{
    --bg:#f6f8fa; --surface:#ffffff; --surface2:#eef1f5; --border:#dce2e9;
    --text:#1b2430; --muted:#5b6675; --accent:#0e8a9b; --accent-ink:#ffffff; --track:#e3e8ee;
    --shadow:0 1px 2px rgba(16,24,40,.06), 0 10px 28px rgba(16,24,40,.08);
  }
  *{box-sizing:border-box;}
  body{margin:0;font-family:var(--font);background:var(--bg);color:var(--text);line-height:1.55;font-size:15px;-webkit-font-smoothing:antialiased;}
  .wrap{max-width:1080px;margin:0 auto;padding:22px 22px 64px;}
  .appbar{display:flex;align-items:center;justify-content:space-between;}
  .brand{display:flex;align-items:center;gap:9px;font-weight:700;font-size:1.15rem;letter-spacing:-.01em;}
  .brand svg{color:var(--accent);}
  .themebtn{background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:9px;padding:7px 12px;cursor:pointer;font-size:.85rem;font-family:inherit;}
  .themebtn:hover{border-color:var(--accent);color:var(--accent);}
  .lead{color:var(--muted);font-size:.92rem;margin:4px 0 18px;}
  .panel{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px 20px;margin:16px 0;box-shadow:var(--shadow);}
  .panel h3{margin:0 0 12px;font-size:1rem;font-weight:650;}
  .fld{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;display:block;margin-bottom:7px;}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;}
  input[type=text]{flex:1;min-width:280px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:10px;padding:11px 13px;font-size:.95rem;font-family:inherit;}
  input[type=text]:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:var(--accent);}
  button.primary{background:var(--accent);color:var(--accent-ink);border:none;border-radius:10px;padding:11px 22px;font-weight:700;cursor:pointer;font-size:.95rem;font-family:inherit;}
  button.primary:disabled{opacity:.6;cursor:default;}
  .status{color:var(--muted);font-size:.9rem;}
  .err{color:var(--crit);margin-top:10px;font-size:.9rem;}
  .opts{margin-top:16px;display:flex;flex-wrap:wrap;gap:10px;align-items:center;}
  .opts .lbl{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;}
  .chk{display:inline-flex;align-items:center;gap:7px;background:var(--surface2);border:1px solid var(--border);border-radius:999px;padding:6px 13px;font-size:.85rem;cursor:pointer;}
  .chk input{accent-color:var(--accent);margin:0;}
  select{background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:9px;padding:7px 10px;font-family:inherit;font-size:.85rem;}
  table{width:100%;border-collapse:collapse;}
  th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--border);font-size:.9rem;vertical-align:middle;}
  th{color:var(--muted);text-transform:uppercase;font-size:.68rem;letter-spacing:.05em;}
  tbody tr:hover{background:var(--surface2);}
  a{color:var(--accent);text-decoration:none;} a:hover{text-decoration:underline;}
  .proj{font-weight:650;} .path{color:var(--muted);font-size:.78rem;word-break:break-all;}
  .scorepill{display:inline-flex;align-items:center;gap:6px;font-weight:700;font-variant-numeric:tabular-nums;}
  .gradedot{width:8px;height:8px;border-radius:50%;display:inline-block;background:currentColor;}
  .score-A{color:var(--ok);} .score-B{color:#3f9f6b;} .score-C{color:var(--med);} .score-D{color:var(--high);} .score-F{color:var(--crit);}
  .sev{font-weight:700;} .c{color:var(--crit);} .h{color:var(--high);} .m{color:var(--med);} .l{color:var(--low);}
  .pill{display:inline-block;background:color-mix(in srgb,var(--high) 20%,transparent);color:var(--high);border-radius:999px;padding:2px 9px;font-size:.78rem;font-weight:700;}
  .empty{color:var(--muted);font-style:italic;}
  .trendrow{display:flex;align-items:center;gap:16px;padding:9px 0;border-bottom:1px solid var(--border);}
  .trendrow:last-child{border-bottom:none;}
  .trendrow .tname{width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .trendrow .tn{color:var(--muted);font-size:.78rem;}
  @media (max-width:640px){ .trendrow .tname{width:120px;} input[type=text]{min-width:160px;} }
</style>
<script>
  (function(){try{var t=localStorage.getItem("observer-theme");if(t)document.documentElement.setAttribute("data-theme",t);}catch(e){}})();
  function toggleTheme(){var d=document.documentElement;var t=d.getAttribute("data-theme")==="light"?"dark":"light";d.setAttribute("data-theme",t);try{localStorage.setItem("observer-theme",t);}catch(e){}}
</script>
</head>
<body>
<div class="wrap">
  <div class="appbar">
    <div class="brand"><svg width="22" height="22" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="1.5" opacity=".45"/><circle cx="10" cy="10" r="3.3" fill="currentColor"/></svg> Observer</div>
    <button class="themebtn" onclick="toggleTheme()" title="Toggle light / dark">◐ Theme</button>
  </div>
  <div class="lead">Scan a project folder and track its security &amp; code-health over time. Past scans are kept below.</div>

  <div class="panel">
    <label class="fld" for="path">Project folder (absolute path)</label>
    <div class="row">
      <input id="path" type="text" placeholder="e.g. C:\laragon\www\ci3-fire-admin  or  /var/www/app">
      <button class="primary" id="scanBtn" onclick="scan()">Scan</button>
      <span class="status" id="status"></span>
    </div>
    <div class="opts">
      <span class="lbl">Include:</span>
      <label class="chk"><input type="checkbox" class="cat" value="Security" checked> Security</label>
      <label class="chk"><input type="checkbox" class="cat" value="Database" checked> Database</label>
      <label class="chk"><input type="checkbox" class="cat" value="Error Handling" checked> Error handling</label>
      <label class="chk"><input type="checkbox" class="cat" value="Performance" checked> Performance</label>
      <label class="chk"><input type="checkbox" class="cat" value="Configuration" checked> Configuration</label>
      <label class="chk"><input type="checkbox" class="cat" value="Dependencies" checked> Dependencies</label>
      <span class="lbl">Min severity:</span>
      <select id="minSev">
        <option value="">All</option>
        <option value="Medium">Medium+</option>
        <option value="High">High+</option>
        <option value="Critical">Critical only</option>
      </select>
    </div>
    <div class="err" id="err"></div>
  </div>

  <div class="panel" id="trendsPanel" style="display:none">
    <h3>Security score trend</h3>
    <div id="trends"></div>
  </div>

  <div class="panel">
    <h3>Scans</h3>
    <table>
      <thead><tr><th>Project</th><th>When</th><th>Security</th><th>Health</th><th>Issues</th><th>New</th><th>Time</th><th>Report</th></tr></thead>
      <tbody id="scans"><tr><td colspan="8" class="empty">Loading…</td></tr></tbody>
    </table>
  </div>
</div>

<script>
function esc(s){return (s||'').replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function fmtDur(ms){if(!ms&&ms!==0)return '';return ms>=1000?(ms/1000).toFixed(2)+'s':ms+'ms';}
function fmtIssues(r){var p=[];if(r.critical)p.push('<span class="sev c">'+r.critical+' crit</span>');if(r.high)p.push('<span class="sev h">'+r.high+' high</span>');if(r.medium)p.push('<span class="sev m">'+r.medium+' med</span>');if(r.low)p.push('<span class="sev l">'+r.low+' low</span>');return (r.total||0)+(p.length?' <span class="muted">('+p.join(', ')+')</span>':'');}
function scoreCell(v,g){return '<span class="scorepill score-'+esc(g)+'"><i class="gradedot"></i>'+(v||0)+'</span> <span class="muted">('+esc(g||'-')+')</span>';}
function sparkline(vals){var W=170,H=34;var pts=vals.map(function(v,i){var x=(vals.length<2?0:(i/(vals.length-1))*W);var y=H-(Math.max(0,Math.min(100,v))/100)*H;return x.toFixed(1)+','+y.toFixed(1);}).join(' ');var last=vals[vals.length-1];var color=last>=80?'#2ea043':last>=60?'#d99700':'#e5484d';var area=pts+' '+W+','+H+' 0,'+H;return '<svg width="'+W+'" height="'+H+'" style="background:var(--surface2);border-radius:6px"><polygon points="'+area+'" fill="'+color+'" opacity=".13"/><polyline points="'+pts+'" fill="none" stroke="'+color+'" stroke-width="2"/></svg>';}
function renderTrends(recs){var byPath={};recs.forEach(function(r){(byPath[r.path]=byPath[r.path]||[]).push(r);});var rows=[];Object.keys(byPath).forEach(function(p){var list=byPath[p].slice().sort(function(a,b){return (a.created_at||'').localeCompare(b.created_at||'');});if(list.length<2)return;var scores=list.map(function(x){return x.security_score||0;});var last=list[list.length-1];rows.push('<div class="trendrow"><span class="tname" title="'+esc(p)+'">'+esc(last.project)+' <span class="tn">('+list.length+' scans)</span></span>'+sparkline(scores)+'<span class="scorepill score-'+esc(last.security_grade)+'"><i class="gradedot"></i>'+(last.security_score||0)+' ('+esc(last.security_grade||'-')+')</span></div>');});document.getElementById('trends').innerHTML=rows.join('');document.getElementById('trendsPanel').style.display=rows.length?'':'none';}
function render(recs){var tb=document.getElementById('scans');if(!recs||!recs.length){tb.innerHTML='<tr><td colspan="8" class="empty">No scans yet — run one above.</td></tr>';return;}tb.innerHTML=recs.map(function(r){var when=(r.created_at||'').replace('T',' ').replace(/(\+|Z).*$/,'');var nw=r.new_since>0?'<span class="pill">+'+r.new_since+'</span>':'';return '<tr>'+
  '<td><div class="proj">'+esc(r.project)+'</div><div class="path">'+esc(r.path)+'</div></td>'+
  '<td class="muted">'+esc(when)+'</td>'+
  '<td>'+scoreCell(r.security_score,r.security_grade)+'</td>'+
  '<td>'+scoreCell(r.health_score,r.health_grade)+'</td>'+
  '<td>'+fmtIssues(r)+'</td>'+
  '<td>'+nw+'</td>'+
  '<td class="muted">'+fmtDur(r.duration_ms)+'</td>'+
  '<td><a href="/report/'+encodeURIComponent(r.id)+'" target="_blank">Open ↗</a></td>'+
  '</tr>';}).join('');}
function refresh(){fetch('/api/scans').then(function(x){return x.json();}).then(function(recs){render(recs);renderTrends(recs);}).catch(function(){});}
function scan(){var path=document.getElementById('path').value.trim();var err=document.getElementById('err');err.textContent='';if(!path){err.textContent='Enter a project folder path.';return;}var cats=Array.prototype.slice.call(document.querySelectorAll('.cat:checked')).map(function(c){return c.value;});var minSev=document.getElementById('minSev').value;var btn=document.getElementById('scanBtn'),st=document.getElementById('status');btn.disabled=true;st.textContent='Scanning…';fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,categories:cats,min_severity:minSev})}).then(function(x){return x.json().then(function(j){return {ok:x.ok,j:j};});}).then(function(r){btn.disabled=false;st.textContent='';if(!r.ok){err.textContent=r.j.error||'Scan failed.';return;}refresh();}).catch(function(){btn.disabled=false;st.textContent='';err.textContent='Request failed.';});}
document.getElementById('path').addEventListener('keydown',function(e){if(e.key==='Enter')scan();});
refresh();
</script>
</body>
</html>`
