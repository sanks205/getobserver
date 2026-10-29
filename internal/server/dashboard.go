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
  .pill-deep{display:inline-block;background:color-mix(in srgb,var(--accent) 22%,transparent);color:var(--accent);border-radius:999px;padding:2px 9px;font-size:.78rem;font-weight:700;}
  .pill-ok{display:inline-block;background:color-mix(in srgb,var(--ok) 20%,transparent);color:var(--ok);border-radius:999px;padding:2px 9px;font-size:.78rem;font-weight:700;}
  .scanbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px;}
  .scanbar input[type=text]{flex:1;min-width:200px;margin:0;}
  .scanbar .lbl{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;}
  .scanNav{display:flex;gap:12px;align-items:center;margin-top:14px;flex-wrap:wrap;}
  .pager{display:flex;gap:8px;align-items:center;}
  .pg{background:var(--surface2);color:var(--text);border:1px solid var(--border);border-radius:9px;padding:7px 14px;cursor:pointer;font-family:inherit;font-size:.85rem;}
  .pg:hover:not([disabled]){border-color:var(--accent);color:var(--accent);}
  .pg[disabled]{opacity:.45;cursor:default;}
  .pg-info{color:var(--muted);font-size:.85rem;}
  .empty{color:var(--muted);font-style:italic;}
  .legend{color:var(--muted);font-size:.8rem;margin:10px 2px 0;line-height:1.5;}
  .trendrow{display:flex;align-items:center;gap:16px;padding:9px 0;border-bottom:1px solid var(--border);}
  .trendrow:last-child{border-bottom:none;}
  .trendrow .tname{width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
  .trendrow .tn{color:var(--muted);font-size:.78rem;}
  @media (max-width:640px){ .trendrow .tname{width:120px;} input[type=text]{min-width:160px;} }
  .eng-card{margin-top:16px;border:1px solid var(--border);border-left:3px solid var(--accent);background:var(--surface2);border-radius:12px;padding:15px 17px;}
  .eng-title{font-weight:700;margin-bottom:4px;}
  .eng-sub{color:var(--muted);font-size:.87rem;margin:0 0 10px;}
  .eng-list{margin:0 0 6px;padding-left:18px;}
  .eng-list li{margin:7px 0;font-size:.9rem;}
  .eng-list code{display:inline-block;margin-top:3px;background:var(--bg);color:var(--accent);border:1px solid var(--border);border-radius:7px;padding:3px 8px;font-family:var(--mono);font-size:.82rem;}
  .eng-auto{color:var(--ok);font-size:.8rem;margin-left:6px;}
  .eng-warn{color:var(--med);font-size:.85rem;margin:8px 0 0;}
  .eng-note{color:var(--high);font-size:.85rem;margin:8px 0 0;}
  .eng-remember{display:flex;align-items:center;gap:7px;margin-top:12px;font-size:.86rem;color:var(--muted);cursor:pointer;}
  .eng-actions{display:flex;gap:10px;margin-top:12px;}
  .eng-actions button{background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:9px;padding:9px 16px;cursor:pointer;font-family:inherit;font-size:.9rem;}
  .eng-actions button:hover{border-color:var(--accent);color:var(--accent);}
  .eng-actions #engContinue{background:var(--accent);color:var(--accent-ink);border-color:var(--accent);font-weight:700;}
  /* Workspace layout adapted from MIT-licensed Sentinel dashboard patterns. */
  body{background:var(--bg);font-size:14px;}
  .app-shell{min-height:100vh;display:grid;grid-template-columns:224px minmax(0,1fr);}
  .side-rail{position:sticky;top:0;height:100vh;border-right:1px solid var(--border);background:var(--surface);padding:18px 14px;display:flex;flex-direction:column;gap:22px;z-index:20;}
  .side-brand{display:flex;align-items:center;gap:10px;padding:4px 8px;color:var(--text);font-weight:750;font-size:1rem;}
  .side-brand svg{color:var(--accent);flex:none;}
  .side-brand small{display:block;color:var(--muted);font-size:.68rem;font-weight:500;margin-top:1px;}
  .side-nav{display:grid;gap:4px;}
  .side-label{padding:8px 10px 5px;color:var(--muted);font-size:.68rem;text-transform:uppercase;letter-spacing:0;font-weight:700;}
  .side-nav a{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:6px;color:var(--muted);font-size:.86rem;font-weight:600;text-decoration:none;}
  .side-nav a:hover,.side-nav a:focus-visible{background:var(--surface2);color:var(--text);text-decoration:none;outline:none;}
  .side-nav a.active{background:color-mix(in srgb,var(--accent) 14%,var(--surface));color:var(--accent);}
  .side-foot{margin-top:auto;border-top:1px solid var(--border);padding:14px 9px 2px;color:var(--muted);font-size:.72rem;line-height:1.5;}
  .workspace{min-width:0;}
  .wrap{max-width:1480px;margin:0 auto;padding:0 28px 56px;display:grid;grid-template-columns:minmax(0,1.55fr) minmax(310px,.75fr);gap:16px;}
  .appbar{grid-column:1/-1;position:sticky;top:0;z-index:15;margin:0 -28px;padding:14px 28px;background:color-mix(in srgb,var(--bg) 92%,transparent);backdrop-filter:blur(14px);border-bottom:1px solid var(--border);}
  .brand{font-size:.9rem;color:var(--muted);font-weight:600;}
  .themebtn{width:42px;height:38px;padding:0;border-radius:6px;font-size:.68rem;display:grid;place-items:center;}
  .lead{grid-column:1/-1;margin:10px 0 2px;font-size:.86rem;}
  .panel{margin:0;border-radius:8px;padding:18px;box-shadow:0 1px 2px rgba(0,0,0,.12);}
  #scanPanel{grid-column:1/2;grid-row:3/span 2;}
  #schedPanel,#trendsPanel{grid-column:2/3;}
  #scansPanel{grid-column:1/-1;}
  #proPanel{grid-column:1/-1;}
  .panel h3{font-size:.92rem;margin-bottom:14px;}
  .fld,.opts .lbl,.scanbar .lbl{letter-spacing:0;font-size:.68rem;font-weight:700;}
  input[type=text]{border-radius:6px;background:var(--surface2);padding:10px 12px;}
  button,button.primary,.pg,.themebtn,select{border-radius:6px;}
  button.primary{padding:10px 18px;}
  .opts{gap:7px;margin-top:14px;}
  .chk{border-radius:6px;padding:6px 9px;background:transparent;font-size:.8rem;}
  .chk:hover{background:var(--surface2);border-color:var(--accent);}
  .table-wrap{width:100%;overflow:auto;border:1px solid var(--border);border-radius:7px;}
  table{min-width:980px;}
  th{background:var(--surface2);font-size:.65rem;letter-spacing:0;white-space:nowrap;}
  th,td{padding:10px 11px;}
  tbody tr:last-child td{border-bottom:0;}
  .scorepill{font-family:var(--mono);}
  .trendrow{display:grid;grid-template-columns:minmax(0,1fr) auto;grid-template-areas:"name score" "chart chart";gap:7px 12px;width:100%;min-width:0;}
  .trendrow .tname{grid-area:name;width:auto;min-width:0;}
  .trendrow>.scorepill{grid-area:score;align-self:start;}
  .trendrow svg{grid-area:chart;display:block;width:100%;height:38px;min-width:0;background:var(--surface2);border-radius:6px;}
  .trend-empty{grid-area:chart;display:grid;place-items:center;width:100%;min-height:38px;text-align:center;font-style:italic;}
  .eng-card{border-radius:7px;}
  .fchip,.pill,.pill-ok,.pill-deep,.trig{border-radius:5px;}
  @media(max-width:1040px){
    .app-shell{grid-template-columns:72px minmax(0,1fr);}
    .side-brand span,.side-nav span,.side-label,.side-foot{display:none;}
    .side-brand{justify-content:center;padding:4px 0;}
    .side-nav a{justify-content:center;font-size:0;padding:11px;}
    .side-nav a::before{content:attr(data-short);font-size:.7rem;}
    .wrap{grid-template-columns:1fr;}
    #scanPanel,#schedPanel,#trendsPanel,#scansPanel,#proPanel{grid-column:1;grid-row:auto;}
  }
  @media(max-width:680px){
    html,body{max-width:100%;overflow-x:hidden;}
    .app-shell{display:block;width:100%;min-width:0;}
    .workspace,.wrap,.panel{width:100%;min-width:0;}
    .side-rail{position:static;height:auto;width:100%;max-width:100vw;border-right:0;border-bottom:1px solid var(--border);padding:10px 14px;display:flex;flex-direction:row;align-items:center;overflow-x:auto;overflow-y:hidden;}
    .side-brand{margin-right:8px;}
    .side-brand span{display:block;white-space:nowrap;}
    .side-nav{display:flex;min-width:0;}
    .side-nav a{font-size:.76rem;white-space:nowrap;padding:8px 10px;}
    .side-nav a::before{display:none;}
    .side-nav span{display:inline;}
    .wrap{padding:0 14px 36px;}
    .appbar{margin:0 -14px;padding:10px 14px;}
    .panel{padding:14px;overflow:hidden;}
    .row{align-items:stretch;}
    input[type=text]{min-width:100%;width:100%;}
    .trendrow{grid-template-columns:minmax(0,1fr) auto;gap:7px 10px;}
  }
</style>
<script>
  (function(){try{var t=localStorage.getItem("observer-theme");if(t)document.documentElement.setAttribute("data-theme",t);}catch(e){}})();
  function toggleTheme(){var d=document.documentElement;var t=d.getAttribute("data-theme")==="light"?"dark":"light";d.setAttribute("data-theme",t);try{localStorage.setItem("observer-theme",t);}catch(e){}}
</script>
</head>
<body>
<div class="app-shell">
<aside class="side-rail" aria-label="Workspace navigation">
  <div class="side-brand"><svg width="24" height="24" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="12" cy="12" r="3.5" fill="currentColor"/></svg><span>Observer<small>Community workspace</small></span></div>
  <nav class="side-nav">
    <div class="side-label">Workspace</div>
    <a class="active" href="#scanPanel" data-short="Scan"><span>New audit</span></a>
    <a href="#trendsPanel" data-short="Trend"><span>Score trends</span></a>
    <a href="#scansPanel" data-short="Runs"><span>Audit history</span></a>

  </nav>
  <div class="side-foot">Local-first code assurance<br>Source stays on this machine</div>
</aside>
<main class="workspace">
<div class="wrap">
  <div class="appbar">
    <div class="brand"><svg width="22" height="22" viewBox="0 0 20 20" aria-hidden="true"><circle cx="10" cy="10" r="8" fill="none" stroke="currentColor" stroke-width="1.5" opacity=".45"/><circle cx="10" cy="10" r="3.3" fill="currentColor"/></svg> Observer</div>
    <button class="themebtn" onclick="toggleTheme()" title="Toggle light / dark">◐ Theme</button>
  </div>
  <div class="lead">Scan a project folder and track its security &amp; code-health over time. Past scans are kept below.</div>

  <div class="panel" id="scanPanel">
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
    <div id="enginePrompt" style="display:none"></div>
  </div>

  <div class="panel" id="trendsPanel" style="display:none">
    <h3>Security score trend</h3>
    <div id="trends"></div>
  </div>

  <div class="panel" id="scansPanel">
    <h3>Scans</h3>
    <div class="scanbar">
      <input id="scanSearch" type="text" placeholder="Search by project name or path…" oninput="onScanSearch()">
      <span class="lbl">Per page</span>
      <select id="scanSize" onchange="onScanSize()">
        <option>10</option><option>25</option><option>50</option><option>100</option>
      </select>
    </div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Project</th><th>When</th><th>Security</th><th>Health</th><th>Issues</th><th>Engines</th><th>Change</th><th>Time</th><th>Report</th></tr></thead>
      <tbody id="scans"><tr><td colspan="9" class="empty">Loading…</td></tr></tbody>
    </table>
    </div>
    <div class="legend"><b>Built-in</b> = Observer's native rules only. <b>Engines</b> = local tools you installed (Semgrep, PHPStan, Bandit, gosec, ESLint) ran too — they surface more, type-aware findings, so issue counts can rise.</div>
    <div id="scanNav" class="scanNav"></div>
  </div>
</div>
</main>
</div>

<script>
function esc(s){return (s||'').replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];});}
function fmtDur(ms){if(!ms&&ms!==0)return '';return ms>=1000?(ms/1000).toFixed(2)+'s':ms+'ms';}
function fmtIssues(r){var p=[];if(r.critical)p.push('<span class="sev c">'+r.critical+' crit</span>');if(r.high)p.push('<span class="sev h">'+r.high+' high</span>');if(r.medium)p.push('<span class="sev m">'+r.medium+' med</span>');if(r.low)p.push('<span class="sev l">'+r.low+' low</span>');return (r.total||0)+(p.length?' <span class="muted">('+p.join(', ')+')</span>':'');}
function scoreCell(v,g){return '<span class="scorepill score-'+esc(g)+'"><i class="gradedot"></i>'+(v||0)+'</span> <span class="muted">('+esc(g||'-')+')</span>';}
function sparkline(vals){var W=170,H=34;var pts=vals.map(function(v,i){var x=(vals.length<2?0:(i/(vals.length-1))*W);var y=H-(Math.max(0,Math.min(100,v))/100)*H;return x.toFixed(1)+','+y.toFixed(1);}).join(' ');var last=vals[vals.length-1];var color=last>=80?'#2ea043':last>=60?'#d99700':'#e5484d';var area=pts+' '+W+','+H+' 0,'+H;return '<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none" role="img" aria-label="Security score history"><polygon points="'+area+'" fill="'+color+'" opacity=".13"/><polyline points="'+pts+'" fill="none" stroke="'+color+'" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>';}
function renderTrends(recs){var byPath={};recs.forEach(function(r){(byPath[r.path]=byPath[r.path]||[]).push(r);});var rows=[];Object.keys(byPath).forEach(function(p){var list=byPath[p].slice().sort(function(a,b){return (a.created_at||'').localeCompare(b.created_at||'');});if(list.length<2)return;var scores=list.map(function(x){return x.security_score||0;});var last=list[list.length-1];rows.push('<div class="trendrow"><span class="tname" title="'+esc(p)+'">'+esc(last.project)+' <span class="tn">('+list.length+' scans)</span></span>'+sparkline(scores)+'<span class="scorepill score-'+esc(last.security_grade)+'"><i class="gradedot"></i>'+(last.security_score||0)+' ('+esc(last.security_grade||'-')+')</span></div>');});document.getElementById('trends').innerHTML=rows.join('');document.getElementById('trendsPanel').style.display=rows.length?'':'none';}
function render(recs){var tb=document.getElementById('scans');if(!recs||!recs.length){tb.innerHTML='<tr><td colspan="9" class="empty">No scans yet — run one above.</td></tr>';return;}tb.innerHTML=recs.map(function(r){var when=(r.created_at||'').replace('T',' ').replace(/(\+|Z).*$/,'');var nw=r.new_since>0?'<span class="pill">+'+r.new_since+'</span>':r.new_since<0?'<span class="pill-ok">'+r.new_since+'</span>':'<span class="pill" style="opacity:.55">0</span>';return '<tr>'+
  '<td><div class="proj">'+esc(r.project)+'</div><div class="path">'+esc(r.path)+'</div></td>'+
  '<td class="muted">'+esc(when)+'</td>'+
  '<td>'+scoreCell(r.security_score,r.security_grade)+'</td>'+
  '<td>'+scoreCell(r.health_score,r.health_grade)+'</td>'+
  '<td>'+fmtIssues(r)+'</td>'+
  '<td>'+(r.engines&&r.engines.length?r.engines.map(function(e){return '<span class="pill-deep">'+esc(e)+'</span>';}).join(' '):(r.engine_mode==='deep'?'<span class="pill-deep">Deep</span>':'<span class="muted">Built-in</span>'))+'</td>'+
  '<td>'+nw+'</td>'+
  '<td class="muted">'+fmtDur(r.duration_ms)+'</td>'+
  '<td><a href="/report/'+encodeURIComponent(r.id)+'" target="_blank">Open ↗</a></td>'+
  '</tr>';}).join('');}
var ALL_RECS=[];var SCAN_PAGE=1;var SCAN_SIZE=10;var SCAN_Q='';
function applyAndRender(){
  var q=SCAN_Q.trim().toLowerCase();
  var filtered=ALL_RECS.filter(function(r){if(!q)return true;return (r.project||'').toLowerCase().indexOf(q)>=0||(r.path||'').toLowerCase().indexOf(q)>=0;});
  var total=filtered.length;
  var pages=Math.max(1,Math.ceil(total/SCAN_SIZE));
  if(SCAN_PAGE>pages)SCAN_PAGE=pages;
  if(SCAN_PAGE<1)SCAN_PAGE=1;
  var start=(SCAN_PAGE-1)*SCAN_SIZE;
  render(filtered.slice(start,start+SCAN_SIZE));
  var nav=document.getElementById('scanNav');
  if(!nav)return;
  if(total<=SCAN_SIZE){nav.innerHTML='';return;}
  nav.innerHTML='<div class="pager">'+'<button class="pg" '+(SCAN_PAGE<=1?'disabled':'')+' onclick="scanGo('+(SCAN_PAGE-1)+')">‹ Prev</button>'+'<span class="pg-info">Page '+SCAN_PAGE+' / '+pages+'</span>'+'<button class="pg" '+(SCAN_PAGE>=pages?'disabled':'')+' onclick="scanGo('+(SCAN_PAGE+1)+')">Next ›</button>'+'</div>';
}
function scanGo(p){SCAN_PAGE=p;applyAndRender();}
function onScanSearch(){SCAN_Q=document.getElementById('scanSearch').value||'';SCAN_PAGE=1;applyAndRender();}
function onScanSize(){SCAN_SIZE=parseInt(document.getElementById('scanSize').value,10)||10;SCAN_PAGE=1;applyAndRender();}
function refresh(){fetch('/api/scans').then(function(x){return x.json();}).then(function(recs){ALL_RECS=(recs||[]).slice().sort(function(a,b){return (b.created_at||'').localeCompare(a.created_at||'');});SCAN_PAGE=1;applyAndRender();renderTrends(ALL_RECS);}).catch(function(){});}
function rememberedChoice(path){try{return localStorage.getItem('observer-choice:'+path);}catch(e){return null;}}
function rememberChoice(path){try{localStorage.setItem('observer-choice:'+path,'continue');}catch(e){}}
function escapeHtml(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

function scan(){
  var path=document.getElementById('path').value.trim();
  var err=document.getElementById('err'); err.textContent='';
  if(!path){err.textContent='Enter a project folder path.';return;}
  var cats=Array.prototype.slice.call(document.querySelectorAll('.cat:checked')).map(function(c){return c.value;});
  var minSev=document.getElementById('minSev').value;
  var btn=document.getElementById('scanBtn'),st=document.getElementById('status');

  // User previously chose to skip the prompt for this folder -> scan directly.
  if(rememberedChoice(path)==='continue'){ doScan(path,cats,minSev,btn,st); return; }

  // Pre-scan: recommend engines (no full scan yet).
  btn.disabled=true; st.textContent='Checking project…';
  fetch('/api/prepare-scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path})})
    .then(function(x){return x.json().then(function(j){return {ok:x.ok,j:j};});})
    .then(function(r){
      btn.disabled=false; st.textContent='';
      if(r.ok && r.j.missing && r.j.missing.length){ showEnginePrompt(path,cats,minSev,r.j,false,btn,st); return; }
      doScan(path,cats,minSev,btn,st);
    })
    .catch(function(){ btn.disabled=false; st.textContent=''; doScan(path,cats,minSev,btn,st); });
}

function showEnginePrompt(path,cats,minSev,pj,rechecked,btn,st){
  var box=document.getElementById('enginePrompt');
  var stack=(pj.stack||[]).join(', ');
  var html='<div class="eng-card">';
  html+='<div class="eng-title">Recommended for accurate analysis of this '+(stack||'project')+' project</div>';
  html+='<div class="eng-sub">Install any to cut false positives. They run as local processes. Semgrep registry configs may download rules; use --assert-offline with a local SEMGREP_CONFIG for air-gapped scans. You can scan now with the built-in engine only, or install first for deeper results.</div>';
  html+='<ul class="eng-list">';
  (pj.missing||[]).forEach(function(e){
    html+='<li><b>'+escapeHtml(e.name)+'</b> — '+escapeHtml(e.reason);
    html+='<br><code>'+escapeHtml(e.command)+'</code>';
    if(e.auto_config){ html+=' <span class="eng-auto">(Observer creates its config)</span>'; }
    html+='</li>';
  });
  html+='</ul>';
  if(pj.large){ html+='<div class="eng-warn">Deep scan on large projects may take a few minutes.</div>'; }
  if(rechecked){ html+='<div class="eng-note">Still not found — make sure the engine is on your PATH, then press Re-scan.</div>'; }
  html+='<label class="eng-remember"><input type="checkbox" id="engRemember"> Remember my choice for this folder</label>';
  html+='<div class="eng-actions"><button id="engContinue">Continue (built-in scan)</button><button id="engRescan">Re-scan after install</button></div>';
  html+='</div>';
  box.innerHTML=html; box.style.display='block';

  document.getElementById('engContinue').onclick=function(){
    box.style.display='none';
    if(document.getElementById('engRemember').checked){ rememberChoice(path); }
    doScan(path,cats,minSev,btn,st);
  };
  document.getElementById('engRescan').onclick=function(){
    st.textContent='Re-checking…';
    fetch('/api/prepare-scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path})})
      .then(function(x){return x.json().then(function(j){return {ok:x.ok,j:j};});})
      .then(function(r){
        if(r.ok && r.j.missing && r.j.missing.length===0){ box.style.display='none'; doScan(path,cats,minSev,btn,st); }
        else { st.textContent=''; showEnginePrompt(path,cats,minSev,(r.ok?r.j:pj),true,btn,st); }
      })
      .catch(function(){ st.textContent=''; showEnginePrompt(path,cats,minSev,pj,true,btn,st); });
  };
}

function doScan(path,cats,minSev,btn,st){
  if(!st){ st=document.getElementById('status'); }
  if(!btn){ btn=document.getElementById('scanBtn'); }
  var err=document.getElementById('err');
  btn.disabled=true; st.textContent='Scanning…';
  fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:path,categories:cats,min_severity:minSev})})
    .then(function(x){return x.json().then(function(j){return {ok:x.ok,j:j};});})
    .then(function(r){ btn.disabled=false; st.textContent=''; if(!r.ok){err.textContent=r.j.error||'Scan failed.';return;} refresh(); })
    .catch(function(){ btn.disabled=false; st.textContent=''; err.textContent='Request failed.'; });
}
document.getElementById('path').addEventListener('keydown',function(e){if(e.key==='Enter')scan();});
refresh();
</script>
</body>
</html>`
