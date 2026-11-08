/* Sentinel views: shell, dashboard panels, investigation workspace and decision ledger.
   Reuses app.js state, render/bind cycle, ids and data attributes; data comes from window.Live (api.js). */
(function(){
  const L=window.Live;
  const E=v=>esc(v==null?'':v);
  const P='<svg viewBox="0 0 24 24" aria-hidden="true" class="ic">';
  const I={
    shield:P+'<path d="M12 2.5l7.5 2.8v5.9c0 4.8-3.2 8.9-7.5 10.3-4.3-1.4-7.5-5.5-7.5-10.3V5.3z"/><path d="M8.6 12.1l2.4 2.4 4.6-4.9"/></svg>',
    chart:P+'<path d="M4 20V11M10 20V5M16 20v-7M21 20H3"/></svg>',
    history:P+'<path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1L3.5 8.4"/><path d="M3.5 3.8v4.6h4.6M12 7.5V12l3 2"/></svg>',
    spark:P+'<path d="M11 3l1.6 4.4L17 9l-4.4 1.6L11 15l-1.6-4.4L5 9l4.4-1.6zM18 14l.8 2.2L21 17l-2.2.8L18 20l-.8-2.2L15 17l2.2-.8z"/></svg>',
    search:P+'<circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.3-4.3"/></svg>',
    bell:P+'<path d="M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 1.5h-15zM10 20.5a2 2 0 0 0 4 0"/></svg>',
    cal:P+'<rect x="3.5" y="5" width="17" height="15.5" rx="2"/><path d="M3.5 9.5h17M8 3v4M16 3v4"/></svg>',
    down:P+'<path d="M6 9l6 6 6-6"/></svg>', right:P+'<path d="M9 6l6 6-6 6"/></svg>',
    refresh:P+'<path d="M20 12a8 8 0 1 1-2.3-5.7L20 8.5"/><path d="M20 3.5v5h-5"/></svg>',
    check:P+'<path d="M5 12.5l4.5 4.5L19 7.5"/></svg>', trend:P+'<path d="M3 17l6-6 4 4 8-8"/><path d="M15 7h6v6"/></svg>',
    cog:P+'<circle cx="12" cy="12" r="3.2"/><path d="M12 2.8v2.6M12 18.6v2.6M4.2 7.5l2.2 1.3M17.6 15.2l2.2 1.3M4.2 16.5l2.2-1.3M17.6 8.8l2.2-1.3"/><circle cx="12" cy="12" r="7"/></svg>',
    expand:P+'<path d="M4 9V4h5M15 4h5v5M4 15v5h5M20 15v5h-5"/></svg>',
    play:P+'<path d="M8 5.5v13l10.5-6.5z"/></svg>',
    collapse:P+'<rect x="3.5" y="4" width="17" height="16" rx="2.5"/><path d="M9 4v16M15.5 9.5L13 12l2.5 2.5"/></svg>',
    expandSb:P+'<rect x="3.5" y="4" width="17" height="16" rx="2.5"/><path d="M9 4v16M12.5 9.5L15 12l-2.5 2.5"/></svg>'
  };
  window.SentinelIcons=I;
  const PRIORITY={Critical:'Immediate action',High:'Urgent',Medium:'Normal',Low:'Non-urgent'};
  const SEVCLR={critical:'#e5484d',high:'#f08c2e',medium:'#e9b73b',low:'#2f9e5b',informational:'#7c93a8'};
  const num=n=>Number(n||0).toLocaleString('en-GB');
  /* SLA (politica_soc.md section 3): deadline computed by the backend, countdown computed here every second. */
  const dur=ms=>{const m=Math.round(Math.abs(ms)/60000);return m<60?`${m}m`:m<1440?`${Math.floor(m/60)}h ${m%60}m`:`${Math.floor(m/1440)}d ${Math.floor(m%1440/60)}h`};
  function slaState(sla){
    if(!sla||!sla.due_at)return null;
    const due=new Date(sla.due_at).getTime(),total=(sla.minutes||1)*60000;
    if(sla.closed_at){const ok=new Date(sla.closed_at).getTime()<=due;return {cls:ok?'s-met':'s-breached',text:ok?'SLA met':`SLA missed by ${dur(new Date(sla.closed_at)-due)}`}}
    const left=due-Date.now();
    if(left<0)return {cls:'s-breached',text:`SLA breached · ${dur(left)} over`};
    return {cls:left<total*0.25?'s-warn':'s-open',text:`SLA ${dur(left)} left`};
  }
  const slaChip=sla=>{const s=slaState(sla);return s?`<span class="sla ${s.cls}" data-sla='${E(JSON.stringify({due_at:sla.due_at,closed_at:sla.closed_at,minutes:sla.minutes}))}' title="Time to triage: ${E(sla.label)} · due ${E(L.fmt(sla.due_at))}">${s.text}</span>`:''};
  window.SentinelSla={slaState,slaChip};
  const pct=(a,b)=>b?Math.round(100*a/b):0;
  const greeting=()=>{const h=new Date().getHours();return h<12?'Good morning':h<20?'Good afternoon':'Good evening'};
  const clock=()=>{const d=new Date();const date=d.toLocaleDateString('en-US',{timeZone:'Europe/Madrid',month:'short',day:'numeric',year:'numeric'});const time=d.toLocaleTimeString('en-GB',{timeZone:'Europe/Madrid',hour12:false});return `${date} · ${time} (${d.toLocaleTimeString('en-GB',{timeZone:'Europe/Madrid',timeZoneName:'short'}).split(' ').pop()})`};
  const ago=()=>L.loadedAt?`Updated ${Math.max(0,Math.round((Date.now()-L.loadedAt)/1000))} seconds ago`:(L.error?'Backend offline':'Connecting…');
  const head=(icon,tone,title,sub,extra,key)=>`<div class="panel-head"><div class="panel-title"><span class="p-ic ${tone}">${icon}</span><div><h3>${title}</h3>${sub?`<p>${sub}</p>`:''}</div>${extra||''}</div><button class="expand" data-expand="${key}" aria-label="Expand panel">${I.expand}</button></div>`;
  const offline=msg=>`<div class="empty"><b>${msg}</b><br/>Start the backend: <span class="mono">python -m src.llm_triage serve --mock</span>${L.error?`<br/><small>${E(L.error)}</small>`:''}</div>`;

  /* ----------------------------------------------------------------------------------------- shell */
  icon=x=>`<span class="nav-icon">${x}</span>`;
  /* Collapsible sidebar: remembered per browser (storage can be unavailable: fall back to memory). */
  try{state.sidebarCollapsed=localStorage.getItem('sentinel.sidebar')==='collapsed'}catch(e){state.sidebarCollapsed=false}
  function toggleSidebar(){
    state.sidebarCollapsed=!state.sidebarCollapsed;
    try{localStorage.setItem('sentinel.sidebar',state.sidebarCollapsed?'collapsed':'open')}catch(e){}
    const app=document.querySelector('.sx.app');if(app)app.classList.toggle('collapsed',state.sidebarCollapsed);
    const b=document.querySelector('[data-sidebar-toggle]');if(b){b.innerHTML=state.sidebarCollapsed?I.expandSb:I.collapse;b.setAttribute('aria-label',state.sidebarCollapsed?'Expand sidebar':'Collapse sidebar');b.setAttribute('aria-expanded',String(!state.sidebarCollapsed))}
  }
  shell=function(content){
    const page=state.page,s=L.stats||{};
    const nav=[['ops',I.chart,'Operations center'],['history',I.history,'Decision history'],['assistant',I.spark,'AI Intelligence Assistant']];
    const titles={ops:['OPERATIONS','Alert operations center'],history:['AUDIT LEDGER','Decision history'],assistant:['INTELLIGENCE ASSISTANT','AI Intelligence Assistant']}[page];
    const status=L.on?['ok','All systems operational']:L.error?['down','Backend offline']:['wait','Connecting…'];
    return `<div class="app sx ${state.sidebarCollapsed?'collapsed':''}"><aside class="sidebar"><div class="brand"><span class="mark">${I.shield}</span><span class="brand-name">sentinel</span><button class="sb-toggle" data-sidebar-toggle aria-label="${state.sidebarCollapsed?'Expand':'Collapse'} sidebar" aria-expanded="${!state.sidebarCollapsed}">${state.sidebarCollapsed?I.expandSb:I.collapse}</button></div>
      <div class="nav-label">Workspace</div><nav class="nav">${nav.map(([k,ic,l])=>`<button class="${page===k?'active':''}" data-page="${k}" aria-current="${page===k?'page':'false'}" title="${l}">${icon(ic)}<span class="nav-text">${l}</span></button>`).join('')}</nav>
      <div class="side-bottom"><div class="engine" title="Processing engine ${L.on?'operational':'unavailable'}"><span class="status-dot ${L.on?'':'off'}"></span><span class="engine-text">Processing engine<br/><b>${L.on?'Operational':'Unavailable'}</b></span></div>
      <div class="profile" title="Paco Gonzalez · Senior analyst"><span class="avatar">PG</span><span class="profile-text"><b>Paco Gonzalez</b><small>Senior analyst</small></span></div></div></aside>
      <main class="main"><header class="topbar"><div class="tb-title"><div class="eyebrow">TARVIA SOC / ${titles[0]}</div><h1>${titles[1]}</h1></div>
      <div class="top-actions"><span class="env pill-btn"><span class="status-dot"></span>${L.on?`${E((L.mode||'').toUpperCase())}: Database mirror`:'DEMO: Offline data'} ${I.down}</span>
      <span class="sys ${status[0]}"><span class="status-dot ${status[0]==='ok'?'':'off'}"></span>${status[1]}</span><span class="tb-sep"></span>
      <button class="notify" data-page="ops" aria-label="${num(s.awaiting_decision)} alerts awaiting approval">${I.bell}${s.awaiting_decision?`<i class="badge">${s.awaiting_decision>99?'99+':s.awaiting_decision}</i>`:''}</button><span class="tb-sep"></span>
      <span class="clock">${I.cal}<span id="sentinel-clock">${clock()}</span></span></div></header>${content}</main></div>`;
  };

  ops=function(){
    return `<div class="workspace"><section class="hello"><span class="hello-ic">${I.check}</span><div><h2>${greeting()}, Paco</h2><p>Here’s the current state of your alert ecosystem.</p></div>
      <div class="refresh"><span class="status-dot ${L.on?'':'off'}"></span><span id="sentinel-updated">${ago()}</span><button class="icon-btn" data-refresh aria-label="Refresh">${I.refresh}</button></div></section>
      <div class="grid">${approval()}${analytics()}${monitor()}</div></div>`;
  };

  /* ----------------------------------------------------------------------------------------- approval queue */
  ticket=function(a){
    const sev=a.priority.toLowerCase();
    return `<article class="ticket sev-${sev}" data-alert="${E(a.id)}" tabindex="0"><div class="ticket-top"><span class="prio ${sev}"><i></i>${PRIORITY[a.priority]}</span><span class="ticket-ids">${slaChip(a.sla)}<span class="mono">${E(a.id)}</span></span></div>
      <h4>${E(a.title)}</h4><div class="question"><span>${E(a.question)}</span>${I.right}</div>
      <div class="ticket-meta"><span>${E(a.category)}</span><span>${E(a.source)}</span><span>${E(a.verdict||'')}</span><span>${a.escalate?`Escalation → ${E((a.automation||{}).escalation_to||((a.ticket.ticket||{}).escalation||{}).to||'N2')}`:a.approvalNeeded?'Approval required':'Pending review'}</span></div>
      <div class="ticket-bottom"><span class="risk"><b class="r-${sev}">Risk ${a.risk}/100</b> · ${E(a.trigger)}</span><span class="conf" title="Model confidence">${a.confidence}%</span></div></article>`;
  };
  getApprovalList=function(){
    const rank={Critical:0,High:1,Medium:2,Low:3},q=(state.filter||'').toLowerCase();
    const due=a=>a.sla&&a.sla.due_at?new Date(a.sla.due_at).getTime():Infinity;
    return state.alerts.filter(a=>a.status==='Pending'&&(!q||`${a.id} ${a.title} ${a.category} ${a.source}`.toLowerCase().includes(q))&&(state.severity==='All'||a.severity===state.severity))
      .sort((a,b)=>(rank[a.priority]-rank[b.priority])||(due(a)-due(b))||(b.waitMinutes-a.waitMinutes));
  };
  approval=function(){
    const list=getApprovalList(),pages=Math.max(1,Math.ceil(list.length/QUEUE_PAGE_SIZE));
    state.queuePage=Math.min(state.queuePage,pages);
    const start=(state.queuePage-1)*QUEUE_PAGE_SIZE,visible=list.slice(start,start+QUEUE_PAGE_SIZE);
    const win=[...new Set([1,state.queuePage-1,state.queuePage,state.queuePage+1,pages])].filter(p=>p>=1&&p<=pages).sort((a,b)=>a-b);
    const body=!L.on&&L.error?offline('Live queue unavailable · showing demo data'):'';
    return `<section class="panel queue">${head(I.shield,'green','Operator approval queue','',`<span class="count">${num(list.length)} pending</span>`,'approval')}
      <div class="panel-tools"><label class="search">${I.search}<input id="queue-search" placeholder="Search alerts..." value="${E(state.filter)}"/></label>
      <label class="select"><select id="queue-severity"><option>All priorities</option>${['Critical','High','Medium','Low'].map(x=>`<option value="${x}" ${state.severity===x?'selected':''}>${PRIORITY[x]} · ${x}</option>`).join('')}</select>${I.down}</label>
      ${(()=>{const n=list.filter(a=>(slaState(a.sla)||{}).cls==='s-breached').length;return n?`<div class="sla-alert"><span class="sla s-breached">${num(n)} SLA breached</span><small>Deadlines from politica_soc.md §3, oldest due first within each priority</small></div>`:''})()}
      <div class="priority-note">${['Critical','High','Medium','Low'].map(x=>`<span class="prio-chip ${x.toLowerCase()}"><i></i>${PRIORITY[x]}</span>`).join('')}</div></div>
      <div class="panel-body">${body}${visible.length?visible.map(ticket).join(''):`<div class="empty">${L.on&&!state.filter&&state.severity==='All'?'The queue is clear: no ticket awaits approval.<br/>Run a triage batch from the Processing monitor.':'No alerts match these filters.'}</div>`}</div>
      <footer class="queue-footer"><span>Showing ${list.length?start+1:0}–${start+visible.length} of ${num(list.length)}</span><span class="queue-pagination"><button data-queue-page="${state.queuePage-1}" ${state.queuePage===1?'disabled':''}>Previous</button>${win.map((p,i)=>`${i&&p-win[i-1]>1?'<span class="gap">…</span>':''}<button data-queue-page="${p}" class="${state.queuePage===p?'current':''}">${p}</button>`).join('')}<button data-queue-page="${state.queuePage+1}" ${state.queuePage===pages?'disabled':''}>Next</button></span></footer></section>`;
  };

  /* ----------------------------------------------------------------------------------------- analytics */
  function lineChart(received,triaged){
    const days=Object.keys(received).sort(),W=300,H=110,max=Math.max(1,...days.map(d=>received[d]||0));
    if(days.length<2)return '<div class="empty small">Not enough data for a trend yet.</div>';
    const x=i=>(i*W/(days.length-1)).toFixed(1),y=v=>(H-6-(H-14)*(v||0)/max).toFixed(1);
    const line=src=>days.map((d,i)=>`${x(i)},${y(src[d])}`).join(' ');
    const area=`0,${H} ${line(triaged)} ${W},${H}`;
    const grid=[0.25,0.5,0.75].map(f=>`<line x1="0" x2="${W}" y1="${(H*f).toFixed(1)}" y2="${(H*f).toFixed(1)}"/>`).join('');
    return `<svg class="lc" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Alerts received and triaged per day"><defs><linearGradient id="lcg" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#2b7de9" stop-opacity=".22"/><stop offset="1" stop-color="#2b7de9" stop-opacity="0"/></linearGradient></defs><g class="lc-grid">${grid}</g><polygon points="${area}" fill="url(#lcg)"/><polyline points="${line(received)}" class="lc-a"/><polyline points="${line(triaged)}" class="lc-b"/></svg><div class="lc-axis"><span>${days[0].slice(5)}</span><span>${days[days.length-1].slice(5)}</span></div>`;
  }
  function donut(counts){
    const keys=['critical','high','medium','low','informational'],tot=keys.reduce((s,k)=>s+(counts[k]||0),0);
    if(!tot)return '<div class="empty small">No tickets yet.</div>';
    let acc=0;const stops=keys.filter(k=>counts[k]).map(k=>{const a=acc;acc+=360*counts[k]/tot;return `${SEVCLR[k]} ${a.toFixed(1)}deg ${acc.toFixed(1)}deg`}).join(',');
    return `<div class="donut-wrap"><div class="donut" style="background:conic-gradient(${stops})"><span><b>${num(tot)}</b><small>tickets</small></span></div><div class="donut-legend">${keys.filter(k=>counts[k]).map(k=>`<span><i style="background:${SEVCLR[k]}"></i><b style="color:${SEVCLR[k]}">${pct(counts[k],tot)}%</b> ${k[0].toUpperCase()+k.slice(1)} <small>${num(counts[k])}</small></span>`).join('')}</div></div>`;
  }
  analytics=function(){
    if(!L.on)return `<section class="panel">${head(I.trend,'blue','Real-time analytics','Triage pipeline','','analytics')}<div class="panel-body">${offline('Analytics unavailable')}</div></section>`;
    const s=L.stats,tactics=Object.entries(s.alerts_by_tactic||{}),tmax=Math.max(1,...tactics.map(t=>t[1]));
    const kpi=(l,v,d,tone)=>`<div class="kpi ${tone||''}"><span class="kpi-label">${l}</span><span class="kpi-val">${v}</span>${d!=null?`<span class="delta">${d}</span>`:''}</div>`;
    return `<section class="panel">${head(I.trend,'blue','Real-time analytics',`Operational data · ${num(s.alerts_total)} alerts in scope`,'','analytics')}<div class="panel-body">
      <div class="kpis">${kpi('Alerts received',num(s.alerts_total))}${kpi('Triaged',num(s.alerts_triaged),`${pct(s.alerts_triaged,s.alerts_total)}%`)}${kpi('Awaiting approval',num(s.awaiting_decision),null,'warn')}${kpi('Auto-resolved',num(s.auto_resolved),`${pct(s.auto_resolved,s.alerts_triaged)}% of triaged`,'good')}
      ${kpi('SLA breached',num((s.sla||{}).breached_open),`${num((s.sla||{}).open)} open · ${num((s.sla||{}).met)} met`,(s.sla||{}).breached_open?'bad':'good')}${kpi('Auto containment',num(Object.entries((s.automation||{}).actions||{}).filter(([k])=>k==='auto:ok').reduce((t,[,n])=>t+n,0)),`${num((s.automation||{}).notifications)} notifications`)}
      ${state.expanded==='analytics'?`${kpi('Escalated',num(s.escalated),null,'bad')}${kpi('Needs more info',num((s.by_verdict||{}).needs_more_info))}${kpi('Avg. LLM triage',`${s.avg_triage_seconds||0}s`)}${kpi('Pending triage',num(s.alerts_pending_triage))}`:''}</div>
      <div class="chart-card"><div class="chart-title">Alert volume <span>Daily · UTC</span></div>${lineChart(s.alerts_by_day||{},s.triaged_by_day||{})}<div class="legend"><span><i class="g"></i>Received</span><span><i class="b"></i>Triaged</span></div></div>
      <div class="chart-card"><div class="chart-title">Alert distribution <span>By final ticket severity</span></div>${donut(s.by_severity||{})}</div>
      <div class="chart-card"><div class="chart-title">Alerts by tactic <span>MITRE ATT&amp;CK</span></div><div class="bars">${tactics.map(([x,n])=>`<div class="bar-row"><span>${E(x)}</span><div class="bar-track"><div class="bar-fill" style="width:${(100*n/tmax).toFixed(1)}%"></div></div><b>${num(n)}</b></div>`).join('')}</div></div></div></section>`;
  };

  /* ----------------------------------------------------------------------------------------- monitor */
  monitor=function(){
    if(!L.on)return `<section class="panel">${head(I.cog,'green','Processing monitor','Automated pipeline monitoring','','monitor')}<div class="panel-body">${offline('Pipeline monitor unavailable')}</div></section>`;
    const s=L.stats,sel=s.selection||{},b=L.batch,running=b&&b.status==='running',route=s.by_route||{},lv=s.live||{},liveOn=!!lv.enabled;
    const decided=Object.entries(s.by_decision||{}).filter(([k])=>k!=='pending').reduce((t,[,n])=>t+n,0);
    const stages=[['Ingested',s.alerts_total,'Alerts stored from the SOC API'],['Enriched',s.embeddings,'Views, context and embeddings'],['Filtered',(sel.kept||0)+(sel.N4||0),'Logs kept or explained (N0–N4)'],['Rules',route.discriminator||0,'Auto-closed by the discriminator'],['AI LLM',route.llm||0,'Tickets produced by the LLM'],['Valid',(s.alerts_triaged||0)-(s.invalid_tickets||0),'Schema + policy valid tickets'],['Decided',decided,'Operator decisions']];
    const activeIdx=running||(liveOn&&!lv.queue_exhausted&&!lv.last_error)?(liveOn&&!running?0:4):-1;
    const status=running?`Triaging batch · ${b.done||0}/${b.total||0} alerts (discriminator → LLM → validation)`
      :liveOn?(lv.last_error?`Live sync error · ${lv.last_error}`:lv.queue_exhausted?`Live · SOC API queue drained · ${num(lv.ingested)} alerts ingested`:`Live · ${num(lv.ingested)} alerts ingested from the SOC API · ${lv.batch} every ${lv.interval}s`)
      :s.alerts_pending_triage?`Idle · ${num(s.alerts_pending_triage)} alerts pending triage`:'All alerts triaged';
    const tag=h=>h.type==='Rule Engine'?['Discriminator','t-green']:h.ticket&&h.ticket.route==='llm'?['Operator · LLM ticket','t-blue']:['Operator','t-blue'];
    return `<section class="panel">${head(I.cog,'green','Processing monitor','Automated pipeline monitoring',`<span class="live ${liveOn?(lv.last_error?'err':''):'idle'}" title="${E(lv.last_error||'')}"><span class="status-dot ${liveOn&&!lv.last_error?'':'off'}"></span>${liveOn?(lv.last_error?'Sync error':'Live sync'):'On demand'}</span>`,'monitor')}<div class="panel-body">
      <ol class="stepper">${stages.map(([l,n],i)=>`<li class="${i===activeIdx?'active':n>0?'done':''}" title="${stages[i][2]}: ${num(n)}"><span class="dot">${n>0&&i!==activeIdx?I.check:''}</span><b>${l}</b><small>${num(n)}</small></li>`).join('')}</ol>
      <div class="current"><b>Current status:</b> ${E(status)}${running?`<div class="progress"><span style="width:${b.total?100*(b.done||0)/b.total:0}%"></span></div>`:''}</div>
      <div class="batch"><button class="action primary" data-batch="20" ${running?'disabled':''}>${I.play}Triage next 20</button><button class="action outline" data-batch="100" ${running?'disabled':''}>Next 100</button><span class="mono">${num(s.alerts_pending_triage)} pending · mode ${E(L.mode)}</span></div>
      <div class="log-head"><h4>Automated action log</h4><span class="mono">Newest first</span></div>
      <ul class="timeline">${(liveOn&&(lv.recent||[]).length?lv.recent.slice(0,8).map(r=>`<li><span class="t-time">${E(L.fmt(r.at).split('·').pop().trim())}</span><div><b>${E(r.alert_id)}</b> · ingested → ${E(L.VERDICT[r.verdict]||r.verdict||'—')} · ${E(r.severity||'')}<br/><span class="tag ${r.route==='discriminator'?'t-green':'t-blue'}">${r.route==='discriminator'?'Discriminator':'AI LLM'}</span> <span class="tag t-grey">SOC API</span></div></li>`)
        :[...((s.automation||{}).recent||[]).slice(0,4).map(r=>`<li><span class="t-time">${E(L.fmt(r.at).split('·').pop().trim())}</span><div><b>${E(r.alert_id)}</b> · ${r.kind==='action'?'Containment':'Notify'} ${E(r.what)}<br/><span class="tag ${/failed|blocked/.test(r.detail)?'t-red':'t-orange'}">Policy automation</span> <span class="tag t-grey">${E(r.detail)}</span></div></li>`),...history.slice(0,4).map(h=>{const [t,c]=tag(h);return `<li><span class="t-time">${E((h.time.split('·')[1]||'').trim())}</span><div><b>${E(h.alert)}</b> · ${E(h.action)}<br/><span class="tag ${c}">${t}</span></div></li>`})]).join('')||'<li class="empty small">No automated actions yet.</li>'}</ul></div></section>`;
  };

  /* ----------------------------------------------------------------------------------------- LLM criterion */
  const MODE_LABEL={'claude-code':'Claude Code (plan session)',anthropic:'Anthropic API',mock:'Mock (no LLM)'};
  function stepHtml(x){
    if(x.type==='contexto')return `<li><span class="tag t-blue">Context request${x.comprobacion?` · ${E(x.comprobacion)}`:''}</span> ${E(x.motivo)}<br/><small class="mono">${E((x.consultas||[]).map(q=>`${q.consulta}(${(q.parametros||[]).join(', ')}) → ${q.filas??'?'} rows`).join(' · '))}</small>${x.is_error?' <span class="tag t-red">rejected</span>':''}</li>`;
    if(x.type==='texto')return `<li><span class="tag t-grey">Reasoning</span> ${E(x.output)}</li>`;
    if(x.type==='ticket')return `<li><span class="tag ${x.errors&&x.errors.length?'t-orange':'t-green'}">Ticket attempt ${E(x.attempt)}</span> ${x.errors&&x.errors.length?E(x.errors.join('; ')):'valid (schema + policy)'}</li>`;
    if(x.type==='politica')return `<li><span class="tag t-orange">Policy automation</span> ${E(x.output)}</li>`;
    if(x.type==='semilla')return `<li><span class="tag t-grey">Seed</span> ${E(x.output)}</li>`;
    if(x.type==='informe')return `<li><span class="tag ${x.errors&&x.errors.length?'t-orange':'t-green'}">Report attempt ${E(x.attempt)}</span> ${x.errors&&x.errors.length?E(x.errors.join('; ')):'valid (N2 schema + database ids)'}</li>`;
    if(x.type==='discriminador')return `<li><span class="tag t-green">Discriminator</span> ${E(x.output)}</li>`;
    return `<li><span class="tag t-grey">${E(x.type)}</span> ${E(x.output||'')}</li>`;
  }
  function aiSection(a){
    const t=a.ticket||{},run=L.analysis[a.id],mode=L.detailMode||'mock';
    const real=t.route==='llm'&&t.model&&t.model!=='mock';
    let body;
    if(run&&(run.status==='running'||run.status==='starting')){
      body=`<div class="ai-run"><span class="spinner"></span><b>Analysing with ${E(MODE_LABEL[run.mode||mode]||mode)}</b><span class="mono">${E(run.elapsed||0)} s</span></div><ul class="ai-steps">${(run.transcript||[]).filter(x=>x.type!=='discriminador').map(stepHtml).join('')||'<li class="muted">Building the prompt and sending it to the model…</li>'}</ul>`;
    }else if(run&&run.status==='error'){
      body=`<div class="ai-msg err"><b>LLM analysis failed.</b> ${E(run.error)}<br/><small>Claude Code: run <span class="mono">claude</span> → /login once. API: set ANTHROPIC_API_KEY in .env.</small></div><button class="action primary" data-analyze>Retry LLM analysis</button>`;
    }else if(real){
      body=`<div class="ai-msg ok"><b>LLM criterion applied</b> · ${E(t.model)} · ${E(t.attempts)} attempt(s) · ${E(t.elapsed_s||0)} s. The verdict, severity, evidence and actions below come from the model and passed schema + policy validation.</div><button class="action outline" data-analyze>Re-run LLM analysis</button>`;
    }else if(mode==='mock'){
      body=`<div class="ai-msg warn"><b>No real LLM configured.</b> This ticket comes from ${t.route==='discriminator'?'the deterministic discriminator':'the mock model'}. Start the server with <span class="mono">--claude-code</span>, <span class="mono">--detail-mode claude-code</span> or an API key to get the LLM criterion.</div>`;
    }else{
      body=`<div class="ai-msg warn"><b>${t.route==='discriminator'?'Closed by the discriminator, without LLM.':'Mock ticket: no LLM criterion yet.'}</b> Ask the model to review this alert with the prompt, the runbook and read-only database queries.</div><button class="action primary" data-analyze>Run LLM analysis · ${E(MODE_LABEL[mode]||mode)}</button>`;
    }
    return `<section class="investigation-section ai-box" id="ai-analysis"><h3>LLM criterion</h3>${body}</section>`;
  }
  L.paintAnalysis=function(a){
    const box=document.getElementById('ai-analysis');
    if(box&&state.selectedAlert&&state.selectedAlert.id===a.id){box.outerHTML=aiSection(a);lockDecisions()}
  };
  function lockDecisions(){
    const a=state.selectedAlert,run=a&&L.analysis[a.id],busy=run&&(run.status==='running'||run.status==='starting');
    document.querySelectorAll('[data-investigation-action]').forEach(b=>{b.disabled=!!busy;b.title=busy?'Wait for the LLM analysis to finish':''});
  }

  /* ----------------------------------------------------------------------------------------- policy automation */
  const STATUS_TAG={ok:'t-green',failed:'t-red',blocked:'t-red',manual:'t-grey',queued:'t-orange'};
  function policySection(a){
    const sla=a.sla,au=a.automation||{},d=a.detail,s=slaState(sla);
    const changes=(au.changes||[]).map(c=>`<span class="tag t-orange">${E({severity_guard:'Severity guard',approval:'Approval',escalation:'Escalation'}[c.rule]||c.rule)}</span> ${E(c.detail)}`);
    const notes=d?(d.notifications||[]).map(n=>`<b>${E(n.recipient)}</b> · ${E(n.channel)} — ${E(n.reason)} <span class="tag ${STATUS_TAG[n.status]||'t-grey'}">${E(n.status)}</span>`):null;
    const acts=d?(d.actions||[]).map(x=>`<span class="tag ${x.mode==='auto'?'t-blue':'t-green'}">${x.mode==='auto'?'Automatic N1':'After approval'}</span> <b>${E(x.action)}</b> → <span class="mono">${E(x.target)}</span> <span class="tag ${STATUS_TAG[x.status]||'t-grey'}">${E(x.status)}</span>${x.status!=='ok'&&x.detail?`<br/><small>${E(x.detail)}</small>`:''}`):null;
    return `<section class="investigation-section policy-box"><h3>Policy automation <small>deterministic, no LLM</small></h3>
      ${sla?`<div class="detail-grid"><div><small>SLA status</small>${s?`<span class="sla ${s.cls}" data-sla='${E(JSON.stringify({due_at:sla.due_at,closed_at:sla.closed_at,minutes:sla.minutes}))}'>${s.text}</span>`:'—'}</div><div><small>Time to triage (${E(a.ticket.ticket&&a.ticket.ticket.severity||'')})</small>${E(sla.label)}</div><div><small>Received by the SOC</small><span class="mono">${E(L.fmt(sla.received_at))}</span></div><div><small>Due</small><span class="mono">${E(L.fmt(sla.due_at))}</span></div><div><small>Escalation path (policy §3)</small>${E(sla.escalation_path||'—')}</div><div><small>Escalated to</small>${E(au.escalation_to||'Not escalated')}</div></div>`:'<p class="muted">No SLA record yet: re-run the triage to apply the policy.</p>'}
      ${(au.reasons||[]).length?`<p><b>Mandatory escalation:</b> ${E(au.reasons.join('; '))}</p>`:''}
      <h4>Changes applied to the ticket</h4><ul class="ticket-list">${list(changes,'None: the ticket already met the policy')}</ul>
      <h4>Notifications <small>simulated outbox</small></h4><ul class="ticket-list">${notes?list(notes,'No notification required for this severity and verdict'):'<li class="muted">Loading…</li>'}</ul>
      <h4>Containment on the SOC API</h4><ul class="ticket-list">${acts?list(acts,'No containment executed'):'<li class="muted">Loading…</li>'}</ul></section>`;
  }

  /* ----------------------------------------------------------------------------------------- attack chain (N2) */
  const day=ts=>String(ts||'').slice(0,10);
  const hhmm=ts=>{const d=new Date(ts);return isNaN(d)?String(ts||''):d.toLocaleTimeString('en-GB',{timeZone:'Europe/Madrid',hour:'2-digit',minute:'2-digit',second:'2-digit'})};
  const span=(a,b)=>{const ms=new Date(b)-new Date(a);if(!(ms>=0))return '';const h=ms/3600000;return h>=48?`${(h/24).toFixed(1)} days`:h>=1?`${h.toFixed(1)} h`:`${Math.max(1,Math.round(ms/60000))} min`};
  const chips=(xs,kind)=>(xs||[]).length?(xs||[]).map(x=>`<span class="chain-chip">${E(typeof x==='string'?x:JSON.stringify(x))}<small>${kind}</small></span>`).join(''):'';
  function chainBody(a,c){
    const r=c.data.report||{},w=r.window||{},sc=r.scope||{},tl=r.timeline||[];
    const days=[];tl.forEach(s=>{const d=day(s.timestamp);let g=days.find(x=>x.d===d);if(!g){g={d,steps:[]};days.push(g)}g.steps.push(s)});
    const step=s=>`<li class="chain-step${s.alert_id===a.id?' focus':''}"><span class="t-time">${E(hhmm(s.timestamp))}</span><div>${s.phase?`<span class="tag t-blue">${E(s.phase)}</span> `:''}${s.mitre?`<span class="tag t-grey">${E(s.mitre)}</span> `:''}${E(s.description)}<br/><small class="mono">${[s.event_id,s.source,s.entity,s.alert_id].filter(Boolean).map(E).join(' · ')}</small></div></li>`;
    const scope=chips(sc.users,'User')+chips(sc.hosts,'Host');
    const rel=(r.related_alerts||[]).map(x=>`<span class="mono">${E(x.alert_id)}</span> — ${E(x.relation)}`);
    const inc=(r.related_incidents||[]).map(x=>`<span class="tag t-orange">${E(x)}</span>`).join(' ');
    const plan=(r.containment_plan||[]).map(x=>`<b>${E(x.action)}</b> → ${E(x.target)}${x.approver?` <span class="tag t-red">Approver: ${E(x.approver)}</span>`:''}${x.business_impact?`<br/><small>${E(x.business_impact)}</small>`:''}`);
    const conf=typeof r.confidence==='number'?Math.round(r.confidence*100)+'%':'—';
    return `<div class="ai-msg ${c.data.valid?'ok':'err'}"><b>${c.data.valid?'Reconstruction valid':'Reconstruction invalid'}</b> · ${E(c.data.model)} · ${E(c.data.attempts)} attempt(s) · ${E(c.data.elapsed_s||0)} s · trigger: ${E(c.data.trigger||'—')} · confidence ${conf}${c.data.valid?'':`<br/>${E((c.data.errors||[]).join('; '))}`}</div>
      <h4 class="chain-h">${E(r.title||'')} <small class="mono">${E(r.incident_id||'')}</small></h4>
      <p class="lead">${E(r.attack_summary||'')}</p>
      <div class="detail-grid chain-origin"><div><small>Patient zero</small><b>${E(r.patient_zero||'—')}</b></div><div><small>Initial access</small>${E(r.initial_access||'—')}</div><div><small>Chain window</small><span class="mono">${E(w.start||'—')} → ${E(w.end||'—')}</span>${w.start&&w.end?`<br/><b>${E(span(w.start,w.end))}</b>`:''}</div><div><small>Root cause</small>${E(r.root_cause||'—')}</div></div>
      <h4 class="chain-h">Timeline <small>${tl.length} steps · ${days.length} day(s)</small></h4>
      ${days.map(g=>`<div class="chain-day"><span>${E(g.d)}</span><ul class="timeline chain-tl">${g.steps.map(step).join('')}</ul></div>`).join('')||'<p class="muted">No steps.</p>'}
      <h4 class="chain-h">Scope</h4><div class="chain-scope">${scope||'<span class="muted">No users or hosts in scope.</span>'}</div>
      <div class="detail-grid"><div><small>Data</small>${E(sc.data||'—')}</div><div><small>Business impact</small>${E(sc.business_impact||'—')}</div></div>
      <h4 class="chain-h">Relation to other incidents</h4><p>${inc||'<span class="muted">No related incidents.</span>'}</p><ul class="ticket-list">${list(rel,'No related alerts')}</ul>
      ${plan.length?`<h4 class="chain-h">Containment plan <small>proposal · requires approval</small></h4><ul class="ticket-list">${list(plan,'')}</ul>`:''}
      ${(r.detection_gaps||[]).length?`<h4 class="chain-h">Detection gaps</h4><ul class="ticket-list">${list(r.detection_gaps.map(E),'')}</ul>`:''}
      ${(r.open_questions||[]).length?`<h4 class="chain-h">Open questions</h4><ul class="ticket-list">${list(r.open_questions.map(E),'')}</ul>`:''}
      <details class="chain-trace"><summary>Investigation trace · ${(c.data.transcript||[]).length} steps</summary><ul class="ai-steps">${(c.data.transcript||[]).map(stepHtml).join('')}</ul></details>
      <button class="action outline" data-chain>Re-run reconstruction</button>`;
  }
  function chainSection(a){
    const c=L.chain[a.id],k=(a.ticket&&a.ticket.ticket)||{},escalated=!!(k.escalation&&k.escalation.escalate);
    let body;
    if(!L.on||!L.chains)body='<p class="muted">Attack-chain reconstruction requires the backend in database mode.</p>';
    else if(!c||c.status==='loading')body='<p class="muted">Loading…</p>';
    else if(c.status==='queued'||c.status==='running')body=`<div class="ai-run"><span class="spinner"></span><b>${c.status==='queued'?'Queued':'Reconstructing'} with ${E(MODE_LABEL[c.mode]||c.mode||'')}</b><span class="mono">${E(c.elapsed||0)} s</span></div><ul class="ai-steps">${(c.transcript||[]).map(stepHtml).join('')||'<li class="muted">Reading the triage description and the seed from the database…</li>'}</ul>`;
    else if(c.status==='error')body=`<div class="ai-msg err"><b>Reconstruction failed.</b> ${E(c.error)}</div><button class="action primary" data-chain>Retry reconstruction</button>`;
    else if(c.status==='done'&&c.data)body=chainBody(a,c);
    else body=`<div class="ai-msg warn"><b>${escalated?'Escalated alert without reconstruction yet.':'Not escalated.'}</b> The model starts from the triage description, reads the database (activity over several days, related alerts and incidents, IOC spread) and returns origin, scope, timeline and relation to other incidents.</div><button class="action primary" data-chain>Reconstruct attack chain</button>`;
    return `<section class="investigation-section ai-box chain-box" id="attack-chain"><h3>Attack chain reconstruction ${escalated?'<span class="tag t-orange">Escalated</span>':''}</h3>${body}</section>`;
  }
  L.paintChain=function(a){
    const box=document.getElementById('attack-chain');
    if(box&&state.selectedAlert&&state.selectedAlert.id===a.id){const open=box.querySelector('details')?.open;box.outerHTML=chainSection(a);if(open){const d=document.querySelector('#attack-chain details');if(d)d.open=true}}
  };

  /* ----------------------------------------------------------------------------------------- investigation */
  const list=(items,empty)=>items&&items.length?items.map(x=>`<li>${x}</li>`).join(''):`<li class="muted">${empty}</li>`;
  investigation=function(a){
    const t=a.ticket;
    if(!t)return `<div class="investigation-backdrop" data-close-investigation><aside class="investigation"><div class="investigation-head"><div><span class="mono">DEMO DATA · ${E(a.id)}</span><h2>${E(a.title)}</h2></div><button class="close" data-close-investigation>×</button></div><div class="investigation-body">${offline('Ticket detail requires the backend')}</div></aside></div>`;
    const k=t.ticket||{},d=a.detail,sev=(k.severity||'low');
    const ev=(k.evidence||[]).map(e=>`<span class="mono">${E(e.event_id)}</span> · ${E(e.source)} — ${E(e.finding)}`);
    const acts=(k.recommended_actions||[]).map(x=>`<b>${E(x.action)}</b> → ${E(x.target)} ${x.requires_approval?'<span class="tag t-red">Requires approval</span>':''}${x.justification?`<br/><small>${E(x.justification)}</small>`:''}`);
    const sel=d?(d.selection||[]).map(s=>`<span class="mono">${E(s.event_id)}</span> · ${E(s.source)} · <span class="tag ${s.state==='kept'||s.state==='unfiltered'?'t-blue':'t-grey'}">${E(s.state)}</span>${s.reference?` ${E(s.reference)}`:''}`):null;
    const steps=d?(d.transcript||[]).map(stepHtml).map(x=>x.replace(/^<li>|<\/li>$/g,'')):null;
    const aff=k.affected||{};
    const ents=[...(aff.hosts||[]).map(x=>['Host',x]),...(aff.business_services||[]).map(x=>['Service',x]),...(aff.users||[]).map(x=>['User',x]),...(aff.customers||[]).map(x=>['Customer',x])];
    return `<div class="investigation-backdrop" data-close-investigation><aside class="investigation" role="dialog" aria-label="Investigation ${E(a.id)}"><div class="investigation-head"><div><span class="mono">INVESTIGATION WORKSPACE · ${E(a.id)} · ${E(t.rule_id)}</span><h2>${E(k.title||a.title)}</h2>
      <div class="investigation-tags"><span class="prio ${a.priority.toLowerCase()}"><i></i>${E(sev)}</span><span class="tag t-blue">${E(L.VERDICT[k.verdict]||k.verdict)}</span><span class="tag ${t.valid?'t-green':'t-red'}">${t.valid?'Schema + policy valid':'Invalid: '+E((t.errors||[]).join('; '))}</span>${k.escalation&&k.escalation.escalate?'<span class="tag t-orange">Escalation proposed</span>':''}</div></div><button class="close" data-close-investigation aria-label="Close">×</button></div>
      <div class="investigation-body">
      ${aiSection(a)}
      ${policySection(a)}
      <section class="investigation-section"><h3>Summary</h3><p class="lead">${E(k.summary)}</p><div class="detail-grid"><div><small>Alert created</small><span class="mono">${E(a.detected)}</span></div><div><small>Rule</small>${E(t.rule_id)} · ${E(t.rule_name)}</div><div><small>Source product</small>${E(t.source_product)}</div><div><small>Runbook</small>${E(t.runbook_id)}</div><div><small>Confidence</small><b>${a.confidence}%</b></div><div><small>Model · attempts</small>${E(t.model)} · ${E(t.attempts)}</div></div></section>
      <section class="investigation-section"><h3>Severity</h3><p>${E(k.severity_rationale||'—')}</p><div class="detail-grid"><div><small>Rule severity</small>${E(t.rule_severity)}</div><div><small>Matrix base (rule × criticality)</small>${E((a.automation||{}).base_severity||'—')}</div>${(a.automation||{}).severity_before&&(a.automation||{}).severity_before!==sev?`<div><small>Proposed before policy guard</small>${E(a.automation.severity_before)}</div>`:''}<div><small>Final severity</small><b class="r-${a.priority.toLowerCase()}">${E(sev)}</b></div></div></section>
      <section class="investigation-section"><h3>Evidence</h3><ul class="ticket-list">${list(ev,'No evidence cited')}</ul></section>
      ${chainSection(a)}
      <section class="investigation-section"><h3>Affected</h3><div class="systems">${ents.map(([kind,x])=>`<div class="system"><span class="system-dot"></span><div><b>${E(x)}</b><small>${kind}</small></div></div>`).join('')||'<div class="empty small">No affected entities resolved.</div>'}</div></section>
      <section class="investigation-section"><h3>Log selection <small>${E(t.informative_logs)}/${E(t.cited_logs)} informative</small></h3><ul class="ticket-list">${sel?list(sel,'No cited logs'):'<li class="muted">Loading…</li>'}</ul></section>
      <section class="investigation-section"><h3>Pipeline trace</h3><ul class="ticket-list">${steps?list(steps,'Decided with the prompt context, no extra queries'):'<li class="muted">Loading…</li>'}</ul></section>
      ${(k.open_questions||[]).length?`<section class="investigation-section"><h3>Open questions</h3><ul class="ticket-list">${list((k.open_questions||[]).map(E),'')}</ul></section>`:''}
      <section class="investigation-section recommendation"><h3>Recommended actions</h3><ul class="ticket-list">${list(acts,'No action proposed')}</ul>${k.escalation&&k.escalation.escalate?`<p><b>Escalation</b> → ${E(k.escalation.to)}: ${E(k.escalation.reason)}</p>`:''}<p class="policy-note">${d&&(d.actions||[]).some(x=>x.status==='ok')?`Executed on the SOC API: ${(d.actions||[]).filter(x=>x.status==='ok').map(x=>E(x.action+' → '+x.target)).join(' · ')}. Actions that need approval run when you approve.`:'The AI only proposes. Actions that need approval run on the SOC API when you approve; N1 containment (block IOC, purge email) runs automatically for confirmed true positives.'}</p></section>
      </div><div class="investigation-footer"><textarea id="decision-comment" placeholder="Optional justification for your decision..."></textarea><div class="decision-actions"><button class="action secondary" data-investigation-action="investigate">Request more information</button><button class="action outline" data-investigation-action="escalate">Escalate</button><button class="action danger" data-investigation-action="reject">Reject</button><button class="action primary" data-investigation-action="approve">Approve</button></div></div></aside></div>`;
  };

  /* ----------------------------------------------------------------------------------------- decision ledger */
  const MAKERS={'Operator':'Human','Discriminator':'Rule Engine'};
  getHistoryRows=function(){
    const q=(state.filter||'').trim().toLowerCase(),type=MAKERS[state.historyMaker];
    return history.filter(x=>(!q||`${x.id} ${x.alert} ${x.maker} ${x.category} ${x.severity} ${x.action} ${x.outcome} ${x.time}`.toLowerCase().includes(q))&&(!type||x.type===type)&&(state.historySeverity==='All'||x.severity===state.historySeverity)&&(state.historyOutcome==='All'||x.outcome===state.historyOutcome));
  };
  historyPage=function(){
    const rows=getHistoryRows(),sel=(id,all,opts,cur)=>`<label class="select"><select id="${id}"><option>${all}</option>${opts.map(o=>`<option ${cur===o?'selected':''}>${o}</option>`).join('')}</select>${I.down}</label>`;
    return `<div class="history-page"><section class="hello slim"><span class="hello-ic">${I.history}</span><div><h2>Decision ledger</h2><p>Every automated and human decision, from detection to the operator's verdict.</p></div><div class="refresh">${num(history.length)} records${L.on?'':' · demo data'}</div></section>
      <div class="filters"><label class="search">${I.search}<input id="history-search" placeholder="Search decision ID, alert ID, category..." value="${E(state.filter)}"/></label>${sel('history-maker','All decision makers',Object.keys(MAKERS),state.historyMaker)}${sel('history-severity','All severities',['Critical','High','Medium','Low'],state.historySeverity)}${sel('history-outcome','All outcomes',['Confirmed','Overridden'],state.historyOutcome)}<button class="action outline" id="history-export" type="button">Export CSV ↓</button></div>
      <div class="table-wrap"><table class="table"><thead><tr><th>Timestamp</th><th>Alert ID</th><th>Category</th><th>Severity</th><th>Decision maker</th><th>Action taken</th><th>Outcome</th><th>Risk</th><th>Confidence</th></tr></thead><tbody>${rows.map(x=>`<tr data-decision="${E(x.id)}" tabindex="0"><td class="mono">${E(x.time)}</td><td class="mono">${E(x.alert)}</td><td>${E(x.category)}</td><td><span class="prio ${x.severity.toLowerCase()}"><i></i>${E(x.severity)}</span></td><td>${E(x.maker)}</td><td>${E(x.action)}</td><td><span class="tag ${x.outcome==='Confirmed'?'t-green':'t-orange'}">${E(x.outcome)}</span></td><td><b>${x.risk}</b></td><td>${x.confidence}%</td></tr>`).join('')}</tbody></table>${rows.length?'':'<div class="empty">No decision records match your search.</div>'}</div></div>`;
  };
  drawer=function(){
    if(!state.selected)return '';
    const x=history.find(h=>h.id===state.selected);if(!x)return '';
    const t=x.ticket||{},k=t.ticket||{};
    return `<div class="drawer-backdrop" data-close><aside class="drawer" role="dialog"><div class="drawer-head"><div><span class="mono">${E(x.id)} · AUDIT INSPECTOR</span><h2>${E(x.alert)}</h2><span class="tag t-green">${E(x.status)}</span></div><button class="close" data-close aria-label="Close">×</button></div>
      <div class="detail-section"><h4>Ticket</h4><p>${E(k.title||'')}<br/><span class="muted">${E(k.summary||'')}</span></p><div class="detail-grid"><div><small>Verdict</small>${E(L.VERDICT[k.verdict]||k.verdict||'—')}</div><div><small>Severity</small>${E(k.severity||x.severity)}</div><div><small>Confidence</small>${x.confidence}%</div><div><small>Route</small>${t.route==='discriminator'?'Discriminator (no LLM)':'LLM · '+E(t.model||'')}</div><div><small>SLA</small>${slaChip(t.sla)||'—'}</div><div><small>Escalated to</small>${E((t.automation||{}).escalation_to||'—')}</div></div></div>
      <div class="detail-section"><h4>Decision</h4><div class="detail-grid"><div><small>Decision maker</small>${E(x.maker)}</div><div><small>Action</small>${E(x.action)}</div><div><small>Comment</small>${E(t.decision_comment||'—')}</div><div><small>Time</small><span class="mono">${E(x.time)}</span></div></div></div>
      <div class="detail-section"><h4>Evidence</h4><ul class="ticket-list">${list((k.evidence||[]).map(e=>`<span class="mono">${E(e.event_id||'')}</span> ${E(e.finding||'')}`),'—')}</ul></div></aside></div>`;
  };

  /* ----------------------------------------------------------------------------------------- interactions */
  document.addEventListener('click',e=>{
    const t=e.target.closest('[data-alert]');if(t){const a=state.alerts.find(x=>x.id===t.dataset.alert);if(a)setTimeout(()=>{L.detail(a);autoAnalyze(a);L.loadChain(a);lockDecisions()},0)}
    if(e.target.closest('[data-chain]')&&state.selectedAlert)L.reconstruct(state.selectedAlert);
    if(e.target.closest('[data-analyze]')&&state.selectedAlert){const note=document.querySelector('#decision-comment')?.value||'';L.analyze(state.selectedAlert,note)}
    const c=e.target.closest('[data-chat-alert]');if(c){const a=state.alerts.find(x=>x.id===c.dataset.chatAlert);if(a)setTimeout(()=>L.detail(a),0)}
    const b=e.target.closest('[data-batch]');if(b&&!b.disabled)L.runBatch(Number(b.dataset.batch));
    if(e.target.closest('[data-refresh]'))L.load();
    if(e.target.closest('[data-sidebar-toggle]'))toggleSidebar();
  });
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape'&&(state.selectedAlert||state.selected)){state.selectedAlert=null;state.selected=null;render();return}
    if(e.key==='Enter'){const el=e.target.closest&&e.target.closest('[data-alert],[data-decision]');if(el)el.click()}
  });
  /* Opening a mock ticket asks the configured real LLM for its criterion automatically (once per alert and session).
     Discriminator tickets keep their deterministic verdict unless the analyst asks for the LLM. */
  function autoAnalyze(a){
    if(!L.on||!a||!a.ticket||(L.detailMode||'mock')==='mock'||L.analysis[a.id])return;
    if(a.ticket.route==='llm'&&a.ticket.model==='mock')L.analyze(a);
  }
  setInterval(()=>{document.querySelectorAll('[data-sla]').forEach(el=>{try{const s=slaState(JSON.parse(el.dataset.sla));if(s){el.textContent=s.text;el.className='sla '+s.cls}}catch(e){}});const c=document.getElementById('sentinel-clock');if(c)c.textContent=clock();const u=document.getElementById('sentinel-updated');if(u)u.textContent=ago()},1000);
  render();
  L.load();
})();
