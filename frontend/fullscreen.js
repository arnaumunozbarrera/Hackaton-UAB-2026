/* Fullscreen panel enhancements.
   Only active while a panel of the Operations center is expanded.
   Home grid, investigation workspace and decision history are not modified. */
(function(){
  const baseRender=render;
  const RANK=['Critical','High','Medium','Low'];
  const SEV_COLOR={Critical:'var(--red)',High:'var(--orange)',Medium:'#aa8a16',Low:'var(--deep)'};
  const PRIORITY_LABEL={Critical:'Immediate action',High:'Urgent',Medium:'Normal',Low:'Non-urgent'};
  const META={
    approval:{crumb:'Operations center / Approval queue',live:'Queue synced · 12 s ago'},
    analytics:{crumb:'Operations center / Real-time analytics',live:'Streaming · last 24 hours'},
    monitor:{crumb:'Operations center / Processing monitor',live:'Pipeline live · 12 s ago'}
  };

  const countBy=(list,key)=>list.reduce((m,x)=>(m[x[key]]=(m[x[key]]||0)+1,m),{});
  const stat=(label,value,sub,accent)=>`<div class="fs-stat" style="--accent:${accent}"><span class="fs-stat-label">${label}</span><span class="fs-stat-value">${value}</span><span class="fs-stat-sub">${sub}</span></div>`;
  const card=(title,meta,body)=>`<section class="fs-card"><div class="fs-card-head"><h4>${title}</h4><span class="mono">${meta}</span></div>${body}</section>`;
  const bars=(entries,total,colorFn)=>`<div class="fs-bars">${entries.map(([k,n])=>`<div class="fs-bar"><span class="fs-bar-label">${esc(k)}</span><div class="fs-bar-track"><div class="fs-bar-fill" style="width:${total?Math.round(n/total*100):0}%;background:${colorFn?colorFn(k):'var(--deep)'}"></div></div><b>${n}</b></div>`).join('')}</div>`;
  const spark=(seed,color)=>{let v=50;const pts=Array.from({length:14},(_,i)=>{v=Math.max(8,Math.min(92,v+((Math.sin(seed*7.3+i*1.9)*23)|0)));return `${(i/13*100).toFixed(1)},${(100-v).toFixed(1)}`}).join(' ');return `<svg class="fs-spark" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="3" vector-effect="non-scaling-stroke"/></svg>`};

  function close(){state.expanded=null;render()}

  function decorate(panel,key){
    panel.classList.add('fs-on','fs-'+key);
    const head=panel.querySelector('.panel-head');
    const titleText=head.querySelector('.panel-title h3');
    if(titleText&&!head.querySelector('.fs-crumb'))titleText.insertAdjacentHTML('beforebegin',`<span class="fs-crumb">${META[key].crumb}</span>`);
    head.insertAdjacentHTML('beforeend',`<div class="fs-actions"><span class="fs-live"><span class="status-dot"></span>${META[key].live}</span><span class="fs-kbd">Esc</span><button type="button" class="fs-close" data-fs-close aria-label="Close fullscreen panel"><span aria-hidden="true">×</span>Close</button></div>`);
    head.querySelector('[data-fs-close]').onclick=close;
    const body=panel.querySelector('.panel-body');
    const layout=document.createElement('div');
    layout.className='fs-layout';
    body.replaceWith(layout);
    layout.appendChild(body);
    return {head,body,layout};
  }

  function aside(layout,html){layout.insertAdjacentHTML('beforeend',`<aside class="fs-aside">${html}</aside>`)}
  function bindAlertLinks(scope){scope.querySelectorAll('[data-fs-alert]').forEach(x=>x.onclick=()=>{state.selectedAlert=state.alerts.find(a=>a.id===x.dataset.fsAlert)||null;render()})}

  function enhanceApproval(panel){
    const {head,layout}=decorate(panel,'approval');
    const pending=state.alerts.filter(a=>a.status==='Pending');
    const byPri=countBy(pending,'priority');
    const avgWait=pending.length?Math.round(pending.reduce((s,a)=>s+a.waitMinutes,0)/pending.length):0;
    const oldest=[...pending].sort((a,b)=>b.waitMinutes-a.waitMinutes);
    const unassigned=pending.filter(a=>a.operator==='Unassigned').length;
    head.insertAdjacentHTML('afterend',`<div class="fs-summary">${[
      stat('Pending approval',pending.length,'Awaiting operator decision','var(--deep)'),
      stat('Immediate action',byPri.Critical||0,'Critical priority','var(--red)'),
      stat('Urgent',byPri.High||0,'High priority','var(--orange)'),
      stat('Average wait',avgWait+'m','Across pending alerts','var(--blue)'),
      stat('Longest wait',(oldest[0]?.waitMinutes||0)+'m',oldest[0]?oldest[0].id:'Queue clear','var(--yellow)'),
      stat('Unassigned',unassigned,'No operator owner','#9aa19b')
    ].join('')}</div>`);
    const total=pending.length;
    const mix=`<div class="fs-stack">${RANK.map(p=>byPri[p]?`<span style="width:${byPri[p]/total*100}%;background:${SEV_COLOR[p]}" title="${p}: ${byPri[p]}"></span>`:'').join('')}</div><div class="fs-legend">${RANK.map(p=>`<span><i style="background:${SEV_COLOR[p]}"></i>${PRIORITY_LABEL[p]}<b>${byPri[p]||0}</b></span>`).join('')}</div>`;
    const buckets=[['Over 30 min',pending.filter(a=>a.waitMinutes>30).length,'var(--red)'],['15 to 30 min',pending.filter(a=>a.waitMinutes>=15&&a.waitMinutes<=30).length,'var(--orange)'],['Under 15 min',pending.filter(a=>a.waitMinutes<15).length,'var(--green)']];
    const sla=`<div class="fs-bars">${buckets.map(([k,n,c])=>`<div class="fs-bar"><span class="fs-bar-label">${k}</span><div class="fs-bar-track"><div class="fs-bar-fill" style="width:${total?Math.round(n/total*100):0}%;background:${c}"></div></div><b>${n}</b></div>`).join('')}</div>`;
    const sources=Object.entries(countBy(pending,'source')).sort((a,b)=>b[1]-a[1]);
    const longest=`<div class="fs-list">${oldest.slice(0,4).map(a=>`<button type="button" class="fs-list-item" data-fs-alert="${a.id}"><span><b class="mono">${a.id}</b><strong>${esc(a.title)}</strong></span><span class="fs-wait" style="color:${SEV_COLOR[a.priority]}">${a.waitMinutes}m</span></button>`).join('')||'<div class="fs-empty">Queue is clear.</div>'}</div>`;
    aside(layout,card('Priority mix',total+' pending',mix)+card('Wait time',"SLA buckets",sla)+card('By source',sources.length+' systems',bars(sources,total))+card('Longest waiting','Oldest first',longest));
    bindAlertLinks(layout);
  }

  function enhanceAnalytics(panel){
    const {head,body}=decorate(panel,'analytics');
    head.insertAdjacentHTML('afterend',`<div class="fs-context"><span class="fs-chip active">Last 24 hours</span><span class="fs-chip">Hourly buckets · UTC</span><span class="fs-chip">Auto-refresh · live</span><span class="fs-context-note">All figures reflect the current production mirror.</span></div>`);
    const accents=['var(--deep)','var(--blue)','var(--orange)','var(--green)','var(--red)','#aa8a16','var(--blue)','var(--deep)'];
    body.querySelectorAll('.kpi').forEach((k,i)=>{k.style.setProperty('--accent',accents[i%accents.length]);k.insertAdjacentHTML('beforeend',spark(i+1,i===4?'#da291c':i%2?'#0076a8':'#86bc25'))});
    const charts=body.querySelectorAll('.chart-card');
    const [vol,dist,cats]=charts;
    if(vol){vol.classList.add('fs-volume');vol.querySelector('.line-chart')?.insertAdjacentHTML('afterend','<div class="fs-xaxis"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>24:00</span></div>');vol.querySelector('.chart-title')?.insertAdjacentHTML('afterend','<div class="fs-chart-kpis"><span><small>Received</small><b>2,481</b></span><span><small>Auto-resolved</small><b>1,948</b></span><span><small>Avg. processing</small><b>02:14</b></span></div>')}
    if(dist)dist.classList.add('fs-dist');
    if(cats)cats.classList.add('fs-cats');
    const pendingCount=state.alerts.filter(a=>a.status==='Pending').length;
    const meters=[['Auto-resolved',78.5,'var(--green)'],['Human intervention',12.6,'var(--blue)'],['False positive rate',4.8,'var(--orange)']];
    const health=`<div class="fs-meters">${meters.map(([k,v,c])=>`<div class="fs-meter"><div class="fs-meter-top"><span>${k}</span><b>${v}%</b></div><div class="fs-bar-track"><div class="fs-bar-fill" style="width:${v}%;background:${c}"></div></div></div>`).join('')}</div><div class="fs-note">${pendingCount} alerts currently require operator approval.</div>`;
    const src=Object.entries(countBy(state.alerts,'source')).sort((a,b)=>b[1]-a[1]);
    body.insertAdjacentHTML('beforeend',`<div class="chart-card fs-health"><div class="chart-title">Automation health <span>Last 24 hours</span></div>${health}</div><div class="chart-card fs-sources"><div class="chart-title">Alert sources <span>Current queue</span></div>${bars(src,state.alerts.length,()=> 'var(--blue)')}</div>`);
  }

  function enhanceMonitor(panel){
    const {head,body,layout}=decorate(panel,'monitor');
    const avg=Math.round(processing.reduce((s,p)=>s+p.progress,0)/processing.length);
    const crit=processing.filter(p=>p.severity==='Critical').length;
    const ready=processing.filter(p=>p.progress>=100).length;
    head.insertAdjacentHTML('afterend',`<div class="fs-summary">${[
      stat('In pipeline',processing.length,'Alerts being processed','var(--deep)'),
      stat('Average progress',avg+'%','Across active alerts','var(--blue)'),
      stat('Critical in pipeline',crit,'Highest severity','var(--red)'),
      stat('Ready for routing',ready,'Processing complete','var(--green)')
    ].join('')}</div>`);
    const first=body.querySelector('.process-card');
    if(first)first.innerHTML=`<div class="process-row"><h4>Currently processing</h4><span class="mono">${processing.length} alerts · all stages</span></div><div class="fs-table-wrap"><table class="fs-table"><thead><tr><th>Alert</th><th>Description</th><th>Source</th><th>Stage</th><th>Severity</th><th>Elapsed</th><th>Progress</th></tr></thead><tbody>${processing.map(p=>`<tr><td class="mono">${p.id}</td><td>${esc(p.desc)}</td><td>${esc(p.source)}</td><td><span class="component">${esc(p.stage)}</span></td><td>${severity(p.severity)}</td><td class="mono">${p.elapsed}</td><td><div class="fs-progress"><div class="progress"><span style="width:${p.progress}%"></span></div><b>${p.progress}%</b></div></td></tr>`).join('')}</tbody></table></div>`;
    const sev=RANK.map(s=>[s,processing.filter(p=>p.severity===s).length]);
    const src=Object.entries(countBy(processing,'source')).sort((a,b)=>b[1]-a[1]);
    const comps=['Data Pipeline','Rule Engine','ML Model','LLM Explainer','Decision Engine'];
    const compHtml=`<div class="fs-components">${comps.map(c=>`<div class="fs-component"><span><span class="status-dot"></span>${c}</span><span class="mono">Operational</span></div>`).join('')}</div>`;
    aside(layout,card('Severity in pipeline',processing.length+' alerts',bars(sev,processing.length,k=>SEV_COLOR[k]))+card('By source',src.length+' systems',bars(src,processing.length,()=> 'var(--blue)'))+card('Engine components','Health',compHtml));
  }

  function enhance(){
    const key=state.expanded;
    const btn=document.querySelector(`.grid [data-expand="${key}"]`);
    const panel=btn&&btn.closest('.panel');
    if(!panel){state.expanded=null;document.body.classList.remove('fs-lock');return}
    panel.classList.add('full');
    document.body.classList.add('fs-lock');
    document.querySelectorAll('.grid [data-expand]').forEach(b=>b.disabled=true);
    ({approval:enhanceApproval,analytics:enhanceAnalytics,monitor:enhanceMonitor})[key]?.(panel);
  }

  render=function(){
    baseRender();
    if(state.page==='ops'&&state.expanded)enhance();
    else document.body.classList.remove('fs-lock');
  };

  // Capture on window so it runs before the legacy document-level expand handler.
  window.addEventListener('click',e=>{
    const b=e.target.closest&&e.target.closest('[data-expand]');
    if(!b)return;
    e.preventDefault();e.stopImmediatePropagation();
    if(state.expanded)return;
    state.expanded=b.dataset.expand;
    render();
  },true);

  document.addEventListener('keydown',e=>{
    if(e.key!=='Escape'||!state.expanded||state.selectedAlert||state.selected)return;
    close();
  });

  render();
})();
