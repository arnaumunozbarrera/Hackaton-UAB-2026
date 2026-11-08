/* Sentinel data layer. Loaded after app.js: replaces the demo arrays of app.js with the triage API
   (python -m src.llm_triage serve) and exposes window.Live for the views in ui.js.
   If the API is not reachable the demo data of app.js stays and the views say so.
   Ticket content can quote attacker-controlled text: views escape every value with esc(). */
(function(){
  const SEV={critical:'Critical',high:'High',medium:'Medium',low:'Low',informational:'Low'};
  const RISK={critical:95,high:80,medium:60,low:35,informational:15};
  const VERDICT={true_positive:'True positive',benign_true_positive:'Benign true positive',false_positive:'False positive',needs_more_info:'Needs more info'};
  const DECISION={approve:'Approved',reject:'Rejected',escalate:'Escalated',investigate:'Investigation requested'};
  const Live={on:false,stats:null,batch:null,error:null,mode:'',loadedAt:null,SEV,RISK,VERDICT,DECISION};
  window.Live=Live;

  const api=(path,opts)=>fetch(path,opts).then(async r=>{const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||r.status);return d});
  const post=(path,body)=>api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const fmt=iso=>{if(!iso)return '—';const d=new Date(iso);return isNaN(d)?String(iso):d.toLocaleString('en-GB',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'}).replace(',',' ·')};
  const mins=iso=>Math.max(0,Math.round((Date.now()-new Date(iso))/60000));
  Live.fmt=fmt;

  function toAlert(t){
    const k=t.ticket||{},sev=k.severity||'low',acts=k.recommended_actions||[];
    const act=acts.find(a=>a.requires_approval)||acts[0],aff=k.affected||{};
    return {id:t.alert_id,title:k.title||t.rule_name,category:t.tactic||'—',severity:SEV[sev]||'Low',priority:SEV[sev]||'Low',
      finalSeverity:sev,risk:RISK[sev]||30,confidence:Math.round((k.confidence||0)*100),time:fmt(t.created_at),
      question:act?`${act.requires_approval?'Approve':'Confirm'}: ${act.action} → ${act.target}`:`Confirm verdict: ${VERDICT[k.verdict]||k.verdict}`,
      source:t.source_product,status:'Pending',operator:'Unassigned',verdict:VERDICT[k.verdict]||k.verdict||'—',
      trigger:`${t.rule_id} · ${t.rule_name}`,evidence:`${t.informative_logs}/${t.cited_logs} informative logs`,
      waitMinutes:mins(t.created_at),detected:fmt(t.alert_created_at),escalate:!!t.escalate,
      affected:[...(aff.hosts||[]),...(aff.business_services||[]),...(aff.users||[])].slice(0,4),
      recommendation:act?act.action:'—',approvalNeeded:!!(act&&act.requires_approval),reversible:true,ticket:t};
  }
  function toHistory(t,i){
    const k=t.ticket||{},auto=t.route==='discriminator';
    return {id:`DEC-${String(i+1).padStart(4,'0')}`,alert:t.alert_id,category:t.tactic||'—',severity:SEV[k.severity]||'Low',
      maker:auto?'Discriminator':(t.decided_by||'Operator'),type:auto?'Rule Engine':'Human',
      action:auto?`Auto-closed · ${VERDICT[k.verdict]||k.verdict}`:`${DECISION[t.decision]||t.decision} · ${VERDICT[k.verdict]||k.verdict}`,
      outcome:auto||t.decision==='approve'?'Confirmed':'Overridden',risk:RISK[k.severity]||30,confidence:Math.round((k.confidence||0)*100),
      status:'Resolved',time:fmt(t.decided_at||t.created_at),stamp:t.decided_at||t.created_at,ticket:t};
  }

  Live.toAlert=toAlert;
  Live.analysis={};  /* alert_id -> {job,status,transcript,elapsed,error,mode} */
  const isReal=t=>t&&t.route==='llm'&&t.model&&t.model!=='mock';
  Live.needsAnalysis=a=>!!(a&&a.ticket&&!isReal(a.ticket));
  Live.analyze=async function(a,note=''){
    if(!Live.on||!a)return;
    const cur=Live.analysis[a.id];if(cur&&cur.status==='running')return;
    Live.analysis[a.id]={status:'starting',transcript:[],elapsed:0};Live.paintAnalysis(a);
    try{
      const {job_id,mode}=await post('/api/analyze',{alert_id:a.id,note});
      Object.assign(Live.analysis[a.id],{job:job_id,mode,status:'running'});
      const poll=async()=>{
        let j;try{j=await api('/api/job?id='+job_id)}catch(e){Object.assign(Live.analysis[a.id],{status:'error',error:e.message});Live.paintAnalysis(a);return}
        Object.assign(Live.analysis[a.id],{status:j.status,transcript:j.transcript||[],elapsed:j.elapsed_s,error:j.error});
        if(j.status==='running'){Live.paintAnalysis(a);setTimeout(poll,1500);return}
        if(j.status==='done'){
          try{const d=await api('/api/tickets/'+encodeURIComponent(a.id));const fresh=toAlert(d);fresh.detail=d;
            const i=state.alerts.findIndex(x=>x.id===a.id);if(i>=0)state.alerts[i]=fresh;
            if(state.selectedAlert&&state.selectedAlert.id===a.id){const c=document.querySelector('#decision-comment')?.value||'';state.selectedAlert=fresh;render();const t=document.querySelector('#decision-comment');if(t)t.value=c}
            toast(`${a.id} · LLM verdict: ${VERDICT[(d.ticket||{}).verdict]||'—'}`);
          }catch(e){toast('Reload failed: '+e.message)}
        }else Live.paintAnalysis(a);
      };
      setTimeout(poll,1200);
    }catch(e){Object.assign(Live.analysis[a.id],{status:'error',error:e.message});Live.paintAnalysis(a)}
  };

  Live.load=async function(){
    try{
      const info=await api('/api/info');
      if(!info.database)throw new Error('backend running without database (serve without --dataset)');
      const [queue,hist,stats]=await Promise.all([api('/api/queue?limit=300'),api('/api/history?limit=300'),api('/api/stats')]);
      const keep=new Map(state.alerts.map(a=>[a.id,a.detail]));
      state.alerts=queue.map(toAlert);state.alerts.forEach(a=>{if(keep.get(a.id))a.detail=keep.get(a.id)});
      history.length=0;hist.forEach((t,i)=>history.push(toHistory(t,i)));
      Object.assign(Live,{on:true,stats,mode:info.mode,detailMode:info.detail_mode||info.mode,error:null,loadedAt:Date.now()});
    }catch(e){Live.error=e.message||String(e)}
    if(!state.selectedAlert&&!state.selected&&!state.expanded)render();
  };

  Live.decide=async function(a,action){
    const comment=document.querySelector('#decision-comment')?.value||'';
    if(!Live.on){toast('Backend offline: decision not recorded');return}
    try{await post('/api/decision',{alert_id:a.id,decision:action,comment,operator:'Paco Gonzalez'});state.selectedAlert=null;toast(`${a.id} · ${DECISION[action]||action}`);await Live.load()}
    catch(e){toast(`Decision failed: ${e.message}`)}
  };
  Live.detail=async function(a){
    if(!a||a.detail||!Live.on)return;
    try{a.detail=await api('/api/tickets/'+encodeURIComponent(a.id));if(state.selectedAlert&&state.selectedAlert.id===a.id)render()}catch(e){toast('Ticket detail failed: '+e.message)}
  };
  Live.runBatch=async function(n){
    try{const {job_id}=await post('/api/batch',{limit:n});Live.batch={status:'running',done:0,total:n};render();
      const poll=async()=>{const j=await api('/api/job?id='+job_id);Live.batch=j;
        if(j.status==='running'){if(!state.selectedAlert&&!state.expanded)render();setTimeout(poll,1500)}
        else{toast(`Batch ${j.status}: ${j.summary?`${j.summary.processed} processed · ${j.summary.llm} LLM · ${j.summary.discriminator} auto`:j.error||''}`);await Live.load()}};
      setTimeout(poll,1000)}catch(e){toast('Batch failed: '+e.message)}
  };

  makeDecision=(a,action)=>Live.decide(a,action);
  /* Refresh every 5 s while the server is in live mode, otherwise every 20 s; never while the operator is typing
     or has a ticket, the ledger inspector or an expanded panel open. */
  let last=0;
  setInterval(()=>{
    const every=Live.stats&&Live.stats.live&&Live.stats.live.enabled?5000:20000;
    const typing=document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
    if(Date.now()-last<every||typing||state.selectedAlert||state.selected||state.expanded||state.page==='assistant')return;
    last=Date.now();Live.load();
  },1000);
})();
