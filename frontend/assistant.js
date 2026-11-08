/* AI Intelligence Assistant: visual refresh.
   Same data, same query logic (assistantQuery / submitAssistant) and same ids/data attributes. */
(function(){
  const PROMPTS=[
    ['Show me all critical alerts','Critical alerts','Alerts flagged for immediate action','!','var(--red)'],
    ['Find alerts pending operator approval','Pending approvals','Alerts waiting for a human decision','◷','var(--orange)'],
    ['Find alerts related to payment processing','Payment processing','Transactions, refunds and beneficiaries','€','var(--blue)'],
    ['Which services are generating the most alerts?','Top alert services','Sources with the highest alert volume','≡','var(--deep)']
  ];

  function message(m){
    const ai=m.role==='assistant';
    return `<div class="chat-message ${m.role}"><div class="chat-avatar ${ai?'ai':''}">${ai?'✦':'PG'}</div><div class="ai-msg-body"><span class="ai-msg-author">${ai?'Sentinel AI':'Paco Gonzalez'}</span><div class="chat-bubble">${m.html||esc(m.text)}</div></div></div>`;
  }

  function welcomeView(){
    return `<div class="assistant-welcome"><span class="welcome-icon">✦</span><h3>How can I help investigate?</h3><p>Ask about priority, status, affected services, or pending operator decisions.</p><div class="welcome-prompts">${PROMPTS.map(([q,t,d,i,c])=>`<button type="button" data-suggestion="${q}"><span class="ai-prompt-icon" style="--c:${c}">${i}</span><span class="ai-prompt-text"><b>${t}</b><small>${d}</small></span><span class="ai-prompt-arrow">→</span></button>`).join('')}</div></div>`;
  }

  assistantPage=function(){
    const welcome=!state.chatMessages.length;
    const pending=state.alerts.filter(a=>a.status==='Pending');
    const critical=pending.filter(a=>a.priority==='Critical').length;
    const sources=new Set(state.alerts.map(a=>a.source)).size;
    const count=state.chatMessages.length;
    return `<div class="assistant-page ai-v2">
      <section class="assistant-hero">
        <div class="assistant-mark">✦</div>
        <div class="ai-hero-text"><span class="assistant-kicker">READ-ONLY ALERT INTELLIGENCE</span><h2>AI Intelligence Assistant</h2><p>Search the alert data layer in plain language and jump directly into the evidence.</p>
          <div class="ai-capabilities"><span>Priority and urgency</span><span>Operator status</span><span>Affected services</span><span>Evidence links</span></div></div>
        <div class="ai-hero-side"><span class="assistant-ready"><span class="status-dot"></span>Ready</span>${welcome?'':'<button type="button" class="ai-reset" data-assistant-reset>New conversation</button>'}</div>
      </section>
      <div class="ai-layout">
        <section class="assistant-shell">
          <div class="ai-shell-head"><span><b>Conversation</b><small>${welcome?'No messages yet':count+' message'+(count===1?'':'s')}</small></span><span class="mono">Scope · alert data layer</span></div>
          <div class="assistant-messages">${welcome?welcomeView():state.chatMessages.map(message).join('')}${state.chatLoading?'<div class="chat-message assistant"><div class="chat-avatar ai">✦</div><div class="ai-msg-body"><span class="ai-msg-author">Sentinel AI</span><div class="chat-bubble loading"><span></span><span></span><span></span> Searching alert data…</div></div></div>':''}</div>
          <form class="assistant-composer" id="assistant-form"><label class="ai-input"><span aria-hidden="true">✦</span><input id="assistant-input" autocomplete="off" placeholder="Ask about alerts, priorities, services, or status…"/></label><button type="submit" ${state.chatLoading?'disabled':''}>Send <span>↗</span></button></form>
          <div class="ai-composer-hint"><span>Read-only access · no actions are executed</span><span>Press Enter to send</span></div>
        </section>
        <aside class="ai-aside">
          <section class="ai-card"><div class="ai-card-head"><h4>Live data snapshot</h4><span class="mono">Now</span></div><div class="ai-snapshot">
            <div style="--c:var(--deep)"><small>Alerts in queue</small><b>${state.alerts.length}</b></div>
            <div style="--c:var(--orange)"><small>Pending approval</small><b>${pending.length}</b></div>
            <div style="--c:var(--red)"><small>Immediate action</small><b>${critical}</b></div>
            <div style="--c:var(--blue)"><small>Source systems</small><b>${sources}</b></div></div></section>
          <section class="ai-card"><div class="ai-card-head"><h4>Quick queries</h4><span class="mono">One click</span></div><div class="ai-quick">${PROMPTS.map(([q,t,,i,c])=>`<button type="button" data-suggestion="${q}" ${state.chatLoading?'disabled':''}><span class="ai-prompt-icon" style="--c:${c}">${i}</span>${t}</button>`).join('')}</div></section>
          <section class="ai-card"><div class="ai-card-head"><h4>Data access</h4><span class="mono">Policy</span></div><ul class="ai-policy"><li>Read-only queries on the alert data layer</li><li>No containment or remediation actions</li><li>Final decisions remain with the operator</li></ul></section>
        </aside>
      </div>
    </div>`;
  };

  const baseRender=render;
  render=function(){
    baseRender();
    if(state.page!=='assistant')return;
    const box=document.querySelector('.ai-v2 .assistant-messages');
    if(box)box.scrollTop=box.scrollHeight;
    const input=document.querySelector('#assistant-input');
    if(input&&!state.chatLoading&&!state.selectedAlert)input.focus({preventScroll:true});
  };

  document.addEventListener('click',e=>{
    if(!e.target.closest('[data-assistant-reset]'))return;
    state.chatMessages=[];state.chatLoading=false;render();
  });

  render();
})();
