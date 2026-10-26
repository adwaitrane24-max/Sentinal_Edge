// State-level dashboard regressions; no browser or external packages required.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync('templates/index.html', 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const newElement = () => ({textContent:'',innerHTML:'',style:{},className:'',hidden:false,clientWidth:400,replaceChildren(){},append(){},getContext(){return {scale(){},beginPath(){},moveTo(){},lineTo(){},stroke(){},fillText(){}};}});
const elements = new Map();
const el = id => {
  if (!elements.has(id)) elements.set(id, newElement());
  return elements.get(id);
};
el('auth').hidden = true;   // the HTML `hidden` attribute
const sockets=[], timers=[], requests=[], stored={}, location={protocol:'http:',host:'localhost:8000',pathname:'/',search:'',hash:'#token=s3cret%2Bx'};
class Socket {constructor(url){this.url=url;sockets.push(this);}close(){this.onclose();}}
const ctx = vm.createContext({document:{getElementById:el,createElement:()=>el(Math.random())},window:{addEventListener(){}},location,history:{replaceState(_s,_t,url){location.hash='';location.url=url;}},sessionStorage:{setItem:(k,v)=>stored[k]=v,getItem:k=>stored[k]??null},devicePixelRatio:1,WebSocket:Socket,setTimeout:(fn,delay)=>timers.push({fn,delay}),setInterval(){},console,fetch:async(path,options)=>{requests.push(options);return {ok:true,json:async()=>path==='/api/alerts'?[]:path==='/api/status'?{total_alerts:0,high_severity:0,total_packets:0}:[]};}});
vm.runInContext(script,ctx);
// Token from the #token= link: sent on every request and the WebSocket, then removed from the address bar
assert.ok(requests.length>0 && requests.every(o=>o.headers.Authorization==='Bearer s3cret+x'));
assert.equal(sockets[0].url,'ws://localhost:8000/ws?token=s3cret%2Bx');
assert.equal(location.hash,'');
assert.equal(stored['sentineledge-token'],'s3cret+x');
assert.equal(el('auth').hidden,true);   // valid token: no access panel
vm.runInContext("renderPacketStats({total_packets:1000,analysed_packets:990,total_bytes:20000,packets_per_second:12,bytes_per_second:240,tcp_packets:700,udp_packets:290,other_packets:10,uptime_seconds:843,mode:'live',interface:'eth0',dry_run:true,status:'running'});renderAlert({id:1,timestamp:new Date().toISOString(),alert_id:'TEST',src_ip:'10.0.0.1',severity:'high',action:'alert_only',category:'test',detail:'<script>bad</script>'});",ctx);
assert.equal(el('packets').textContent,'1,000');
assert.equal(el('alerts').textContent,'1');
assert.equal(el('high').textContent,'1');
assert.equal(el('uptime').textContent,'00:14:03');
assert.ok(el('feed').innerHTML.includes('&lt;script&gt;'));
vm.runInContext("renderAlert(alerts[0]);",ctx);
assert.equal(el('alerts').textContent,'1');
for(let i=0;i<120;i++) vm.runInContext('renderPacketStats(latest)',ctx);
assert.equal(vm.runInContext('samples.length',ctx),90);
sockets[0].onclose();
assert.ok(el('connection').textContent.includes('DISCONNECTED'));
assert.equal(el('capture-state').textContent,'CAPTURE STATUS UNKNOWN');
timers.at(-1).fn();
assert.equal(sockets.length,2);
assert.equal(sockets[1].url,sockets[0].url);   // reconnect keeps the stored token
console.log('Dashboard checks passed: packet/alert separation, deduplication, uptime, safe text, chart bounds, reconnect, access token.');

// Opened without a valid token (plain localhost:8000, or an old link after a restart):
// show the "Access token needed" panel instead of an endless DISCONNECTED, and accept a pasted link.
function noTokenPage(hash, status) {
  const els = new Map(), get = id => { if (!els.has(id)) els.set(id, newElement()); return els.get(id); };
  get('auth').hidden = true;
  const page = {sockets: [], timers: [], reloads: 0, get, location: {protocol:'http:', host:'localhost:8000', pathname:'/', search:'', hash, reload() { page.reloads++; }}};
  class S { constructor(url) { this.url = url; page.sockets.push(this); } close() { this.onclose(); } }
  page.ctx = vm.createContext({document:{getElementById:get, createElement:()=>get(Math.random())}, window:{addEventListener(){}},
    location: page.location, history:{replaceState(){}}, sessionStorage:{setItem(){}, getItem:()=>null}, devicePixelRatio:1,
    WebSocket:S, setTimeout:(fn,delay)=>page.timers.push({fn,delay}), setInterval(){}, console, FormData:class { constructor(f) { this.f = f; } get() { return this.f.value; } },
    fetch: async () => ({ok:false, status, json: async () => ({detail:'Missing or invalid access token'})})});
  vm.runInContext(script, page.ctx);
  return page;
}
(async () => {
  const missing = noTokenPage('', 401);
  assert.equal(missing.get('auth').hidden, false);
  assert.ok(missing.get('auth-reason').textContent.includes('no access token'));
  missing.sockets[0].onclose();                                   // server rejects the WebSocket
  assert.ok(missing.get('connection').textContent.includes('TOKEN REQUIRED'));
  assert.ok(!missing.timers.some(t => t.fn.name === 'connectWS'));  // no pointless reconnect loop
  // Pasting the whole printed link uses its token
  missing.get('auth-form').onsubmit({preventDefault(){}, currentTarget:{value:'  http://127.0.0.1:8000/#token=n3w%2Btok  '}});
  assert.equal(missing.location.hash, 'token=n3w%2Btok');
  assert.equal(missing.reloads, 1);

  const stale = noTokenPage('#token=old-token', 401);            // link from before a restart
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(stale.get('auth').hidden, false);
  assert.ok(stale.get('auth-reason').textContent.includes('rejected'));
  console.log('Dashboard checks passed: missing/stale token guidance, pasted link.');
})().catch(err => { console.error(err); process.exit(1); });
