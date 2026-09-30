// State-level dashboard regressions; no browser or external packages required.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync('templates/index.html', 'utf8');
const elements = new Map();
const el = id => {
  if (!elements.has(id)) elements.set(id, {textContent:'',innerHTML:'',style:{},className:'',hidden:false,clientWidth:400,replaceChildren(){},append(){},getContext(){return {scale(){},beginPath(){},moveTo(){},lineTo(){},stroke(){},fillText(){}};}});
  return elements.get(id);
};
const sockets=[], timers=[];
class Socket {constructor(){sockets.push(this);}close(){this.onclose();}}
const ctx = vm.createContext({document:{getElementById:el,createElement:()=>el(Math.random())},window:{addEventListener(){}},location:{protocol:'http:',host:'localhost:8000'},devicePixelRatio:1,WebSocket:Socket,setTimeout:(fn,delay)=>timers.push({fn,delay}),setInterval(){},console,fetch:async path=>({ok:true,json:async()=>path==='/api/alerts'?[]:path==='/api/status'?{total_alerts:0,high_severity:0,total_packets:0}:[]})});
vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1],ctx);
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
console.log('Dashboard checks passed: packet/alert separation, deduplication, uptime, safe text, chart bounds, reconnect.');
