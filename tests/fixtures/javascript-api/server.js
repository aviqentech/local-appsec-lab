const http = require('node:http');
const net = require('node:net');
const port = Number(process.env.PORT || 8765);
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const actor = req.headers['x-test-user'];
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('X-Appsec-Lab-Identity', 'fixture-node-v1');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  const send = (status, body) => {res.statusCode=status; res.end(JSON.stringify(body));};
  if (url.pathname === '/health') return send(200, {ready:true});
  if (url.pathname === '/public') return send(200, {message:'synthetic public data'});
  if (url.pathname === '/protected') return actor === 'alice' ? send(200,{message:'SYNTHETIC_PROTECTED'}) : send(401,{error:'authentication required'});
  if (url.pathname === '/records/vulnerable/42') return actor ? send(200,{owner:'alice',data:'SYNTHETIC_ALICE_RECORD_42'}) : send(401,{error:'authenticate'});
  if (url.pathname === '/records/secure/42') return actor === 'alice' ? send(200,{owner:'alice',data:'SYNTHETIC_ALICE_RECORD_42'}) : send(403,{error:'forbidden'});
  if (url.pathname === '/validate') return /^\d{1,3}$/.test(url.searchParams.get('id')||'') ? send(200,{valid:true}) : send(400,{error:'id must be 1-3 digits'});
  if (url.pathname === '/html-insecure' || url.pathname === '/html-secure') {
    res.setHeader('Content-Type','text/html');
    if (url.pathname === '/html-secure') res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'");
    res.end('<!doctype html><title>Synthetic frontend</title><h1>Local security fixture</h1>'); return;
  }
  if (url.pathname === '/egress-probe') {
    const socket=net.connect({host:'127.0.0.1',port:Number(process.env.CANARY_PORT||9998)});
    socket.once('connect',()=>{socket.destroy();send(200,{egress:'reached'});});
    socket.once('error',()=>send(200,{egress:'denied'}));
    socket.setTimeout(1000,()=>{socket.destroy();send(200,{egress:'timeout'});});return;
  }
  return send(404,{error:'not found'});
});
server.listen(port,'127.0.0.1');
process.on('SIGTERM',()=>server.close(()=>process.exit(0)));
