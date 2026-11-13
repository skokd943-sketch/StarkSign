const express = require('express'), multer = require('multer'), fs = require('fs'), path = require('path');
const { execFile } = require('child_process'), crypto = require('crypto');
const AdmZip = require('adm-zip'), plist = require('simple-plist');
const pty = require('node-pty');

// Railway без Volume: используем только временное хранилище контейнера.
// DATA_DIR можно переопределить, но для текущего деплоя оставляем /tmp/stark.
const ROOT = path.resolve(process.env.DATA_DIR || '/tmp/stark');
const UPLOADS = path.join(ROOT, 'up');
const KEY = process.env.ACCESS_KEY || '';
const ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const TTL = 24 * 3600 * 1000;

fs.mkdirSync(UPLOADS, { recursive: true });

const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', ORIGIN);
  res.set('Access-Control-Allow-Headers', 'x-key, content-type, cache-control');
  res.set('Access-Control-Max-Age', '600');
  res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.end();
  next();
});

const up = multer({ dest: UPLOADS, limits: { fileSize: 600 * 1024 * 1024 } });
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const okId = id => /^[a-f0-9]{16}$/.test(id);

app.get('/', (q, r) => r.send('Stark Sign server OK'));

app.post('/api/sign',
  (req, res, next) => (KEY && req.get('x-key') !== KEY) ? res.status(401).json({ error: 'Неверный ключ доступа' }) : next(),
  up.fields([{ name: 'ipa', maxCount: 1 }, { name: 'p12', maxCount: 1 }, { name: 'prov', maxCount: 1 }]),
  (req, res) => {
    const F = req.files || {};
    const clean = () => Object.values(F).flat().forEach(f => fs.rm(f.path, { force: true }, () => {}));
    if (!F.ipa || !F.p12 || !F.prov) { clean(); return res.status(400).json({ error: 'Нужны ipa, p12 и mobileprovision' }); }

    const id = crypto.randomBytes(8).toString('hex'), dir = path.join(ROOT, id);
    fs.mkdirSync(dir);
    const out = path.join(dir, 'signed.ipa');
    let info = { name: 'App', bundle: 'app.unknown', version: '1.0' };
    try {
      const z = new AdmZip(F.ipa[0].path);
      const e = z.getEntries().find(x => /^Payload\/[^/]+\.app\/Info\.plist$/.test(x.entryName));
      if (!e) throw new Error('Info.plist не найден');
      const p = plist.parse(e.getData());
      info = { name: p.CFBundleDisplayName || p.CFBundleName || 'App', bundle: p.CFBundleIdentifier, version: p.CFBundleShortVersionString || '1.0' };
    } catch (e) {
      fs.rmSync(dir, { recursive: true, force: true });
      clean();
      return res.status(400).json({ error: 'Некорректный IPA: ' + e.message });
    }

    execFile('zsign', ['-k', F.p12[0].path, '-p', String(req.body.pass || ''), '-m', F.prov[0].path, '-o', out, '-z', '5', F.ipa[0].path],
      { timeout: 5 * 60 * 1000, maxBuffer: 10 * 1024 * 1024 }, (err, so, se) => {
        clean();
        if (err || !fs.existsSync(out)) {
          fs.rmSync(dir, { recursive: true, force: true });
          return res.status(500).json({ error: 'Не удалось подписать: ' + String(se || so || err.message).slice(-250) });
        }
        fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify(info));
        res.json({ id, name: info.name, bundle: info.bundle, version: info.version });
      });
  });

app.get('/api/manifest/:id.plist', (req, res) => {
  const id = req.params.id;
  if (!okId(id)) return res.sendStatus(404);
  let m; try { m = JSON.parse(fs.readFileSync(path.join(ROOT, id, 'meta.json'))); } catch (e) { return res.sendStatus(404); }
  const url = `https://${req.get('host')}/api/ipa/${id}.ipa`;
  res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>items</key><array><dict>
<key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${esc(url)}</string></dict></array>
<key>metadata</key><dict><key>bundle-identifier</key><string>${esc(m.bundle)}</string><key>bundle-version</key><string>${esc(m.version)}</string><key>kind</key><string>software</string><key>title</key><string>${esc(m.name)}</string></dict>
</dict></array></dict></plist>`);
});

app.get('/api/ipa/:id.ipa', (req, res) => {
  if (!okId(req.params.id)) return res.sendStatus(404);
  const f = path.join(ROOT, req.params.id, 'signed.ipa');
  fs.existsSync(f) ? res.type('application/octet-stream').sendFile(f) : res.sendStatus(404);
});

// Удаляем старые подписанные IPA и осиротевшие временные загрузки.
// Проверка mtime защищает от удаления файлов, которые ещё обрабатываются.
function cleanupExpired() {
  const cutoff = Date.now() - TTL;
  let entries = [];
  try { entries = fs.readdirSync(ROOT, { withFileTypes: true }); } catch (e) { return; }

  for (const entry of entries) {
    const full = path.join(ROOT, entry.name);
    if (entry.name === 'up' && entry.isDirectory()) {
      let uploads = [];
      try { uploads = fs.readdirSync(full, { withFileTypes: true }); } catch (e) {}
      for (const file of uploads) {
        const filePath = path.join(full, file.name);
        try {
          const stat = fs.statSync(filePath);
          if (stat.mtimeMs < cutoff) fs.rmSync(filePath, { recursive: true, force: true });
        } catch (e) {}
      }
      continue;
    }
    if (!okId(entry.name) || !entry.isDirectory()) continue;
    try {
      if (fs.statSync(full).mtimeMs < cutoff) fs.rmSync(full, { recursive: true, force: true });
    } catch (e) {}
  }
}

cleanupExpired();
const cleanupTimer = setInterval(cleanupExpired, 60 * 60 * 1000);
if (cleanupTimer.unref) cleanupTimer.unref();


/* iOS UDID enrollment (Apple OTA Profile Service).
   Apple device signatures are verified against Apple's iPhone Device CA;
   the challenge is random, single-use, and expires after 20 minutes. */
const { execFileSync } = require('child_process');
const ENROLL_DIR = path.join(ROOT, 'enrollment');
const APPLE_DEVICE_CA = path.join(ENROLL_DIR, 'apple-iphone-device-ca.pem');
const SIGN_KEY = path.join(ENROLL_DIR, 'profile-signing-key.pem');
const SIGN_CERT = path.join(ENROLL_DIR, 'profile-signing-cert.pem');
const enrollments = new Map();
const enrollRate = new Map();
fs.mkdirSync(ENROLL_DIR, { recursive: true });
fs.writeFileSync(APPLE_DEVICE_CA, "-----BEGIN CERTIFICATE-----\nMIIDaTCCAlGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB5MQswCQYDVQQGEwJVUzET\nMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv\nbiBBdXRob3JpdHkxLTArBgNVBAMTJEFwcGxlIGlQaG9uZSBDZXJ0aWZpY2F0aW9u\nIEF1dGhvcml0eTAeFw0wNzA0MTYyMjU0NDZaFw0xNDA0MTYyMjU0NDZaMFoxCzAJ\nBgNVBAYTAlVTMRMwEQYDVQQKEwpBcHBsZSBJbmMuMRUwEwYDVQQLEwxBcHBsZSBp\nUGhvbmUxHzAdBgNVBAMTFkFwcGxlIGlQaG9uZSBEZXZpY2UgQ0EwgZ8wDQYJKoZI\nhvcNAQEBBQADgY0AMIGJAoGBAPGUSsnquloYYK3Lok1NTlQZaRdZB2bLl+hmmkdf\nRq5nerVKc1SxywT2vTa4DFU4ioSDMVJl+TPhl3ecK0wmsCU/6TKqewh0lOzBSzgd\nZ04IUpRai1mjXNeT9KD+VYW7TEaXXm6yd0UvZ1y8Cxi/WblshvcqdXbSGXH0KWO5\nJQuvAgMBAAGjgZ4wgZswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w\nHQYDVR0OBBYEFLL+ISNEhpVqedWBJo5zENinTI50MB8GA1UdIwQYMBaAFOc0Ki4i\n3jlga7SUzneDYS8xoHw1MDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly93d3cuYXBw\nbGUuY29tL2FwcGxlY2EvaXBob25lLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAd13P\nZ3pMViukVHe9WUg8Hum+0I/0kHKvjhwVd/IMwGlXyU7DhUYWdja2X/zqj7W24Aq5\n7dEKm3fqqxK5XCFVGY5HI0cRsdENyTP7lxSiiTRYj2mlPedheCn+k6T5y0U4Xr40\nFXwWb2nWqCF1AgIudhgvVbxlvqcxUm8Zz7yDeJ0JFovXQhyO5fLUHRLCQFssAbf8\nB4i8rYYsBUhYTspVJcxVpIIltkYpdIRSIARA49HNvKK4hzjzMS/OhKQpVKw+OCEZ\nxptCVeN2pjbd9uzi175oVo/u6B2ArKAW17u6XEHIdDMOe7cb33peVI6TD15W4MI\npyQPbp8orlXe+tA8JA==\n-----END CERTIFICATE-----");
function ensureProfileSigner() {
  if (fs.existsSync(SIGN_KEY) && fs.existsSync(SIGN_CERT)) return;
  execFileSync('openssl', ['req','-x509','-newkey','rsa:2048','-keyout',SIGN_KEY,'-out',SIGN_CERT,'-days','3650','-nodes','-subj','/CN=Stark Sign Profile Service'], { stdio:'ignore' });
  try { fs.chmodSync(SIGN_KEY, 0o600); } catch (_) {}
}
ensureProfileSigner();
const xmlEsc = v => String(v).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function plistString(v) { return '<string>'+xmlEsc(v)+'</string>'; }
// ВАЖНО: по документации Apple (Profile Service Payload) сам верхнеуровневый
// .mobileconfig ДОЛЖЕН иметь PayloadType "Profile Service", а PayloadContent —
// это словарь (URL/DeviceAttributes/Challenge), а не массив вложенных payload'ов.
// Если обернуть это в профиль типа "Configuration" (как было раньше), iOS
// ставит профиль как обычный пустой конфиг и НЕ шлёт автоматический callback
// с UDID — внешне выглядит так, будто "после установки ничего не происходит".
function profileXml(token, challenge, req) {
  const base = (process.env.PUBLIC_URL || ('https://' + req.get('host'))).replace(/\/+$/,'');
  return '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>'
    + '<key>PayloadContent</key><dict><key>URL</key>'+plistString(base+'/api/udid/response/'+token)
    + '<key>DeviceAttributes</key><array>'+plistString('UDID')+'</array>'
    + '<key>Challenge</key>'+plistString(challenge)+'</dict>'
    + '<key>PayloadDescription</key>'+plistString('Запрашивается только UDID устройства для подготовки подписи приложения.')
    + '<key>PayloadDisplayName</key>'+plistString('Stark Sign — получение UDID')
    + '<key>PayloadOrganization</key>'+plistString('Stark Sign')
    + '<key>PayloadIdentifier</key>'+plistString('com.starksign.udid.profile-service')
    + '<key>PayloadUUID</key>'+plistString(crypto.randomUUID())
    + '<key>PayloadVersion</key><integer>1</integer>'
    + '<key>PayloadType</key>'+plistString('Profile Service')
    + '</dict></plist>';
}
function signedProfile(xml, outFile) {
  const inFile = path.join(ENROLL_DIR, crypto.randomUUID()+'.plist');
  fs.writeFileSync(inFile, xml);
  try {
    execFileSync('openssl', ['cms','-sign','-binary','-in',inFile,'-signer',SIGN_CERT,'-inkey',SIGN_KEY,'-outform','DER','-out',outFile,'-nodetach'], {stdio:'pipe'});
  } finally { fs.rmSync(inFile,{force:true}); }
}
app.post('/api/udid/start', (req,res) => {
  const ip = String(req.ip || req.socket.remoteAddress || 'unknown');
  const now = Date.now();

  // Reuse an active request from this device/IP instead of consuming another rate-limit slot.
  for (const [existingToken, existing] of enrollments) {
    if (existing.clientIp === ip && !existing.used && now-existing.created < 20*60*1000) {
      const base = (process.env.PUBLIC_URL || ('https://' + req.get('host'))).replace(/\/+$/,'');
      return res.json({url:base+'/enroll/'+existingToken+'.mobileconfig',token:existingToken,expiresIn:Math.max(0,Math.floor((20*60*1000-(now-existing.created))/1000)),reused:true});
    }
  }

  const recent = (enrollRate.get(ip)||[]).filter(t=>now-t<60*60*1000);
  if (recent.length >= 10) return res.status(429).json({error:'Лимит новых запросов UDID: 10 в час. Уже созданный запрос можно использовать повторно.'});
  recent.push(now); enrollRate.set(ip,recent);
  const token = crypto.randomBytes(32).toString('hex');
  enrollments.set(token,{challenge:crypto.randomBytes(32).toString('hex'),created:now,used:false,udid:null,clientIp:ip});
  const base = (process.env.PUBLIC_URL || ('https://' + req.get('host'))).replace(/\/+$/,'');
  const url = base+'/enroll/'+token+'.mobileconfig';
  console.info('[UDID] enrollment created/reused; ip:',ip,'token:',token.slice(0,8));
  res.json({url,token,expiresIn:1200,reused:false});
});
app.get('/enroll/:token.mobileconfig', (req,res) => {
  console.info('[UDID] profile requested; token:',String(req.params.token).slice(0,8));
  const token=req.params.token, session=enrollments.get(token);
  if (!/^[a-f0-9]{64}$/.test(token) || !session || Date.now()-session.created>20*60*1000 || session.used) return res.status(410).send('Ссылка истекла. Создай новый запрос в Stark Sign.');
  try {
    const out=path.join(ENROLL_DIR,token+'.signed');
    signedProfile(profileXml(token,session.challenge,req),out);
    const data=fs.readFileSync(out); fs.rmSync(out,{force:true});
    res.set({'Content-Type':'application/x-apple-aspen-config','Content-Disposition':'attachment; filename="StarkSign-UDID.mobileconfig"','Cache-Control':'no-store'});
    res.send(data);
  } catch(e) { console.error('UDID profile generation failed:',e.message); res.status(500).send('Не удалось создать профиль.'); }
});
app.post('/api/udid/response/:token', express.raw({type:()=>true,limit:'256kb'}), (req,res) => {
  const token=req.params.token, session=enrollments.get(token);
  console.info('[UDID] device callback received; token:',String(token).slice(0,8),'content-type:',req.get('content-type')||'none','bytes:',Buffer.isBuffer(req.body)?req.body.length:0);
  if (!/^[a-f0-9]{64}$/.test(token) || !session || session.used || Date.now()-session.created>20*60*1000) return res.status(410).send('Enrollment expired');
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).send('Missing signed device response');
  const id=crypto.randomUUID(), cms=path.join(ENROLL_DIR,id+'.cms'), decoded=path.join(ENROLL_DIR,id+'.plist'), signer=path.join(ENROLL_DIR,id+'.pem');
  let verifyStage='save CMS';
  try {
    fs.writeFileSync(cms,req.body);
    verifyStage='verify Apple device signature';
    execFileSync('openssl',['cms','-verify','-binary','-inform','DER','-in',cms,'-CAfile',APPLE_DEVICE_CA,'-partial_chain','-no_check_time','-purpose','any','-out',decoded,'-signer',signer],{stdio:'pipe',timeout:15000});
    verifyStage='check Apple device certificate';
    const issuer=execFileSync('openssl',['x509','-in',signer,'-noout','-issuer','-nameopt','RFC2253'],{encoding:'utf8'}).trim();
    if (!issuer.includes('CN=Apple iPhone Device CA')) throw new Error('Signer is not an Apple iPhone device certificate');
    verifyStage='parse device response';
    const attrs=plist.parse(fs.readFileSync(decoded,'utf8'));
    const udid=String(attrs.UDID||attrs.Udid||'').toUpperCase();
    const challengeKey=Object.keys(attrs).find(k=>k.toUpperCase()==='CHALLENGE');
    const challenge=String(challengeKey?attrs[challengeKey]:'');
    const got=Buffer.from(challenge), expected=Buffer.from(session.challenge);
    if (!/^[A-F0-9]{40}$/.test(udid) || got.length!==expected.length || !crypto.timingSafeEqual(got,expected)) throw new Error('Invalid UDID or challenge');
    verifyStage='save verified UDID';
    session.used=true; session.udid=udid; session.completed=Date.now();
    const store=path.join(ROOT,'udids.json'); let rows=[];
    try { rows=JSON.parse(fs.readFileSync(store,'utf8')); if(!Array.isArray(rows)) rows=[]; } catch(_){}
    rows=rows.filter(x=>x.token!==token); rows.push({token,udid,created:new Date().toISOString()});
    fs.writeFileSync(store,JSON.stringify(rows,null,2));
    const doneXml='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>PayloadContent</key><array/><key>PayloadDisplayName</key>'+plistString('Stark Sign — завершено')+'<key>PayloadIdentifier</key>'+plistString('com.starksign.udid.complete.'+token)+'<key>PayloadType</key>'+plistString('Configuration')+'<key>PayloadUUID</key>'+plistString(crypto.randomUUID())+'<key>PayloadVersion</key><integer>1</integer></dict></plist>';
    const signed=path.join(ENROLL_DIR,id+'.response'); signedProfile(doneXml,signed);
    res.set('Content-Type','application/x-apple-aspen-config').send(fs.readFileSync(signed)); fs.rmSync(signed,{force:true});
  } catch(e) {
    console.warn('[UDID] enrollment rejected at stage:',verifyStage,'error:',e.message,'details:',e.stderr?String(e.stderr).slice(-1200):'none');
    res.status(400).send('Device signature could not be verified');
  } finally { for(const f of [cms,decoded,signer]) fs.rmSync(f,{force:true}); }
});
app.get('/api/udid/status/:token', (req,res) => {
  const token=req.params.token, session=enrollments.get(token);
  if (!/^[a-f0-9]{64}$/.test(token) || !session) return res.status(404).json({error:'Запрос не найден'});
  if(Date.now()-session.created>30*60*1000){enrollments.delete(token);return res.status(410).json({error:'Запрос истёк'});}
  res.json(session.udid?{status:'complete',udid:session.udid}:{status:'pending'});
});
setInterval(()=>{const now=Date.now();for(const [t,s] of enrollments)if(now-s.created>30*60*1000)enrollments.delete(t);for(const [ip,a] of enrollRate)if(!a.some(t=>now-t<60*60*1000))enrollRate.delete(ip);},5*60*1000).unref();



/* Automatic free Apple Developer signing through the Sideloader CLI.
   Credentials are held only in process memory until the PTY consumes them.
   The Apple account's local ADI/key material is isolated by Apple-ID hash. */
const appleSessions = new Map();
const appleLocks = new Set();
const appleAttempts = new Map();
function appleRateLimit(req,res,next) {
  const ip=String(req.ip || req.socket.remoteAddress || 'unknown'), now=Date.now();
  const recent=(appleAttempts.get(ip)||[]).filter(t=>now-t<60*60*1000);
  if(recent.length>=5) return res.status(429).json({error:'Слишком много попыток входа. Попробуй через час.'});
  recent.push(now); appleAttempts.set(ip,recent); next();
}
const appleAccess = (req,res,next) => (KEY && req.get('x-key') !== KEY)
  ? res.status(401).json({error:'Неверный ключ доступа'}) : next();

function requireAppleHttps(req,res,next) {
  if (!req.secure && !['localhost','127.0.0.1'].includes(req.hostname)) return res.status(400).json({error:'Вход Apple ID разрешён только по HTTPS'});
  next();
}
function knownUdid(value) {
  if (!/^[A-Fa-f0-9]{40}$/.test(String(value || ''))) return false;
  try {
    const rows = JSON.parse(fs.readFileSync(path.join(ROOT,'udids.json'),'utf8'));
    return Array.isArray(rows) && rows.some(x => String(x.udid).toUpperCase() === String(value).toUpperCase());
  } catch (_) { return false; }
}
function applePublicStatus(s) {
  return {id:s.id,status:s.status,message:s.message || '',error:s.error || '',
    downloadUrl:s.status === 'complete' ? '/api/apple/download/'+s.id+'.ipa' : undefined,
    name:s.meta && s.meta.name, bundle:s.meta && s.meta.bundle, version:s.meta && s.meta.version};
}

app.post('/api/apple/start', appleAccess, appleRateLimit, requireAppleHttps, up.single('ipa'), (req,res) => {
  const fail = (code,msg) => { if(req.file) fs.rm(req.file.path,{force:true},()=>{}); return res.status(code).json({error:msg}); };
  const appleId = String(req.body.appleId || '').trim();
  const password = String(req.body.password || '');
  const udid = String(req.body.udid || '').toUpperCase();
  if (!req.file) return fail(400,'Выбери IPA-файл');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(appleId) || !password) return fail(400,'Проверь Apple ID и пароль');
  if (!knownUdid(udid)) return fail(400,'Сначала получи и подтверди UDID на этом устройстве');
  const accountKey = crypto.createHash('sha256').update(appleId.toLowerCase()).digest('hex');
  if (appleLocks.has(accountKey)) return fail(409,'Для этого Apple ID уже выполняется подписание');
  let meta;
  try {
    const z = new AdmZip(req.file.path);
    const e = z.getEntries().find(x => /^Payload\/[^/]+\.app\/Info\.plist$/.test(x.entryName));
    if (!e) throw new Error('Info.plist не найден');
    const p = plist.parse(e.getData());
    meta = {name:p.CFBundleDisplayName || p.CFBundleName || 'App',bundle:p.CFBundleIdentifier,version:p.CFBundleShortVersionString || '1.0'};
    if (!meta.bundle) throw new Error('Bundle ID не найден');
  } catch(e) { return fail(400,'Некорректный IPA: '+e.message); }

  const id = crypto.randomBytes(12).toString('hex');
  const work = path.join(ROOT,'apple-jobs',id);
  const config = path.join(ROOT,'apple-accounts',accountKey);
  fs.mkdirSync(work,{recursive:true,mode:0o700});
  fs.mkdirSync(config,{recursive:true,mode:0o700});
  try { fs.chmodSync(work,0o700); fs.chmodSync(config,0o700); } catch(_){}
  const input = path.join(work,id+'.ipa'), output = path.join(work,'signed.ipa');
  fs.renameSync(req.file.path,input);
  const session = {id,work,input,output,config,accountKey,appleId, password,udid,meta,status:'starting',message:'Запускаю безопасный вход Apple…',error:'',buffer:'',sentId:false,sentPassword:false,waitingCode:false,created:Date.now(),proc:null};
  appleSessions.set(id,session);
  appleLocks.add(accountKey);
  try {
    const proc = pty.spawn('sideloader',['starksign','--udid',udid,'--input',input,'--output',output],{
      name:'xterm-256color',cols:100,rows:30,cwd:'/app',
      env:{...process.env,SIDELOADER_CONFIG_DIR:config,TERM:'xterm-256color'}
    });
    session.proc = proc;
    proc.onData(data => {
      const clean = data.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/\r/g,'');
      session.buffer = (session.buffer + clean).slice(-12000);
      const tail = session.buffer.slice(-500);
      if (!session.sentId && /Apple ID:\s*$/i.test(tail)) {
        session.sentId = true; proc.write(session.appleId+'\r'); session.appleId='';
        session.status='authenticating'; session.message='Проверяю Apple ID…';
      }
      if (session.sentId && !session.sentPassword && /Password:\s*$/i.test(tail)) {
        session.sentPassword = true; proc.write(session.password+'\r'); session.password='';
        session.status='authenticating'; session.message='Выполняю вход в Apple…';
      }
      if (/type .?resend.? to resend one|please type it here/i.test(tail)) {
        session.waitingCode = true; session.status='awaiting_code';
        session.message='Apple отправила код подтверждения. Введи 6-значный код.';
      }
      if (/STARKSIGN_AUTH_OK/.test(tail)) { session.status='preparing'; session.message='Apple ID подтверждён. Подготавливаю устройство…'; }
      if (/STARKSIGN_DEVICE_OK/.test(tail)) { session.status='preparing'; session.message='Устройство зарегистрировано. Создаю сертификат…'; }
      if (/STARKSIGN_CERT_OK/.test(tail)) { session.status='preparing'; session.message='Сертификат готов. Создаю provisioning profile…'; }
      if (/STARKSIGN_SIGNING|Signing application|Signing .*\.app/i.test(tail)) {
        session.status='signing'; session.message='Подписываю приложение…';
      }
      if (/STARKSIGN_SUCCESS:/i.test(tail)) {
        session.status='packaging'; session.message='Подпись готова, завершаю упаковку…';
      }
    });
    proc.onExit(({exitCode}) => {
      appleLocks.delete(accountKey);
      session.password=''; session.appleId=''; session.proc=null; session.waitingCode=false;
      if (exitCode === 0 && fs.existsSync(output)) {
        session.status='complete'; session.message='IPA успешно подписан';
        try { fs.rmSync(input,{force:true}); } catch(_){}
      } else {
        session.status='error';
        const safe = session.buffer.replaceAll(appleId,'[Apple ID]').replaceAll(password,'[REDACTED]').slice(-1800);
        session.error = safe || ('Sideloader завершился с кодом '+exitCode);
        session.message='Не удалось подписать IPA';
        try { fs.rmSync(input,{force:true}); fs.rmSync(output,{force:true}); } catch(_){}
      }
    });
    res.status(202).json(applePublicStatus(session));
  } catch(e) {
    appleLocks.delete(accountKey); appleSessions.delete(id);
    fs.rmSync(work,{recursive:true,force:true});
    return res.status(500).json({error:'Не удалось запустить Sideloader: '+e.message});
  }
});

app.post('/api/apple/code/:id', appleAccess, express.json({limit:'2kb'}), (req,res) => {
  const s=appleSessions.get(req.params.id), code=String(req.body.code || '').trim();
  if (!s || s.status !== 'awaiting_code' || !s.proc || !s.waitingCode) return res.status(409).json({error:'Сейчас код подтверждения не ожидается'});
  if (!/^\d{4,8}$/.test(code)) return res.status(400).json({error:'Введи код из SMS или доверенного устройства'});
  s.waitingCode=false; s.status='authenticating'; s.message='Проверяю код Apple…';
  s.proc.write(code+'\r');
  res.json({ok:true});
});
app.get('/api/apple/status/:id', appleAccess, (req,res) => {
  const s=appleSessions.get(req.params.id);
  if (!s) return res.status(404).json({error:'Задача не найдена'});
  res.json({...applePublicStatus(s),error:s.error});
});
app.get('/api/apple/manifest/:id.plist', (req,res) => {
  const s=appleSessions.get(req.params.id);
  if (!s || s.status !== 'complete' || !fs.existsSync(s.output)) return res.sendStatus(404);
  const base=(process.env.PUBLIC_URL || ('https://'+req.get('host'))).replace(/\/+$/,'');
  const ipaUrl=base+'/api/apple/download/'+s.id+'.ipa';
  res.set('Cache-Control','no-store').type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${esc(ipaUrl)}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${esc(s.meta.bundle)}</string><key>bundle-version</key><string>${esc(s.meta.version)}</string><key>kind</key><string>software</string><key>title</key><string>${esc(s.meta.name)}</string></dict></dict></array></dict></plist>`);
});
app.get('/api/apple/download/:id.ipa', (req,res) => {
  const s=appleSessions.get(req.params.id);
  if (!s || s.status !== 'complete' || !fs.existsSync(s.output)) return res.sendStatus(404);
  res.set('Cache-Control','no-store').type('application/octet-stream').sendFile(s.output);
});
setInterval(() => {
  const cutoff=Date.now()-TTL;
  for (const [id,s] of appleSessions) if (s.created<cutoff) {
    if (s.proc) { try { s.proc.kill(); } catch(_){} }
    try { fs.rmSync(s.work,{recursive:true,force:true}); } catch(_){}
    appleSessions.delete(id);
    appleLocks.delete(s.accountKey);
  }
},60*60*1000).unref();

app.listen(process.env.PORT || 3000, () => console.log('Stark Sign server started; temporary data: ' + ROOT));

// Диагностика Sideloader. Не запрашивает и не сохраняет Apple ID.
if (process.env.RECON === '1') {
  const cmds = [['version'], ['-h'], ['sign', '-h'], ['install', '-h'], ['team', '-h'], ['device', '-h'], ['cert', '-h'], ['app-id', '-h'], ['tool', '-h']];
  (async () => {
    execFile('sh', ['-c', 'which sideloader; ldd $(which sideloader) | grep -i "not found"'], (e, so, se) => console.log('RECON binary\\n' + (so || '') + (se || '') + (e ? ' (нет бинарника или все библиотеки на месте)' : '')));
    for (const a of cmds) {
      await new Promise(r => execFile('sideloader', a, { timeout: 20000 }, (e, so, se) => {
        console.log('RECON sideloader ' + a.join(' ') + '\\n' + (so || '') + (se || '') + (e && !so && !se ? 'ERR ' + e.message : ''));
        r();
      }));
    }
    console.log('RECON done');
  })();
}
