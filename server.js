const express = require('express'), multer = require('multer'), fs = require('fs'), path = require('path');
const { execFile } = require('child_process'), crypto = require('crypto');
const AdmZip = require('adm-zip'), plist = require('simple-plist');

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
  res.set('Access-Control-Allow-Headers', 'x-key');
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
function profileXml(token, challenge, req) {
  const base = process.env.PUBLIC_URL || ('https://' + req.get('host'));
  const payload = '<dict><key>PayloadType</key>'+plistString('Profile Service')+
    '<key>PayloadVersion</key><integer>1</integer><key>PayloadIdentifier</key>'+plistString('com.starksign.udid.profile-service')+
    '<key>PayloadUUID</key>'+plistString(crypto.randomUUID())+
    '<key>PayloadDisplayName</key>'+plistString('Stark Sign — получение UDID')+
    '<key>PayloadDescription</key>'+plistString('Запрашивается только UDID устройства для подготовки подписи приложения.')+
    '<key>PayloadContent</key><dict><key>URL</key>'+plistString(base+'/api/udid/response/'+token)+
    '<key>DeviceAttributes</key><array>'+plistString('UDID')+'</array><key>Challenge</key>'+plistString(challenge)+'</dict></dict>';
  return '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>PayloadContent</key><array>'+payload+'</array><key>PayloadDescription</key>'+plistString('Одноразовый запрос идентификатора устройства для Stark Sign')+'<key>PayloadDisplayName</key>'+plistString('Stark Sign UDID')+'<key>PayloadIdentifier</key>'+plistString('com.starksign.udid.'+token)+'<key>PayloadOrganization</key>'+plistString('Stark Sign')+'<key>PayloadRemovalDisallowed</key><false/><key>PayloadType</key>'+plistString('Configuration')+'<key>PayloadUUID</key>'+plistString(crypto.randomUUID())+'<key>PayloadVersion</key><integer>1</integer></dict></plist>';
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
  const now = Date.now(), recent = (enrollRate.get(ip)||[]).filter(t=>now-t<60*60*1000);
  if (recent.length >= 5) return res.status(429).json({error:'Слишком много запросов. Попробуй через час.'});
  recent.push(now); enrollRate.set(ip,recent);
  const token = crypto.randomBytes(32).toString('hex');
  enrollments.set(token,{challenge:crypto.randomBytes(32).toString('hex'),created:now,used:false,udid:null});
  const url = (process.env.PUBLIC_URL || ('https://'+req.get('host'))).replace(/\/$/,'')+'/enroll/'+token+'.mobileconfig';
  res.json({url,token,expiresIn:1200});
});
app.get('/enroll/:token.mobileconfig', (req,res) => {
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
  if (!/^[a-f0-9]{64}$/.test(token) || !session || session.used || Date.now()-session.created>20*60*1000) return res.status(410).send('Enrollment expired');
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).send('Missing signed device response');
  const id=crypto.randomUUID(), cms=path.join(ENROLL_DIR,id+'.cms'), decoded=path.join(ENROLL_DIR,id+'.plist'), signer=path.join(ENROLL_DIR,id+'.pem');
  try {
    fs.writeFileSync(cms,req.body);
    execFileSync('openssl',['cms','-verify','-binary','-inform','DER','-in',cms,'-CAfile',APPLE_DEVICE_CA,'-partial_chain','-no_check_time','-purpose','any','-out',decoded,'-signer',signer],{stdio:'pipe',timeout:15000});
    const issuer=execFileSync('openssl',['x509','-in',signer,'-noout','-issuer','-nameopt','RFC2253'],{encoding:'utf8'}).trim();
    if (!issuer.includes('CN=Apple iPhone Device CA')) throw new Error('Signer is not an Apple iPhone device certificate');
    const attrs=plist.parse(fs.readFileSync(decoded,'utf8'));
    const udid=String(attrs.UDID||'').toUpperCase(), challenge=String(attrs.CHALLENGE||attrs.Challenge||'');
    if (!/^[A-F0-9]{ 40 }$/.test(udid) || !crypto.timingSafeEqual(Buffer.from(challenge),Buffer.from(session.challenge))) throw new Error('Invalid UDID or challenge');
    session.used=true; session.udid=udid; session.completed=Date.now();
    const store=path.join(ROOT,'udids.json'); let rows=[];
    try { rows=JSON.parse(fs.readFileSync(store,'utf8')); if(!Array.isArray(rows)) rows=[]; } catch(_){}
    rows=rows.filter(x=>x.token!==token); rows.push({token,udid,created:new Date().toISOString()});
    fs.writeFileSync(store,JSON.stringify(rows,null,2));
    const doneXml='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>PayloadContent</key><array/><key>PayloadDisplayName</key>'+plistString('Stark Sign — завершено')+'<key>PayloadIdentifier</key>'+plistString('com.starksign.udid.complete.'+token)+'<key>PayloadType</key>'+plistString('Configuration')+'<key>PayloadUUID</key>'+plistString(crypto.randomUUID())+'<key>PayloadVersion</key><integer>1</integer></dict></plist>';
    const signed=path.join(ENROLL_DIR,id+'.response'); signedProfile(doneXml,signed);
    res.set('Content-Type','application/x-apple-aspen-config').send(fs.readFileSync(signed)); fs.rmSync(signed,{force:true});
  } catch(e) {
    console.warn('UDID enrollment rejected:',e.message);
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
