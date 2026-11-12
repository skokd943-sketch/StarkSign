const express = require('express'), multer = require('multer'), fs = require('fs'), path = require('path');
const { execFile } = require('child_process'), crypto = require('crypto');
const AdmZip = require('adm-zip'), plist = require('simple-plist');

const ROOT = process.env.DATA_DIR || '/tmp/stark';
const KEY = process.env.ACCESS_KEY || '';          // необязательный ключ доступа
const ORIGIN = process.env.ALLOWED_ORIGIN || '*';  // например https://skokd943-sketch.github.io
const TTL = 24 * 3600 * 1000;                      // подписанные файлы живут 24 часа
fs.mkdirSync(path.join(ROOT, 'up'), { recursive: true });

const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set('Access-Control-Allow-Origin', ORIGIN);
  res.set('Access-Control-Allow-Headers', 'x-key');
  res.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') return res.end();
  next();
});

const up = multer({ dest: path.join(ROOT, 'up'), limits: { fileSize: 600 * 1024 * 1024 } });
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
      const p = plist.parse(e.getData());
      info = { name: p.CFBundleDisplayName || p.CFBundleName || 'App', bundle: p.CFBundleIdentifier, version: p.CFBundleShortVersionString || '1.0' };
    } catch (e) { /* имя не вытащили — не страшно */ }

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

setInterval(() => {
  for (const d of fs.readdirSync(ROOT)) {
    const p = path.join(ROOT, d);
    if (okId(d) && Date.now() - fs.statSync(p).mtimeMs > TTL) fs.rmSync(p, { recursive: true, force: true });
  }
}, 3600 * 1000);

app.listen(process.env.PORT || 3000, () => console.log('Stark Sign server started'));
