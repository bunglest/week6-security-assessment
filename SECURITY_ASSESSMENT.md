# Security Vulnerability Assessment Report
## TaskFlow MVP — Independent Security Audit

**Prepared for:** TaskFlow Founders (Pre-Seed Investor Review)
**Prepared by:** Devin Hickman, Security Consultant
**Date:** May 2026
**Repository:** https://github.com/bunglest/week6-security-assessment

---

## 1. Executive Summary

TaskFlow is a task management MVP with user authentication, team collaboration, and
file attachment features, built using AI-assisted development tooling (Claude Code).
This assessment was commissioned ahead of the company's seed funding round to
independently verify whether the application is safe to launch to end users.

**Overall verdict:** **Not safe for production.** The application contains five
exploitable vulnerabilities across four OWASP Top 10 categories, two of which are
rated **Critical** and allow complete authentication bypass and unauthorised data
access by any anonymous attacker. A determined adversary could fully compromise the
user database and read every customer's tasks within minutes of discovery.

| Severity | Count | Categories |
|----------|-------|------------|
| Critical | 2     | SQL Injection, Insecure Direct Object Reference (IDOR) |
| High     | 2     | Stored XSS, Cryptographic Failures (hardcoded secret + plaintext passwords) |
| Medium   | 1     | Unrestricted File Upload |

**Recommendation:** Block the production launch. All five fixes have been
implemented in a parallel `patched/` codebase included in this engagement and
require no architectural changes — only disciplined use of existing libraries
(parameterised queries, bcrypt, helmet, express-rate-limit). Estimated
remediation effort: **one engineer-day**.

---

## 2. Scope and Methodology

**In scope:** the full TaskFlow web application source tree, including the
Express.js API server (`server.js`), the SQLite data layer (`db.js`), the static
HTML/JavaScript frontend (`public/`), and the file upload handler.

**Out of scope:** infrastructure, network configuration, third-party dependencies'
internal vulnerabilities (Snyk-equivalent scan), and social engineering vectors.

**Methodology:** static source code review followed by dynamic exploit
verification. Each finding is supported by a working proof-of-concept that was
successfully executed against a live local instance of the application. Tools used:
manual code inspection (VS Code), `curl` / PowerShell `Invoke-RestMethod` for API
fuzzing, and the Chromium DevTools Console for client-side payload delivery.

**Severity rubric:** ratings follow the OWASP risk model — *Critical* indicates
unauthenticated remote exploitation with high impact; *High* indicates authenticated
exploitation or partial compromise; *Medium* indicates exploitation requiring
chained conditions or limited impact.

---

## 3. Findings

### Finding 1 — SQL Injection in Login Endpoint
**OWASP:** A03:2021 Injection · **Severity:** Critical · **File:** `vulnerable/server.js:35`

The login endpoint constructs its SQL query by concatenating untrusted user input
directly into a string. An attacker can break out of the string literal and inject
arbitrary SQL conditions, bypassing the password check entirely.

**Vulnerable code:**
```javascript
const query = `SELECT * FROM users WHERE username = '${username}'
               AND password = '${password}'`;
db.get(query, (err, user) => { /* … */ });
```

**Proof of concept:** sending the payload `' OR '1'='1' --` as the username and
any value as the password results in a fully authenticated session as the first
user in the database. Verified with:
```powershell
curl.exe -X POST http://localhost:3000/api/login `
  -H "Content-Type: application/json" `
  -d '{"username":"'' OR ''1''=''1'' --","password":""}'
```
The server returns a valid signed JWT for user `alice`.

**Remediation:** use parameterised queries. The SQLite driver substitutes values
into placeholders without ever interpreting them as SQL syntax. Implemented in
`patched/server.js`:
```javascript
db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
  /* … */
});
```

---

### Finding 2 — Insecure Direct Object Reference (IDOR)
**OWASP:** A01:2021 Broken Access Control · **Severity:** Critical · **File:** `vulnerable/server.js:79`

The `GET /api/tasks/:id` endpoint authenticates the request but does not verify
that the requested task actually belongs to the authenticated user. Any logged-in
user can retrieve any task in the system by guessing or enumerating numeric IDs.

**Vulnerable code:**
```javascript
app.get('/api/tasks/:id', auth, (req, res) => {
  db.get('SELECT * FROM tasks WHERE id = ?', [req.params.id], (err, task) => {
    if (!task) return res.status(404).json({ error: 'Not found' });
    res.json(task);  // No check that task.user_id === req.user.id
  });
});
```

**Proof of concept:** logged in as `alice` (user id 1), the following request
returns a task owned by `bob` (user id 2) — including a confidential field
embedded in its description:
```powershell
curl.exe http://localhost:3000/api/tasks/1 -H "Authorization: Bearer $aliceToken"
# → { "id":1, "user_id":2, "title":"Bob's Private Task",
#     "description":"Confidential: investor deck password is Seed2024!" }
```

The same flaw exists on the `DELETE /api/tasks/:id` route, allowing an attacker
to destroy any user's tasks.

**Remediation:** include the authenticated user's ID in the WHERE clause. A
non-owner receives the same `404 Not Found` response as if the resource did not
exist, preventing both data leakage and resource enumeration:
```javascript
db.get('SELECT * FROM tasks WHERE id = ? AND user_id = ?',
       [req.params.id, req.user.id], (err, task) => {
  if (!task) return res.status(404).json({ error: 'Task not found' });
  res.json(task);
});
```

---

### Finding 3 — Stored Cross-Site Scripting (XSS)
**OWASP:** A03:2021 Injection · **Severity:** High · **File:** `vulnerable/public/index.html:158`

Task titles and descriptions are stored verbatim in the database, then later
rendered into the DOM via `innerHTML`. Any HTML — including `<script>` tags and
event handlers — submitted as a task title is executed in the browser of every
user who subsequently views the task list.

**Vulnerable code:**
```javascript
list.innerHTML = tasks.map(t => `
  <div class="task-title">${t.title}</div>
  <div class="task-desc">${t.description || ''}</div>
`).join('');
```

**Proof of concept:** creating a task with the title
`<img src=x onerror="alert(document.cookie)">` causes the JavaScript to fire
on every visit to the task list. In a real attack, `document.cookie` would be
exfiltrated via `fetch()` to an attacker-controlled endpoint, allowing full
session hijack.

**Remediation:** apply HTML entity encoding to all user-controlled data at render
time, and add a Content-Security-Policy header as defence-in-depth. The patched
frontend uses an `escapeHTML()` helper, and the patched server enables `helmet()`
which sets `script-src 'self'` (blocking inline scripts even if escaping is
forgotten elsewhere):
```javascript
function escapeHTML(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                  .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
list.innerHTML = tasks.map(t => `
  <div class="task-title">${escapeHTML(t.title)}</div>
  <div class="task-desc">${escapeHTML(t.description || '')}</div>
`).join('');
```

---

### Finding 4 — Cryptographic Failures
**OWASP:** A02:2021 Cryptographic Failures · **Severity:** High · **File:** `vulnerable/server.js:18`, `db.js:24`

Two related cryptographic weaknesses compound each other. First, the JWT signing
secret is hardcoded as the literal string `'secret123'`. Second, user passwords
are stored in plaintext in the SQLite database.

**Vulnerable code:**
```javascript
const JWT_SECRET = 'secret123';
const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET);
// — and in db.js —
db.run(`INSERT INTO users (username, password) VALUES ('${username}', '${password}')`);
```

**Proof of concept (token forgery):** because the secret is visible in source,
anyone with read access to the repository can sign a token claiming to be any
user. The following Node one-liner produces a valid token for `bob` (id 2)
without ever knowing his password:
```powershell
$forged = node -e "console.log(require('jsonwebtoken').sign({id:2, username:'bob'}, 'secret123'))"
curl.exe http://localhost:3000/api/tasks -H "Authorization: Bearer $forged"
# → returns bob's tasks
```

**Proof of concept (plaintext password disclosure):** any read of the `users`
table — through the SQL injection in Finding 1, a database backup leak, or a
stolen laptop — yields immediate credential compromise:
```powershell
node -e "require('./db').db.all('SELECT username, password FROM users', (e,r)=>console.log(r))"
# → [ {username:'alice', password:'password123'}, {username:'bob', password:'hunter2'} ]
```

**Remediation:** load the JWT secret from a `.env` file at boot (with a fail-fast
check), set token expiry to one hour, and bcrypt-hash passwords with a cost
factor of 12 before storage:
```javascript
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET not set'); process.exit(1); }
const token = jwt.sign({ id: user.id, username: user.username },
                       JWT_SECRET, { expiresIn: '1h' });
const hash = await bcrypt.hash(password, 12);
db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash]);
```

---

### Finding 5 — Unrestricted File Upload
**OWASP:** A04:2021 Insecure Design · **Severity:** Medium · **File:** `vulnerable/server.js:131`

The file upload endpoint accepts any file type and any file size. While the
uploads are stored outside the public web root in this configuration (limiting
direct RCE risk), an attacker can still consume unbounded disk space, upload
phishing pages or malware for later distribution, and use the server as
attacker-controlled file hosting.

**Vulnerable code:**
```javascript
const upload = multer({ dest: 'uploads/' });
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  res.json({ originalName: req.file.originalname, path: `/uploads/${req.file.filename}` });
});
```

**Remediation:** enforce a MIME type and file extension whitelist, plus a size
cap. Reject anything else with a clear error message:
```javascript
const ALLOWED_TYPES = ['image/jpeg','image/png','image/gif','application/pdf'];
const ALLOWED_EXTS  = ['.jpg','.jpeg','.png','.gif','.pdf'];
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_TYPES.includes(file.mimetype) || !ALLOWED_EXTS.includes(ext)) {
      return cb(new Error('Only jpg/png/gif/pdf files are allowed'));
    }
    cb(null, true);
  }
});
```

---

## 4. Remediation Roadmap

The fixes split cleanly into three phases. **Phase 1 must complete before any
launch.**

| Phase | Priority | Item | Effort | Risk if skipped |
|-------|----------|------|--------|-----------------|
| 1 | P0 — pre-launch blocker | Parameterise all SQL queries (Finding 1) | 1 hr | Anonymous account takeover |
| 1 | P0 — pre-launch blocker | Add `WHERE user_id = ?` ownership checks (Finding 2) | 1 hr | Any user reads any data |
| 1 | P0 — pre-launch blocker | Move `JWT_SECRET` to `.env`, add token expiry, bcrypt passwords (Finding 4) | 2 hr | Universal account takeover |
| 2 | P1 — pre-launch hardening | Escape HTML on render + add `helmet()` middleware (Finding 3) | 1 hr | Session hijack via stored payload |
| 2 | P1 — pre-launch hardening | File upload whitelist + size cap (Finding 5) | 30 min | Disk exhaustion, malware hosting |
| 3 | P2 — operational | Add rate limiting on `/api/login`, generic error messages, structured logging | 2 hr | Brute-force, info disclosure |

**Total estimated engineer time:** approximately one full working day. All
remediations are implemented and verified working in the `patched/` directory of
the deliverable repository. Each fix is the minimum change required — no
architectural rewrites or library swaps were necessary.

---

## 5. Conclusion

TaskFlow's current codebase is representative of a common pattern in
AI-assisted MVPs: feature-complete and superficially polished, but with several
high-impact security primitives left in their default permissive state. None of
the findings are exotic — every one is an OWASP Top 10 category, and the
remediation patterns are all well-documented and supported by mature open-source
libraries already present in the dependency tree (`jsonwebtoken`, `bcryptjs`,
`helmet`, `express-rate-limit`).

The combination of SQL injection and IDOR is particularly dangerous because they
chain together: the SQL injection yields a valid session for the lowest-numbered
user, and the IDOR then allows that session to enumerate every task in the
system. An attacker would need under five minutes from first reconnaissance to
full data exfiltration.

**Final recommendation:** apply the Phase 1 and Phase 2 fixes from the roadmap
above before any external traffic is permitted. After remediation, schedule a
follow-up assessment to verify the fixes and to expand scope to dependency
auditing and infrastructure review prior to handling regulated user data.

---

*End of Report*
