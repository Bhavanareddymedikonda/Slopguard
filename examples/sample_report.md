# SlopGuard report

**Target:** `examples/vulnerable_app`  
**Scanned:** 7 files · 122 lines · dotenv (1), dockerfile (1), python (1), shell (1), go (1), requirements (1)

## Health score: 0/100

> 12 high-impact issue(s) need attention first; 20 security, 14 slop, 14 gaps/loose ends

| Severity | Count |
|---|---|
| 🔴 critical | 1 |
| 🟠 high | 11 |
| 🟡 medium | 14 |
| 🔵 low | 22 |

| Category | Count |
|---|---|
| Security | 20 |
| Slop | 14 |
| Gaps & loose ends | 14 |

## Fix these first

1. 🔴 **AWS access key id** - `app.py:13` (security)
   - Revoke the key and use IAM roles or environment variables.
2. 🟠 **TLS certificate verification disabled** - `app.py:47` (security)
   - Keep verification on; pin or install the proper CA instead.
3. 🟠 **TLS certificate verification disabled** - `main.go:10` (security)
   - Keep verification on; pin or install the proper CA instead.
4. 🟠 **Sensitive file in repository** - `.env:1` (security)
   - Remove it from history and add it to .gitignore.
5. 🟠 **Credentials embedded in a URL** - `app.py:14` (security)
   - Use environment variables for credentials and never commit them.
6. 🟠 **Hardcoded credential** - `app.py:12` (security)
   - Move it to an environment variable or secret manager and rotate it.
7. 🟠 **Hardcoded credential** - `server.js:5` (security)
   - Move it to an environment variable or secret manager and rotate it.
8. 🟠 **Shell command built from dynamic input** - `app.py:30` (security)
   - Pass arguments as a list (no shell) and validate or escape every input.
9. 🟠 **Unsafe deserialisation** - `app.py:35` (security)
   - Use JSON or yaml.safe_load, and never deserialise untrusted input.
10. 🟠 **Shell command built from dynamic input** - `server.js:10` (security)
   - Pass arguments as a list (no shell) and validate or escape every input.

## Security (20)

### 🔴 AWS access key id · `SEC002` · critical
`app.py:13` · confidence 90%

```
AWS_KEY = "AKIAQ3X9TRVLMD4HZPW2"
```

Looks like an AWS access key id.

**Fix:** Revoke the key and use IAM roles or environment variables.

### 🟠 TLS certificate verification disabled · `SEC013` · high
`app.py:47` · confidence 85%

```
return requests.get(url, verify=False).text
```

Disabling TLS verification exposes traffic to man-in-the-middle attacks.

**Fix:** Keep verification on; pin or install the proper CA instead.

### 🟠 TLS certificate verification disabled · `SEC013` · high
`main.go:10` · confidence 85%

```
tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
```

Disabling TLS verification exposes traffic to man-in-the-middle attacks.

**Fix:** Keep verification on; pin or install the proper CA instead.

### 🟠 Sensitive file in repository · `SEC026` · high
`.env:1` · confidence 80%

`.env` usually holds secrets and should not be committed.

**Fix:** Remove it from history and add it to .gitignore.

### 🟠 Credentials embedded in a URL · `SEC006` · high
`app.py:14` · confidence 80%

```
DATABASE_URL = "postgres://admin:hunter2pass@db.internal:5432/prod"
```

A connection string contains a username and password.

**Fix:** Use environment variables for credentials and never commit them.

### 🟠 Hardcoded credential · `SEC004` · high
`app.py:12` · confidence 75%

```
DB_PASSWORD = "Sup3rS3cretPr0d!2024"
```

A password, key or token appears to be hardcoded.

**Fix:** Move it to an environment variable or secret manager and rotate it.

### 🟠 Hardcoded credential · `SEC004` · high
`server.js:5` · confidence 75%

```
const apiKey = "k9Xv2LmQ8rTz4WnB7cYpHd3JfGs6AaEu";
```

A password, key or token appears to be hardcoded.

**Fix:** Move it to an environment variable or secret manager and rotate it.

### 🟠 Shell command built from dynamic input · `SEC008` · high
`app.py:30` · confidence 70%

```
return subprocess.check_output(f"ping -c 1 {host}", shell=True)
```

A shell command is assembled by concatenating or formatting strings.

**Fix:** Pass arguments as a list (no shell) and validate or escape every input.

### 🟠 Unsafe deserialisation · `SEC011` · high
`app.py:35` · confidence 70%

```
obj = pickle.loads(request.data)
```

Deserialising untrusted data can lead to remote code execution.

**Fix:** Use JSON or yaml.safe_load, and never deserialise untrusted input.

### 🟠 Shell command built from dynamic input · `SEC008` · high
`server.js:10` · confidence 70%

```
exec('ls ' + req.query.dir, (err, out) => { });
```

A shell command is assembled by concatenating or formatting strings.

**Fix:** Pass arguments as a list (no shell) and validate or escape every input.

### 🟠 SQL built with string formatting · `SEC010` · high
`app.py:22` · confidence 65%

```
rows = conn.execute("SELECT * FROM users WHERE id = " + uid).fetchall()
```

SQL appears to be built by string concatenation or interpolation.

**Fix:** Use parameterised queries or an ORM.

### 🟠 Dynamic code execution (eval/exec) · `SEC007` · high
`app.py:36` · confidence 65%

```
return str(eval(request.args.get("expr")))
```

Evaluating dynamic strings can run attacker-controlled code.

**Fix:** Use a safe parser (ast.literal_eval, JSON) or an explicit dispatch table.

### 🟡 Insecure temp file or world-writable permissions · `SEC019` · medium
`deploy.sh:3` · confidence 70%

```
chmod 777 /var/www
```

Predictable temp files or 777 permissions invite local attacks.

**Fix:** Use secure temp APIs and least-privilege permissions.

### 🟡 Docker: runs as root or unpinned image · `SEC022` · medium
`Dockerfile:1` · confidence 60%

```
FROM python:latest
```

Container runs as root or uses an unpinned/latest base image.

**Fix:** Pin the image version/digest and add a non-root USER.

### 🟡 Docker: runs as root or unpinned image · `SEC022` · medium
`Dockerfile:2` · confidence 60%

```
USER root
```

Container runs as root or uses an unpinned/latest base image.

**Fix:** Pin the image version/digest and add a non-root USER.

### 🟡 Debug mode enabled · `SEC016` · medium
`app.py:67` · confidence 60%

```
app.run(host="0.0.0.0", debug=True)
```

Debug mode can leak stack traces and enable remote consoles in production.

**Fix:** Drive debug flags from the environment and default to off.

### 🟡 Remote script piped into a shell · `SEC023` · medium
`deploy.sh:2` · confidence 60%

```
curl -s https://example.com/install.sh | sudo bash
```

Executing a downloaded script without verifying it is risky.

**Fix:** Download, verify a checksum/signature, then run.

### 🟡 Weak hash for security purposes · `SEC012` · medium
`app.py:41` · confidence 55%

```
hashed = hashlib.md5(password.encode()).hexdigest()
```

MD5/SHA-1 are broken for passwords and signatures.

**Fix:** Use SHA-256+ (or bcrypt/argon2 for passwords).

### 🟡 Cross-site scripting sink · `SEC018` · medium
`server.js:16` · confidence 55%

```
document.getElementById('x').innerHTML = req.query.html;
```

Writing untrusted data into the DOM unescaped enables XSS.

**Fix:** Use textContent / escaping, or sanitise with a vetted library.

### 🟡 Server bound to all interfaces · `SEC017` · medium
`server.js:26` · confidence 40%

```
app.listen(3000, '0.0.0.0');
```

Listening on 0.0.0.0 exposes the service on every network interface.

**Fix:** Bind to 127.0.0.1 unless public access is intended, and put it behind a proxy.


## Slop (14)

### 🟡 Swallowed exception · `SLP001` · medium
`app.py:48` · confidence 80%

```
except: / pass
```

An error is caught and silently ignored.

**Fix:** Log it, handle it or re-raise it.

### 🟡 Swallowed exception · `SLP001` · medium
`main.go:14` · confidence 80%

```
if err != nil {
```

An error is checked and then ignored.

**Fix:** Return or log the error.

### 🟡 AI-assistant leftover / boilerplate phrase · `SLP005` · medium
`app.py:53` · confidence 70%

```
# Here is the updated code
```

Text typical of an AI assistant or unfinished scaffolding was left in the code.

**Fix:** Replace it with the real implementation or remove it.

### 🟡 AI-assistant leftover / boilerplate phrase · `SLP005` · medium
`server.js:22` · confidence 70%

```
// In a real application, you would replace this with real logic
```

Text typical of an AI assistant or unfinished scaffolding was left in the code.

**Fix:** Replace it with the real implementation or remove it.

### 🔵 Unused import · `SLP013` · low
`app.py:1` · confidence 90%

```
import os
```

`os` is imported but never used.

**Fix:** Remove the import.

### 🔵 Unused import · `SLP013` · low
`app.py:2` · confidence 90%

```
import sys
```

`sys` is imported but never used.

**Fix:** Remove the import.

### 🔵 Block of commented-out code · `SLP012` · low
`app.py:54` · confidence 60%

```
# for item in data:
```

5 consecutive comment lines look like disabled code.

**Fix:** Delete it - version control remembers.

### 🔵 Overly generic identifier · `SLP007` · low
`app.py:52` · confidence 55%

```
def process_data(data):
```

Placeholder-style names indicate unfinished or low-effort code.

**Fix:** Give it a name that says what it does.

### 🔵 Overly generic identifier · `SLP007` · low
`app.py:62` · confidence 55%

```
def helper():
```

Placeholder-style names indicate unfinished or low-effort code.

**Fix:** Give it a name that says what it does.

### 🔵 Overly generic identifier · `SLP007` · low
`server.js:21` · confidence 55%

```
function doSomething() {
```

Placeholder-style names indicate unfinished or low-effort code.

**Fix:** Give it a name that says what it does.

### 🔵 Pointless narrating comment · `SLP006` · low
`app.py:21` · confidence 45%

```
# Loop through the results
```

A comment that only restates the code is classic AI/boilerplate padding.

**Fix:** Delete it, or explain *why* instead of *what*.

### 🔵 Debug output left in code · `SLP003` · low
`server.js:11` · confidence 45%

```
console.log(out);
```

Debug statements usually should not ship.

**Fix:** Replace with proper logging or delete.

### 🔵 Pointless narrating comment · `SLP006` · low
`server.js:20` · confidence 45%

```
// This function is used to start the server
```

A comment that only restates the code is classic AI/boilerplate padding.

**Fix:** Delete it, or explain *why* instead of *what*.

### 🔵 Returns a hardcoded stub value · `SLP009` · low
`server.js:23` · confidence 40%

```
return "success";
```

A function returns a canned value that may be a stub.

**Fix:** Implement the real behaviour or mark the function clearly as a stub.


## Gaps & loose ends (14)

### 🟡 No README · `GAP020` · medium
`(repository)` · confidence 70%

The repository has no README.

**Fix:** Add a README.md.

### 🟡 No tests · `GAP022` · medium
`(repository)` · confidence 60%

Source files exist but no tests were found.

**Fix:** Add automated tests.

### 🔵 TODO / FIXME / HACK marker · `GAP001` · low
`app.py:40` · confidence 85%

```
# TODO: implement real authentication
```

An unfinished or flagged piece of work is noted in a comment.

**Fix:** Resolve it or link it to a tracked issue.

### 🔵 TODO / FIXME / HACK marker · `GAP001` · low
`deploy.sh:4` · confidence 85%

```
# HACK: skip checks for now
```

An unfinished or flagged piece of work is noted in a comment.

**Fix:** Resolve it or link it to a tracked issue.

### 🔵 TODO / FIXME / HACK marker · `GAP001` · low
`main.go:13` · confidence 85%

```
// FIXME: handle errors properly
```

An unfinished or flagged piece of work is noted in a comment.

**Fix:** Resolve it or link it to a tracked issue.

### 🔵 Unimplemented stub · `GAP002` · low
`app.py:63` · confidence 70%

```
raise NotImplementedError
```

Code path is declared but not implemented.

**Fix:** Implement it or remove the dead path.

### 🔵 Unpinned dependency · `GAP007` · low
`requirements.txt:1` · confidence 60%

```
flask
```

Dependency has no version constraint, making builds non-reproducible.

**Fix:** Pin or bound the version.

### 🔵 Unpinned dependency · `GAP007` · low
`requirements.txt:2` · confidence 60%

```
requests
```

Dependency has no version constraint, making builds non-reproducible.

**Fix:** Pin or bound the version.

### 🔵 Network call without timeout · `GAP006` · low
`app.py:47` · confidence 55%

```
return requests.get(url, verify=False).text
```

HTTP calls without a timeout can hang forever.

**Fix:** Pass an explicit timeout.

### 🔵 No LICENSE · `GAP021` · low
`(repository)` · confidence 50%

No license file found.

**Fix:** Add a LICENSE.

### 🔵 No .gitignore · `GAP023` · low
`(repository)` · confidence 50%

Missing .gitignore.

**Fix:** Add one to avoid committing build/secret files.

### 🔵 Empty function / placeholder body · `GAP003` · low
`app.py:52` · confidence 45%

```
def process_data(data):
```

Function body is empty.

**Fix:** Implement it, or document that it is an abstract hook.

### 🔵 Ignored error return · `GAP011` · low
`main.go:12` · confidence 45%

```
_, _ = os.Open("/tmp/x")
```

An error value is thrown away.

**Fix:** Handle the returned error.

### 🔵 Hardcoded localhost URL · `GAP009` · low
`server.js:17` · confidence 35%

```
fetch('http://localhost:3000/api').then(r => r.json());
```

Development URL is hardcoded.

**Fix:** Read the base URL from configuration.


---
_Generated by SlopGuard 1.0.0._
