# ReconLens Analyzers Documentation

Comprehensive list of all 23 URL analyzers available in ReconLens.

---

## Quick Reference

| # | Analyzer | Category | Description |
|---|----------|----------|-------------|
| 1 | [api_endpoints](#api_endpoints) | Recon | Detect API endpoint URLs |
| 2 | [backup_files](#backup_files) | Recon | Detect backup/temp files |
| 3 | [crlf](#crlf) | Vuln | CRLF injection candidates |
| 4 | [debug](#debug) | Info | Debug/info disclosure endpoints |
| 5 | [documents](#documents) | Recon | Document files (PDF, Word, etc) |
| 6 | [emails](#emails) | Recon | URLs containing email addresses |
| 7 | [idor](#idor) | Vuln | Insecure Direct Object Reference |
| 8 | [js_files](#js_files) | Recon | JavaScript files for secrets |
| 9 | [jwt](#jwt) | Recon | URLs containing JWT tokens |
| 10 | [lfi](#lfi) | Vuln | Local File Inclusion params |
| 11 | [open_redirect](#open_redirect) | Vuln | Open redirect params |
| 12 | [params](#params) | Recon | Unique parameters collection |
| 13 | [rce](#rce) | Vuln | Remote Code Execution params |
| 14 | [robots](#robots) | Recon | robots.txt files |
| 15 | [sensitive_params](#sensitive_params) | Recon | Sensitive query params |
| 16 | [sensitive_paths](#sensitive_paths) | Recon | Admin/login/debug paths |
| 17 | [sqli](#sqli) | Vuln | SQL Injection params |
| 18 | [ssrf](#ssrf) | Vuln | Server-Side Request Forgery |
| 19 | [ssti](#ssti) | Vuln | Server-Side Template Injection |
| 20 | [upload](#upload) | Vuln | File upload endpoints |
| 21 | [websocket](#websocket) | Recon | WebSocket endpoints |
| 22 | [xss](#xss) | Vuln | Cross-Site Scripting params |
| 23 | [xxe](#xxe) | Vuln | XML External Entity |

---

## Vulnerability Analyzers

### api_endpoints
**File:** `analyzers/api_endpoints.py`  
**Output:** `api_endpoints.txt`

Detects API endpoint URLs for further testing.

**Matches:**
- Path patterns: `/api/`, `/v1/`, `/rest/`, `/graphql`, etc.
- Extensions: `.json`, `.xml`
- Framework-specific: `/wp-json/`, `/_next/data/`

---

### backup_files
**File:** `analyzers/backup_files.py`  
**Output:** `backup_files.txt`

Detects backup and temporary files that may expose source code.

**Matches:**
- Extensions: `.bak`, `.old`, `.backup`, `.tmp`, `.swp`, `.tar`, `.gz`, `.zip`
- Paths: `.git/`, `.svn/`, `backup/`, `old/`
- Patterns: `_backup`, `-old`, `~` suffix

---

### crlf
**File:** `analyzers/crlf.py`  
**Output:** `crlf_candidates.txt`

Detects CRLF injection candidates.

**Target params:** `url`, `redirect`, `location`, `header`, `host`, `origin`, `cookie`

---

### debug
**File:** `analyzers/debug.py`  
**Output:** `debug_endpoints.txt`

Detects debug and info disclosure endpoints.

**Matches:**
- PHP: `/phpinfo`, `/info.php`, `/test.php`
- Debug: `/debug`, `/trace`, `/profiler`, `/console`
- Status: `/status`, `/health`, `/metrics`, `/actuator`
- Config: `/env`, `.env`, `/config`
- Logs: `/log`, `/logs`, `/error`
- Tools: `/_debugbar`, `/_profiler`, `/telescope`

---

### documents
**File:** `analyzers/documents.py`  
**Output:** `documents.txt`

Detects URLs pointing to sensitive document files.

**Extensions:** `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.csv`, `.sql`, `.db`, `.sqlite`, `.bak`

---

### emails
**File:** `analyzers/emails.py`  
**Output:** `emails.txt`

Detects URLs containing email addresses with validation.

---

### idor
**File:** `analyzers/idor.py`  
**Output:** `idor_candidates.txt`

Detects Insecure Direct Object Reference vulnerabilities.

**Matches:**
- Numeric IDs in params: `?id=123`, `?user_id=456`
- UUIDs in params
- Numeric IDs in paths: `/user/123/orders`

**Target params:** `id`, `uid`, `user_id`, `account_id`, `order_id`, `file_id`, `document_id`, `org_id`, etc.

---

### js_files
**File:** `analyzers/js_files.py`  
**Output:** `js_files.txt`

Detects JavaScript files for secrets hunting.

**Extensions:** `.js`, `.mjs`, `.jsx`, `.ts`, `.tsx`, `.map`

**Metadata:**
- `is_minified`: Minified files
- `is_bundle`: Bundle/chunk files
- `is_vendor`: Vendor/node_modules
- `is_source_map`: Source maps

---

### jwt
**File:** `analyzers/jwt.py`  
**Output:** `jwt_candidates.txt`

Detects URLs containing JWT tokens with header validation.

**Validates:** Base64 header with `alg` and `typ` fields.

---

### lfi
**File:** `analyzers/lfi.py`  
**Output:** `lfi_candidates.txt`

Detects Local File Inclusion vulnerabilities.

**Target params:** `file`, `filename`, `path`, `include`, `page`, `template`, `read`, `load`, `log`, `config`, `lang`

**Detects:**
- Path traversal: `../`
- System paths: `/etc/`, `c:\`

---

### open_redirect
**File:** `analyzers/open_redirect.py`  
**Output:** `open_redirect_candidates.txt`

Detects open redirect vulnerabilities.

**Target params:** `url`, `next`, `redirect`, `return`, `continue`, `callback`, `dest`, `target`, `go`, `link`, `redir`, `path`

**Metadata:** Detects if values contain URLs.

---

### params
**File:** `analyzers/params.py`  
**Output:** `params.txt`

Collects unique parameter names (excluding noise).

**Excludes:**
- Cache busters: `_`, `cb`, `v`, `timestamp`
- UTM tracking: `utm_source`, `utm_medium`, etc.
- Social tracking: `gclid`, `fbclid`
- Analytics: `_ga`, `_gl`

---

### rce
**File:** `analyzers/rce.py`  
**Output:** `rce_candidates.txt`

Detects Remote Code Execution vulnerabilities.

**Target params:** `cmd`, `command`, `exec`, `execute`, `run`, `shell`, `code`, `eval`, `system`, `ping`, `script`, `payload`

---

### robots
**File:** `analyzers/robots.py`  
**Output:** `robots.txt`

Detects URLs pointing to robots.txt files.

---

### sensitive_params
**File:** `analyzers/sensitive_params.py`  
**Output:** `sensitive_params.txt`

Detects URLs with sensitive query parameters.

**Target params:** `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, `auth`, `session`, `private_key`

---

### sensitive_paths
**File:** `analyzers/sensitive_paths.py`  
**Output:** `sensitive_paths.txt`

Detects URLs with admin, login, debug paths.

**Categories:**
- Admin: `/admin`, `/administrator`, `/manage`, `/dashboard`
- Auth: `/login`, `/signin`, `/auth`, `/register`
- Debug: `/debug`, `/test`, `/dev`, `/staging`
- Config: `/config`, `/settings`, `/setup`

---

### sqli
**File:** `analyzers/sqli.py`  
**Output:** `sqli_candidates.txt`

Detects SQL Injection vulnerabilities.

**Target params:** `id`, `search`, `query`, `q`, `sort`, `order`, `filter`, `select`, `column`, `table`, `category`, `date`

---

### ssrf
**File:** `analyzers/ssrf.py`  
**Output:** `ssrf_candidates.txt`

Detects Server-Side Request Forgery vulnerabilities.

**Target params:** `url`, `uri`, `host`, `server`, `target`, `fetch`, `load`, `proxy`, `callback`, `webhook`, `img`, `src`, `api`

**Detects:**
- URL values: `http://`, `https://`
- Internal IPs: `127.0.0.1`, `localhost`, `192.168.`, `10.`

---

### ssti
**File:** `analyzers/ssti.py`  
**Output:** `ssti_candidates.txt`

Detects Server-Side Template Injection vulnerabilities.

**Target params:** `template`, `tpl`, `layout`, `theme`, `view`, `render`, `email_template`, `content`, `format`, `lang`

---

### upload
**File:** `analyzers/upload.py`  
**Output:** `upload_endpoints.txt`

Detects file upload endpoints.

**Matches:**
- Paths: `/upload`, `/uploads`, `/file-upload`, `/attachment`, `/import`
- Params: `file`, `files`, `upload`, `attachment`, `image`, `avatar`

---

### websocket
**File:** `analyzers/websocket.py`  
**Output:** `websocket_endpoints.txt`

Detects WebSocket endpoints.

**Matches:** `/ws`, `/websocket`, `/socket.io`, `/sockjs`, `/signalr`, `/realtime`, `/live`, `/stream`, `/graphql-ws`

---

### xss
**File:** `analyzers/xss.py`  
**Output:** `xss_candidates.txt`

Detects Cross-Site Scripting vulnerabilities.

**Target params:** `q`, `query`, `search`, `message`, `text`, `comment`, `name`, `title`, `error`, `callback`, `html`

---

### xxe
**File:** `analyzers/xxe.py`  
**Output:** `xxe_candidates.txt`

Detects XML External Entity vulnerabilities.

**Matches:**
- Extensions: `.xml`, `.xsl`, `.dtd`, `.svg`, `.soap`, `.wsdl`
- Paths: `/soap`, `/wsdl`, `/xml`, `/rss`, `/feed`, `/sitemap`
- Params: `xml`, `xmldata`, `soap`, `wsdl`, `import`

---

## Usage

### API

```bash
# List all analyzers
curl http://localhost:8000/api/v2/analyzers

# Run single analyzer
curl -X POST "http://localhost:8000/api/v2/analyzers/{scope}/{analyzer}/run"

# Run all analyzers
curl -X POST "http://localhost:8000/api/v2/analyzers/{scope}/run-all"

# Get results
curl "http://localhost:8000/api/v2/analyzers/{scope}/results"
```

### Python

```python
from analyzers import get_analyzer, list_analyzers
from core.types import Target

# List all
print(list_analyzers())  # 23 analyzers

# Run one
analyzer = get_analyzer("open_redirect")
target = Target(scope="example.com")
result = analyzer.analyze(urls, target)
print(f"Found {result.match_count} matches")
```

---

*Last updated: December 2025*
