#!/usr/bin/env python3.
"""
==============================
   License & Contact Info
==============================

GitHub   : https://github.com/oscaroffc  
WhatsApp : +6282210466813
By       : oscaroffc

"""

import os
import re
import json
import time
import socket
import argparse
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------
# Config
# -----------------------
USER_AGENT = "web-deep-extractor/1.0"
TIMEOUT = 8
MAX_PAGES = 200           # maximum pages to crawl
MAX_JS_FETCH = 200 * 1024  # 200 KB per JS/file
MAX_CONCURRENT_FETCH = 8
SESSIONS_DIR = "sessions"
ALLOWED_HOSTS_ONLY = True  # only fetch resources from same host as target
REQUEST_DELAY = 0.2        # polite crawl delay (seconds)
requests.packages.urllib3.disable_warnings()

# patterns for detecting credential-like strings
CRED_KEYWORDS = [
    "username","user","userid","login","email",
    "password","passwd","pwd","pass",
    "apikey","api_key","apiKey","token","auth","secret","client_secret"
]
# regex to extract string literals in JS/HTML attributes (single/double/backtick)
STRING_LITERAL_RE = re.compile(r"""(['"`])(?P<s>[^'"`]{3,200})\1""", re.DOTALL)
# patterns for JS assignment keywords (var/let/const/prop: value)
JS_ASSIGN_RE = re.compile(r"""(?i)\b(?:var|let|const)?\s*([A-Za-z0-9_\-]+)\s*[:=]\s*(['"`])(?P<val>[^'"`]{3,200})\2""")
# visible "Username: alice" style
VISIBLE_PAIR_RE = re.compile(r"\b(?:username|user|email|login)\b[:\s\-]{1,8}([A-Za-z0-9@._\-\+]{3,120})", flags=re.I)

# ensure sessions dir
os.makedirs(SESSIONS_DIR, exist_ok=True)

# -----------------------
# Helpers
# -----------------------
def normalize_target(raw):
    raw = (raw or "").strip()
    if not raw:
        return None
    if not urlparse(raw).scheme:
        raw = "http://" + raw
    p = urlparse(raw)
    if not p.scheme or not p.netloc:
        return None
    return f"{p.scheme}://{p.netloc}"

def gh_headers():
    return {"User-Agent": USER_AGENT, "Accept": "*/*"}

def safe_get_text(url, max_bytes=None):
    """Fetch text content with limit. Return dict with ok, status, headers, text (truncated if needed), final_url, error."""
    try:
        r = requests.get(url, headers=gh_headers(), timeout=TIMEOUT, allow_redirects=True, stream=True, verify=False)
    except Exception as e:
        return {"ok": False, "error": str(e), "url": url}
    status = r.status_code
    headers = dict(r.headers)
    final = r.url
    # read up to max_bytes safely
    text = ""
    if status == 200:
        if max_bytes:
            try:
                chunks = []
                total = 0
                for chunk in r.iter_content(chunk_size=8192, decode_unicode=True):
                    if chunk is None:
                        break
                    if isinstance(chunk, bytes):
                        try:
                            chunk = chunk.decode(errors="replace")
                        except Exception:
                            chunk = str(chunk)
                    chunks.append(chunk)
                    total += len(chunk.encode('utf-8', errors='replace'))
                    if total >= max_bytes:
                        break
                text = "".join(chunks)
            except Exception:
                try:
                    text = r.text
                except Exception:
                    text = ""
        else:
            try:
                text = r.text
            except Exception:
                text = ""
    else:
        # still try to get small text for error pages
        try:
            text = r.text[:4096]
        except Exception:
            text = ""
    return {"ok": True, "status": status, "headers": headers, "text": text, "final_url": final, "url": url}

def get_ip(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def same_host(url_a, url_b):
    try:
        return urlparse(url_a).hostname == urlparse(url_b).hostname
    except Exception:
        return False

# -----------------------
# Crawl (domain-limited BFS, conservative)
# -----------------------
def crawl_domain(base_url, max_pages=100, delay=0.2, use_sitemap=True):
    parsed = urlparse(base_url)
    base_root = f"{parsed.scheme}://{parsed.netloc}"
    to_visit = [base_root]
    seen = set()
    pages = []  # list of dicts: url, final_url, status, headers, text
    # try sitemap
    if use_sitemap:
        s_result = safe_get_text(urljoin(base_root, "/sitemap.xml"))
        if s_result.get("ok") and "xml" in (s_result.get("headers",{}).get("Content-Type","")):
            try:
                soup = BeautifulSoup(s_result["text"], "xml")
                for loc in soup.find_all("loc"):
                    u = (loc.text or "").strip()
                    if u and urlparse(u).netloc == parsed.netloc and u not in to_visit:
                        to_visit.append(u)
            except Exception:
                pass
    while to_visit and len(pages) < max_pages:
        u = to_visit.pop(0)
        if u in seen:
            continue
        seen.add(u)
        res = safe_get_text(u)
        if not res.get("ok"):
            # record error entry
            pages.append({"url": u, "final_url": res.get("url"), "status": None, "headers": {}, "text": "", "error": res.get("error")})
            continue
        # record
        pages.append({"url": u, "final_url": res.get("final_url"), "status": res.get("status"), "headers": res.get("headers"), "text": res.get("text")})
        # if HTML, extract same-host links
        ct = (res.get("headers") or {}).get("Content-Type","").lower()
        if "text/html" in ct and res.get("text"):
            soup = BeautifulSoup(res["text"], "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith("mailto:") or href.startswith("javascript:"):
                    continue
                full = urljoin(u, href)
                # only same host
                if same_host(full, base_root) and full not in seen and full not in to_visit and len(pages)+len(to_visit) < max_pages:
                    to_visit.append(full)
        time.sleep(delay)
    return pages

# -----------------------
# Extract scripts and resources
# -----------------------
def extract_js_urls_from_html(html, base_url):
    soup = BeautifulSoup(html or "", "html.parser")
    urls = []
    # external script tags
    for s in soup.find_all("script", src=True):
        src = s.get("src").strip()
        try:
            full = urljoin(base_url, src)
            urls.append(full)
        except Exception:
            continue
    # also consider inline scripts content separately (return empty for urls)
    return list(dict.fromkeys(urls))  # unique

# -----------------------
# Scan text for credential-like literals
# -----------------------
def scan_for_credentials(text):
    """Return list of findings: {'type': 'js_literal'|'visible_text'|'input_default', 'key','value','context_snippet'}"""
    findings = []
    if not text:
        return findings
    # 1) visible patterns e.g. 'Username: alice'
    for m in VISIBLE_PAIR_RE.finditer(text):
        val = m.group(1).strip()
        findings.append({"type":"visible_text","label":m.group(0).split()[0],"value":val,"snippet":m.group(0)[:200]})
    # 2) JS assignments / object properties e.g. var user = "admin";  password: "123"
    for m in JS_ASSIGN_RE.finditer(text):
        varname = m.group(1)
        val = m.group("val")
        low = varname.lower()
        if any(k in low for k in CRED_KEYWORDS) or any(k in val.lower() for k in CRED_KEYWORDS):
            findings.append({"type":"js_literal","key":varname,"value":val,"snippet":m.group(0)[:200]})
    # 3) any string literal that contains credential keywords near it
    for m in STRING_LITERAL_RE.finditer(text):
        s = m.group("s").strip()
        # check if nearby keyword or string itself contains keyword
        low = s.lower()
        if any(k in low for k in CRED_KEYWORDS):
            findings.append({"type":"string_literal","value":s,"snippet":s[:200]})
    return findings

# -----------------------
# Main analysis orchestration
# -----------------------
def analyze_target(base_url, max_pages=100, max_js_fetch=MAX_JS_FETCH, concurrent_fetch=8):
    base = normalize_target(base_url)
    if not base:
        raise ValueError("Invalid target URL")
    parsed = urlparse(base)
    host = parsed.hostname
    ip = get_ip(host)
    started = datetime.utcnow().isoformat() + "Z"

    report = {
        "target": base,
        "host": host,
        "ip": ip,
        "started_at": started,
        "pages": [],    # each page: url, status, headers, forms, findings, js_urls
        "js_fetched": [],  # each js: url, status, findings
        "aggregate_findings": []
    }

    pages = crawl_domain(base, max_pages=max_pages, delay=REQUEST_DELAY, use_sitemap=True)
    # collect external JS urls to fetch (same-host only by default)
    js_urls = set()
    for p in pages:
        entry = {"url": p.get("url"), "final_url": p.get("final_url"), "status": p.get("status"), "headers": p.get("headers"), "forms": [], "findings":[]}
        text = p.get("text") or ""
        # forms
        try:
            soup = BeautifulSoup(text, "html.parser")
            for form in soup.find_all("form"):
                form_info = {"method": (form.get("method") or "GET").upper(), "action_raw": form.get("action") or "", "action": urljoin(p.get("final_url") or base, form.get("action") or "")}
                inputs = []
                for inp in form.find_all(["input","textarea","select"]):
                    inputs.append({"name": inp.get("name"), "type": (inp.get("type") or inp.name or "text").lower(), "value": inp.get("value"), "placeholder": inp.get("placeholder")})
                form_info["inputs"] = inputs
                # analyze form (simple flags)
                form_issues = []
                if form_info["method"] == "GET":
                    form_issues.append("uses GET")
                if form_info["action"].lower().startswith("http://"):
                    form_issues.append("action uses http://")
                if ALLOWED_HOSTS_ONLY:
                    try:
                        if urlparse(form_info["action"]).hostname and urlparse(form_info["action"]).hostname != host:
                            form_issues.append("posts to external host")
                    except Exception:
                        pass
                # detect password/username and default values
                for inp in inputs:
                    if (inp.get("type") or "").lower() == "password":
                        form_issues.append("contains password input")
                    nm = (inp.get("name") or "").lower()
                    if nm and any(k in nm for k in ("user","email","login","loginid","userid")):
                        form_issues.append(f"username-like input name='{inp.get('name')}'")
                    if inp.get("value"):
                        form_issues.append(f"default value present for '{inp.get('name')}'")
                form_info["issues"] = list(dict.fromkeys(form_issues))
                entry["forms"].append(form_info)
        except Exception:
            pass

        # find inline JS and visible credential-like text
        inline_js_texts = []
        try:
            soup = BeautifulSoup(text, "html.parser")
            for script in soup.find_all("script"):
                if script.get("src"):
                    src = urljoin(p.get("final_url") or base, script.get("src"))
                    if not ALLOWED_HOSTS_ONLY or same_host(src, base):
                        js_urls.add(src)
                else:
                    if script.string:
                        inline_js_texts.append(script.string)
        except Exception:
            pass

        # scan inline JS & page text for credentials
        findings = []
        # scan visible/page text
        findings.extend(scan_for_credentials(text))
        # scan inline scripts
        for js in inline_js_texts:
            findings.extend(scan_for_credentials(js))
        # dedupe by value+type
        dedup = []
        seen = set()
        for f in findings:
            key = (f.get("type"), f.get("key") or f.get("label") or f.get("value"))
            if key not in seen:
                dedup.append(f)
                seen.add(key)
        entry["findings"] = dedup
        if dedup:
            for d in dedup:
                report["aggregate_findings"].append({"source_page": p.get("url"), **d})
        report["pages"].append(entry)

    # fetch external JS in parallel (same-host only unless ALLOWED_HOSTS_ONLY False)
    js_urls = [u for u in js_urls if u]
    js_fetched = []
    def fetch_js(u):
        # ignore too-big resources by head-check (optional)
        # perform safe get text truncated
        if ALLOWED_HOSTS_ONLY and not same_host(u, base):
            return {"url": u, "skipped":"different-host"}
        res = safe_get_text(u, max_bytes=max_js_fetch)
        if not res.get("ok"):
            return {"url": u, "ok": False, "error": res.get("error")}
        txt = res.get("text") or ""
        findings = scan_for_credentials(txt)
        return {"url": u, "ok": True, "status": res.get("status"), "findings": findings, "final_url": res.get("final_url")}

    if js_urls:
        with ThreadPoolExecutor(max_workers=concurrent_fetch) as ex:
            futures = {ex.submit(fetch_js, u): u for u in js_urls}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                except Exception as e:
                    r = {"url": futures[fut], "ok": False, "error": str(e)}
                js_fetched.append(r)
                # aggregate findings
                if r.get("ok") and r.get("findings"):
                    for f in r.get("findings"):
                        report["aggregate_findings"].append({"source_js": r.get("url"), **f})
    report["js_fetched"] = js_fetched
    # dedupe aggregate findings
    # final processing: reduce duplicates
    unique = []
    seen_vals = set()
    for f in report["aggregate_findings"]:
        val = (f.get("type"), f.get("key") or f.get("label") or f.get("value"))
        if val not in seen_vals:
            unique.append(f)
            seen_vals.add(val)
    report["aggregate_findings"] = unique
    return report

# -----------------------
# Save report
# -----------------------
def save_report(report):
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_host = (report.get("host") or "unknown").replace(":", "_")
    txt_path = os.path.join(SESSIONS_DIR, f"{safe_host}_{ts}.txt")
    json_path = os.path.join(SESSIONS_DIR, f"{safe_host}_{ts}.json")

    lines = []
    lines.append(f"WEB DEEP EXTRACTOR REPORT for {report.get('target')}")
    lines.append(f"IP: {report.get('ip')}  time: {report.get('started_at')}")
    lines.append("\n-- Pages fetched --")
    for p in report.get("pages", []):
        lines.append(f"{p.get('url')}  status={p.get('status')}")
        hdrs = p.get("headers") or {}
        lines.append(f"  Server: {hdrs.get('Server')}  X-Powered-By: {hdrs.get('X-Powered-By')}  Content-Type: {hdrs.get('Content-Type')}")
        if p.get("forms"):
            for f in p.get("forms", []):
                lines.append(f"    FORM: method={f.get('method')} action={f.get('action')} issues={f.get('issues')}")
                for inp in f.get("inputs", []):
                    lines.append(f"      - input name={inp.get('name')} type={inp.get('type')} value_present={bool(inp.get('value'))}")
        if p.get("findings"):
            for ff in p.get("findings"):
                lines.append(f"    FINDING (page): {ff}")
    lines.append("\n-- JS fetched --")
    for j in report.get("js_fetched", [])[:200]:
        lines.append(f"  {j.get('url')} status={j.get('status')} ok={j.get('ok')} skipped={j.get('skipped') if 'skipped' in j else ''}")
        if j.get("findings"):
            for ff in j.get("findings"):
                lines.append(f"    FINDING (js): {ff}")
    lines.append("\n-- Aggregate findings --")
    if report.get("aggregate_findings"):
        for a in report["aggregate_findings"]:
            lines.append(f" - {a}")
    else:
        lines.append("No credential-like strings detected in public sources.")

    try:
        with open(txt_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        return txt_path, json_path
    except Exception as e:
        return None, None

# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Web Deep Extractor (passive, read-only).")
    parser.add_argument("--target", "-t", help="Target URL or host (eg https://example.com)")
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES)
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--allow-cross-host-js", action="store_true", help="Allow fetching JS from other hosts (use carefully)")
    args = parser.parse_args()

    target = args.target or input("Target URL or host (e.g. https://example.com): ").strip()
    target = normalize_target(target)
    if not target:
        print("Invalid target. Exiting.")
        return
    print("\n*** IMPORTANT: confirm you have EXPLICIT permission to analyze this target (type YES) ***")
    if input("> ").strip().upper() != "YES":
        print("Permission not confirmed. Aborting.")
        return

    global ALLOWED_HOSTS_ONLY
    if args.allow_cross_host_js:
        ALLOWED_HOSTS_ONLY = False

    print(f"[info] Analyzing {target} (max_pages={args.max_pages}) ...")
    report = analyze_target(target, max_pages=args.max_pages, max_js_fetch=MAX_JS_FETCH, concurrent_fetch=MAX_CONCURRENT_FETCH)
    print("[info] Analysis complete. Found", len(report.get("aggregate_findings", [])), "aggregate findings.")

    if not args.no_save:
        txt_path, json_path = save_report(report)
        if txt_path:
            print(f"[ok] Report saved: {txt_path}")
            print(f"[ok] JSON saved:   {json_path}")
        else:
            print("[err] Failed to save report.")
    else:
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
