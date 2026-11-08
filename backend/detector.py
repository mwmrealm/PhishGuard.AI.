"""
detector.py — Phishing Email Detection Engine
Combines hand-crafted rules with a real ML model (TF-IDF + Logistic Regression).
The ML model trains once on phishing_email.csv and caches to model.pkl.
"""

import re
import os
import csv
import sys
import pickle
import urllib.parse

# Raise CSV field size limit (some emails are very long)
# 100MB is plenty for any email; avoids Windows overflow
try:
    csv.field_size_limit(100_000_000)
except Exception:
    pass

# ----------------------------------------------------------------------
#  Knowledge base
# ----------------------------------------------------------------------

TRUSTED = {
    "paypal": "paypal.com", "google": "google.com", "apple": "apple.com",
    "amazon": "amazon.com", "microsoft": "microsoft.com", "facebook": "facebook.com",
    "netflix": "netflix.com", "chase": "chase.com", "wellsfargo": "wellsfargo.com",
    "citibank": "citibank.com", "hsbc": "hsbc.com", "bankofamerica": "bankofamerica.com",
    "linkedin": "linkedin.com", "dropbox": "dropbox.com", "instagram": "instagram.com",
}

FREE_MAIL = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
             "icloud.com", "protonmail.com", "zoho.com", "mail.com", "yandex.com",
             "163.com", "qq.com", "live.com", "msn.com"}

SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "cutt.ly",
              "rb.gy", "ow.ly", "buff.ly", "tiny.cc", "s.id", "rebrand.ly"}

URGENCY = [
    "act now", "account suspended", "verify your identity", "verify your account",
    "urgent", "immediately", "within 24 hours", "final notice", "reactivate",
    "limited time", "you have won", "unusual activity", "account locked",
    "security alert", "claim your", "payment failed", "update your",
    "click here", "confirm your", "login now", "expires today", "password expired",
]

SENSITIVE = [
    "password", "credit card", "card number", "cvv", "ssn", "social security",
    "bank account", "routing number", "gift card", "bitcoin", "atm pin",
    "verify your identity", "update payment", "wire transfer", "itunes card",
]

MISSPELLINGS = ["verifiy", "acount", "recieve", "securty", "passwrod", "responce",
                "informatiion", "enail", "payemnt", "loging", "unsesual",
                "attentiion", "immediatley", "confirmaton"]

DANGEROUS_ATTACH = [".exe", ".scr", ".bat", ".js", ".zip", ".rar", ".lnk", ".vbs", ".cmd"]

# ----------------------------------------------------------------------
#  Parsing helpers
# ----------------------------------------------------------------------

def get_domain(addr):
    m = re.search(r"@([\w.\-]+)", addr or "")
    return m.group(1).lower() if m else None


def get_display_name(addr):
    m = re.match(r"^([^<@]+?)\s*<", addr or "")
    if m:
        name = m.group(1).strip().strip('"')
        return name.lower() if name else None
    return None


def extract_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", "ignore")
                except Exception:
                    continue
    else:
        try:
            body = msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8", "ignore")
        except Exception:
            body = msg.get_payload() or ""
    return body.replace("=\r\n", "").replace("=20", " ").replace("=3D", "=").replace("=0A", "\n")


def parse_email(text):
    from email import policy
    from email.parser import Parser
    info = {"subject": "", "from": "", "reply_to": "", "body": text, "has_headers": False,
            "received": [], "auth_results": ""}
    try:
        msg = Parser(policy=policy.default).parsestr(text)
    except Exception:
        return info
    if not msg.keys():
        return info
    info["has_headers"] = True
    info["subject"] = msg.get("Subject", "")
    info["from"] = msg.get("From", "")
    info["reply_to"] = msg.get("Reply-To", "")
    info["body"] = extract_body(msg)
    info["received"] = msg.get_all("Received", [])
    info["auth_results"] = msg.get("Authentication-Results", "")
    return info


def domain_parts(host):
    try:
        import tldextract
        ex = tldextract.extract(host)
        return ex.domain, ex.suffix
    except Exception:
        parts = host.split(".")
        if len(parts) >= 2:
            return parts[-2], parts[-1]
        return parts[0], ""


def check_lookalike(host):
    dom, suf = domain_parts(host)
    for brand, official in TRUSTED.items():
        off_suffix = ".".join(official.split(".")[1:])
        if dom == brand and suf != off_suffix:
            return True, brand
        if brand in host and host != official and not host.endswith("." + official):
            return True, brand
    return False, None


def is_ip(host):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)) or host == "localhost"

# ----------------------------------------------------------------------
#  Rule-based analysis
# ----------------------------------------------------------------------

def analyze_rules(text):
    info = parse_email(text)
    reasons, cats, urls = [], {}, []
    score = 0
    low = (info["subject"] + " " + info["body"]).lower()

    def add(cat, pts, reason):
        nonlocal score
        score += pts
        cats[cat] = cats.get(cat, 0) + pts
        reasons.append(reason)

    s_domain = get_domain(info["from"])
    r_domain = get_domain(info["reply_to"])
    if s_domain and r_domain and s_domain != r_domain:
        add("Header", 3, f"Sender ({s_domain}) and Reply-To ({r_domain}) domains do not match")

    dname = get_display_name(info["from"])
    if dname and s_domain:
        for brand in TRUSTED:
            if brand in dname and s_domain in FREE_MAIL:
                add("Spoof", 3, f"Display name claims \"{brand}\" but domain is free mail ({s_domain})")
                break

    url_list = re.findall(r"https?://[^\s<>\"']+", info["body"])
    ip_count = short_count = lookalike_count = 0
    for u in url_list:
        host = (urllib.parse.urlparse(u).hostname or "").lower()
        entry = {"url": u, "flag": "Seems normal"}
        if not host:
            continue
        if is_ip(host):
            ip_count += 1
            entry["flag"] = "IP address"
        else:
            base = ".".join(domain_parts(host))
            if host in SHORTENERS or base in SHORTENERS:
                short_count += 1
                entry["flag"] = "Shortened link"
            else:
                lo, brand = check_lookalike(host)
                if lo:
                    lookalike_count += 1
                    entry["flag"] = f"Lookalike domain (fake {brand})"
                elif urllib.parse.urlparse(u).scheme != "https" and any(k in low for k in ("login", "verify", "signin", "secure")):
                    entry["flag"] = "Non-secure login/verify link"
        urls.append(entry)

    for m in re.finditer(r"\[([^\]]+)\]\((https?://[^)]+)\)", info["body"]):
        label = m.group(1).lower()
        url_host = (urllib.parse.urlparse(m.group(2)).hostname or "").lower()
        for brand, official in TRUSTED.items():
            if brand in label and brand not in url_host:
                add("URL", 3, f"Link text says \"{brand}\" but the URL goes to {url_host}")
                urls.append({"url": m.group(2), "flag": "Text/URL mismatch"})
                break

    if ip_count:
        add("URL", 2, f"IP-address URL ({ip_count})")
    if short_count:
        add("URL", 1, f"Shortened link ({short_count})")
    if lookalike_count:
        add("URL", 3, f"Lookalike domain ({lookalike_count})")

    matched_urg = [k for k in URGENCY if k in low]
    if matched_urg:
        pts = 1 + min(len(matched_urg), 3)
        add("Urgency", pts, f"Pressure language: \"{matched_urg[0]}\"" + (f" (+{len(matched_urg)-1} more)" if len(matched_urg) > 1 else ""))

    matched_sens = [k for k in SENSITIVE if k in low]
    if matched_sens:
        add("Sensitive", min(len(matched_sens), 4), f"Asks for sensitive data: {', '.join(matched_sens[:3])}")

    found_att = [a for a in DANGEROUS_ATTACH if a in low]
    if found_att:
        add("Attachment", 2, f"Dangerous attachment: {', '.join(found_att)}")

    miss = [m for m in MISSPELLINGS if m in low]
    if miss:
        add("Spelling", min(len(miss), 3), f"Possible misspellings: {', '.join(miss[:3])}")

    if info.get("has_headers") and info.get("received"):
        auth = (info.get("auth_results") or "").lower()
        if not any(k in auth for k in ("spf=pass", "dkim=pass", "dmarc=pass")):
            add("Auth", 1, "No SPF/DKIM/DMARC authentication found")

    verdict = "SAFE" if score <= 2 else ("SUSPICIOUS" if score <= 5 else "DANGEROUS")
    if not reasons:
        reasons.append("No obvious phishing indicators found")

    return {
        "subject": info["subject"], "from": info["from"], "reply_to": info["reply_to"],
        "score": score, "verdict": verdict, "reasons": reasons,
        "cats": cats, "urls": urls,
    }

# ----------------------------------------------------------------------
#  AI / ML model (TF-IDF + Logistic Regression)
# ----------------------------------------------------------------------

_MODEL = None
_MODEL_READY = False


def _find_csv():
    """Search this folder AND parent folders for a CSV dataset."""
    names = ("phishing_email.csv", "phishing.csv", "dataset.csv",
             "CEAS_08.csv", "Enron.csv", "Nazario.csv")
    base = os.path.dirname(os.path.abspath(__file__))
    # search this folder, then up to 3 parent levels
    for depth in range(4):
        folder = base if depth == 0 else os.path.dirname(base)
        if depth > 0:
            base = folder
        for name in names:
            p = os.path.join(folder, name)
            if os.path.exists(p):
                print(f"[AI] Found CSV: {p}")
                return p
        base = folder
    print("[AI] No CSV dataset found in this or parent folders.")
    return None


def load_or_train():
    """Train the ML model on first run; cache to model.pkl."""
    global _MODEL, _MODEL_READY
    if _MODEL_READY:
        return _MODEL is not None

    pkl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl")
    if os.path.exists(pkl_path):
        try:
            with open(pkl_path, "rb") as f:
                _MODEL = pickle.load(f)
            _MODEL_READY = True
            print("[AI] Loaded cached model from model.pkl")
            return True
        except Exception as e:
            print(f"[AI] Could not load model.pkl: {e}")

    csv_path = _find_csv()
    if not csv_path:
        _MODEL_READY = True
        return False

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        print("[AI] scikit-learn imported OK")
    except Exception as e:
        print(f"[AI] scikit-learn not available: {e}")
        _MODEL_READY = True
        return False

    texts, labels = [], []
    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)
        print(f"[AI] CSV loaded: {len(rows)} rows, header = {rows[0] if rows else 'EMPTY'}")
        header = rows[0]
        text_col = label_col = None
        for i, h in enumerate(header):
            hl = h.strip().lower()
            if text_col is None and any(k in hl for k in ("text", "email", "body", "message", "content")):
                text_col = i
            if label_col is None and any(k in hl for k in ("label", "class", "is_phish", "spam", "type")):
                label_col = i
        print(f"[AI] text column = {text_col}, label column = {label_col}")
        if text_col is None:
            print("[AI] No text column found — cannot train.")
            _MODEL_READY = True
            return False
        for row in rows[1:]:
            if len(row) <= text_col:
                continue
            t = row[text_col].strip()
            if not t:
                continue
            texts.append(t)
            if label_col is not None and len(row) > label_col:
                try:
                    labels.append(int(float(row[label_col])))
                except Exception:
                    labels.append(0)
            else:
                labels.append(0)
        print(f"[AI] Parsed {len(texts)} emails, labels = {set(labels)}")
    except Exception as e:
        print(f"[AI] Error reading CSV: {e}")
        _MODEL_READY = True
        return False

    if len(texts) < 50 or len(set(labels)) < 2:
        print(f"[AI] Not enough data to train (need 50+ rows with 2 labels, got {len(texts)})")
        _MODEL_READY = True
        return False

    try:
        print("[AI] Training model... (this takes 10-30 seconds)")
        pipe = Pipeline([
            ("tfidf", TfidfVectorizer(stop_words="english", max_features=5000, ngram_range=(1, 2))),
            ("clf", LogisticRegression(max_iter=1000)),
        ])
        pipe.fit(texts, labels)
        _MODEL = pipe
        with open(pkl_path, "wb") as f:
            pickle.dump(pipe, f)
        _MODEL_READY = True
        print("[AI] Model trained and saved to model.pkl ✅")
        return True
    except Exception as e:
        print(f"[AI] Training failed: {e}")
        _MODEL_READY = True
        return False


def ai_predict(text):
    """Return (is_phishing_probability, model_ready). Probability 0..1."""
    if not load_or_train() or _MODEL is None:
        return None, False
    try:
        proba = _MODEL.predict_proba([text])[0]
        classes = list(_MODEL.classes_)
        if 1 in classes:
            return float(proba[classes.index(1)]), True
        return float(1.0 - proba[0]), True
    except Exception:
        return None, False

# ----------------------------------------------------------------------
#  Combined result
# ----------------------------------------------------------------------

def analyze(text):
    rule = analyze_rules(text)
    ai_prob, ai_ready = ai_predict(text)

    # The supplied model can be overconfident; it must not label a message
    # dangerous without independent rule-based evidence.
    if ai_prob is not None:
        final = rule["verdict"]
        if final == "SAFE" and ai_prob >= 0.9:
            final = "SUSPICIOUS"
            rule["reasons"].append(
                "The AI model flagged this message, but no rule-based warning signs were found"
            )
        elif final == "SUSPICIOUS" and ai_prob >= 0.95:
            final = "DANGEROUS"
    else:
        final = rule["verdict"]

    rule["ai_prob"] = ai_prob
    rule["ai_ready"] = ai_ready
    rule["final_verdict"] = final
    return rule

# ----------------------------------------------------------------------
#  Samples
# ----------------------------------------------------------------------

SAMPLE_PHISH = """From: security@paypa1-secure.com
Reply-To: refunds@gmail.com
Subject: Urgent: Your account has been suspended

Dear Customer,
Your PayPal account has been suspended due to unusual activity. Verify your identity immediately to avoid permanent closure within 24 hours.
Click here to login and confirm: http://paypa1-login.com/verify
Enter your password and credit card number to reactivate. Act now before your account is locked forever.
"""

SAMPLE_SAFE = """From: alex@university.edu
Subject: Meeting notes

Hi,
Thanks for the meeting today. Please review the attached notes and give me your feedback by Friday.
Best,
Alex
"""
