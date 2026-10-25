import ipaddress
import re
from urllib.parse import urlparse

import streamlit as st


SUSPICIOUS_TERMS = {
    "login", "verify", "update", "secure", "account",
    "password", "bank", "confirm", "signin", "wallet",
    "payment", "urgent", "support"
}
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "shorturl.at", "rb.gy", "ow.ly"
}
SUSPICIOUS_TLDS = {".zip", ".mov", ".click", ".top", ".work", ".gq", ".tk"}


def normalize_url(raw_url: str):

    raw_url = raw_url.strip()
    if not raw_url:
        return None, 

    if any(ch.isspace() for ch in raw_url):
        return None, 

    candidate = raw_url if re.match(r"^https?://", raw_url, re.I) else "https://" + raw_url

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
 
        _ = parsed.port
    except ValueError:
        return None, 

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return None, 

    if "." not in hostname and hostname.lower() != "localhost":
        return None, 

    return parsed, None


def analyze_url(raw_url: str):

    parsed, error = normalize_url(raw_url)
    if error:
        return {"error": error}

    url = parsed.geturl()
    host = (parsed.hostname or "").lower()
    reasons = []
    score = 0


    if parsed.scheme.lower() == "http":
        score += 1
        reasons.append(("Low", "The URL uses HTTP rather than HTTPS."))


    try:
        ipaddress.ip_address(host)
        score += 2
        reasons.append(("Medium", "The host is an IP address instead of a domain name."))
    except ValueError:
        pass


    if parsed.username is not None or "@" in parsed.netloc:
        score += 2
        reasons.append(("High", "The URL contains user-info or an '@' symbol that may disguise the destination."))


    if "xn--" in host:
        score += 2
        reasons.append(("Medium", "The domain contains punycode; check the spelling carefully."))


    if len(host.split(".")) >= 5:
        score += 1
        reasons.append(("Low", "The hostname contains many domain labels/subdomains."))


    found_terms = sorted(term for term in SUSPICIOUS_TERMS if term in url.lower())
    if found_terms:
        score += 1
        reasons.append(("Low", "Potentially sensitive terms appear in the URL: " + ", ".join(found_terms) + "."))


    if host in SHORTENER_DOMAINS:
        score += 2
        reasons.append(("Medium", "The domain is a URL-shortening service, so the final destination is hidden."))


    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 1
        reasons.append(("Low", "The domain uses a TLD that deserves extra scrutiny; this alone does not prove danger."))


    if len(url) > 120:
        score += 1
        reasons.append(("Low", "The URL is unusually long."))


    if host.count("-") >= 3:
        score += 1
        reasons.append(("Low", "The hostname contains several hyphens."))

    if score >= 5:
        level = "High Risk"
        advice = "Avoid entering passwords or payment details. Verify the domain through an official channel."
    elif score >= 3:
        level = "Medium Risk"
        advice = "Check the exact domain and destination carefully before interacting with the site."
    else:
        level = "Low Risk"
        advice = "No strong warning patterns were found by these simple checks. This does not guarantee the site is safe."

    if not reasons:
        reasons.append(("Info", "No suspicious patterns from this rule set were detected."))

    return {
        "url": url,
        "host": host,
        "score": score,
        "level": level,
        "reasons": reasons,
        "advice": advice,
    }


st.set_page_config(
    page_title="PhishGuard | URL Risk Checker",
    page_icon="🛡️",
    layout="centered",
)

st.markdown(
    """
    <style>
    .main {background: linear-gradient(180deg, #f5f9ff 0%, #ffffff 50%);}
    .hero {
        padding: 1.35rem 1.4rem; border-radius: 18px;
        background: linear-gradient(120deg, #102a43, #176b87);
        color: white; margin-bottom: 1rem;
    }
    .hero h1 {color: white; margin: 0; font-size: 2.15rem;}
    .hero p {color: #e2f3ff; margin-bottom: 0;}
    .small-note {font-size: 0.88rem; color: #526477;}
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <h1>🛡️ PhishGuard</h1>
      <p>Phishing URL Risk Checker · Educational cybersecurity project</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.write(
    "Check a URL for common warning signs. PhishGuard examines the URL text only; "
    "it does not visit the website or confirm whether a site is malicious."
)

with st.form("url_scan_form"):
    url_input = st.text_input(
        "Website URL",
        placeholder="https://example.com",
        help="Enter a full URL or a domain name. The website will not be opened.",
    )
    submitted = st.form_submit_button("🔍 Scan URL", use_container_width=True)

if submitted:
    result = analyze_url(url_input)

    if "error" in result:
        st.error(result["error"])
    else:
        st.divider()
        st.subheader("Scan result")
        left, right = st.columns(2)
        left.metric("Risk category", result["level"])
        right.metric("Rule-based risk score", result["score"])

        if result["level"] == "High Risk":
            st.error("⚠️ High Risk — several warning patterns were found.")
        elif result["level"] == "Medium Risk":
            st.warning("⚠️ Medium Risk — review this URL carefully.")
        else:
            st.success("✓ Low Risk — few warning patterns were found.")

        st.write("**Checked host:**", result["host"])
        st.write("**Why this result?**")
        for severity, reason in result["reasons"]:
            st.markdown(f"- **{severity}:** {reason}")

        st.info(result["advice"])

st.divider()
with st.expander("How does the risk score work?"):
    st.markdown(
        """
        - Different URL patterns add different numbers of points.
        - The score is a simple heuristic, not a probability or machine-learning prediction.
        - High: 5 or more points; Medium: 3–4 points; Low: 0–2 points.
        - Legitimate sites can trigger warnings, and phishing sites can avoid these rules.
        """
    )

st.markdown(
    '<p class="small-note">For learning and demonstration only. Never rely on this tool alone '
    'to decide whether a website is safe. When in doubt, use the organisation’s official website '
    'or contact channel.</p>',
    unsafe_allow_html=True,
)

