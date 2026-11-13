"""Church System Management: license server. Takes Paystack payments, emails activation codes, and lets you issue codes by hand.
Deploy it on a host that can run Python (Render, Railway, a VPS). Settings come from environment variables (see README_VENDOR.txt)."""
import base64, hashlib, hmac, json, os, re, secrets, sqlite3, urllib.request
from datetime import date, datetime, timezone
from html import escape

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask, Response, jsonify, redirect, request

app = Flask(__name__)
E = os.environ.get
PAYSTACK_SECRET = E("PAYSTACK_SECRET", "")
AMOUNT_MINOR = int(E("AMOUNT_MINOR", "2000"))      # 2000 = $20.00 (or GHS 20.00 if CURRENCY=GHS); amounts are in cents/pesewas
CURRENCY = E("CURRENCY", "USD")
RENEW_DAYS = int(E("RENEW_DAYS", "365"))
BASE_URL = E("BASE_URL", "").rstrip("/")
ADMIN_PASSWORD = E("ADMIN_PASSWORD", "")
DB_PATH = E("DB_PATH", "vendor.db")
DEVICE_RE = re.compile(r"^[0-9A-F]{4}(-[0-9A-F]{4}){3}$")
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_code(device, days):
    payload = "%s|%d|%s|%s" % (device, days, date.today().strftime("%Y%m%d"), secrets.token_hex(3))
    key = Ed25519PrivateKey.from_private_bytes(unb64(E("PRIVATE_KEY", "").strip()))
    return b64(payload.encode()) + "." + b64(key.sign(payload.encode()))


def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS codes (id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, device TEXT, email TEXT, church TEXT, source TEXT, code TEXT, emailed INTEGER, created TEXT)")
    return c


def post_json(url, body, headers):
    req = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode() or "{}")


def send_email(to, church, code):
    key = E("BREVO_API_KEY")
    if not (key and to):
        return False
    html = ("<p>Thank you%s.</p><p>Your Church System Management activation code is below. Open the app, go to <b>More &gt; License</b>, paste the code in "
            "<b>Enter your activation code</b> and press Activate.</p><pre style=\"white-space:pre-wrap;word-break:break-all;background:#eef3fb;padding:12px\">%s</pre>"
            "<p>The code works once, on the computer that made the payment.</p>") % ((" for " + escape(church)) if church else "", escape(code))
    try:
        post_json("https://api.brevo.com/v3/smtp/email", {"sender": {"name": E("SENDER_NAME", "Church System Management"), "email": E("SENDER_EMAIL", "")},
                  "to": [{"email": to}], "subject": "Your Church System Management activation code", "htmlContent": html}, {"api-key": key})
        return True
    except Exception:
        return False


def save(ref, device, email, church, source, code, emailed):
    c = db()
    c.execute("INSERT OR IGNORE INTO codes (ref,device,email,church,source,code,emailed,created) VALUES (?,?,?,?,?,?,?,?)",
              (ref, device, email, church, source, code, int(emailed), datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")))
    c.commit()


@app.route("/")
def home():
    return "License server is running."


@app.route("/pay")
def pay():
    device, email, church = request.args.get("device", "").upper(), request.args.get("email", "").strip(), request.args.get("church", "")
    if not DEVICE_RE.match(device) or "@" not in email:
        return "Invalid request.", 400
    try:
        r = post_json("https://api.paystack.co/transaction/initialize", {"email": email, "amount": AMOUNT_MINOR, "currency": CURRENCY, "callback_url": BASE_URL + "/thanks",
                      "metadata": {"device_id": device, "church": church}}, {"Authorization": "Bearer " + PAYSTACK_SECRET})
        return redirect(r["data"]["authorization_url"])
    except Exception as e:
        return "Could not start the payment: %s" % escape(str(e)), 502


@app.route("/thanks")
def thanks():
    return "<body style='font-family:sans-serif;max-width:520px;margin:60px auto'><h2>Payment received. Thank you!</h2><p>Your activation code is being emailed to you. You can also return to Church System Management and press <b>I have paid: activate now</b>.</p></body>"


@app.route("/paystack/webhook", methods=["POST"])
def webhook():
    raw = request.get_data()
    want = hmac.new(PAYSTACK_SECRET.encode(), raw, hashlib.sha512).hexdigest()
    if not PAYSTACK_SECRET or not hmac.compare_digest(request.headers.get("x-paystack-signature", ""), want):
        return "bad signature", 401
    ev = json.loads(raw)
    if ev.get("event") != "charge.success":
        return "ignored", 200
    d = ev["data"]
    meta = d.get("metadata") or {}
    device = (meta.get("device_id") or "").upper()
    if not DEVICE_RE.match(device) or d.get("currency") != CURRENCY or int(d.get("amount", 0)) < AMOUNT_MINOR:
        return "ignored", 200
    ref, email = d["reference"], (d.get("customer") or {}).get("email", "")
    if db().execute("SELECT 1 FROM codes WHERE ref=?", (ref,)).fetchone():
        return "ok", 200
    code = make_code(device, RENEW_DAYS)
    save(ref, device, email, meta.get("church", ""), "paystack", code, send_email(email, meta.get("church", ""), code))
    return "ok", 200


@app.route("/claim")
def claim():
    device = request.args.get("device", "").upper()
    if not DEVICE_RE.match(device):
        return jsonify(error="bad device"), 400
    r = db().execute("SELECT code FROM codes WHERE device=? ORDER BY id DESC LIMIT 1", (device,)).fetchone()
    return jsonify(code=r["code"] if r else None)


def authed():
    a = request.authorization
    return bool(ADMIN_PASSWORD and a and hmac.compare_digest(a.password or "", ADMIN_PASSWORD))


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not authed():
        return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="Admin"'})
    msg = ""
    if request.method == "POST":
        device = request.form["device"].strip().upper()
        days = int(request.form.get("days") or RENEW_DAYS)
        email, church = request.form.get("email", "").strip(), request.form.get("church", "").strip()
        if not DEVICE_RE.match(device):
            msg = "<p style='color:#c0392b'>That Device ID is not in the right format, for example B038-D343-8E74-EE79.</p>"
        else:
            code = make_code(device, days)
            sent = send_email(email, church, code)
            save("manual-" + secrets.token_hex(4), device, email, church, "manual", code, sent)
            wa = "https://wa.me/?text=" + urllib.request.quote("Your Church System Management activation code (paste it on the License page):\n\n" + code)
            msg = ("<div style='background:#e6f4ea;padding:14px;border-radius:8px'><b>Activation code for %s (%d days)</b>%s<br><textarea id=c readonly rows=4 style='width:100%%'>%s</textarea>"
                   "<br><button onclick=\"c.select();document.execCommand('copy')\">Copy</button> <a href='%s' target=_blank>Send on WhatsApp</a></div>") % (
                   escape(device), days, " (also emailed)" if sent else "", escape(code), escape(wa))
    rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % tuple(escape(str(x or "")) for x in (r["created"], r["source"], r["church"], r["device"], r["email"]))
                   for r in db().execute("SELECT * FROM codes ORDER BY id DESC LIMIT 40"))
    return ("<body style='font-family:sans-serif;max-width:900px;margin:30px auto;padding:0 14px'><h2 style='color:#1e4fa3'>Issue an activation code</h2>%s"
            "<form method=POST><p>Device ID<br><input name=device size=30 placeholder='B038-D343-8E74-EE79' required></p><p>Church name (optional)<br><input name=church size=30></p>"
            "<p>Email to send it to (optional)<br><input name=email type=email size=30></p><p>Days<br><input name=days type=number value=%d></p><button>Generate code</button></form>"
            "<h3>Recent codes</h3><table border=1 cellpadding=6 style='border-collapse:collapse'><tr><th>When (UTC)</th><th>How</th><th>Church</th><th>Device</th><th>Email</th></tr>%s</table></body>") % (msg, RENEW_DAYS, rows)
