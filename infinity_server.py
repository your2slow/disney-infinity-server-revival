
# disney account flask server for Wii U, it could work for xbox 360/ps3 if you change the /wiiu paths to /x360 and /ps3 respectivley but i dunno for sure

import json, os, re, sqlite3, time, uuid, hashlib, secrets, gzip, urllib.parse
from datetime import date
from flask import Flask, request, jsonify, g

DB_PATH = os.environ.get("INF_DB", "infinity.db")
LOG_PATH = os.environ.get("INF_LOG", "requests.log")
TOKEN_TTL = 3600

app = Flask(__name__)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS accounts(
        swid TEXT PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE,
        pw_hash TEXT, pw_salt TEXT, email TEXT UNIQUE COLLATE NOCASE,
        parent_email TEXT, first_name TEXT, last_name TEXT, display_name TEXT,
        dob TEXT, gender TEXT, region TEXT, language TEXT,
        marketing INTEGER DEFAULT 0, created REAL);
    CREATE TABLE IF NOT EXISTS links(      -- Nintendo account <-> Disney ID
        platform TEXT, platform_id TEXT, swid TEXT,
        PRIMARY KEY(platform, platform_id));
    CREATE TABLE IF NOT EXISTS tokens(
        token TEXT PRIMARY KEY, kind TEXT, swid TEXT, expires REAL);
    """)
    c.commit(); c.close()


def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()


def new_swid():
    return "{" + str(uuid.uuid4()).upper() + "}"


def issue(kind, swid, ttl):
    t = secrets.token_urlsafe(32)
    db().execute("INSERT INTO tokens VALUES(?,?,?,?)", (t, kind, swid, time.time() + ttl))
    db().commit()
    return t


def lookup_token(t, kind):
    r = db().execute("SELECT * FROM tokens WHERE token=? AND kind=?", (t, kind)).fetchone()
    if r and r["expires"] > time.time():
        return r["swid"]
    return None

def log_request(resp=None):
    try:
        raw = request.get_data()
        if raw[:2] == b"\x1f\x8b":
            try: raw = gzip.decompress(raw)
            except Exception: pass
        body = raw.decode("utf-8", "replace")
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "t": time.strftime("%H:%M:%S"), "m": request.method,
                "url": request.full_path.rstrip("?"),
                "hdr": {k: v for k, v in request.headers.items()
                        if k.lower() in ("authorization", "x-inf-sig", "x-inf-date",
                                         "content-type", "content-encoding")},
                "body": body[:4000],
                "status": resp.status_code if resp is not None else None,
                "resp": (resp.get_data().decode("utf-8", "replace")[:1500]
                         if resp is not None and not resp.direct_passthrough
                         and resp.mimetype in ("application/json", "text/html", "text/plain") else None),
            }) + "\n")
    except Exception as e:  # logging must never break serving
        print("log error", e)


@app.after_request
def _after(resp):
    log_request(resp)
    return resp


def body_json():
    d = request.get_json(force=True, silent=True)
    return d if isinstance(d, dict) else {}


def pick(d, *names, default=""):
    """first present key among names (case-insensitive), searching one nested level"""
    low = {k.lower(): v for k, v in d.items()}
    for n in names:
        if n.lower() in low:
            return low[n.lower()]
    for v in d.values():
        if isinstance(v, dict):
            r = pick(v, *names, default=None)
            if r is not None:
                return r
    return default


# the CKFIdentityParseError reads top-level "code" (atoi) and "name"
ERROR_CODES = {
    "INPUT.MISSING_DATA.UNKNOWN": 1, "INPUT.MISSING_DATA.GRANT_TYPE": 1,
    "INPUT.MISSING_DATA.USERNAME": 1, "INPUT.MISSING_DATA.PASSWORD": 1,
    "INPUT.MISSING_DATA.ASSERTION_ID": 1, "INPUT.MISSING_DATA.REFRESH_TOKEN": 1,
    "INPUT.MISSING_DATA.FIRST_NAME": 1, "INPUT.MISSING_DATA.LAST_NAME": 1,
    "INPUT.MISSING_DATA.DOB": 1, "INPUT.MISSING_DATA.EMAIL": 1,
    "APP.INVALID_FIRST_NAME_SIZE": 1, "APP.INVALID_LAST_NAME_SIZE": 1,
    "APP.INVALID_USERNAME_SIZE": 1, "APP.PASSWORD_INVALID_SIZE": 1,
    "APP.INVALID_DOB": 1, "APP.INVALID_EMAIL_ADDRESS": 1,
    "INPUT.DISALLOWED_VALUE": 1, "APP.UPDATE_FAILED": 1, "APP.INVALID_DISPLAY_NAME": 1,
    "SECURITY.INVALID_USER": 100, "SECURITY.INVALID_OR_EXPIRED_TOKEN": 100,
    "SECURITY.INVALID_REFRESH_TOKEN": 100,
    "APP.GRANT_TYPE_UNKNOWN": 110, "APP.ASSERTION_PLATFORM_UNKNOWN": 110,
    "APP.ACCOUNT_NOT_LINKED": 110,
    "SYSTEM.UNEXPECTED.GUESTCONTROLLER_FATAL": 200,
    "APP.USERNAME_ALREADY_EXISTS": 2002,
}


def err(name, http=400):
    code = ERROR_CODES.get(name, 200)
    return jsonify({"code": str(code), "name": name}), http


def age_band(dob):
    try:
        y, m, d = (int(x) for x in dob.split("-")[:3])
        today = date.today()
        age = today.year - y - ((today.month, today.day) < (m, d))
    except Exception:
        return "ADULT", 18
    return ("CHILD" if age < 13 else "TEEN" if age < 18 else "ADULT"), age


def profile_fields(a):
    band, age = age_band(a["dob"] or "")
    return {
        "swid": a["swid"], "username": a["username"], "login_username": a["username"],
        "displayName": a["display_name"] or a["username"], "first_name": a["first_name"] or "",
        "last_name": a["last_name"] or "", "date_of_birth": a["dob"] or "", "email": a["email"] or "",
        "parentEmail": a["parent_email"] or "", "gender": a["gender"] or "",
        "countryCodeDetected": a["region"] or "US", "ageBand": band, "age": age,
    }


def token_response(a):
    r = profile_fields(a)
    r["access_token"] = issue("access", a["swid"], TOKEN_TTL)
    r["refresh_token"] = issue("refresh", a["swid"], 60 * 60 * 24 * 365)
    r["ttl"] = TOKEN_TTL
    return jsonify(r)

# this is what the game first requests and from there gets all the paths
def config_doc():
    b = os.environ.get("INF_BASE") or request.host_url.rstrip("/")
    return {
        "url_cg_did_auth": f"{b}/coregames/did/v3/",
        "url_inf_profile": f"{b}/infinity/profile/v2/wiiu/",
        "url_inf_ugc": f"{b}/infinity/ugc/v2/wiiu/",
        "url_inf_leaderboard": f"{b}/infinity/leaderboard/v1/wiiu/",
        "url_inf_entitlement": f"{b}/infinity/entitlement/v1/wiiu",
        "url_inf_ticker": f"{b}/infinity/ticker/v1/wiiu/",
        "url_inf_prestige": f"{b}/infinity/prestige/v1",
        "url_inf_moderation": f"{b}/infinity/moderation/v1",
        "url_inf_videolist": f"{b}/infinity/videolist/v1/",
        "url_inf_magic_band": f"{b}/infinity/magicband/v1/",
        "url_inf_access": f"{b}/infinity/access/v1",
        "url_cg_friends": f"{b}/coregames/friends/v1/wiiu",
        "url_cg_p2p_session": f"{b}/coregames/sessions/v1/",
        "url_cg_bi": f"{b}/datatech/log/v1/batch",
        "url_activity_stream_social": f"{b}/disneynetwork/activitystream/v2/",
        "url_activity_stream_links": f"{b}/",
        "url_activity_stream_icons": f"{b}/infinity3cdn/as",
        "url_cdn_posters": f"{b}/infinity3cdn/posters",
        "url_inf_ums": f"{b}/UMFrontier/",
        "url_ums_icons": f"{b}/infinity3cdn/ums",
        "url_prestige_icons": f"{b}/infinity3cdn/prestige",
        "url_radio_disney": f"{b}/radio/stream.mp3" if radio_tracks() else "INACTIVE",
        "domain_cg_natneg": "disney.com", # NAT negoation server. multiplayer is handled by NEX and is not implenete dyet so this is currently not working
        "big_endians": ["x360", "ps3", "wiiu"],
    }


@app.route("/coregames/config/v1/infinity3/wiiu/", defaults={"p": ""})
@app.route("/coregames/config/v1/infinity3/wiiu/<path:p>")
def config(p):
    return jsonify(config_doc())

DID = "/coregames/did/v3/"


def client_ok():
    h = request.headers.get("Authorization", "")
    return "A341D250-7AD3-49B1-B02B-5C1845A619A2" in h or True  # is lenient for now


def bearer():
    m = re.search(r"BEARER\s+([^\s,]+)", request.headers.get("Authorization", ""))
    return m.group(1) if m else None


def account_by_swid(swid):
    return db().execute("SELECT * FROM accounts WHERE swid=?", (swid,)).fetchone()


def link(plat, pid, swid):
    if plat and pid:
        db().execute("INSERT OR REPLACE INTO links VALUES(?,?,?)", (str(plat).lower(), str(pid), swid))
        db().commit()


@app.route(DID + "authenticate", methods=["POST"])
def did_authenticate():
    d = body_json()
    grant = str(pick(d, "grant_type")).lower()
    if not grant:
        return err("INPUT.MISSING_DATA.GRANT_TYPE")
    if grant == "password":
        user = str(pick(d, "username", "login_username")).strip()
        pw = str(pick(d, "password"))
        if not user:
            return err("INPUT.MISSING_DATA.USERNAME")
        if not pw:
            return err("INPUT.MISSING_DATA.PASSWORD")
        a = db().execute("SELECT * FROM accounts WHERE username=? OR email=?", (user, user)).fetchone()
        if not a or hash_pw(pw, a["pw_salt"]) != a["pw_hash"]:
            return err("SECURITY.INVALID_USER")
        link(pick(d, "assertion_platform"), pick(d, "assertion_id"), a["swid"])
        return token_response(a)
    if grant in ("assertion", "platform"):
        plat = str(pick(d, "assertion_platform", default="wiiu") or "wiiu").lower()
        pid = str(pick(d, "assertion_id"))
        if not pid:
            return err("INPUT.MISSING_DATA.ASSERTION_ID")
        l = db().execute("SELECT swid FROM links WHERE platform=? AND platform_id=?", (plat, pid)).fetchone()
        a = account_by_swid(l["swid"]) if l else None
        if not a:
            return err("APP.ACCOUNT_NOT_LINKED")
        return token_response(a)
    if grant == "refresh_token":
        return refresh_with(pick(d, "refresh_token"))
    return err("APP.GRANT_TYPE_UNKNOWN")


def refresh_with(tok):
    if not tok:
        return err("INPUT.MISSING_DATA.REFRESH_TOKEN")
    swid = lookup_token(str(tok), "refresh")
    a = account_by_swid(swid) if swid else None
    if not a:
        return err("SECURITY.INVALID_REFRESH_TOKEN")
    return token_response(a)


@app.route(DID + "refresh", methods=["POST"])
def did_refresh():
    return refresh_with(pick(body_json(), "refresh_token"))


def norm_dob(v):
    v = str(v or "").strip()
    m = re.match(r"^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", v)
    if m:
        return f"{int(m.group(1)):04d}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    m = re.match(r"^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})", v)
    if m:
        return f"{int(m.group(3)):04d}-{int(m.group(1)):02d}-{int(m.group(2)):02d}"
    return v


@app.route(DID + "create", methods=["POST"])
def did_create():
    d = body_json()
    first = str(pick(d, "first_name")).strip(); last = str(pick(d, "last_name")).strip()
    email = str(pick(d, "email") or "").strip()
    user = str(pick(d, "username") or pick(d, "displayName", "display_name") or email).strip()
    disp = str(pick(d, "displayName", "display_name") or user).strip()
    parent = str(pick(d, "parentEmail", "parents_email", "parent_email") or "").strip()
    dob = norm_dob(pick(d, "date_of_birth", "dateOfBirth", "dob"))
    pw = str(pick(d, "password"))
    if not first: return err("INPUT.MISSING_DATA.FIRST_NAME")
    if not last: return err("INPUT.MISSING_DATA.LAST_NAME")
    if not user: return err("INPUT.MISSING_DATA.USERNAME")
    if not pw: return err("INPUT.MISSING_DATA.PASSWORD")
    if len(first) > 50: return err("APP.INVALID_FIRST_NAME_SIZE")
    if len(last) > 50: return err("APP.INVALID_LAST_NAME_SIZE")
    if not (2 <= len(user) <= 50): return err("APP.INVALID_USERNAME_SIZE")
    if not (4 <= len(pw) <= 64): return err("APP.PASSWORD_INVALID_SIZE")
    for e in (email, parent):
        if e and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e):
            return err("APP.INVALID_EMAIL_ADDRESS")
    if db().execute("SELECT 1 FROM accounts WHERE username=?", (user,)).fetchone():
        return err("APP.USERNAME_ALREADY_EXISTS")
    if email and db().execute("SELECT 1 FROM accounts WHERE email=?", (email,)).fetchone():
        email_col = None
    else:
        email_col = email or None
    salt = secrets.token_hex(8)
    swid = new_swid()
    db().execute(
        "INSERT INTO accounts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (swid, user, hash_pw(pw, salt), salt, email_col, parent, first, last, disp, dob,
         str(pick(d, "gender") or ""), str(pick(d, "regCountry", "region", default="US") or "US"),
         str(pick(d, "langPref", "language", default="en-US") or "en-US"),
         1 if str(pick(d, "marketing_optin", "marketing")).lower() == "true" else 0, time.time()))
    db().commit()
    link(pick(d, "assertion_platform"), pick(d, "assertion_id"), swid)
    return token_response(account_by_swid(swid))


@app.route(DID + "update", methods=["POST", "PUT"])
def did_update():
    d = body_json()
    swid = lookup_token(bearer() or "", "access")
    a = account_by_swid(swid) if swid else None
    if not a:
        return err("SECURITY.INVALID_OR_EXPIRED_TOKEN")
    m = {"first_name": "first_name", "last_name": "last_name",
         "parentEmail": "parent_email", "displayName": "display_name", "gender": "gender"}
    for k, col in m.items():
        v = pick(d, k, default=None)
        if v not in (None, ""):
            db().execute(f"UPDATE accounts SET {col}=? WHERE swid=?", (str(v), a["swid"]))
    v = pick(d, "username", default=None)
    if v and str(v).lower() != a["username"].lower():
        if db().execute("SELECT 1 FROM accounts WHERE username=?", (str(v),)).fetchone():
            return err("APP.USERNAME_ALREADY_EXISTS")
        db().execute("UPDATE accounts SET username=? WHERE swid=?", (str(v), a["swid"]))
    v = pick(d, "email", default=None)
    if v and not db().execute("SELECT 1 FROM accounts WHERE email=? AND swid<>?", (str(v), a["swid"])).fetchone():
        db().execute("UPDATE accounts SET email=? WHERE swid=?", (str(v), a["swid"]))
    db().commit()
    return token_response(account_by_swid(a["swid"]))


LEGAL_TEXT = {
    "CLOUD_DID_Form_MoreInfo": "this is a community revival server. your account only exists on this server.",
    "CLOUD_DID_Form_MarketingToggle": "Send me news (does nothing on this server)",
    "CLOUD_DID_Form_ToSToggle": "I agree to the Terms of Use",
    "CLOUD_DID_Form_CookiesToggle": "I accept the Cookies Policy",
    "CLOUD_DID_Form_CookiesToggle_EU": "I accept the Cookies Policy",
    "CLOUD_DID_TermsOfUse_Body": "community revival server for Disney Infinity 3.0, not affiliated with Disney. "
                                 "Be nice, do not upload any toybox that is illegal or offensive.",
    "CLOUD_DID_PrivacyPolicy_Body": "Please note that there might be some interference with this DID server if you log onto a second, seperate DID server as it connects your account's principal id. ",
    "CLOUD_DID_CookiesPolicy_Body": "No cookies are used.",
    "CLOUD_DID_CookiesPolicy_Body_EU": "No cookies are used.",
    "CLOUD_DID_CompanyOverview": "Disney Infinity community revival.",
    "CLOUD_DID_ChildPrivacyPolicy": "ChildPrivacyPolicy placeholder",
    "CLOUD_DID_Form_SEAToggle": "I agree to the regional terms",
    "CLOUD_DID_SEAPolicy": "No additional regional terms apply on this server.",
}


@app.route(DID + "check", methods=["POST", "GET"])
def did_check():
    d = body_json()
    try:
        y = int(pick(d, "birthYear", default=2000)); mo = int(pick(d, "birthMonth", default=1))
        dy = int(pick(d, "birthDay", default=1))
        band, _ = age_band(f"{y:04d}-{mo:02d}-{dy:02d}")
    except (TypeError, ValueError):
        band = "ADULT"
    return jsonify({
        "compliance": {
            "fields": {"profile": {"parentEmail": {"use": "REQUIRED" if band == "CHILD" else "OPTIONAL"}}},
            "legalRequirements": {"CREATE": {"cookiePermissions": {
                "TARGETING_ADVERTISING": {"permissionDefault": "OPT_OUT"}}}},
        },
        "legal": {"documents": {}},
        "child_privacy_policy": LEGAL_TEXT["CLOUD_DID_ChildPrivacyPolicy"],
        "text_tags": LEGAL_TEXT,
    })


@app.route(DID + "recovery", methods=["POST"])
def did_recovery():
    # th real service emailed a reset link but here just acknowledge
    return jsonify({"status": "ok"})


@app.route(DID + "unlink", methods=["POST"])
def did_unlink():
    d = body_json()
    db().execute("DELETE FROM links WHERE platform=? AND platform_id=?",
                 (pick(d, "assertion_platform"), pick(d, "assertion_id")))
    db().commit()
    return jsonify({"status": "ok"})


def inbox_for(swid):
    rows = db().execute("SELECT m.*, COALESCE(s.read, 0) rd FROM inbox m LEFT JOIN inbox_state s "
                        "ON s.id=m.id AND s.swid=? WHERE COALESCE(s.deleted, 0)=0 ORDER BY m.created DESC",
                        (swid,)).fetchall()
    return rows


@app.route("/UMFrontier/", defaults={"p": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/UMFrontier/<path:p>", methods=["GET", "POST", "PUT", "DELETE"])
def umfrontier(p):
    m = re.match(r"^guests/([^/]+)/inboxes/[^/]+/messages(?:/([^/?]+))?", p)
    if not m:
        return jsonify({"unreadMessageCount": 0, "totalMessageCount": 0, "records": []})
    swid, mid = urllib.parse.unquote(m.group(1)), m.group(2)
    if mid:
        r = db().execute("SELECT * FROM inbox WHERE id=?", (mid,)).fetchone()
        if not r:
            return ("", 404)
        if request.method == "DELETE":
            db().execute("INSERT INTO inbox_state VALUES(?,?,1,1) ON CONFLICT(id,swid) DO UPDATE SET deleted=1",
                         (mid, swid))
            db().commit()
            return jsonify({})
        db().execute("INSERT INTO inbox_state VALUES(?,?,1,0) ON CONFLICT(id,swid) DO UPDATE SET read=1", (mid, swid))
        db().commit()
        return jsonify({"id": r["id"], "subject": json.dumps({"subject": r["subject"], "target_platform": "wiiu"}),
                        "content": json.dumps({"body": r["body"], "image": ""})})
    rows = inbox_for(swid)
    try: limit = int(request.args.get("limit", 50))
    except ValueError: limit = 50
    recs = [{"id": r["id"], "subject": json.dumps({"subject": r["subject"], "target_platform": "wiiu"}),
             "flags": {"read": "true" if r["rd"] else "false"}, "dateReceived": str(int(r["created"]))}
            for r in rows[:limit]]
    return jsonify({"records": recs, "totalMessageCount": len(rows),
                    "unreadMessageCount": sum(1 for r in rows if not r["rd"])})


ADMIN_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Inbox</title>
<style>
body{font-family:sans-serif;max-width:640px;margin:20px auto;padding:0 10px}
input,textarea{width:100%;box-sizing:border-box;margin:4px 0 10px;padding:6px}
textarea{height:120px}
.m{border:1px solid #ccc;padding:8px;margin:8px 0}
.m small{color:#666}
</style></head><body>
<h2>Send announcement</h2>
<p>{msg}</p>
<form method="post">
{pw}
<label>Subject</label><input name="subject" maxlength="100" required>
<label>Message</label><textarea name="body" required></textarea>
<button name="action" value="send">Send to everyone</button>
</form>
<h2>Sent</h2>
{list}
</body></html>"""


def admin_ok():
    want = os.environ.get("INF_ADMIN_PASS", "")
    if want:
        return request.form.get("password", request.args.get("password", "")) == want
    return request.remote_addr in ("127.0.0.1", "::1")


@app.route("/admin", methods=["GET", "POST"])
def admin():
    import html
    msg = ""
    if not admin_ok():
        if request.method == "POST" or not os.environ.get("INF_ADMIN_PASS"):
            return ("Forbidden", 403)
    elif request.method == "POST":
        if request.form.get("action") == "send":
            subject = request.form.get("subject", "").strip()
            body = request.form.get("body", "").strip()
            if subject and body:
                db().execute("INSERT INTO inbox VALUES(?,?,?,?)", (uuid.uuid4().hex[:24], subject, body, time.time()))
                db().commit()
                msg = "Sent."
        elif request.form.get("action") == "delete":
            mid = request.form.get("id", "")
            db().execute("DELETE FROM inbox WHERE id=?", (mid,))
            db().execute("DELETE FROM inbox_state WHERE id=?", (mid,))
            db().commit()
            msg = "Deleted."
    pw = ""
    if os.environ.get("INF_ADMIN_PASS"):
        pw = ('<label>Password</label><input type="password" name="password" value="%s" required>'
              % html.escape(request.form.get("password", request.args.get("password", ""))))
    items = []
    for r in db().execute("SELECT * FROM inbox ORDER BY created DESC").fetchall():
        items.append('<div class="m"><b>%s</b> <small>%s</small><p>%s</p><form method="post">%s'
                     '<input type="hidden" name="id" value="%s"><button name="action" value="delete">Delete</button>'
                     '</form></div>' % (html.escape(r["subject"]),
                                        time.strftime("%Y-%m-%d %H:%M", time.localtime(r["created"])),
                                        html.escape(r["body"]).replace("\n", "<br>"),
                                        pw.replace('type="password"', 'type="hidden"').replace("<label>Password</label>", ""),
                                        html.escape(r["id"])))
    page = (ADMIN_HTML.replace("{msg}", msg).replace("{pw}", pw)
            .replace("{list}", "".join(items) or "<p>Nothing sent yet.</p>"))
    return Response(page, mimetype="text/html")


import gzip, base64
from flask import Response

def caller_swid():
    return lookup_token(bearer() or "", "access")


def extra_init():
    c = sqlite3.connect(DB_PATH)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS ugc(
        id TEXT PRIMARY KEY, scope TEXT, swid TEXT, creator TEXT, name TEXT, descr TEXT,
        type TEXT, genres TEXT, version INTEGER DEFAULT 1, likes INTEGER DEFAULT 0,
        downloads INTEGER DEFAULT 0, shared INTEGER DEFAULT 1, created REAL, updated REAL,
        meta TEXT, content BLOB, shot BLOB, shot_info TEXT);
    CREATE TABLE IF NOT EXISTS ugc_likes(id TEXT, swid TEXT, PRIMARY KEY(id,swid));
    CREATE TABLE IF NOT EXISTS friends(swid TEXT, friend_net_id TEXT, friend_name TEXT,
        PRIMARY KEY(swid,friend_net_id));
    CREATE TABLE IF NOT EXISTS scores(board TEXT, swid TEXT, score INTEGER, updated REAL,
        PRIMARY KEY(board,swid));
    CREATE TABLE IF NOT EXISTS profile(swid TEXT, k TEXT, v BLOB, PRIMARY KEY(swid,k));
    CREATE TABLE IF NOT EXISTS inbox(id TEXT PRIMARY KEY, subject TEXT, body TEXT, created REAL);
    CREATE TABLE IF NOT EXISTS inbox_state(id TEXT, swid TEXT, read INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0,
        PRIMARY KEY(id,swid));
    """)
    if "cloud" not in [r[1] for r in c.execute("PRAGMA table_info(ugc)")]:
        c.execute("ALTER TABLE ugc ADD COLUMN cloud INTEGER DEFAULT 1")
    c.commit(); c.close()


def maybe_gunzip(b):
    if request.headers.get("Content-Encoding", "").lower() == "gzip" or b[:2] == b"\x1f\x8b":
        try: return gzip.decompress(b)
        except Exception: pass
    return b


def parse_multipart(body, ctype):
    """multipart/vnd.disney.infinity.toybox+form-data as built by CreateContentAndImageMFD:
    --B CRLF hdrs CRLF CRLF toybox-json CRLF --B CRLF hdrs CRLF CRLF screenshotInfo-json --B CRLF
    hdrs CRLF CRLF dds CRLF --B--   (no CRLF before the screenshot boundary)"""
    m = re.search(r'boundary="?([^";\s]+)"?', ctype or "")
    parts = {}
    if not m:
        return parts
    marker = b"--" + m.group(1).encode()
    for chunk in body.split(marker)[1:]:
        if chunk.startswith(b"--"):
            break
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        hdr, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]
        nm = re.search(rb'name="?([^";\r\n]+)"?', hdr)
        if nm:
            parts[nm.group(1).decode().strip()] = data
    return parts


def ugc_meta(parts):
    try:
        meta = json.loads(parts.get("toybox", b"").decode("utf-8", "ignore") or "{}")
        return meta if isinstance(meta, dict) else {}
    except Exception:
        return {}


def ugc_header(r):
    meta = json.loads(r["meta"] or "{}")
    oc = meta.get("object_counts", {})
    return {
        "_id": r["id"], "_creatorId": r["swid"], "name": r["name"] or "", "desc": r["descr"] or "",
        "object_counts": oc if isinstance(oc, dict) else {}, "shared": bool(r["shared"]),
        "last_update_time": int(r["updated"]), "creation_time": int(r["created"]),
        "version": ugc_format(r), "_status": "approved",
    }


def ugc_format(r):
    try:
        return int(json.loads(r["meta"] or "{}")["levels"]["setheader"]["CSaveGameSlot"]["INFINITY_VERSION"])
    except Exception:
        return 3


def ugc_flag(r, key):
    try:
        return bool(json.loads(r["meta"] or "{}").get(key))
    except Exception:
        return False


def ugc_item(r, swid=None):
    liked = bool(swid and db().execute("SELECT 1 FROM ugc_likes WHERE id=? AND swid=?", (r["id"], swid)).fetchone())
    return {
        "_id": r["id"], "name": r["name"], "desc": r["descr"], "_creatorId": r["swid"],
        "creator_display_name": r["creator"], "creator_platform_name": r["creator"],
        "type": r["type"], "last_update_time": int(r["updated"]), "creation_time": int(r["created"]),
        "version": ugc_format(r), "count": {"likes": r["likes"], "downloads": r["downloads"]},
        "likes": r["likes"], "downloads": r["downloads"], "shared": bool(r["shared"]),
        "user_can_like": not liked, "hasTextToy": ugc_flag(r, "hasTextToy"),
        "leaderboard_id": f"ugc_{r['id']}" if ugc_flag(r, "supports_leaderboard") else "", "video_id": "",
        "platform_performance": "", "_status": "published",
        "genres": json.loads(r["genres"] or "[]"),
    }


def ugc_list(rows, swid):
    page = max(int(request.args.get("page", 1)), 1)
    size = max(min(int(request.args.get("page_size", request.args.get("limit", 20))), 100), 1)
    total = len(rows)
    sl = rows[(page - 1) * size: page * size]
    return jsonify({"items": [ugc_item(r, swid) for r in sl], "page_size": size,
                    "page_count": max(1, -(-total // size)), "total_items": total})


UGC = "/infinity/ugc/v2/wiiu/"

@app.route(UGC, defaults={"p": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route(UGC + "<path:p>", methods=["GET", "POST", "PUT", "DELETE"])
def ugc(p):
    p = p.strip("/")
    me = caller_swid()
    m = request.method
    mm = re.match(r"^(public|private)/toybox$", p)
    if mm and m == "POST":
        parts = parse_multipart(maybe_gunzip(request.get_data()), request.headers.get("Content-Type"))
        meta = ugc_meta(parts)
        a = account_by_swid(me) if me else None
        rid = uuid.uuid4().hex[:24]
        now = time.time()
        db().execute("INSERT INTO ugc(id, scope, swid, creator, name, descr, type, genres, version, likes, "
                     "downloads, shared, created, updated, meta, content, shot, shot_info, cloud) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)", (
            rid, mm.group(1), me or "", a["display_name"] if a else "", str(meta.get("name", "")),
            str(meta.get("desc", "")), str(meta.get("type", "toybox")), json.dumps(meta.get("genres", [])),
            1, 0, 0, 1 if mm.group(1) == "public" else 0, now, now, json.dumps(meta),
            parts.get("toybox", b""), parts.get("screenshot", b""),
            parts.get("screenshotInfo", b"").decode("utf-8", "ignore")))
        db().commit()
        return jsonify(ugc_header(db().execute("SELECT * FROM ugc WHERE id=?", (rid,)).fetchone()))
    mm = re.match(r"^(public|private)/toybox/(?!(?:trending|search|popular|featured|recent)(?:/|$))([0-9A-Za-z]+)(?:/(like|screenshot|object_counts|report|flag))?$", p)
    if mm:
        scope, rid, sub = mm.groups()
        r = db().execute("SELECT * FROM ugc WHERE id=?", (rid,)).fetchone()
        if sub == "like":
            if r and me and m in ("POST", "PUT"):
                db().execute("INSERT OR IGNORE INTO ugc_likes VALUES(?,?)", (rid, me))
                n = db().execute("SELECT COUNT(*) c FROM ugc_likes WHERE id=?", (rid,)).fetchone()["c"]
                db().execute("UPDATE ugc SET likes=? WHERE id=?", (n, rid)); db().commit()
                return jsonify({"count": n})
            return jsonify({"count": r["likes"] if r else 0})
        if sub in ("report", "flag"):
            return jsonify({})
        if sub == "object_counts":
            oc = json.loads(r["meta"] or "{}").get("object_counts", {}) if r else {}
            return jsonify(oc if isinstance(oc, dict) else {})
        if not r:
            return ("", 204) if m == "DELETE" else ("", 404)
        if sub == "screenshot":
            if not r["shot"]:
                return ("", 404)
            resp = Response(r["shot"], mimetype="image/x-dds")
            info = (r["shot_info"] or "").replace("\r", " ").replace("\n", " ").strip()
            if info:
                resp.headers["x-binary-metadata"] = info
            return resp
        if m == "GET":
            db().execute("UPDATE ugc SET downloads=downloads+1 WHERE id=?", (rid,)); db().commit()
            return Response(r["content"] or b"", mimetype="application/octet-stream")
        if m in ("PUT", "POST"):
            parts = parse_multipart(maybe_gunzip(request.get_data()), request.headers.get("Content-Type"))
            meta = ugc_meta(parts)
            if parts.get("toybox"):
                db().execute("UPDATE ugc SET content=?, meta=? WHERE id=?", (parts["toybox"], json.dumps(meta), rid))
            if parts.get("screenshot"):
                db().execute("UPDATE ugc SET shot=?, shot_info=? WHERE id=?",
                             (parts["screenshot"], parts.get("screenshotInfo", b"").decode("utf-8", "ignore"), rid))
            db().execute("UPDATE ugc SET name=COALESCE(NULLIF(?,''),name), descr=COALESCE(NULLIF(?,''),descr),"
                         " version=version+1, updated=? WHERE id=?",
                         (str(meta.get("name", "")), str(meta.get("desc", "")), time.time(), rid))
            if scope == "private":
                db().execute("UPDATE ugc SET cloud=1 WHERE id=?", (rid,))
            db().commit()
            return jsonify(ugc_header(db().execute("SELECT * FROM ugc WHERE id=?", (rid,)).fetchone()))
        if m == "DELETE":
            if r["swid"] != me:
                return err("SECURITY.INVALID_USER", 403)
            if scope == "private" and r["scope"] == "public":
                db().execute("UPDATE ugc SET cloud=0 WHERE id=?", (rid,))
            elif scope == "public" and r["cloud"]:
                db().execute("UPDATE ugc SET scope='private', shared=0 WHERE id=?", (rid,))
            else:
                db().execute("DELETE FROM ugc WHERE id=?", (rid,))
                db().execute("DELETE FROM ugc_likes WHERE id=?", (rid,))
            db().commit()
            return ("", 204)
    if p.startswith("rooms/"):
        # Toy Box Theater stuff
        enc = (request.args.get("enclosures") or "").split(",")[0]
        try:
            pins = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "theatre.json"),
                                  encoding="utf-8")).get(enc)
        except Exception:
            pins = None
        if isinstance(pins, list) and pins:
            rows = [r for i in pins for r in db().execute("SELECT * FROM ugc WHERE id=? AND scope='public'", (str(i),)).fetchall()]
        else:
            rows = db().execute("SELECT * FROM ugc WHERE scope='public' ORDER BY likes DESC, updated DESC").fetchall()
        return ugc_list(rows, me)
    if p.endswith("object_counts"):
        return jsonify({})
    if p.startswith("playtests/upload_file"):
        return jsonify({})
    if m == "GET":
        cols = {"creation_time": "created", "last_update_time": "updated", "likes.count": "likes",
                "likes": "likes", "downloads.count": "downloads", "downloads": "downloads", "name": "name COLLATE NOCASE"}
        sf = cols.get(request.args.get("sort_field", ""))
        sd = "ASC" if request.args.get("sort_direction", "").lower() == "asc" else "DESC"
        if p.startswith("private"):
            rows = db().execute(f"SELECT * FROM ugc WHERE swid=? AND cloud=1 "
                                f"ORDER BY {sf or 'updated'} {sd if sf else 'DESC'}", (me or "",)).fetchall()
        else:
            if sf:
                order = f"{sf} {sd}, updated DESC"
            else:
                order = "likes DESC, updated DESC" if "trending" in p or "popular" in p else "updated DESC"
            term = request.args.get("term") or request.args.get("q") or request.args.get("search") or request.args.get("name")
            where, args = "scope='public'", []
            if term:
                where += " AND name LIKE ?"; args.append(f"%{term}%")
            creators = request.args.get("creators", "")
            for _ in range(2):
                creators = urllib.parse.unquote(creators)
            creators = [c for c in creators.split(",") if c.strip()]
            if creators:
                where += f" AND swid IN ({','.join('?' * len(creators))})"; args += creators
            rows = db().execute(f"SELECT * FROM ugc WHERE {where} ORDER BY {order}", args).fetchall()
        return ugc_list(rows, me)
    return jsonify({})


# ------------------------------------------------------------------ friends
FRIENDS = "/coregames/friends/v1/wiiu"

def norm_nid(x):
    s = str(x or "").strip().upper()
    if s.startswith("0X"): s = s[2:]
    return s.zfill(8) if s else ""


def net_id_for(swid):
    r = db().execute("SELECT platform_id FROM links WHERE swid=? AND platform='wiiu'", (swid,)).fetchone()
    return norm_nid(r["platform_id"]) if r else ""


@app.route(FRIENDS, defaults={"p": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route(FRIENDS + "/<path:p>", methods=["GET", "POST", "PUT", "DELETE"])
def friends(p):
    me = caller_swid()
    if request.method in ("POST", "PUT"):
        try: lst = json.loads(request.get_data(as_text=True) or "[]")
        except Exception: lst = []
        if me and isinstance(lst, list):
            db().execute("DELETE FROM friends WHERE swid=?", (me,))
            for f in lst:
                if isinstance(f, dict) and f.get("network_id"):
                    db().execute("INSERT OR REPLACE INTO friends VALUES(?,?,?)",
                                 (me, norm_nid(f["network_id"]), f.get("network_name", "")))
            db().commit()
        return jsonify({})
    # GET: console friends that also have a linked Disney ID
    items = []
    if me:
        linked = {}
        for l in db().execute("SELECT swid, platform_id FROM links WHERE platform='wiiu'").fetchall():
            linked[norm_nid(l["platform_id"])] = l["swid"]
        for f in db().execute("SELECT * FROM friends WHERE swid=?", (me,)).fetchall():
            nid = norm_nid(f["friend_net_id"])
            a = account_by_swid(linked[nid]) if nid in linked else None
            if a and a["swid"] != me:
                items.append({"disney_name": a["display_name"] or a["username"], "swid": a["swid"],
                              "network_name": f["friend_name"], "network_id": nid})
    start = int(request.args.get("start", 0)); limit = int(request.args.get("limit", 100))
    return jsonify({"total_count": len(items), "items": items[start:start + limit]})


LB = "/infinity/leaderboard/v1/wiiu/"

def lb_is_time(board):
    return "_TT" in board.upper()


@app.route(LB + "updatescore/<board>", methods=["POST", "PUT"])
def lb_update(board):
    d = body_json()
    swid = caller_swid() or pick(d, "swid")
    try: score = int(float(pick(d, "score", default=0)))
    except (TypeError, ValueError): score = 0
    if swid:
        best = "MIN" if lb_is_time(board) else "MAX"
        db().execute("INSERT INTO scores VALUES(?,?,?,?) ON CONFLICT(board,swid) DO UPDATE SET "
                     f"updated=CASE WHEN {best}(score,excluded.score)<>score THEN excluded.updated ELSE updated END, "
                     f"score={best}(score,excluded.score)", (board, swid, score, time.time()))
        db().commit()
    return jsonify({})


@app.route(LB, defaults={"p": ""})
@app.route(LB + "<path:p>")
def lb_ranks(p):
    board = request.args.get("id") or p.split("/")[-1] or "default"
    try: limit = max(min(int(request.args.get("limit", 10)), 100), 1)
    except ValueError: limit = 10
    me = caller_swid()
    tm = lb_is_time(board)
    window = {"d": 86400, "w": 7 * 86400, "m": 30 * 86400}.get(request.args.get("roll", "l"))
    q = ("SELECT s.*, a.display_name n FROM scores s LEFT JOIN accounts a ON a.swid=s.swid WHERE board=?")
    args = [board]
    if window:
        q += " AND s.updated>=?"; args.append(time.time() - window)
    if request.args.get("friends") == "true" and me:
        ids = {me}
        linked = {norm_nid(l["platform_id"]): l["swid"] for l in
                  db().execute("SELECT swid, platform_id FROM links WHERE platform='wiiu'").fetchall()}
        for f in db().execute("SELECT friend_net_id FROM friends WHERE swid=?", (me,)).fetchall():
            if norm_nid(f["friend_net_id"]) in linked:
                ids.add(linked[norm_nid(f["friend_net_id"])])
        q += f" AND s.swid IN ({','.join('?' * len(ids))})"; args += list(ids)
    q += f" ORDER BY score {'ASC' if tm else 'DESC'}, s.updated ASC"
    rows = db().execute(q, args).fetchall()
    items = [{"name": r["n"] or "", "isPlayer": r["swid"] == me, "value": r["score"], "rank": i + 1}
             for i, r in enumerate(rows)]
    top = items[:limit]
    mine = next((x for x in items if x["isPlayer"]), None)
    if mine and mine not in top:      # always include the player's own row
        top.append(mine)
    return jsonify({"_id": board, "name": board, "locid": board, "sort": "asc" if tm else "desc",
                    "type": "time" if tm else "score", "config": {},
                    "views": [{"type": "friends" if request.args.get("friends") == "true" else "global",
                               "items": top}], "items": top})


PROF = "/infinity/profile/v2/wiiu/"


def load_stats(swid):
    r = db().execute("SELECT v FROM profile WHERE swid=? AND k='stats'", (swid,)).fetchone()
    try:
        d = json.loads(r["v"]) if r else {}
    except Exception:
        d = {}
    return d if isinstance(d, dict) else {}


def merge_stats(old, raw):
    try:
        new = json.loads(raw)
    except Exception:
        return old
    if not isinstance(new, dict):
        return old

    def deep(a, b):
        for k, v in b.items():
            if isinstance(v, dict) and isinstance(a.get(k), dict):
                deep(a[k], v)
            else:
                a[k] = v
    deep(old, new)
    return old

@app.route(PROF, defaults={"p": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route(PROF + "<path:p>", methods=["GET", "POST", "PUT", "DELETE"])
def profile(p):
    me = caller_swid()
    key = p.strip("/") or "root"
    if request.method in ("POST", "PUT"):
        if me:
            data = maybe_gunzip(request.get_data())
            if key == "stats":
                data = json.dumps(merge_stats(load_stats(me), data)).encode()
            db().execute("INSERT OR REPLACE INTO profile VALUES(?,?,?)", (me, key, data))
            db().commit()
        return jsonify({})
    if request.method == "GET":
        r = db().execute("SELECT v FROM profile WHERE swid=? AND k=?", (me or "", key)).fetchone() if me else None
        if key == "unlocks" and r:
            return Response(r["v"], mimetype="application/vnd.disney.infinity.unlocks+content-stream")
        if key == "stats" and r:
            return Response(r["v"], mimetype="application/json")
        if key.startswith("platforms"): return jsonify({"platforms": []})
        return jsonify({"exists": True})
    return jsonify({})


# moderation/prestige and text toy shit
MOD_KEY = bytes.fromhex("6f2fb2f845ae9fcf091ad3c360701b6a")
_SBOX = [0] * 256


def _init_sbox():
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        _SBOX[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    _SBOX[0] = 0x63


_init_sbox()


def _xt(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xt(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


_RK = _expand(MOD_KEY)


def _enc_block(b):
    s = [x ^ k for x, k in zip(b, _RK[0])]
    for r in range(1, 11):
        s = [_SBOX[x] for x in s]
        s = [s[(c * 4 + i + 4 * i) % 16] for c in range(4) for i in range(4)]
        if r != 10:
            m = []
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[i] ^ t ^ _xt(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = m
        s = [x ^ k for x, k in zip(s, _RK[r])]
    return bytes(s)


def mod_encrypt(data):
    pad = 16 - len(data) % 16
    data += bytes([pad]) * pad
    iv = secrets.token_bytes(16)
    out, prev = [iv], iv
    for i in range(0, len(data), 16):
        prev = _enc_block([a ^ b for a, b in zip(data[i:i + 16], prev)])
        out.append(prev)
    return b"".join(out)


# the words in moderation.txt (one per line, next to this script) get the text replaced
def _blocked_words():
    try:
        with open(os.environ.get("INF_MODERATION", "moderation.txt"), encoding="utf-8") as f:
            return [w.strip().lower() for w in f if w.strip()]
    except Exception:
        return []


@app.route("/infinity/moderation/v1/filtertext", methods=["POST"])
def mod_filter():
    text = str(pick(body_json(), "content") or "")
    out = text
    for w in _blocked_words():
        out = re.sub(re.escape(w), "*" * len(w), out, flags=re.IGNORECASE)
    reply = {"contentAction": "allow"} if out == text else {"contentAction": "replace", "replacement": out}
    return Response(mod_encrypt(json.dumps(reply).encode()), mimetype="application/octet-stream")


@app.route("/infinity/moderation/v1/flag", methods=["POST"])
def mod_flag():
    return jsonify({})


@app.route("/infinity/prestige/v1", defaults={"p": ""}, methods=["GET", "POST", "PUT"])
@app.route("/infinity/prestige/v1/<path:p>", methods=["GET", "POST", "PUT"])
def prestige(p):
    me = caller_swid()
    p = p.strip("/")
    if request.method in ("PUT", "POST"):
        tok = str(pick(body_json(), "title", default=""))
        if me and any(t["token"] == tok for t in prestige_titles(prestige_xp(me)[1])):
            db().execute("INSERT OR REPLACE INTO profile VALUES(?,?,?)", (me, "prestige_title", tok.encode()))
            db().commit()
            return jsonify({"title": tok})
        return err("INPUT.DISALLOWED_VALUE")
    if not me:
        return err("SECURITY.INVALID_OR_EXPIRED_TOKEN", 401)
    xp, level, last_t, next_t = prestige_xp(me)
    titles = prestige_titles(level)
    if p.startswith("titles"):
        return jsonify({"titles": titles})
    if p.startswith("objectives"):
        return jsonify(prestige_objectives(me))
    r = db().execute("SELECT v FROM profile WHERE swid=? AND k='prestige_title'", (me,)).fetchone()
    chosen = r["v"].decode() if r else titles[-1]["token"]
    name = next((t["translation"] for t in titles if t["token"] == chosen), titles[-1]["translation"])
    icon_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cdn", "prestige")
    icon = next((f for f in (f"level_{level}.png", "default.png") if os.path.isfile(os.path.join(icon_dir, f))), "")
    return jsonify({"status": {"title": {"name": name}, "image_icon": icon, "level": str(level),
                               "current_tier": str(xp), "last_tier": str(last_t), "next_tier": str(next_t)}})


# XP needed to reach each prestige level (level 1 = 0 XP). Edit freely.
PRESTIGE_LEVELS = [0, 500, 1500, 3000, 5000, 8000, 12000, 17000, 23000, 30000,
                   40000, 52000, 66000, 82000, 100000]
# (level needed, token, shown name)
PRESTIGE_TITLES = [(1, "TITLE_ROOKIE", "Rookie"), (2, "TITLE_BUILDER", "Builder"),
                   (3, "TITLE_ADVENTURER", "Adventurer"), (4, "TITLE_EXPLORER", "Explorer"),
                   (5, "TITLE_CREATOR", "Creator"), (6, "TITLE_HERO", "Hero"),
                   (8, "TITLE_CHAMPION", "Champion"), (10, "TITLE_MASTER_BUILDER", "Master Builder"),
                   (12, "TITLE_LEGEND", "goat"), (15, "TITLE_INFINITY_MASTER", "Infinity Master")]


def _num(v):
    try:
        return max(int(float(v)), 0)
    except (TypeError, ValueError):
        return 0


def prestige_xp(swid):
    st = load_stats(swid)
    xp = 0
    for a in (st.get("avatars") or {}).values():  
        if isinstance(a, dict):
            xp += 150 * _num(a.get("level"))
    for v in (st.get("player_achievements") or {}).values():
        xp += 100 * min(_num(v), 50)
    for v in (st.get("player_stats") or {}).values():
        xp += 10 * min(_num(v), 500)
    ugc = db().execute("SELECT COUNT(*) n, COALESCE(SUM(likes),0) l, COALESCE(SUM(downloads),0) d "
                       "FROM ugc WHERE swid=? AND scope='public'", (swid,)).fetchone()
    xp += 300 * ugc["n"] + 25 * ugc["l"] + 5 * ugc["d"]
    level = sum(1 for t in PRESTIGE_LEVELS if xp >= t)
    last_t = PRESTIGE_LEVELS[level - 1]
    next_t = PRESTIGE_LEVELS[level] if level < len(PRESTIGE_LEVELS) else last_t
    return xp, level, last_t, next_t


def prestige_titles(level):
    return [{"token": t, "translation": n} for lv, t, n in PRESTIGE_TITLES if level >= lv]


def prestige_objectives(swid):
    st = load_stats(swid)
    ach = st.get("player_achievements") or {}
    ps = st.get("player_stats") or {}
    shared = db().execute("SELECT COUNT(*) n FROM ugc WHERE swid=? AND scope='public'", (swid,)).fetchone()["n"]
    # weekly window, Monday 00:00 UTC
    now = time.time()
    start = int(now - (now - 4 * 86400) % (7 * 86400))
    iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    goals = [("share a Toy Box with the community", shared, "300 XP"),
             ("complete Toy Box feats", _num(ach.get("ACH_FEATS_COMPLETE")), "100 XP each"),
             ("save Toy Box worlds", _num(ach.get("ACH_SAVE_NUMBER_TOYBOX_WORLDS")), "100 XP each"),
             ("collect Toy Box collectables", _num(ps.get("TOYBOX_COLLECTABLES")), "10 XP each"),
             ("level up your characters", sum(_num(a.get("level")) for a in (st.get("avatars") or {}).values()
                                              if isinstance(a, dict)), "150 XP per level")]
    return {"nameL10n": "Prestige", "titleL10n": "Weekly Objectives",
            "descriptionL10n": "Earn XP by playing, building and sharing Toy Boxes.", "imageURL": "",
            "objectives": [{"name": n, "starts_at": iso(start), "ends_at": iso(start + 7 * 86400),
                            "achievedCount": str(c), "rewards": [r]} for n, c, r in goals]}


# toybox tv, no videos ar ein the repo but you can add some. it uses .bk2 (bink) format
VIDEO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "videos")
VIDEO_CATS = ["characterReveals", "toyboxTV", "communityVideos", "tutorials"]
VIDEO_EXT = (".bk2", ".bik", ".mp4")


def video_files(cat):
    d = os.path.join(VIDEO_DIR, cat)
    try:
        return sorted(f for f in os.listdir(d) if f.lower().endswith(VIDEO_EXT))
    except OSError:
        return []


def video_entry(cat, fn, base):
    stem = os.path.splitext(fn)[0]
    d = os.path.join(VIDEO_DIR, cat)
    thumb = next((f"{base}/videos/{cat}/{stem}{e}" for e in (".png", ".jpg", ".jpeg")
                  if os.path.exists(os.path.join(d, stem + e))), "")
    try:
        desc = open(os.path.join(d, stem + ".txt"), encoding="utf-8").read().strip()
    except OSError:
        desc = ""
    return {"title": stem.replace("_", " "), "short_description": desc,
            "asset_thumbnail_image": thumb, "coreId": f"{cat}~{stem}"}


@app.route("/infinity/videolist/v1/", defaults={"p": ""})
@app.route("/infinity/videolist/v1/<path:p>")
def videolist(p):
    base = os.environ.get("INF_BASE") or request.host_url.rstrip("/")
    p = p.strip("/")
    if p.startswith("list/"):
        cat = p[5:].split("/")[0]
        if cat not in VIDEO_CATS:
            return jsonify({"videoList": []})
        return jsonify({"videoList": [video_entry(cat, f, base) for f in video_files(cat)]})
    if p.startswith("details/"):
        core = p[8:].split("/")[0]
        cat, _, stem = core.partition("~")
        fn = next((f for f in video_files(cat) if os.path.splitext(f)[0] == stem), None) if cat in VIDEO_CATS else None
        if not fn:
            return err("INPUT.DISALLOWED_VALUE", 404)
        return jsonify({"title": stem.replace("_", " "), "url": f"{base}/videos/{cat}/{fn}"})
    return jsonify({c: (c if video_files(c) else "") for c in VIDEO_CATS})


@app.route("/videos/<cat>/<path:fn>")
def video_file(cat, fn):
    from flask import send_from_directory
    if cat not in VIDEO_CATS:
        return ("", 404)
    return send_from_directory(os.path.join(VIDEO_DIR, cat), fn, conditional=True)


@app.route("/infinity/magicband/v1/", defaults={"p": ""})
@app.route("/infinity/magicband/v1/<path:p>")
def magicband(p):
    return jsonify({"magic_band_type": "INVALID"})


@app.route("/infinity/ticker/v1/wiiu/", defaults={"p": ""})
@app.route("/infinity/ticker/v1/wiiu/<path:p>")
def ticker(p):
    # edit news.json (same folder) to change the ticker; image "" = no image request.
    items = None
    try:
        with open(os.environ.get("INF_NEWS", "news.json"), encoding="utf-8") as f:
            items = json.load(f)
    except Exception:
        pass
    if not isinstance(items, list):
        items = [{"title": "Disney Infinity Revival", "body": "online services are running on a custom server!", "image": ""}]
    m = re.search(r"count=(\d+)", request.query_string.decode())
    if m:
        items = items[:max(int(m.group(1)), 1)]
    base = os.environ.get("INF_BASE") or request.host_url.rstrip("/")

    def img(v):
        # images have to be .png or it wont load, .jpg for example wont work
        v = str(v or "")
        return v if (not v or "://" in v) else f"{base}/news/{v}"
    return jsonify([{"title": str(i.get("title", "")), "body": str(i.get("body", "")), "image": img(i.get("image"))}
                    for i in items if isinstance(i, dict)])


@app.route("/news/<path:fn>")
def news_image(fn):
    from flask import send_from_directory
    return send_from_directory(os.path.join(os.path.dirname(os.path.abspath(__file__)), "news"), fn)


@app.route("/infinity/entitlement/v1/wiiu", defaults={"p": ""}, methods=["GET", "POST"])
@app.route("/infinity/entitlement/v1/wiiu/<path:p>", methods=["GET", "POST"])
def entitlement(p):
    if p.startswith("sampleset"):
        return ("", 404)
    if p.startswith("unlockigp"):
        return err("APP.ALREADY_REDEEMED", 409)
    return ("", 404)


@app.route("/coregames/did/v3/guests/<path:p>", methods=["GET", "POST"])
@app.route("/guests/<path:p>", methods=["GET", "POST"])
def inbox(p):
    return jsonify([])


@app.route("/disneynetwork/activitystream/v2/", defaults={"p": ""}, methods=["GET", "POST", "PUT"])
@app.route("/disneynetwork/activitystream/v2/<path:p>", methods=["GET", "POST", "PUT"])
def activity(p):
    return jsonify({})


@app.route("/infinity/access/v1", defaults={"p": ""}, methods=["GET", "POST"])
@app.route("/infinity/access/v1/<path:p>", methods=["GET", "POST"])
def access(p):
    return jsonify({})


# p2p stuff; again multiplayer doesnt work yet but this is future proofing it
SESSIONS = {}

@app.route("/coregames/sessions/v1/", defaults={"p": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/coregames/sessions/v1/<path:p>", methods=["GET", "POST", "PUT", "DELETE"])
def sessions(p):
    now = time.time()
    for k in [k for k, v in SESSIONS.items() if now - v["_t"] > 120]:
        SESSIONS.pop(k, None)
    if request.method in ("POST", "PUT"):
        d = body_json()
        key = pick(d, "session_key") or str(uuid.uuid4())
        if str(pick(d, "state")).upper() in ("ENDED", "END", "CLOSED"):
            SESSIONS.pop(key, None)
        else:
            d["_t"] = now; SESSIONS[key] = d
        return jsonify({"session_key": key})
    return jsonify({"items": [{k: v for k, v in s.items() if k != "_t"} for s in SESSIONS.values()]})


app.add_url_rule("/coregames/session/v1/", endpoint="sessions_singular", view_func=sessions,
                 defaults={"p": ""}, methods=["GET", "POST", "PUT", "DELETE"])
app.add_url_rule("/coregames/session/v1/<path:p>", endpoint="sessions_singular_p", view_func=sessions,
                 methods=["GET", "POST", "PUT", "DELETE"])


@app.route("/datatech/log/v1/batch", methods=["POST"])
def telemetry():
    return ("", 204)

@app.route("/cdn/<path:p>")
@app.route("/infinity3cdn/<path:p>")
def cdn(p):
    # optional local files for example liek /cdn/posters/THEATRE_1.png for the Toy Box Theater screens
    from flask import send_from_directory
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cdn")
    if p and os.path.isfile(os.path.join(root, p)):
        return send_from_directory(root, p)
    return ("", 404)


@app.route("/c/", defaults={"p": ""})
@app.route("/c/<path:p>")
def config_short(p):
    return jsonify(config_doc())     

# radio disney, if there is no mp3 file in path it will not stream anything, if there is it will.
RADIO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "radio")
_BR = {1: [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
       2: [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]}
_SR = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000]}


def radio_tracks():
    try:
        return sorted(os.path.join(RADIO_DIR, f) for f in os.listdir(RADIO_DIR)
                      if f.lower().endswith(".mp3"))
    except OSError:
        return []


def mp3_frames(data):
    i = 0
    if data[:3] == b"ID3" and len(data) > 10:                    # ID3v2 header
        i = 10 + ((data[6] & 0x7f) << 21 | (data[7] & 0x7f) << 14 | (data[8] & 0x7f) << 7 | (data[9] & 0x7f))
    n = len(data) - (128 if data[-128:-125] == b"TAG" else 0)    # ID3v1 trailer
    while i + 4 <= n:
        h = int.from_bytes(data[i:i + 4], "big")
        ver, layer, bri, sri, pad = (h >> 19) & 3, (h >> 17) & 3, (h >> 12) & 15, (h >> 10) & 3, (h >> 9) & 1
        if (h >> 21) != 0x7ff or ver == 1 or layer != 1 or bri in (0, 15) or sri == 3:
            i += 1                                               # resync
            continue
        sr = _SR[ver][sri]
        br = _BR[1 if ver == 3 else 2][bri] * 1000
        samples = 1152 if ver == 3 else 576
        size = samples // 8 * br // sr + pad
        if i + size > n:
            break
        yield data[i:i + size], samples / sr, (sr, (h >> 6) & 3 == 3)
        i += size


@app.route("/radio/stream.mp3")
def radio_stream():
    tracks = radio_tracks()
    if not tracks:
        return ("", 404)

    def gen():
        import random
        start, played, fmt = time.monotonic(), 0.0, None
        while True:
            order = tracks[:]
            random.shuffle(order)
            for path in order:
                try:
                    data = open(path, "rb").read()
                except OSError:
                    continue
                for frame, dur, f in mp3_frames(data):
                    fmt = fmt or f                   # game locks rate/channels on 1st frame
                    if f != fmt:
                        print("radio: skipping", os.path.basename(path), "(different sample rate/channels)")
                        break
                    ahead = played - (time.monotonic() - start)
                    if ahead > 2.0:
                        time.sleep(ahead - 2.0)
                    yield frame
                    played += dur

    return Response(gen(), mimetype="audio/mpeg",
                    headers={"Cache-Control": "no-cache", "Connection": "close"})


@app.route("/", defaults={"p": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/<path:p>", methods=["GET", "POST", "PUT", "DELETE"])
def catch_all(p):
    return jsonify({}), 200


if __name__ == "__main__":
    init_db(); extra_init()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 80)), threaded=True)
