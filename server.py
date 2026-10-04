#!/usr/bin/env python3
"""Dealer car search. Proxies unhuman.autos and keeps real used dealer listings."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = os.environ.get("HOST") or ("0.0.0.0" if os.environ.get("PORT") else "127.0.0.1")
PORT = int(os.environ.get("PORT", "8765"))
ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATA = ROOT / "data"
DB_PATH = DATA / "accounts.db"
UPSTREAM = "https://unhuman.autos/api/cars"
UA = "DealerCarsNearYou/1.0 (+local product)"
CURRENT_YEAR = date.today().year
RESULT_LIMIT = 8
PAGE_ROWS = 50
MAX_PAGES = 2
ABSOLUTE_MIN_PRICE = 5000
SESSION_COOKIE = "carshop_session"
PBKDF2_ITERATIONS = 260000

BODY_ALIASES = {
    "suv": "suv",
    "suvs": "suv",
    "crossover": "suv",
    "crossovers": "suv",
    "sedan": "sedan",
    "sedans": "sedan",
    "truck": "truck",
    "trucks": "truck",
    "pickup": "truck",
    "pickups": "truck",
    "coupe": "coupe",
    "coupes": "coupe",
    "convertible": "convertible",
    "convertibles": "convertible",
    "van": "van",
    "vans": "van",
    "minivan": "van",
    "wagon": "wagon",
    "wagons": "wagon",
    "hatchback": "hatchback",
    "hatchbacks": "hatchback",
}

MAKES = [
    "acura", "alfa romeo", "audi", "bmw", "buick", "cadillac", "chevrolet", "chevy",
    "chrysler", "dodge", "fiat", "ford", "genesis", "gmc", "honda", "hyundai",
    "infiniti", "jaguar", "jeep", "kia", "land rover", "lexus", "lincoln", "mazda",
    "mercedes", "mercedes-benz", "mini", "mitsubishi", "nissan", "porsche", "ram",
    "subaru", "tesla", "toyota", "volkswagen", "vw", "volvo",
]

MAKE_MAP = {
    "chevy": "chevrolet",
    "vw": "volkswagen",
    "mercedes": "mercedes-benz",
}

AD_HOSTS = (
    "facebook.com", "instagram.com", "youtube.com", "twitter.com", "x.com",
    "tiktok.com", "google.com", "doubleclick", "adservice",
)

# Brand homepages and ad landers, not a specific dealer's inventory page.
OEM_HOSTS = (
    "www.honda.com", "automobiles.honda.com", "www.ford.com", "www.toyota.com",
    "www.chevrolet.com", "www.nissanusa.com", "www.hyundaiusa.com", "www.kia.com",
    "www.bmwusa.com", "www.mbusa.com", "www.audiusa.com", "www.vw.com",
    "www.subaru.com", "www.mazdausa.com", "www.jeep.com", "www.dodge.com",
    "www.chrysler.com", "www.buick.com", "www.cadillac.com", "www.gmc.com",
    "www.lexus.com", "www.acura.com",
)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def init_db() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                email_confirmed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS email_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                used_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        # Older local DBs created before email confirmation.
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "email_confirmed" not in cols:
            conn.execute(
                "ALTER TABLE users ADD COLUMN email_confirmed INTEGER NOT NULL DEFAULT 0"
            )
            conn.commit()


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return digest.hex(), salt.hex()


def verify_password(password: str, password_hash: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    digest, _ = hash_password(password, salt)
    return secrets.compare_digest(digest, password_hash)


def user_public(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "email_confirmed": bool(row["email_confirmed"]) if "email_confirmed" in row.keys() else False,
    }


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_id, now_iso()),
        )
        conn.commit()
    return token


def create_email_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("DELETE FROM email_tokens WHERE user_id = ? AND used_at IS NULL", (user_id,))
        conn.execute(
            "INSERT INTO email_tokens (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_id, now_iso()),
        )
        conn.commit()
    return token


def delete_session(token: str | None) -> None:
    if not token:
        return
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


def user_from_token(token: str | None) -> dict | None:
    if not token:
        return None
    with db() as conn:
        row = conn.execute(
            """
            SELECT u.id, u.name, u.email, u.email_confirmed
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (token,),
        ).fetchone()
    if not row or not row["email_confirmed"]:
        return None
    return user_public(row)


def parse_want(text: str) -> dict:
    """Extract optional filters from a short free-text want string."""
    out: dict = {}
    if not text:
        return out
    lower = text.strip().lower()

    for alias, body in BODY_ALIASES.items():
        if re.search(rf"\b{re.escape(alias)}\b", lower):
            out["body_type"] = body
            break

    m = re.search(r"(?:under|below|max(?:imum)?|<)?\s*(\d[\d,]*)\s*k\s*miles?", lower)
    if m:
        out["miles_max"] = int(m.group(1).replace(",", "")) * 1000
    else:
        m2 = re.search(r"(?:under|below|max(?:imum)?|<)\s*(\d[\d,]*)\s*(?:mi|miles)\b", lower)
        if m2:
            out["miles_max"] = int(m2.group(1).replace(",", ""))

    if re.search(r"\bused\b", lower):
        out["inventory_type"] = "used"
    elif re.search(r"\bnew\b", lower):
        out["inventory_type"] = "new"
    elif re.search(r"\bcpo\b|certified", lower):
        out["inventory_type"] = "cpo"

    for make in sorted(MAKES, key=len, reverse=True):
        if re.search(rf"\b{re.escape(make)}\b", lower):
            canon = MAKE_MAP.get(make, make)
            out["make"] = canon
            rest = lower.split(make, 1)[1].strip(" ,.-")
            stop = r"\b(?:used|new|cpo|certified|under|below|with|near|suv|sedan|truck|coupe|convertible|van|wagon|hatchback|miles?|mi)\b"
            model_m = re.match(r"([a-z0-9][a-z0-9\-]*(?:\s+[a-z0-9][a-z0-9\-]*){0,2})", rest)
            if model_m:
                model = re.split(stop, model_m.group(1).strip())[0].strip()
                if model and model not in BODY_ALIASES:
                    out["model"] = model
            break

    y = re.search(r"\b(20\d{2}|19\d{2})\b", lower)
    if y:
        out["year"] = y.group(1)

    return out


def price_floor(budget: int) -> int:
    """Ignore beaters and prices that are nonsense for the budget.

    Always drop under $5,000. At $15,000 and up, also drop anything under
    about 15% of the budget so a $48,000 search does not lead with a $2,000 car.
    """
    floor = ABSOLUTE_MIN_PRICE
    if budget >= 15000:
        floor = max(floor, int(budget * 0.15))
    return floor


def listing_year(raw: dict) -> int | None:
    build = raw.get("build") or {}
    raw_year = build.get("year") if build.get("year") is not None else raw.get("year")
    try:
        return int(raw_year)
    except (TypeError, ValueError):
        return None


def as_int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        digits = re.sub(r"[^\d]", "", value)
        if digits:
            return int(digits)
    return None


def is_real_vin(vin: str) -> bool:
    return bool(re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin.strip().upper()))


def host_is(host: str, name: str) -> bool:
    """True when host is exactly name or a subdomain of it."""
    host = host.lower().split(":")[0].rstrip(".")
    name = name.lower().lstrip(".")
    return host == name or host.endswith("." + name)


def is_ad_url(url: str) -> bool:
    host = urllib.parse.urlparse(url).netloc.lower()
    if any(host_is(host, h) for h in AD_HOSTS):
        return True
    if "doubleclick." in host or "adservice" in host:
        return True
    if any(host_is(host, h) for h in OEM_HOSTS):
        return True
    return False


def is_junk_price(price: int, year: int | None, budget: int) -> bool:
    if price < ABSOLUTE_MIN_PRICE:
        return True
    # Nearly-new metal listed under $5,000 is bad data, not a deal.
    if year is not None and year >= CURRENT_YEAR - 1 and price < ABSOLUTE_MIN_PRICE:
        return True
    if budget >= 15000 and price < budget * 0.15:
        return True
    return False


def normalize_listing(raw: dict, budget: int) -> dict | None:
    seller = (raw.get("seller_type") or "").strip().lower()
    if seller != "dealer":
        return None

    inventory = (raw.get("inventory_type") or "").strip().lower()
    # Upstream often ignores inventory_type=used and still returns new cars.
    if inventory == "new":
        return None

    dealer = raw.get("dealer")
    if not isinstance(dealer, dict) or not (dealer.get("name") or "").strip():
        return None

    vin = (raw.get("vin") or "").strip().upper()
    if not is_real_vin(vin):
        return None

    url = (raw.get("vdp_url") or "").strip()
    if not url.startswith(("http://", "https://")) or is_ad_url(url):
        return None

    price = as_int(raw.get("price"))
    if price is None or price > budget:
        return None

    year = listing_year(raw)
    if is_junk_price(price, year, budget):
        return None

    heading = (raw.get("heading") or "").strip()
    if not heading:
        return None

    build = raw.get("build") or {}
    city = (dealer.get("city") or "").strip()
    state = (dealer.get("state") or "").strip()
    place = ", ".join(p for p in (city, state) if p)
    miles = as_int(raw.get("miles"))
    dealer_name = (dealer.get("name") or "").strip()

    return {
        "name": heading,
        "price": price,
        "mileage": miles,
        "dealer": dealer_name,
        "city": place or city or "City not listed",
        "location": place or "Location not listed",
        "url": url,
        "make": build.get("make") or raw.get("make"),
        "model": build.get("model") or raw.get("model"),
        "year": year,
        "body_type": build.get("body_type") or raw.get("body_type"),
        "vin": vin,
        "seller_type": seller,
        "inventory_type": inventory or None,
        "distance_miles": raw.get("dist"),
    }


def fetch_page(params: dict) -> dict:
    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None and v != ""})
    url = f"{UPSTREAM}?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        return {"ok": False, "error": f"Upstream HTTP {e.code}: {body}", "listings": []}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"Upstream fetch failed: {e}", "listings": []}
    return {"ok": True, "listings": data.get("listings") or [], "query": qs}


def select_listings(base_params: dict, budget: int) -> dict:
    """Pull the closest-to-budget page, then keep a short useful set."""
    kept: list[dict] = []
    seen: set[tuple[str, str]] = set()
    scanned = 0
    dropped_new = 0
    queries: list[str] = []
    last_error = None

    for page in range(MAX_PAGES):
        params = dict(base_params)
        params["rows"] = str(PAGE_ROWS)
        params["start"] = str(page * PAGE_ROWS)
        # Price descending so the page is the cars near the budget, not $2,000 beaters.
        params["sort_by"] = "price"
        params["sort_order"] = "desc"
        params["inventory_type"] = "used"
        page_data = fetch_page(params)
        if not page_data.get("ok"):
            last_error = page_data.get("error")
            if page == 0:
                return {
                    "ok": False,
                    "error": last_error,
                    "listings": [],
                    "queries": queries,
                }
            break
        queries.append(page_data.get("query") or "")
        rows = page_data["listings"]
        scanned += len(rows)
        for raw in rows:
            if (raw.get("inventory_type") or "").strip().lower() == "new":
                dropped_new += 1
            item = normalize_listing(raw, budget)
            if not item:
                continue
            key = (item["name"].casefold(), item["dealer"].casefold())
            if key in seen:
                continue
            seen.add(key)
            kept.append(item)
        if len(rows) < PAGE_ROWS or len(kept) >= RESULT_LIMIT:
            break

    kept.sort(key=lambda item: (-(item.get("year") or 0), abs(budget - item["price"]), item["price"]))
    chosen = kept[:RESULT_LIMIT]
    return {
        "ok": True,
        "listings": chosen,
        "scanned": scanned,
        "dropped_new": dropped_new,
        "queries": queries,
        "error": last_error,
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "DealerCars/1.0"

    def log_message(self, fmt, *args):
        print(f"[car-shop] {self.address_string()} {fmt % args}")

    def _send(
        self,
        code: int,
        body: bytes,
        content_type: str,
        *,
        set_cookie: str | None = None,
        clear_cookie: bool = False,
    ):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if set_cookie:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={set_cookie}; Path=/; HttpOnly; SameSite=Lax",
            )
        if clear_cookie:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict, **kwargs):
        return self._send(
            code,
            json.dumps(payload).encode("utf-8"),
            "application/json; charset=utf-8",
            **kwargs,
        )

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > 100_000:
            raise ValueError("Request body too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _session_token(self) -> str | None:
        cookie = SimpleCookie()
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        cookie.load(raw)
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _current_user(self) -> dict | None:
        return user_from_token(self._session_token())

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/confirm":
            return self._send(200, (STATIC / "confirm.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/styles.css":
            return self._send(200, (STATIC / "styles.css").read_bytes(), "text/css; charset=utf-8")
        if path == "/app.js":
            return self._send(200, (STATIC / "app.js").read_bytes(), "application/javascript; charset=utf-8")
        if path == "/confirm.js":
            return self._send(200, (STATIC / "confirm.js").read_bytes(), "application/javascript; charset=utf-8")
        if path == "/api/search":
            return self._handle_search(parsed.query)
        if path == "/api/health":
            return self._json(200, {"ok": True, "source": UPSTREAM})
        if path == "/api/me":
            user = self._current_user()
            return self._json(200, {"ok": True, "user": user})
        if path == "/api/confirm":
            return self._handle_confirm(parsed.query)
        self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            if path == "/api/signup":
                return self._handle_signup()
            if path == "/api/login":
                return self._handle_login()
            if path == "/api/logout":
                return self._handle_logout()
            self._json(404, {"error": "not found"})
        except ValueError as e:
            self._json(400, {"ok": False, "error": str(e)})
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "Invalid JSON body."})

    def _handle_signup(self):
        data = self._read_json()
        name = str(data.get("name") or "").strip()
        email = str(data.get("email") or "").strip().lower()
        password = str(data.get("password") or "")

        if len(name) < 1 or len(name) > 80:
            return self._json(400, {"ok": False, "error": "Enter your name."})
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            return self._json(400, {"ok": False, "error": "Enter a valid email."})
        if len(password) < 8:
            return self._json(400, {"ok": False, "error": "Password must be at least 8 characters."})
        if len(password) > 200:
            return self._json(400, {"ok": False, "error": "Password is too long."})

        password_hash, salt = hash_password(password)
        try:
            with db() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO users (name, email, password_hash, salt, email_confirmed, created_at)
                    VALUES (?, ?, ?, ?, 0, ?)
                    """,
                    (name, email, password_hash, salt, now_iso()),
                )
                user_id = cur.lastrowid
                conn.commit()
        except sqlite3.IntegrityError:
            return self._json(409, {"ok": False, "error": "An account with that email already exists."})

        confirm_token = create_email_token(user_id)
        confirm_path = f"/confirm?token={urllib.parse.quote(confirm_token)}"
        return self._json(
            201,
            {
                "ok": True,
                "needs_confirmation": True,
                "email": email,
                "name": name,
                # Local demo only: no email provider is wired up.
                "confirm_url": confirm_path,
                "message": "Check your email to confirm your account.",
            },
            clear_cookie=True,
        )

    def _handle_confirm(self, query: str):
        q = urllib.parse.parse_qs(query, keep_blank_values=True)
        token = (q.get("token") or [""])[0].strip()
        if not token:
            return self._json(400, {"ok": False, "error": "Missing confirmation token."})

        with db() as conn:
            row = conn.execute(
                """
                SELECT t.token, t.user_id, t.used_at, u.email_confirmed, u.name, u.email
                FROM email_tokens t
                JOIN users u ON u.id = t.user_id
                WHERE t.token = ?
                """,
                (token,),
            ).fetchone()
            if not row:
                return self._json(400, {"ok": False, "error": "This confirmation link is invalid."})
            if row["used_at"] or row["email_confirmed"]:
                # Already confirmed — still allow a clean signed-in state if they click again.
                if row["email_confirmed"]:
                    session = create_session(row["user_id"])
                    return self._json(
                        200,
                        {
                            "ok": True,
                            "already_confirmed": True,
                            "user": {"id": row["user_id"], "name": row["name"], "email": row["email"], "email_confirmed": True},
                        },
                        set_cookie=session,
                    )
                return self._json(400, {"ok": False, "error": "This confirmation link was already used."})

            conn.execute(
                "UPDATE users SET email_confirmed = 1 WHERE id = ?",
                (row["user_id"],),
            )
            conn.execute(
                "UPDATE email_tokens SET used_at = ? WHERE token = ?",
                (now_iso(), token),
            )
            conn.commit()

        session = create_session(row["user_id"])
        return self._json(
            200,
            {
                "ok": True,
                "user": {
                    "id": row["user_id"],
                    "name": row["name"],
                    "email": row["email"],
                    "email_confirmed": True,
                },
            },
            set_cookie=session,
        )

    def _handle_login(self):
        data = self._read_json()
        email = str(data.get("email") or "").strip().lower()
        password = str(data.get("password") or "")
        if not email or not password:
            return self._json(400, {"ok": False, "error": "Enter email and password."})

        with db() as conn:
            row = conn.execute(
                "SELECT id, name, email, password_hash, salt, email_confirmed FROM users WHERE email = ?",
                (email,),
            ).fetchone()
        if not row or not verify_password(password, row["password_hash"], row["salt"]):
            return self._json(401, {"ok": False, "error": "Email or password is wrong."})

        if not row["email_confirmed"]:
            # Re-issue a confirm token so the local demo link stays available.
            confirm_token = create_email_token(row["id"])
            confirm_path = f"/confirm?token={urllib.parse.quote(confirm_token)}"
            return self._json(
                403,
                {
                    "ok": False,
                    "needs_confirmation": True,
                    "email": row["email"],
                    "confirm_url": confirm_path,
                    "error": "Confirm your email before signing in.",
                },
                clear_cookie=True,
            )

        delete_session(self._session_token())
        token = create_session(row["id"])
        return self._json(
            200,
            {
                "ok": True,
                "user": {
                    "id": row["id"],
                    "name": row["name"],
                    "email": row["email"],
                    "email_confirmed": True,
                },
            },
            set_cookie=token,
        )

    def _handle_logout(self):
        delete_session(self._session_token())
        return self._json(200, {"ok": True}, clear_cookie=True)

    def _handle_search(self, query: str):
        q = urllib.parse.parse_qs(query, keep_blank_values=True)

        def one(key, default=""):
            vals = q.get(key, [default])
            return (vals[0] if vals else default).strip()

        budget_s = one("budget")
        zip_code = one("zip")
        body_style = one("body")
        want = one("want")

        if not zip_code or not re.fullmatch(r"\d{5}", zip_code):
            return self._json(400, {"ok": False, "error": "Enter a valid 5-digit US ZIP code.", "listings": []})

        try:
            budget = int(re.sub(r"[^\d]", "", budget_s))
            if budget <= 0:
                raise ValueError
        except ValueError:
            return self._json(
                400,
                {"ok": False, "error": "Enter a max budget in USD (whole dollars).", "listings": []},
            )

        parsed_want = parse_want(want)
        body = body_style.lower()
        if body in ("", "any"):
            # Blank means all bodies. Do not force SUV.
            body = ""
        elif body in BODY_ALIASES:
            body = BODY_ALIASES[body]
        else:
            body = ""

        # Free-text body only fills in when the form did not choose one.
        if not body and not body_style:
            body = parsed_want.get("body_type", "")

        floor = price_floor(budget)
        if floor >= budget:
            result = {
                "ok": True,
                "listings": [],
                "note": "Found 0 dealer listings.",
                "source": "US dealer inventory",
                "filters": {
                    "budget": budget,
                    "zip": zip_code,
                    "body": body or None,
                    "price_floor": floor,
                },
            }
            return self._json(200, result)

        params = {
            "zip": zip_code,
            "radius": "50",
            "price_range": f"{floor}-{budget}",
        }
        if body:
            params["body_type"] = body
        if parsed_want.get("make"):
            params["make"] = parsed_want["make"]
        if parsed_want.get("model"):
            params["model"] = parsed_want["model"]
        if parsed_want.get("year"):
            params["year"] = parsed_want["year"]
        if parsed_want.get("miles_max"):
            params["miles_range"] = f"0-{parsed_want['miles_max']}"

        selected = select_listings(params, budget)
        listings = selected.get("listings") or []
        count = len(listings)
        noun = "listing" if count == 1 else "listings"
        result = {
            "ok": bool(selected.get("ok")),
            "listings": listings,
            "note": f"Found {count} dealer {noun}.",
            "source": "US dealer inventory",
            "filters": {
                "budget": budget,
                "zip": zip_code,
                "body": body or None,
                "price_floor": floor,
                "inventory_type": "used",
            },
        }
        if not selected.get("ok"):
            result["error"] = selected.get("error") or "Search failed."
            result["note"] = result["error"]
        code = 200 if result["ok"] else 502
        return self._json(code, result)


class Server(ThreadingHTTPServer):
    allow_reuse_address = True


def main():
    STATIC.mkdir(parents=True, exist_ok=True)
    init_db()
    httpd = Server((HOST, PORT), Handler)
    print(f"Dealer cars running at http://{HOST}:{PORT}/")
    print(f"Listings source: {UPSTREAM}")
    print(f"Accounts DB: {DB_PATH}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
