#!/usr/bin/env python3
"""Dealer car search. Reads a public CarGurus results page for nearby dealer listings."""

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
CG_SEARCH = "https://www.cargurus.com/search"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
CURRENT_YEAR = date.today().year
RESULT_LIMIT = 8
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


BODY_GROUP = {
    "suv": "7",
    "sedan": "6",
    "truck": "5",
    "coupe": "0",
    "convertible": "1",
    "hatchback": "3",
    "van": "4",
    "wagon": "9",
}

BODY_WORDS = {
    "suv": ("suv", "crossover"),
    "sedan": ("sedan",),
    "truck": ("truck", "pickup"),
    "coupe": ("coupe",),
    "convertible": ("convertible",),
    "hatchback": ("hatchback",),
    "van": ("van",),
    "wagon": ("wagon",),
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


def price_floor(budget: int, min_budget: int | None = None) -> int:
    """Price floor for a search.

    A min the user typed replaces the automatic floors. Otherwise drop under
    $5,000, and at a max of $15,000 or more also drop anything under about 15%
    of that max so a $48,000 search does not lead with a $2,000 car.
    """
    if min_budget is not None:
        return min_budget
    floor = ABSOLUTE_MIN_PRICE
    if budget >= 15000:
        floor = max(floor, int(budget * 0.15))
    return floor


def parse_whole_dollars(raw: str) -> int:
    """Whole-dollar amount. Commas and a leading $ are fine. Blank is an error."""
    text = raw.strip().replace(",", "").replace("$", "").replace(" ", "")
    if text.startswith("-") or not re.fullmatch(r"\d+", text):
        raise ValueError
    return int(text)


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


def is_junk_price(
    price: int,
    year: int | None,
    budget: int,
    *,
    apply_auto_floor: bool = True,
) -> bool:
    if not apply_auto_floor:
        return False
    if price < ABSOLUTE_MIN_PRICE:
        return True
    # Nearly-new metal listed under $5,000 is bad data, not a deal.
    if year is not None and year >= CURRENT_YEAR - 1 and price < ABSOLUTE_MIN_PRICE:
        return True
    if budget >= 15000 and price < budget * 0.15:
        return True
    return False


def normalize_listing(
    raw: dict,
    budget: int,
    *,
    floor: int | None = None,
    apply_auto_floor: bool = True,
) -> dict | None:
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
    if floor is not None and price < floor:
        return None

    year = listing_year(raw)
    if is_junk_price(price, year, budget, apply_auto_floor=apply_auto_floor):
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


def body_matches(body_name: str | None, wanted: str) -> bool:
    if not wanted:
        return True
    text = (body_name or "").casefold()
    return any(word in text for word in BODY_WORDS.get(wanted, (wanted,)))


def looks_blocked(html: str) -> bool:
    if "LISTING_" in html:
        return False
    head = html[:4000].casefold()
    markers = (
        "just a moment",
        "page unavailable",
        "access denied",
        "captcha",
        "verify you are human",
    )
    return any(marker in head for marker in markers)


def fetch_html(url: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            html = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code in (403, 429, 503):
            return {
                "ok": False,
                "error": "The listing site blocked this search. Try again later.",
                "html": "",
            }
        return {"ok": False, "error": "The listing site didn't return listings.", "html": ""}
    except Exception:
        return {
            "ok": False,
            "error": "Couldn't reach the listing site. Try again in a minute.",
            "html": "",
        }
    if looks_blocked(html):
        return {
            "ok": False,
            "error": "The listing site blocked this search. Try again later.",
            "html": "",
        }
    return {"ok": True, "html": html, "error": None}


def make_paths(html: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for label, value in re.findall(r'"label":"([^"\\]+)","value":"(m\d+)"', html):
        found[label.casefold()] = value
    return found


def parse_cargurus_listings(html: str) -> list[dict]:
    decoder = json.JSONDecoder()
    rows: list[dict] = []
    idx = 0
    needle = '{"type":"LISTING_'
    while True:
        i = html.find(needle, idx)
        if i < 0:
            break
        try:
            obj, end = decoder.raw_decode(html, i)
        except json.JSONDecodeError:
            idx = i + len(needle)
            continue
        idx = end
        data = obj.get("data") if isinstance(obj, dict) else None
        if isinstance(data, dict):
            rows.append(data)
    return rows


def cargurus_to_raw(data: dict) -> dict | None:
    seller = data.get("sellerData") or {}
    dealer_name = (seller.get("serviceProviderName") or "").strip()
    if not dealer_name:
        return None
    listing_id = data.get("id")
    if not listing_id:
        return None
    ont = data.get("ontologyData") or {}
    price = (data.get("priceData") or {}).get("current")
    miles = (data.get("mileageData") or {}).get("value")
    dist = data.get("distance")
    if isinstance(dist, (int, float)):
        dist = round(float(dist), 1)
    year = ont.get("carYear")
    make = ont.get("makeName") or ""
    model = ont.get("modelName") or ""
    title = (data.get("listingTitle") or "").strip()
    if not title:
        title = " ".join(str(part) for part in (year, make, model) if part)
    return {
        "seller_type": "dealer",
        "inventory_type": "new" if data.get("isNew") else "used",
        "dealer": {
            "name": dealer_name,
            "city": (seller.get("city") or "").strip(),
            "state": (seller.get("region") or "").strip(),
        },
        "vin": data.get("vin") or "",
        "vdp_url": f"https://www.cargurus.com/details/{listing_id}",
        "price": price,
        "build": {
            "year": year,
            "make": make,
            "model": model,
            "body_type": ont.get("bodyTypeName"),
        },
        "heading": title,
        "miles": miles,
        "dist": dist,
        "make": make,
        "model": model,
        "year": year,
        "body_type": ont.get("bodyTypeName"),
    }


def search_url(
    base_params: dict,
    budget: int,
    make_path: str | None = None,
    floor: int | None = None,
) -> str:
    price_range = base_params.get("price_range") or ""
    if "-" in str(price_range):
        low, high = str(price_range).split("-", 1)
    else:
        low = str(floor if floor is not None else price_floor(budget))
        high = str(budget)
    query = {
        "zip": base_params.get("zip") or "",
        "distance": base_params.get("radius") or "50",
        "minPrice": low,
        "maxPrice": high,
        "sortType": "NEWEST_CAR_YEAR",
        "sortDirection": "ASC",
    }
    inventory = (base_params.get("inventory_type") or "used").lower()
    if inventory == "cpo":
        query["newUsed"] = "8"
    elif inventory != "new":
        query["newUsed"] = "2"
    body = base_params.get("body_type") or ""
    if body in BODY_GROUP:
        query["bodyTypeGroup"] = BODY_GROUP[body]
    if base_params.get("year"):
        query["startYear"] = base_params["year"]
        query["endYear"] = base_params["year"]
    miles = str(base_params.get("miles_range") or "")
    if "-" in miles:
        query["maxMileage"] = miles.split("-", 1)[1]
    if make_path:
        query["makeModelTrimPaths"] = make_path
    return CG_SEARCH + "?" + urllib.parse.urlencode(query)


def within_radius(raw: dict, radius: float) -> bool:
    dist = raw.get("dist")
    if dist is None:
        return True
    try:
        return float(dist) <= radius + 0.5
    except (TypeError, ValueError):
        return True


def select_listings(
    base_params: dict,
    budget: int,
    *,
    floor: int | None = None,
    apply_auto_floor: bool = True,
) -> dict:
    """Read one public results page and keep a short used-dealer set."""
    url = search_url(base_params, budget, floor=floor)
    page = fetch_html(url)
    if not page.get("ok"):
        return {
            "ok": False,
            "error": page.get("error") or "Couldn't load dealer listings.",
            "listings": [],
            "queries": [url],
        }
    html = page["html"]
    make = (base_params.get("make") or "").casefold()
    if make:
        path = make_paths(html).get(make)
        if path:
            url = search_url(base_params, budget, make_path=path, floor=floor)
            page = fetch_html(url)
            if not page.get("ok"):
                return {
                    "ok": False,
                    "error": page.get("error") or "Couldn't load dealer listings.",
                    "listings": [],
                    "queries": [url],
                }
            html = page["html"]

    wanted_body = base_params.get("body_type") or ""
    wanted_model = (base_params.get("model") or "").casefold()
    try:
        radius = float(base_params.get("radius") or 50)
    except (TypeError, ValueError):
        radius = 50.0
    kept: list[dict] = []
    seen: set[str] = set()
    scanned = 0
    dropped_new = 0
    for data in parse_cargurus_listings(html):
        raw = cargurus_to_raw(data)
        if not raw:
            continue
        scanned += 1
        if raw["inventory_type"] == "new":
            dropped_new += 1
        if not within_radius(raw, radius):
            continue
        if wanted_body and not body_matches(raw.get("body_type"), wanted_body):
            continue
        got_make = (raw.get("make") or "").casefold()
        if make and got_make != make and make not in got_make:
            continue
        if wanted_model and wanted_model not in (raw.get("model") or "").casefold():
            continue
        item = normalize_listing(
            raw, budget, floor=floor, apply_auto_floor=apply_auto_floor
        )
        if not item:
            continue
        if item["vin"] in seen:
            continue
        seen.add(item["vin"])
        kept.append(item)

    kept.sort(key=lambda item: (-(item.get("year") or 0), abs(budget - item["price"]), item["price"]))
    chosen = kept[:RESULT_LIMIT]
    real_page = ("LISTING_" in html) or ("minPrice" in html) or ("BODY_TYPE_GROUP" in html)
    if not chosen and not real_page:
        return {
            "ok": False,
            "error": "The listing site didn't include any listings.",
            "listings": [],
            "queries": [url],
        }
    return {
        "ok": True,
        "listings": chosen,
        "scanned": scanned,
        "dropped_new": dropped_new,
        "queries": [url],
        "error": None,
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
            return self._json(200, {"ok": True, "source": CG_SEARCH})
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
        min_s = one("min")
        zip_code = one("zip")
        body_style = one("body")
        want = one("want")

        if not zip_code or not re.fullmatch(r"\d{5}", zip_code):
            return self._json(400, {"ok": False, "error": "Enter a valid 5-digit US ZIP code.", "listings": []})

        try:
            budget = parse_whole_dollars(budget_s)
            if budget <= 0:
                raise ValueError
        except ValueError:
            return self._json(
                400,
                {"ok": False, "error": "Enter a max budget in USD (whole dollars).", "listings": []},
            )

        min_budget = None
        if min_s:
            try:
                min_budget = parse_whole_dollars(min_s)
            except ValueError:
                return self._json(
                    400,
                    {"ok": False, "error": "Enter a min budget in USD (whole dollars).", "listings": []},
                )
            if min_budget > budget:
                return self._json(
                    400,
                    {
                        "ok": False,
                        "error": "Min budget can't be higher than max budget.",
                        "listings": [],
                    },
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

        user_set_min = min_budget is not None
        floor = price_floor(budget, min_budget)
        # Automatic floor can sit above a tiny max. An explicit min equal to
        # the max is a real search for that exact price.
        if not user_set_min and floor >= budget:
            result = {
                "ok": True,
                "listings": [],
                "note": "Found 0 dealer listings.",
                "source": "CarGurus public dealer listings",
                "filters": {
                    "budget": budget,
                    "min": None,
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

        selected = select_listings(
            params, budget, floor=floor, apply_auto_floor=not user_set_min
        )
        listings = selected.get("listings") or []
        count = len(listings)
        noun = "listing" if count == 1 else "listings"
        result = {
            "ok": bool(selected.get("ok")),
            "listings": listings,
            "note": f"Found {count} dealer {noun}.",
            "source": "CarGurus public dealer listings",
            "filters": {
                "budget": budget,
                "min": min_budget,
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
    print(f"Listings source: {CG_SEARCH}")
    print(f"Accounts DB: {DB_PATH}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
