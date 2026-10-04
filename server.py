#!/usr/bin/env python3
"""Dealer car search. Reads nearby dealer inventory pages, then CarGurus if those pages do not fill the list."""

from __future__ import annotations

import hashlib
import html as html_lib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
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


DEALER_FETCH_LIMIT = 40
DEALER_WAVE = 6
DEALER_WORKERS = 5
DEALER_PAGE_TIMEOUT = 12
RADIUS_METERS = 80467
_CACHE_LOCK = threading.Lock()
_GEO_CACHE: dict[str, tuple[float, float] | None] = {}
_DEALER_CACHE: dict[tuple[float, float], list[dict]] = {}

# Skip directories and brand homepages. A dealer site that answers 403 is skipped later.
SKIP_SITE_HOSTS = AD_HOSTS + OEM_HOSTS + (
    "cargurus.com", "cars.com", "autotrader.com", "edmunds.com", "carfax.com",
    "yelp.com", "bbb.org", "yellowpages.com", "tesla.com", "rivian.com",
    "truecar.com", "kbb.com", "carvana.com",
)

LISTING_INDEX = re.compile(
    r"newandusedcars|used-inventory|used-vehicles|/inventory(?:[/?#]|$)|cars-for-sale|used_cars|searchused",
    re.I,
)

# When a dealer page has no body-style field, match the model name.
SUV_MODELS = (
    "rav4", "cr-v", "crv", "hr-v", "hrv", "pilot", "passport", "mdx", "rdx",
    "cx-5", "cx-50", "cx-9", "cx-90", "cx-30", "cx5", "cx9", "tucson", "santa fe",
    "palisade", "venue", "kona", "sportage", "sorento", "telluride", "seltos",
    "niro", "rogue", "murano", "pathfinder", "armada", "explorer", "escape",
    "edge", "expedition", "bronco", "equinox", "traverse", "tahoe", "suburban",
    "blazer", "trailblazer", "trax", "outback", "forester", "crosstrek", "ascent",
    "wrangler", "grand cherokee", "cherokee", "compass", "renegade", "durango",
    "glc", "gle", "gls", "gla", "glb", "macan", "cayenne", "q3", "q5", "q7", "q8",
    "x1", "x3", "x5", "x7", "model y", "ioniq 5", "ev6", "id.4", "atlas", "tiguan",
    "taos", "enclave", "encore", "envision", "xt4", "xt5", "xt6", "escalade",
    "highlander", "4runner", "sequoia", "venza", "corolla cross", "outlander",
    "eclipse cross", "navigator", "aviator", "corsair", "nautilus", "discovery",
    "range rover", "defender", "xc40", "xc60", "xc90", "gv70", "gv80", "rx350",
    "rx450", "nx", "gx", "lx", "ux", "mdx", "rdx", "cayenne", "levante",
    "stelvio", "urus", "bentayga", "cullinan", "dbx",
)

VIN_TRANSLIT = {
    **{str(i): i for i in range(10)},
    **dict(zip(
        "ABCDEFGHJKLMNPRSTUVWXYZ",
        [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 7, 9, 2, 3, 4, 5, 6, 7, 8, 9],
    )),
}
VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def vin_check_digit(vin: str) -> bool:
    """17-character VIN whose check digit matches. Drops random strings."""
    vin = vin.strip().upper()
    if not is_real_vin(vin):
        return False
    total = 0
    for index, char in enumerate(vin):
        value = VIN_TRANSLIT.get(char)
        if value is None:
            return False
        total += value * VIN_WEIGHTS[index]
    check = total % 11
    expected = "X" if check == 10 else str(check)
    return vin[8] == expected


def haversine_miles(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    import math
    radius = 3958.8
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlon / 2) ** 2
    return 2 * radius * math.asin(min(1.0, math.sqrt(a)))


def site_host(url: str) -> str:
    return urllib.parse.urlsplit(url).netloc.lower().split(":")[0].rstrip(".")


def skip_directory_site(url: str) -> bool:
    host = site_host(url)
    if not host:
        return True
    return any(host_is(host, name) for name in SKIP_SITE_HOSTS)


def site_origin(url: str) -> str | None:
    raw = (url or "").strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parts = urllib.parse.urlsplit(raw)
    host = parts.netloc.lower().split(":")[0]
    if not host or "." not in host:
        return None
    scheme = parts.scheme if parts.scheme in ("http", "https") else "https"
    return f"{scheme}://{host}/"


def is_wall(html: str) -> bool:
    """Bot wall or captcha page. A page that already lists VINs is not a wall."""
    if not html or not html.strip():
        return False
    sample = html[:8000].casefold()
    markers = (
        "captcha-delivery.com",
        "please enable js and disable any ad blocker",
        "cf-browser-verification",
        "just a moment",
        "attention required",
        "verify you are human",
        "access denied",
        "/cdn-cgi/challenge",
    )
    if not any(marker in sample for marker in markers):
        return False
    folded = html.casefold()
    if "hdndwinventorylist" in folded or folded.count("optvin") >= 1:
        return False
    if len(re.findall(r"\b[A-HJ-NPR-Z0-9]{17}\b", html[:200000])) >= 2:
        return False
    return True


def fetch_public(url: str) -> dict:
    """Plain GET of a public page. A 403 or captcha is a skip, not a retry."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=DEALER_PAGE_TIMEOUT) as resp:
            html = resp.read(2_000_000).decode("utf-8", "replace")
            final = resp.geturl()
    except urllib.error.HTTPError as e:
        if e.code in (401, 403, 429, 503):
            return {"ok": False, "blocked": True, "html": "", "url": url, "error": "blocked"}
        return {"ok": False, "blocked": False, "html": "", "url": url, "error": "empty"}
    except Exception:
        return {"ok": False, "blocked": False, "html": "", "url": url, "error": "unreachable"}
    if is_wall(html):
        return {"ok": False, "blocked": True, "html": "", "url": final, "error": "blocked"}
    return {"ok": True, "blocked": False, "html": html, "url": final, "error": None}


def classify_body(*parts: str) -> str:
    text = " ".join(part for part in parts if part).casefold()
    if not text:
        return ""
    if any(word in text for word in ("sport utility", "suv", "crossover")):
        return "suv"
    if any(word in text for word in ("pickup", "pick-up", "truck", "crew cab", "extended cab", "regular cab", "supercrew")):
        return "truck"
    for body, words in BODY_WORDS.items():
        if body in ("suv", "truck"):
            continue
        if any(re.search(rf"\b{re.escape(word)}\b", text) for word in words):
            return body
    for model in SUV_MODELS:
        if re.search(rf"\b{re.escape(model)}\b", text):
            return "suv"
    return ""


def absolute_url(page_url: str, href: str) -> str:
    return urllib.parse.urljoin(page_url, html_lib.unescape(href.strip()))


def inventory_index_links(html: str, page_url: str) -> list[str]:
    origin = site_host(page_url)
    found: list[str] = []
    for href in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
        if href.startswith(("javascript:", "mailto:", "#", "tel:")):
            continue
        abs_url = absolute_url(page_url, href).split("#", 1)[0]
        if site_host(abs_url) != origin:
            continue
        if not LISTING_INDEX.search(abs_url):
            continue
        if "/vdp/" in abs_url.casefold():
            continue
        if abs_url not in found:
            found.append(abs_url)
    return found[:3]


def _new_flag(value) -> bool:
    if value is True:
        return True
    if isinstance(value, str) and value.strip().casefold() in {"new", "n", "true", "1"}:
        return True
    return False


def parse_dealerweb(html: str, page_url: str) -> list[dict]:
    marker = html.find("hdnDWInventoryList")
    if marker < 0:
        return []
    chunk = html[marker:marker + 500000]
    start = chunk.find("{")
    if start < 0:
        return []
    payload = chunk[start:]
    try:
        data, _end = json.JSONDecoder().raw_decode(payload)
    except json.JSONDecodeError:
        try:
            data, _end = json.JSONDecoder().raw_decode(html_lib.unescape(payload))
        except json.JSONDecodeError:
            return []
    cars = data.get("InvPageList") if isinstance(data, dict) else None
    if not isinstance(cars, list):
        return []
    rows: list[dict] = []
    for car in cars:
        if not isinstance(car, dict):
            continue
        vin = str(car.get("Vin") or "").strip().upper()
        if not vin_check_digit(vin):
            continue
        price = as_int(car.get("InternetPrice"))
        if price is None or price < 1000:
            price = as_int(car.get("SuggSalePrice"))
        if price is None or price < 1000:
            continue
        year = as_int(car.get("Year"))
        make = str(car.get("Make") or "").strip()
        model = str(car.get("Model") or "").strip()
        trim = str(car.get("Trim") or "").strip()
        body = classify_body(str(car.get("BodyType") or ""), model, trim)
        title = " ".join(part for part in (str(year or ""), make, model, trim) if part).strip()
        detail = str(car.get("InventoryDetailURL") or "").strip()
        url = absolute_url(page_url, detail) if detail else ""
        token = str(car.get("URLEncodedEncrInvID") or "").strip()
        if not url and token:
            match = re.search(r'href="([^"]*' + re.escape(token) + r'[^"]*)"', html)
            if match:
                url = absolute_url(page_url, match.group(1))
        if not url:
            vin_at = html.find(vin)
            if vin_at >= 0:
                region = html[vin_at:vin_at + 2500]
                match = re.search(r'href="(https?://[^"]+)"', region)
                if match:
                    url = absolute_url(page_url, match.group(1))
        if not url.startswith(("http://", "https://")):
            continue
        rows.append({
            "vin": vin,
            "price": price,
            "year": year,
            "make": make,
            "model": model,
            "trim": trim,
            "body": body,
            "title": title,
            "miles": as_int(car.get("Miles")),
            "url": url,
            "inventory_type": "new" if _new_flag(car.get("NewOrUsed")) else "used",
        })
    return rows


def parse_dealer_car_search(html: str, page_url: str) -> list[dict]:
    if "/vdp/" not in html:
        return []
    ordered: list[tuple[int, str]] = []
    seen: set[str] = set()
    for match in re.finditer(r"/vdp/(\d+)/", html):
        vid = match.group(1)
        if vid in seen:
            continue
        seen.add(vid)
        ordered.append((match.start(), vid))
    rows: list[dict] = []
    for index, (pos, vid) in enumerate(ordered):
        end = ordered[index + 1][0] if index + 1 < len(ordered) else pos + 8000
        window = html[max(0, pos - 500): min(end, pos + 8000)]
        path_match = re.search(rf'href="([^"]*/vdp/{vid}/[^"]*)"', window)
        if not path_match:
            continue
        path = html_lib.unescape(path_match.group(1))
        path_l = path.casefold()
        if re.search(r"/new-|new-\d{4}", path_l):
            inventory = "new"
        else:
            inventory = "used"
        vin_match = re.search(r"\b([A-HJ-NPR-Z0-9]{17})\b", window)
        if not vin_match or not vin_check_digit(vin_match.group(1)):
            continue
        price_match = re.search(
            rf"compareChecked\(\s*this\s*,\s*'{vid}'\s*,\s*'\$([\d,]+)'",
            html,
        )
        if not price_match:
            price_match = re.search(r"\$\s?([\d,]{4,})", window)
        if not price_match:
            continue
        price = as_int(price_match.group(1))
        if price is None or price < 1000:
            continue
        title_match = re.search(rf'aria-label="([^"]+)"[^>]*href="[^"]*/vdp/{vid}/', window)
        if not title_match:
            title_match = re.search(rf'href="[^"]*/vdp/{vid}/[^"]*"[^>]*aria-label="([^"]+)"', window)
        title = html_lib.unescape(title_match.group(1)) if title_match else ""
        title = re.sub(r"\s+", " ", title).strip()
        miles_match = re.search(r"Mileage:\s*</label>\s*([\d,]+)", window, re.S | re.I)
        miles = as_int(miles_match.group(1)) if miles_match else None
        year_match = re.search(r"\b(19\d{2}|20\d{2})\b", title)
        year = int(year_match.group(1)) if year_match else None
        body = classify_body(title, path)
        rows.append({
            "vin": vin_match.group(1).upper(),
            "price": price,
            "year": year,
            "make": "",
            "model": "",
            "trim": "",
            "body": body,
            "title": title,
            "miles": miles,
            "url": absolute_url(page_url, path.split("?")[0]),
            "inventory_type": inventory,
        })
    return rows


def parse_jsonld_vehicles(html: str, page_url: str) -> list[dict]:
    rows: list[dict] = []
    for block in re.findall(
        r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        html,
        re.S | re.I,
    ):
        try:
            data = json.loads(block.strip())
        except json.JSONDecodeError:
            continue
        stack = data if isinstance(data, list) else [data]
        flat: list[dict] = []
        while stack:
            item = stack.pop()
            if isinstance(item, list):
                stack.extend(item)
                continue
            if not isinstance(item, dict):
                continue
            if "@graph" in item and isinstance(item["@graph"], list):
                stack.extend(item["@graph"])
            flat.append(item)
        for item in flat:
            kind = item.get("@type") or ""
            if isinstance(kind, list):
                kind = " ".join(str(part) for part in kind)
            if "vehicle" not in str(kind).casefold() and "car" not in str(kind).casefold():
                continue
            vin = str(item.get("vehicleIdentificationNumber") or "").strip().upper()
            if not vin_check_digit(vin):
                continue
            offers = item.get("offers") or {}
            if isinstance(offers, list):
                offers = offers[0] if offers else {}
            price = as_int(offers.get("price") if isinstance(offers, dict) else None)
            if price is None:
                price = as_int(item.get("price"))
            if price is None or price < 1000:
                continue
            url = ""
            if isinstance(offers, dict):
                url = str(offers.get("url") or "")
            if not url:
                url = str(item.get("url") or "")
            url = absolute_url(page_url, url) if url else ""
            if not url.startswith(("http://", "https://")):
                continue
            year = as_int(item.get("vehicleModelDate") or item.get("modelDate") or item.get("releaseDate"))
            make = item.get("brand") or item.get("manufacturer") or ""
            if isinstance(make, dict):
                make = make.get("name") or ""
            model = str(item.get("model") or "").strip()
            name = str(item.get("name") or "").strip()
            body = classify_body(str(item.get("bodyType") or ""), name, model)
            miles = None
            odo = item.get("mileageFromOdometer")
            if isinstance(odo, dict):
                miles = as_int(odo.get("value"))
            else:
                miles = as_int(odo)
            condition = str(item.get("itemCondition") or "").casefold()
            inventory = "new" if "newcondition" in condition else "used"
            rows.append({
                "vin": vin,
                "price": price,
                "year": year,
                "make": str(make or "").strip(),
                "model": model,
                "trim": "",
                "body": body,
                "title": name,
                "miles": miles,
                "url": url.split("?")[0],
                "inventory_type": inventory,
            })
    return rows


def parse_dealer_inventory(html: str, page_url: str) -> list[dict]:
    rows = parse_dealerweb(html, page_url)
    if rows:
        return rows
    rows = parse_dealer_car_search(html, page_url)
    if rows:
        return rows
    return parse_jsonld_vehicles(html, page_url)


def geocode_zip(zip_code: str) -> tuple[float, float] | None:
    with _CACHE_LOCK:
        if zip_code in _GEO_CACHE:
            return _GEO_CACHE[zip_code]
    url = "https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode({
        "postalcode": zip_code,
        "country": "us",
        "format": "json",
        "limit": "1",
    })
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "carbuyingagents/1.0 (dealer search)", "Accept": "application/json"},
    )
    point = None
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        if data:
            point = (float(data[0]["lat"]), float(data[0]["lon"]))
    except Exception:
        point = None
    with _CACHE_LOCK:
        _GEO_CACHE[zip_code] = point
    return point


def _overpass(query: str) -> list[dict] | None:
    payload = urllib.parse.urlencode({"data": query}).encode()
    # The public map sometimes times out. Retry the same query once, then one backup.
    attempts = (
        ("https://overpass-api.de/api/interpreter", 25),
        ("https://overpass-api.de/api/interpreter", 25),
        ("https://overpass.kumi.systems/api/interpreter", 20),
    )
    for index, (endpoint, timeout) in enumerate(attempts):
        if index:
            time.sleep(2)
        req = urllib.request.Request(
            endpoint,
            data=payload,
            headers={"User-Agent": "carbuyingagents/1.0 (public dealer search)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            elements = data.get("elements")
            if isinstance(elements, list):
                return elements
        except Exception:
            continue
    return None


def nearby_dealer_sites(lat: float, lon: float, radius_miles: float) -> tuple[list[dict], str | None]:
    key = (round(lat, 2), round(lon, 2), int(radius_miles))
    with _CACHE_LOCK:
        cached = _DEALER_CACHE.get(key)
    if cached is not None:
        return cached, None
    meters = int(radius_miles * 1609.344)
    # One tag keeps the public map query small enough to answer. A heavier query times out.
    query = (
        f'[out:json][timeout:25];'
        f'nwr["shop"="car"]["website"](around:{meters},{lat},{lon});'
        f'out tags center;'
    )
    elements = _overpass(query)
    if elements is None:
        return [], "Couldn't look up nearby dealer websites."
    dealers: list[dict] = []
    seen_hosts: set[str] = set()
    for el in elements:
        tags = el.get("tags") or {}
        website = tags.get("website") or tags.get("contact:website") or ""
        origin = site_origin(website)
        if not origin or skip_directory_site(origin):
            continue
        host = site_host(origin)
        if host in seen_hosts:
            continue
        center = el.get("center") or {}
        el_lat = el.get("lat", center.get("lat"))
        el_lon = el.get("lon", center.get("lon"))
        try:
            miles = haversine_miles(lat, lon, float(el_lat), float(el_lon))
        except (TypeError, ValueError):
            continue
        if miles > radius_miles + 0.5:
            continue
        seen_hosts.add(host)
        name = (tags.get("name") or host).strip()
        dealers.append({
            "name": name,
            "city": (tags.get("addr:city") or "").strip(),
            "state": (tags.get("addr:state") or "").strip(),
            "miles": round(miles, 1),
            "origin": origin,
            "host": host,
        })
    dealers.sort(key=lambda row: row["miles"])
    with _CACHE_LOCK:
        _DEALER_CACHE[key] = dealers
    return dealers, None


def _raw_from_parsed(parsed: dict, dealer: dict) -> dict:
    title = parsed.get("title") or ""
    year = parsed.get("year")
    make = parsed.get("make") or ""
    model = parsed.get("model") or ""
    if not title:
        title = " ".join(str(part) for part in (year, make, model) if part).strip()
    return {
        "seller_type": "dealer",
        "inventory_type": parsed.get("inventory_type") or "used",
        "dealer": {
            "name": dealer["name"],
            "city": dealer["city"],
            "state": dealer["state"],
        },
        "vin": parsed["vin"],
        "vdp_url": parsed["url"],
        "price": parsed["price"],
        "build": {
            "year": year,
            "make": make,
            "model": model,
            "body_type": parsed.get("body") or "",
        },
        "heading": title,
        "miles": parsed.get("miles"),
        "dist": dealer["miles"],
        "make": make,
        "model": model,
        "year": year,
        "body_type": parsed.get("body") or "",
    }


def read_dealer_inventory(dealer: dict) -> dict:
    """Fetch one dealer origin and, if needed, one public inventory index."""
    home = fetch_public(dealer["origin"])
    if home.get("blocked"):
        return {"status": "blocked", "dealer": dealer, "rows": []}
    if not home.get("ok"):
        # Published http links often redirect only on https. One same-site retry.
        if dealer["origin"].startswith("http://"):
            dealer = dict(dealer)
            dealer["origin"] = "https://" + dealer["origin"][len("http://"):]
            home = fetch_public(dealer["origin"])
        if home.get("blocked"):
            return {"status": "blocked", "dealer": dealer, "rows": []}
        if not home.get("ok"):
            status = "blocked" if home.get("blocked") else "unreachable"
            return {"status": status, "dealer": dealer, "rows": []}
    rows = parse_dealer_inventory(home["html"], home["url"])
    if rows:
        return {"status": "listings", "dealer": dealer, "rows": rows}
    links = inventory_index_links(home["html"], home["url"])
    if not links:
        links = [
            urllib.parse.urljoin(dealer["origin"], path)
            for path in ("/newandusedcars?clearall=1", "/used-inventory/index.htm")
        ]
    blocked_follow = False
    for link in links[:2]:
        page = fetch_public(link)
        if page.get("blocked"):
            blocked_follow = True
            continue
        if not page.get("ok"):
            continue
        rows = parse_dealer_inventory(page["html"], page["url"])
        if rows:
            return {"status": "listings", "dealer": dealer, "rows": rows}
    if blocked_follow and not rows:
        return {"status": "blocked", "dealer": dealer, "rows": []}
    return {"status": "empty", "dealer": dealer, "rows": []}


def passes_filters(raw: dict, base_params: dict, radius: float) -> bool:
    if not within_radius(raw, radius):
        return False
    wanted_body = base_params.get("body_type") or ""
    if wanted_body and not body_matches(raw.get("body_type"), wanted_body):
        return False
    make = (base_params.get("make") or "").casefold()
    got_make = (raw.get("make") or "").casefold()
    heading = (raw.get("heading") or "").casefold()
    if make and got_make != make and make not in got_make and make not in heading:
        return False
    wanted_model = (base_params.get("model") or "").casefold()
    if wanted_model and wanted_model not in (raw.get("model") or "").casefold() and wanted_model not in heading:
        return False
    if base_params.get("year"):
        try:
            if int(raw.get("year") or 0) != int(base_params["year"]):
                return False
        except (TypeError, ValueError):
            return False
    miles_range = str(base_params.get("miles_range") or "")
    if "-" in miles_range:
        try:
            miles_max = int(miles_range.split("-", 1)[1])
        except ValueError:
            miles_max = None
        miles = as_int(raw.get("miles"))
        if miles_max is not None and miles is not None and miles > miles_max:
            return False
    return True


def search_dealer_sites(
    base_params: dict,
    budget: int,
    *,
    floor: int | None = None,
    apply_auto_floor: bool = True,
) -> dict:
    """Read public inventory pages for dealerships near the ZIP."""
    zip_code = base_params.get("zip") or ""
    try:
        radius = float(base_params.get("radius") or 50)
    except (TypeError, ValueError):
        radius = 50.0
    point = geocode_zip(zip_code)
    if not point:
        return {
            "ok": False,
            "listings": [],
            "blocked": [],
            "empty": [],
            "worked": [],
            "error": "Couldn't look up that ZIP for nearby dealers.",
        }
    dealers, lookup_error = nearby_dealer_sites(point[0], point[1], radius)
    if lookup_error:
        return {
            "ok": False,
            "listings": [],
            "blocked": [],
            "empty": [],
            "worked": [],
            "error": lookup_error,
        }
    shortlist = dealers[:DEALER_FETCH_LIMIT]
    kept: list[dict] = []
    seen: set[str] = set()
    blocked: list[str] = []
    empty: list[str] = []
    worked: list[str] = []
    unreachable: list[str] = []

    def take(result: dict) -> None:
        dealer = result["dealer"]
        status = result["status"]
        if status == "blocked":
            blocked.append(dealer["host"])
            return
        if status == "unreachable":
            unreachable.append(dealer["host"])
            return
        if status != "listings":
            empty.append(dealer["name"])
            return
        added = False
        for parsed in result["rows"]:
            raw = _raw_from_parsed(parsed, dealer)
            if not passes_filters(raw, base_params, radius):
                continue
            item = normalize_listing(
                raw, budget, floor=floor, apply_auto_floor=apply_auto_floor
            )
            if not item or item["vin"] in seen:
                continue
            # Keep the dealer's own vehicle page. Aggregator and ad hosts are dropped.
            link_host = site_host(item["url"]).removeprefix("www.")
            dealer_host = dealer["host"].removeprefix("www.")
            if link_host != dealer_host and not host_is(link_host, dealer_host):
                continue
            item["listing_source"] = "dealer_site"
            seen.add(item["vin"])
            kept.append(item)
            added = True
        if added or result["rows"]:
            worked.append(dealer["name"])

    waves = [shortlist[i:i + DEALER_WAVE] for i in range(0, len(shortlist), DEALER_WAVE)]
    with ThreadPoolExecutor(max_workers=DEALER_WORKERS) as pool:
        for wave in waves:
            if len(kept) >= RESULT_LIMIT:
                break
            futures = [pool.submit(read_dealer_inventory, dealer) for dealer in wave]
            for future in as_completed(futures):
                try:
                    take(future.result())
                except Exception:
                    continue
    return {
        "ok": True,
        "listings": kept,
        "blocked": blocked,
        "empty": empty,
        "worked": worked,
        "unreachable": unreachable,
        "dealers_considered": len(shortlist),
        "error": None,
    }


def listing_sort_key(item: dict, budget: int) -> tuple:
    return (-(item.get("year") or 0), abs(budget - item["price"]), item["price"])


def search_market(
    base_params: dict,
    budget: int,
    *,
    floor: int | None = None,
    apply_auto_floor: bool = True,
) -> dict:
    """Dealer websites first. CarGurus fills in when those pages come up short."""
    dealer = search_dealer_sites(
        base_params, budget, floor=floor, apply_auto_floor=apply_auto_floor
    )
    dealer_listings = dealer.get("listings") or []
    cg: dict = {"ok": True, "listings": [], "error": None}
    if len(dealer_listings) < RESULT_LIMIT:
        cg = select_listings(
            base_params, budget, floor=floor, apply_auto_floor=apply_auto_floor
        )
    cg_listings = cg.get("listings") or []
    seen = {item["vin"] for item in dealer_listings}
    merged = list(dealer_listings)
    for item in cg_listings:
        item["listing_source"] = "cargurus"
        if item["vin"] in seen:
            continue
        seen.add(item["vin"])
        merged.append(item)
    merged.sort(key=lambda item: listing_sort_key(item, budget))
    chosen = merged[:RESULT_LIMIT]
    dealer_in_results = any(item.get("listing_source") == "dealer_site" for item in chosen)
    if dealer_listings and not dealer_in_results:
        best = min(dealer_listings, key=lambda item: listing_sort_key(item, budget))
        chosen = (chosen[: RESULT_LIMIT - 1] if len(chosen) == RESULT_LIMIT else chosen) + [best]
        chosen.sort(key=lambda item: listing_sort_key(item, budget))
    dealer_count = sum(1 for item in chosen if item.get("listing_source") == "dealer_site")
    count = len(chosen)
    noun = "listing" if count == 1 else "listings"
    if dealer_count and dealer_count == count:
        note = f"Found {count} dealer {noun} from nearby dealer websites."
        source = "Nearby dealer websites"
    elif dealer_count:
        note = f"Found {count} dealer {noun} from nearby dealer websites and CarGurus."
        source = "Nearby dealer websites and CarGurus"
    elif chosen and not dealer.get("ok"):
        reason = (dealer.get("error") or "Nearby dealer sites didn't return a public inventory page").rstrip(".")
        note = f"Found {count} dealer {noun}. {reason}, so these are from CarGurus."
        source = "CarGurus public dealer listings"
    elif chosen:
        note = (
            f"Found {count} dealer {noun}. Nearby dealer sites didn't return a public "
            "inventory page, so these are from CarGurus."
        )
        source = "CarGurus public dealer listings"
    else:
        note = "Found 0 dealer listings."
        source = "Nearby dealer websites and CarGurus"
    ok = bool(chosen) or bool(cg.get("ok")) or bool(dealer.get("ok"))
    error = None
    if not ok:
        error = cg.get("error") or dealer.get("error") or "Couldn't load dealer listings."
        note = error
    return {
        "ok": ok,
        "listings": chosen if ok else [],
        "error": error,
        "note": note,
        "source": source,
        "dealer_sites_used": dealer.get("worked") or [],
        "dealer_sites_blocked": dealer.get("blocked") or [],
        "dealer_sites_empty": dealer.get("empty") or [],
        "dealer_sites_unreachable": dealer.get("unreachable") or [],
    }


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
        item["listing_source"] = "cargurus"
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

        selected = search_market(
            params, budget, floor=floor, apply_auto_floor=not user_set_min
        )
        listings = selected.get("listings") or []
        result = {
            "ok": bool(selected.get("ok")),
            "listings": listings,
            "note": selected.get("note") or "Found 0 dealer listings.",
            "source": selected.get("source") or "Nearby dealer websites and CarGurus",
            "filters": {
                "budget": budget,
                "min": min_budget,
                "zip": zip_code,
                "body": body or None,
                "price_floor": floor,
                "inventory_type": "used",
            },
            "dealer_sites_used": selected.get("dealer_sites_used") or [],
            "dealer_sites_blocked": selected.get("dealer_sites_blocked") or [],
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
