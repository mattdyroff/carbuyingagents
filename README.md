# Dealer cars near you

Small local search page. Enter a ZIP code and a max budget, optionally a body style, and get used cars from dealerships.

## Run

```bash
python3 /workspace/car-shop/server.py
```

Open http://127.0.0.1:8765/

## What it shows

Live dealer inventory from the public [CarGurus](https://www.cargurus.com) search page for that ZIP. No API key.

A row is kept only when it is a dealer listing, has a real 17-character VIN, an http(s) listing URL, and a price at or under the budget. New cars are dropped. Manufacturer and social ad hosts are dropped. Results stay inside a 50-mile radius.

Prices under $5,000 are ignored. When the budget is $15,000 or more, prices under 15% of the budget are ignored too. Results are sorted by newer year, then closest to the budget, and capped at 8 cars.

Leaving body blank searches all body styles. The page defaults the menu to SUV.

If the listing site blocks the request or doesn't return a page, search says so in plain language instead of showing the upstream error.
