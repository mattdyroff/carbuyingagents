# Dealer cars near you

Small local search page. Enter a ZIP code, a max budget, an optional min budget, and optionally a body style, and get used cars from dealerships.

## Run

```bash
python3 /workspace/car-shop/server.py
```

Open http://127.0.0.1:8765/

## What it shows

Live dealer inventory from the public [CarGurus](https://www.cargurus.com) search page for that ZIP. No API key.

A row is kept only when it is a dealer listing, has a real 17-character VIN, an http(s) listing URL, and a price at or under the max budget. New cars are dropped. Manufacturer and social ad hosts are dropped. Results stay inside a 50-mile radius.

Min budget is optional. Leave it blank and prices under $5,000 are ignored. When the max is $15,000 or more, prices under 15% of the max are ignored too. If you enter a min, that amount is the price floor instead of those automatic floors, and anything over the max is still dropped. If min is higher than max, the search is rejected.

Both budget fields take any whole-dollar amount. ZIP is a 5-digit text field so a leading zero is kept.

Results are sorted by newer year, then closest to the max budget, and capped at 8 cars.

Leaving body blank searches all body styles. The page defaults the menu to SUV.

If the listing site blocks the request or doesn't return a page, search says so in plain language instead of showing the upstream error.
