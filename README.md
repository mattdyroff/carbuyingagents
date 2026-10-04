# Dealer cars near you

Small local search page. Enter a ZIP code and a max budget, optionally a body style, and get used cars from dealerships.

## Run

```bash
python3 /workspace/car-shop/server.py
```

Open http://127.0.0.1:8765/

## What it shows

Live US dealer inventory from [unhuman.autos](https://unhuman.autos) `GET /api/cars`.

A row is kept only when it is a dealer listing (`seller_type=dealer`), has a real 17-character VIN, an http(s) vehicle listing URL, and a price. New cars are dropped even if the upstream ignores `inventory_type=used`. Manufacturer and social ad hosts are dropped.

Prices under $5,000 are ignored. When the budget is $15,000 or more, prices under 15% of the budget are ignored too. Results are sorted by newer year, then closest to the budget, and capped at 8 distinct cars (same name and dealer are combined).

Leaving body blank searches all body styles. The page defaults the menu to SUV.
