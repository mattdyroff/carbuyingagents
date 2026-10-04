# Dealer cars near you

Small local search page. Enter a ZIP code, a max budget, an optional min budget, and optionally a body style, and get used cars from dealerships.

## Run

```bash
python3 /workspace/car-shop/server.py
```

Open http://127.0.0.1:8765/

## What it shows

Used cars from dealership inventory pages near that ZIP, inside 50 miles. Dealer sites are found from the public map of car dealerships, then each site is read with a normal page request. If a dealer site answers with a block, a captcha, or no inventory, it is skipped. CarGurus is the fallback when those pages don't fill the list. No API key.

A row is kept only when it is a dealer listing, has a real 17-character VIN, an http(s) listing URL, and a price at or under the max budget. Dealer-site links point at that dealer's vehicle page. New cars are dropped. Manufacturer and social ad hosts are dropped.

Min budget is optional. Leave it blank and prices under $5,000 are ignored. When the max is $15,000 or more, prices under 15% of the max are ignored too. If you enter a min, that amount is the price floor instead of those automatic floors, and anything over the max is still dropped. If min is higher than max, the search is rejected.

Both budget fields take any whole-dollar amount. ZIP is a 5-digit text field so a leading zero is kept.

Results are sorted by newer year, then closest to the max budget, and capped at 8 cars.

Each result adds a monthly payment estimate (60 months at 7%, before tax and fees). When the free public sources have them, the card also shows open NHTSA recalls for that VIN, the NHTSA crash-test rating, and EPA combined fuel economy. A car with high miles for its age, or a price at the top of the max budget, gets a short note.

Leaving body blank searches all body styles. The page defaults the menu to SUV.

If a listing site blocks the request or doesn't return a page, search says so in plain language instead of showing the upstream error.
