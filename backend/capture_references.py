import asyncio
import os
from features.visual.screenshot_capture import capture_screenshot

BRANDS = {
    "sbi": "https://retail.onlinesbi.sbi",
    "hdfc": "https://netbanking.hdfcbank.com",
    "icici": "https://www.icicibank.com/login",
    "paytm": "https://paytm.com",
    "google": "https://accounts.google.com",
    "axis_bank": "https://www.axisbank.com/",
    "kotak_bank": "https://www.kotak.com/",
    "bank_of_baroda": "https://www.bankofbaroda.in/",
    "pnb": "https://www.pnbindia.in/",
    "phonepe": "https://www.phonepe.com/",
    "irctc": "https://www.irctc.co.in/",
    "income_tax_efiling": "https://www.incometax.gov.in/iec/foportal/",
}

OUTPUT_DIR = "features/visual/reference_brands"

async def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    for brand, url in BRANDS.items():
        path = os.path.join(OUTPUT_DIR, f"{brand}.png")
        if os.path.exists(path):
            print(f"Skipping {brand} - already captured")
            continue
        print(f"Capturing {brand} ({url})...")
        result = await capture_screenshot(url)
        if result["success"]:
            with open(path, "wb") as f:
                f.write(result["screenshot_bytes"])
            print(f"  Saved to {path}")
        else:
            print(f"  FAILED: {result['error']}")

asyncio.run(main())
