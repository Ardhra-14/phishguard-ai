import asyncio
import os
from features.visual.screenshot_capture import capture_screenshot

BRANDS = {
    "sbi": "https://retail.onlinesbi.sbi",
    "hdfc": "https://netbanking.hdfcbank.com",
    "icici": "https://www.icicibank.com/login",
    "paytm": "https://paytm.com",
    "google": "https://accounts.google.com",
}

OUTPUT_DIR = "features/visual/reference_brands"

async def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    for brand, url in BRANDS.items():
        print(f"Capturing {brand} ({url})...")
        result = await capture_screenshot(url)
        if result["success"]:
            path = os.path.join(OUTPUT_DIR, f"{brand}.png")
            with open(path, "wb") as f:
                f.write(result["screenshot_bytes"])
            print(f"  Saved to {path}")
        else:
            print(f"  FAILED: {result['error']}")

asyncio.run(main())
