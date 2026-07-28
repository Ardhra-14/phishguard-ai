"""
Screenshot capture - Phase 4 (Visual Detection).

Uses Playwright (headless Chromium) to load a URL and capture both a
full-page screenshot AND the rendered HTML content, for downstream visual
(OCR/image) analysis and real DOM analysis respectively.
"""
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

NAVIGATION_TIMEOUT_MS = 15000
VIEWPORT = {"width": 1280, "height": 800}


async def capture_screenshot(url: str) -> dict:
    """
    Load `url` in headless Chromium and capture a full-page screenshot
    plus the rendered HTML.

    Returns:
        {
            "success": bool,
            "screenshot_bytes": bytes | None,
            "html_content": str | None,
            "final_url": str | None,
            "status_code": int | None,
            "error": str | None,
        }
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context = await browser.new_context(
                viewport=VIEWPORT,
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/127.0.0.0 Safari/537.36"
                ),
            )
            page = await context.new_page()

            try:
                response = await page.goto(
                    url, timeout=NAVIGATION_TIMEOUT_MS, wait_until="networkidle"
                )
            except PlaywrightTimeoutError:
                response = None

            screenshot_bytes = await page.screenshot(full_page=True, type="png")
            html_content = await page.content()

            return {
                "success": True,
                "screenshot_bytes": screenshot_bytes,
                "html_content": html_content,
                "final_url": page.url,
                "status_code": response.status if response else None,
                "error": None,
            }

        except Exception as e:
            return {
                "success": False,
                "screenshot_bytes": None,
                "html_content": None,
                "final_url": None,
                "status_code": None,
                "error": str(e),
            }
        finally:
            await browser.close()
