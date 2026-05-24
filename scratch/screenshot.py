import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        # Go to overview
        await page.goto("http://localhost:8003/targets/jobsdb.com/ai")
        await page.wait_for_timeout(1000)
        # Click the command button
        await page.click("text=Command")
        await page.wait_for_timeout(2000)
        
        # Take screenshot
        await page.screenshot(path="scratch/blank_issue.png")
        # Also print the HTML
        html = await page.content()
        with open("scratch/blank_issue.html", "w") as f:
            f.write(html)
        
        await browser.close()

asyncio.run(run())
