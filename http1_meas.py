import asyncio
import aiohttp
import re
import time

base_url = "https://liquigas.duckdns.org/"
img_urls = []

def extract_img_urls(html: str):
    """Extract all <img src="..."> from HTML content."""
    return re.findall(r'<img\s+[^>]*src="([^"]+)"', html)

async def fetch(session: aiohttp.ClientSession, url: str):
    async with session.get(url) as resp:
        data = await resp.read()

    # extract image URLs if HTML
    if not url.lower().endswith((".jpg", ".png")):
        html_content = data.decode(errors="ignore")
        new_imgs = extract_img_urls(html_content)
        for img in new_imgs:
            img_urls.append(base_url + img)

    return data

async def main():
    # limit number of concurrent connections (like multiplexing)
    connector = aiohttp.TCPConnector(limit=6)  # adjust number of connections
    async with aiohttp.ClientSession(connector=connector) as session:
        # First fetch (HTML page)
        await fetch(session, base_url)

        # Now fetch all images concurrently using same connector
        tasks = [fetch(session, url) for url in img_urls]
        results = await asyncio.gather(*tasks)

        # Print results
        for url, data in zip(img_urls, results):
            print(f"Fetched {url}, {len(data)} bytes")

if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(main())
    print(f"{round((time.time() - start_time)*1000)} ms")
