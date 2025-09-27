import asyncio
import ssl
import re
import time
from urllib.parse import urlparse

from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.protocol import QuicConnectionProtocol

base_url = "https://liquigas.duckdns.org/"
img_urls = []


def extract_img_urls(html: str):
    """Extract all <img src="..."> from HTML content."""
    return re.findall(r'<img\s+[^>]*src="([^"]+)"', html)


class SimpleHttpClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.h3_connection = H3Connection(self._quic)
        self._responses = {}  # stream_id -> asyncio.Future

    def quic_event_received(self, event):
        # pass event to H3 layer
        for http_event in self.h3_connection.handle_event(event):
            self.handle_http_event(http_event)

    def handle_http_event(self, event):
        stream_id = getattr(event, "stream_id", None)
        if stream_id is None:
            return

        # initialize future for new stream
        if stream_id not in self._responses:
            self._responses[stream_id] = {
                "future": asyncio.get_event_loop().create_future(),
                "headers": [],
                "data": b""
            }

        resp = self._responses[stream_id]

        if isinstance(event, HeadersReceived):
            resp["headers"] = event.headers
        elif isinstance(event, DataReceived):
            resp["data"] += event.data

        # mark stream as done
        if getattr(event, "stream_ended", False):
            if not resp["future"].done():
                resp["future"].set_result((resp["headers"], resp["data"]))


async def fetch(client: SimpleHttpClient, url: str):
    parsed = urlparse(url)
    host = parsed.hostname
    path = parsed.path or "/"

    # get next available QUIC stream ID for this request
    stream_id = client._quic.get_next_available_stream_id()

    # initialize the response future for this stream
    client._responses[stream_id] = {
        "future": asyncio.get_event_loop().create_future(),
        "headers": [],
        "data": b"",
    }

    # send GET request
    client.h3_connection.send_headers(
        stream_id=stream_id,
        headers=[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", host.encode()),
            (b":path", path.encode()),
        ],
        end_stream=True
    )
    #client.h3_connection.send_data(stream_id, b"", end_stream=True)
    client.transmit()

    # await response
    headers, data = await client._responses[stream_id]["future"]

    # extract img URLs if HTML
    if "jpg" not in url and "png" not in url:
        html_content = data.decode(errors="ignore")
        new_imgs = extract_img_urls(html_content)
        for img in new_imgs:
            img_urls.append(base_url + img)

    return data


async def main():
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    #configuration.verify_mode = ssl.CERT_NONE  # skip verification for simplicity

    # Open a single QUIC connection
    parsed = urlparse(base_url)
    async with connect(
        parsed.hostname,
        parsed.port or 443,
        configuration=configuration,
        create_protocol=SimpleHttpClient,
    ) as client:
        client = client  # type: SimpleHttpClient

        # First fetch (HTML page)
        await fetch(client, base_url)

        # Now fetch all images concurrently over the same QUIC connection
        tasks = [fetch(client, url) for url in img_urls]
        results = await asyncio.gather(*tasks)

        # Print results
        for url, data in zip(img_urls, results):
            print(f"Fetched {url}, {len(data)} bytes")


if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(main())
    print(f"{round((time.time() - start_time)*1000)} ms")

