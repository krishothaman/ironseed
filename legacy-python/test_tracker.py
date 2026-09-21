import asyncio
import logging
from torrent import Torrent
from tracker import Tracker

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

async def main():
    t = Torrent('ubuntu-25.10-desktop-amd64.iso.torrent')
    tr = Tracker(t)
    print("Connecting to tracker...")
    res = await tr.connect(first=True)
    if res.failed:
        print("Failed:", res.failure_reason)
    else:
        print("Interval:", res.interval)
        print("Peers count:", len(res.peers))
        print("First few peers:", res.peers[:5])

if __name__ == '__main__':
    asyncio.run(main())
