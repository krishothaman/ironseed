import sys
import asyncio
import logging

from torrent import Torrent
from client import TorrentClient

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_torrent_file>")
        sys.exit(1)

    path = sys.argv[1]
    torrent = Torrent(path)

    print(f"Torrent name: {torrent.output_file}")
    total_size_mb = torrent.total_length / (1024 * 1024)
    print(f"Total size: {total_size_mb:.2f} MB")
    print(f"Number of pieces: {torrent.number_of_pieces}")

    client = TorrentClient(torrent)

    try:
        asyncio.run(client.start())
        print("Download complete!")
    except KeyboardInterrupt:
        print("Download interrupted.")

if __name__ == '__main__':
    main()
