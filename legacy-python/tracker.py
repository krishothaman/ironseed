import random
import socket
import struct
import urllib.parse
import aiohttp

from torrent import Torrent
from bencoding import Decoder

class TrackerResponse:
    def __init__(self, raw: dict):
        self.raw = raw
        
    @property
    def peers(self) -> list[tuple[str, int]]:
        peers = []
        if b'peers' in self.raw:
            raw_peers = self.raw[b'peers']
            # Compact format: 6 bytes per peer (4 bytes IP + 2 bytes port)
            if isinstance(raw_peers, bytes):
                for i in range(0, len(raw_peers), 6):
                    if i + 6 <= len(raw_peers):
                        ip_bytes = raw_peers[i:i+4]
                        port_bytes = raw_peers[i+4:i+6]
                        ip_str = socket.inet_ntoa(ip_bytes)
                        port_int = struct.unpack(">H", port_bytes)[0]
                        peers.append((ip_str, port_int))
            # Some trackers might return a dictionary model for peers, but instruction says compact
        return peers
        
    @property
    def interval(self) -> int:
        return self.raw.get(b'interval', 60)
        
    @property
    def failed(self) -> bool:
        return b'failure reason' in self.raw
        
    @property
    def failure_reason(self) -> str:
        if self.failed:
            return self.raw[b'failure reason'].decode('utf-8')
        return ""

class Tracker:
    def __init__(self, torrent: Torrent):
        self.torrent = torrent
        self.peer_id = self.generate_peer_id()
        
    def generate_peer_id(self) -> bytes:
        digits = ''.join(str(random.randint(0, 9)) for _ in range(12))
        return f'-PC0001-{digits}'.encode('utf-8')
        
    async def connect(self, uploaded: int = 0, downloaded: int = 0, first: bool = False) -> TrackerResponse:
        params = {
            'info_hash': self.torrent.info_hash,
            'peer_id': self.peer_id,
            'port': 6889,
            'uploaded': uploaded,
            'downloaded': downloaded,
            'left': self.torrent.total_length - downloaded,
            'compact': 1
        }
        
        # urlencode safely converts integers and handles bytes properly
        encoded_params = urllib.parse.urlencode(params)
        url = f"{self.torrent.announce}?{encoded_params}"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                content = await response.read()
                raw_response = Decoder(content).decode()
                return TrackerResponse(raw_response)
