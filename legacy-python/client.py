import asyncio
import time
import logging

from tracker import Tracker
from pieces import PieceManager
from protocol import PeerConnection

MAX_PEER_CONNECTIONS = 5

class TorrentClient:
    def __init__(self, torrent):
        self.torrent = torrent
        self.tracker = Tracker(torrent)
        self.piece_manager = PieceManager(torrent)
        self.queue = asyncio.Queue()
        self.peer_connections = []
        for _ in range(MAX_PEER_CONNECTIONS):
            pc = PeerConnection(
                self.queue, 
                self.torrent.info_hash, 
                self.tracker.peer_id, 
                self.piece_manager, 
                self._on_block_retrieved
            )
            self.peer_connections.append(pc)

    async def start(self):
        tasks = [asyncio.create_task(pc.start()) for pc in self.peer_connections]
        
        last_announce = 0
        interval = 0
        first = True
        
        try:
            while True:
                if self.piece_manager.complete:
                    break
                    
                now = time.time()
                if now - last_announce > interval:
                    logging.info("Requesting tracker...")
                    tracker_res = await self.tracker.connect(
                        uploaded=self.piece_manager.bytes_uploaded,
                        downloaded=self.piece_manager.bytes_downloaded,
                        first=first
                    )
                    first = False
                    logging.info(f"Tracker response received, parsing ({len(tracker_res.peers)} peers found)")
                    
                    if tracker_res.failed:
                        logging.warning(f"Tracker request failed: {tracker_res.failure_reason}")
                        await asyncio.sleep(5)
                        continue
                        
                    interval = tracker_res.interval
                    last_announce = now
                    
                    # Drain old queue
                    while not self.queue.empty():
                        try:
                            self.queue.get_nowait()
                            self.queue.task_done()
                        except asyncio.QueueEmpty:
                            break
                        
                    # Fill queue with new peers
                    for peer in tracker_res.peers:
                        self.queue.put_nowait(peer)
                        
                else:
                    await asyncio.sleep(5)
        finally:
            self.stop()
            for task in tasks:
                task.cancel()

    def stop(self):
        for pc in self.peer_connections:
            pc.stop()

    def _on_block_retrieved(self, piece_index: int, offset: int, data: bytes):
        self.piece_manager.block_received(piece_index, offset, data)
