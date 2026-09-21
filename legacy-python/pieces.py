import hashlib
import logging
import os
from typing import List, Optional

from torrent import Torrent

BLOCK_SIZE = 2**14

class Block:
    def __init__(self, piece_index: int, offset: int, length: int):
        self.piece_index = piece_index
        self.offset = offset
        self.length = length
        self.data: Optional[bytes] = None

class Piece:
    def __init__(self, index: int, hash_value: bytes, length: int):
        self.index = index
        self.hash_value = hash_value
        self.blocks: List[Block] = []
        
        # Initialize blocks
        num_blocks = (length + BLOCK_SIZE - 1) // BLOCK_SIZE
        for i in range(num_blocks):
            block_length = BLOCK_SIZE
            if i == num_blocks - 1:
                block_length = length - (i * BLOCK_SIZE)
            self.blocks.append(Block(index, i * BLOCK_SIZE, block_length))

    def is_complete(self) -> bool:
        return all(block.data is not None for block in self.blocks)
        
    def is_valid(self) -> bool:
        data = b''.join(block.data for block in self.blocks)
        return hashlib.sha1(data).digest() == self.hash_value
        
    def reset(self):
        for block in self.blocks:
            block.data = None

class PieceManager:
    def __init__(self, torrent: Torrent):
        self.torrent = torrent
        self.missing: List[Piece] = []
        self.ongoing: List[Piece] = []
        self.done: List[Piece] = []
        self.peer_bitfields = {} # peer_id -> set of piece indices
        
        # Initialize the output file with the requested size
        with open(self.torrent.output_file, 'wb') as f:
            f.truncate(self.torrent.total_length)
            
        # Build pieces from the torrent meta object
        for tp in self.torrent.pieces:
            piece_len = self.torrent.piece_size(tp.index)
            self.missing.append(Piece(tp.index, tp.hash_value, piece_len))

    def next_request(self, peer_id: bytes, have_pieces: set) -> Optional[Block]:
        # Prefer ongoing pieces that the peer has
        for piece in self.ongoing:
            if piece.index in have_pieces:
                for block in piece.blocks:
                    if block.data is None:
                        return block
        
        # Try finding a missing piece that the peer has
        for piece in self.missing:
            if piece.index in have_pieces:
                self.missing.remove(piece)
                self.ongoing.append(piece)
                return piece.blocks[0]
                
        return None

    def block_received(self, piece_index: int, offset: int, data: bytes):
        for piece in self.ongoing:
            if piece.index == piece_index:
                for block in piece.blocks:
                    if block.offset == offset:
                        block.data = data
                        break
                
                if piece.is_complete():
                    if piece.is_valid():
                        logging.info(f"Piece {piece_index} verified")
                        self.ongoing.remove(piece)
                        self.done.append(piece)
                        self._write_piece(piece)
                    else:
                        logging.warning(f"Piece {piece_index} failed hash, resetting")
                        piece.reset()
                        self.ongoing.remove(piece)
                        self.missing.append(piece)
                break
                
    def _write_piece(self, piece: Piece):
        with open(self.torrent.output_file, 'r+b') as f:
            f.seek(piece.index * self.torrent.piece_length)
            data = b''.join(block.data for block in piece.blocks)
            f.write(data)

    def add_peer(self, peer_id: bytes, bitfield: bytes):
        pieces = set()
        for i, byte in enumerate(bitfield):
            for j in range(8):
                if (byte & (1 << (7 - j))):
                    pieces.add(i * 8 + j)
        self.peer_bitfields[peer_id] = pieces

    def update_peer(self, peer_id: bytes, piece_index: int):
        if peer_id in self.peer_bitfields:
            self.peer_bitfields[peer_id].add(piece_index)
        else:
            self.peer_bitfields[peer_id] = {piece_index}

    def remove_peer(self, peer_id: bytes):
        if peer_id in self.peer_bitfields:
            del self.peer_bitfields[peer_id]

    @property
    def complete(self) -> bool:
        return len(self.done) == self.torrent.number_of_pieces

    @property
    def bytes_downloaded(self) -> int:
        ongoing_bytes = sum(sum(b.length for b in p.blocks if b.data) for p in self.ongoing)
        done_bytes = sum(self.torrent.piece_size(p.index) for p in self.done)
        return ongoing_bytes + done_bytes

    @property
    def bytes_uploaded(self) -> int:
        return 0
