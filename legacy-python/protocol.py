import asyncio
import struct
import logging

MSG_CHOKE = 0
MSG_UNCHOKE = 1
MSG_INTERESTED = 2
MSG_NOT_INTERESTED = 3
MSG_HAVE = 4
MSG_BITFIELD = 5
MSG_REQUEST = 6
MSG_PIECE = 7
MSG_CANCEL = 8

class Handshake:
    def __init__(self, info_hash: bytes, peer_id: bytes):
        self.info_hash = info_hash
        self.peer_id = peer_id

    def encode(self):
        return b'\x13BitTorrent protocol' + (b'\x00' * 8) + self.info_hash + self.peer_id

    @classmethod
    def decode(cls, data: bytes):
        info_hash = data[28:48]
        peer_id = data[48:68]
        return cls(info_hash, peer_id)

class KeepAlive:
    def encode(self):
        return struct.pack('>I', 0)

    @classmethod
    def decode(cls, data: bytes):
        return cls()

class Choke:
    def encode(self):
        return struct.pack('>IB', 1, MSG_CHOKE)

    @classmethod
    def decode(cls, data: bytes):
        return cls()

class Unchoke:
    def encode(self):
        return struct.pack('>IB', 1, MSG_UNCHOKE)

    @classmethod
    def decode(cls, data: bytes):
        return cls()

class Interested:
    def encode(self):
        return struct.pack('>IB', 1, MSG_INTERESTED)

    @classmethod
    def decode(cls, data: bytes):
        return cls()

class NotInterested:
    def encode(self):
        return struct.pack('>IB', 1, MSG_NOT_INTERESTED)

    @classmethod
    def decode(cls, data: bytes):
        return cls()

class Have:
    def __init__(self, piece_index: int):
        self.piece_index = piece_index

    def encode(self):
        return struct.pack('>IBI', 5, MSG_HAVE, self.piece_index)

    @classmethod
    def decode(cls, data: bytes):
        piece_index = struct.unpack('>I', data[1:5])[0]
        return cls(piece_index)

class BitField:
    def __init__(self, bitfield: bytes):
        self.bitfield = bitfield

    def encode(self):
        return struct.pack(f'>IB{len(self.bitfield)}s', 1 + len(self.bitfield), MSG_BITFIELD, self.bitfield)

    @classmethod
    def decode(cls, data: bytes):
        return cls(data[1:])

class Request:
    def __init__(self, index: int, begin: int, length: int):
        self.index = index
        self.begin = begin
        self.length = length

    def encode(self):
        return struct.pack('>IBIII', 13, MSG_REQUEST, self.index, self.begin, self.length)

    @classmethod
    def decode(cls, data: bytes):
        index, begin, length = struct.unpack('>III', data[1:13])
        return cls(index, begin, length)

class Piece:
    def __init__(self, index: int, begin: int, block: bytes):
        self.index = index
        self.begin = begin
        self.block = block

    def encode(self):
        return struct.pack(f'>IBII{len(self.block)}s', 9 + len(self.block), MSG_PIECE, self.index, self.begin, self.block)

    @classmethod
    def decode(cls, data: bytes):
        index, begin = struct.unpack('>II', data[1:9])
        block = data[9:]
        return cls(index, begin, block)

class Cancel:
    def __init__(self, index: int, begin: int, length: int):
        self.index = index
        self.begin = begin
        self.length = length

    def encode(self):
        return struct.pack('>IBIII', 13, MSG_CANCEL, self.index, self.begin, self.length)

    @classmethod
    def decode(cls, data: bytes):
        index, begin, length = struct.unpack('>III', data[1:13])
        return cls(index, begin, length)

class PeerStreamIterator:
    def __init__(self, reader: asyncio.StreamReader, initial_buffer: bytes = b''):
        self.reader = reader
        self.buffer = initial_buffer

    def __aiter__(self):
        return self

    async def __anext__(self):
        while True:
            try:
                # Need at least 4 bytes for length prefix
                while len(self.buffer) < 4:
                    data = await self.reader.read(4096)
                    if not data:
                        raise StopAsyncIteration
                    self.buffer += data

                length = struct.unpack('>I', self.buffer[:4])[0]
                if length == 0:
                    self.buffer = self.buffer[4:]
                    return KeepAlive()

                # Read until we have the full message
                while len(self.buffer) < 4 + length:
                    data = await self.reader.read(4096)
                    if not data:
                        raise StopAsyncIteration
                    self.buffer += data

                msg_data = self.buffer[4:4+length]
                self.buffer = self.buffer[4+length:]

                msg_id = msg_data[0]
                
                if msg_id == MSG_CHOKE:
                    return Choke.decode(msg_data)
                elif msg_id == MSG_UNCHOKE:
                    return Unchoke.decode(msg_data)
                elif msg_id == MSG_INTERESTED:
                    return Interested.decode(msg_data)
                elif msg_id == MSG_NOT_INTERESTED:
                    return NotInterested.decode(msg_data)
                elif msg_id == MSG_HAVE:
                    return Have.decode(msg_data)
                elif msg_id == MSG_BITFIELD:
                    return BitField.decode(msg_data)
                elif msg_id == MSG_REQUEST:
                    return Request.decode(msg_data)
                elif msg_id == MSG_PIECE:
                    return Piece.decode(msg_data)
                elif msg_id == MSG_CANCEL:
                    return Cancel.decode(msg_data)
                else:
                    # unknown or unhandled message id
                    continue
            except asyncio.IncompleteReadError:
                raise StopAsyncIteration
            except ConnectionError:
                raise StopAsyncIteration


class PeerConnection:
    def __init__(self, queue: asyncio.Queue, info_hash: bytes, peer_id: bytes, piece_manager, on_block_cb):
        self.queue = queue
        self.info_hash = info_hash
        self.peer_id = peer_id
        self.piece_manager = piece_manager
        self.on_block_cb = on_block_cb
        self._stop = False
        self.choked = True
        self.interested = False
        self.peer_pieces = set()
        self.remote_peer_id = None

    async def start(self):
        while not self._stop:
            try:
                ip, port = await self.queue.get()
                logging.info(f"Connecting to peer {ip}:{port}")
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=5)
                self.remote_peer_id = f"{ip}:{port}".encode('utf-8')
                await self._do_session(reader, writer)
            except Exception as e:
                pass
            finally:
                if self.remote_peer_id:
                    self.piece_manager.remove_peer(self.remote_peer_id)
                self.queue.task_done()

    async def _do_session(self, reader, writer):
        # send handshake
        handshake = Handshake(self.info_hash, self.peer_id)
        writer.write(handshake.encode())
        await writer.drain()

        # read handshake
        try:
            hs_data = await asyncio.wait_for(reader.readexactly(68), timeout=5)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return

        if hs_data[28:48] != self.info_hash:
            raise ValueError("Invalid info hash in handshake")

        logging.info(f"Connected to peer successfully")

        # Read optional BitField
        # Usually sent immediately after handshake, we can just process it via the iterator but
        # standard specifies it optionally before any other messages. We'll let the iterator handle it.
        # But wait! The spec says: read optional BitField, sends Interested
        # Sending interested right away is typical.
        writer.write(Interested().encode())
        await writer.drain()

        async for msg in PeerStreamIterator(reader):
            if isinstance(msg, KeepAlive):
                continue
            elif isinstance(msg, Choke):
                self.choked = True
            elif isinstance(msg, Unchoke):
                self.choked = False
                req = self._next_request()
                if req:
                    writer.write(req.encode())
                    await writer.drain()
            elif isinstance(msg, Have):
                self.peer_pieces.add(msg.piece_index)
                self.piece_manager.update_peer(self.remote_peer_id, msg.piece_index)
                if not self.choked:
                    req = self._next_request()
                    if req:
                        writer.write(req.encode())
                        await writer.drain()
            elif isinstance(msg, BitField):
                pieces = set()
                for i, byte in enumerate(msg.bitfield):
                    for j in range(8):
                        if (byte & (1 << (7 - j))):
                            pieces.add(i * 8 + j)
                self.peer_pieces = pieces
                self.piece_manager.add_peer(self.remote_peer_id, msg.bitfield)
            elif isinstance(msg, Piece):
                self.on_block_cb(msg.index, msg.begin, msg.block)
                if not self.choked:
                    req = self._next_request()
                    if req:
                        writer.write(req.encode())
                        await writer.drain()

    def _next_request(self):
        block = self.piece_manager.next_request(self.remote_peer_id, self.peer_pieces)
        if block:
            return Request(block.piece_index, block.offset, block.length)
        return None

    def stop(self):
        self._stop = True
