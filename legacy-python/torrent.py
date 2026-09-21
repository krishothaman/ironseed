# torrent.py
import hashlib
import math
from collections import namedtuple
from bencoding import Decoder, Encoder


# A small data container representing one piece of the file.
# index      = which piece number (0, 1, 2, ...)
# hash_value = the expected SHA1 hash bytes for this piece (20 bytes)
TorrentPiece = namedtuple('TorrentPiece', ['index', 'hash_value'])


class Torrent:
    """
    A clean Python wrapper around a decoded .torrent file.

    Hides all the binary key lookups and gives the rest of your
    client simple properties to read from.
    """

    def __init__(self, path: str):
        """
        Read the .torrent file from disk and decode it immediately.
        Everything is ready to use after __init__ completes.
        """
        with open(path, 'rb') as f:
            raw_bytes = f.read()
        
        if not raw_bytes:
            raise ValueError(f"Torrent file is empty: {path}")

        print(f"Read {len(raw_bytes)} bytes from torrent file")

        # _meta is the raw OrderedDict from the bencoding decoder.
        # All keys are bytes (b'announce', b'info', etc.)
        self._meta = Decoder(raw_bytes).decode()

        # Shortcut — we'll access this nested dict a lot
        self._info = self._meta[b'info']

    # ── Basic info ────────────────────────────────────────────────

    @property
    def announce(self) -> str:
        """
        The HTTP URL of the tracker.
        e.g. 'http://torrent.ubuntu.com:6969/announce'
        """
        return self._meta[b'announce'].decode('utf-8')

    @property
    def output_file(self) -> str:
        """
        The name of the file we're downloading.
        e.g. 'ubuntu-16.04-desktop-amd64.iso'
        """
        return self._info[b'name'].decode('utf-8')

    @property
    def total_length(self) -> int:
        """
        Total size of the complete download in bytes.
        e.g. 1485881344
        """
        return self._info[b'length']

    # ── Piece info ────────────────────────────────────────────────

    @property
    def piece_length(self) -> int:
        """
        How many bytes each piece contains.
        Usually a power of 2 — commonly 524288 (512 KB).
        The LAST piece is often smaller than this.
        """
        return self._info[b'piece length']

    @property
    def pieces(self) -> list:
        """
        Returns a list of TorrentPiece objects, one per piece.

        The raw b'pieces' value is a big blob of bytes where
        every 20 bytes is one SHA1 hash for one piece.

        We split it up here so the PieceManager can use it easily.
        """
        raw = self._info[b'pieces']
        # Every 20 bytes = one SHA1 hash
        return [
            TorrentPiece(
                index=i,
                hash_value=raw[i * 20: (i + 1) * 20]
            )
            for i in range(len(raw) // 20)
        ]

    @property
    def number_of_pieces(self) -> int:
        return len(self.pieces)

    # ── The info_hash ─────────────────────────────────────────────

    @property
    def info_hash(self) -> bytes:
        """
        The SHA1 hash of the re-encoded 'info' dictionary.
        This is THE most important value in your whole client.

        It uniquely identifies this torrent everywhere:
          - Sent to the tracker so it knows which torrent you want
          - Checked against each peer's handshake to confirm
            you're both downloading the same thing
          - Included in the magnet link

        HOW IT'S COMPUTED:
          1. Take the raw info dict (an OrderedDict with binary keys)
          2. Re-encode it back to bencoded bytes using our Encoder
          3. SHA1 hash those bytes
          4. The result is 20 raw bytes

        CRITICAL: This only works correctly because we used OrderedDict
        in the decoder. Key order must be preserved exactly as it was
        in the original .torrent file.
        """
        raw_info = Encoder(self._info).encode()
        return hashlib.sha1(raw_info).digest()

    # ── Convenience / debugging ───────────────────────────────────

    @property
    def info_hash_hex(self) -> str:
        """Human-readable hex version of the info_hash, useful for debugging."""
        return self.info_hash.hex()

    def last_piece_length(self) -> int:
        """
        The last piece is usually smaller than piece_length.
        This computes its actual size.

        Example:
          total_length  = 135168 bytes
          piece_length  = 49152 bytes
          pieces        = [0: 49152, 1: 49152, 2: ???]
          last piece    = 135168 - (49152 * 2) = 36864 bytes
        """
        remainder = self.total_length % self.piece_length
        # If it divides evenly, the last piece is a full piece
        return remainder if remainder != 0 else self.piece_length

    def piece_size(self, piece_index: int) -> int:
        """
        Returns the actual byte size of a specific piece.
        All pieces are piece_length bytes EXCEPT the last one.
        """
        if piece_index == self.number_of_pieces - 1:
            return self.last_piece_length()
        return self.piece_length

    def __repr__(self):
        return (
            f"Torrent("
            f"file='{self.output_file}', "
            f"size={self.total_length / 1_000_000:.1f} MB, "
            f"pieces={self.number_of_pieces}, "
            f"piece_length={self.piece_length // 1024} KB"
            f")"
        )