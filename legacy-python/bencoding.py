from collections import OrderedDict

class Decoder:

    def __init__(self, data):
        self._data = data
        self._index = 0

    def decode(self):
        if self._index >= len(self._data):
            raise ValueError(f"Unexpected end of data at index {self._index}")

        char = self._data[self._index: self._index + 1]

        if char == b'i':
            return self._decode_int()
        elif char == b'l':
            return self._decode_list()
        elif char == b'd':
            return self._decode_dict()
        elif char.isdigit():
            return self._decode_string()
        else:
            raise ValueError(
                f"Unknown type token '{char}' at index {self._index}"
            )

    def _decode_int(self):
        self._index += 1
        end = self._data.index(b'e', self._index)
        value = int(self._data[self._index:end])    
        self._index = end + 1                        
        return value

    def _decode_list(self):
        self._index += 1
        result = []
        while self._data[self._index: self._index + 1] != b'e':
            result.append(self.decode())

        self._index += 1
        return result

    def _decode_dict(self):
        self._index += 1
        result = OrderedDict()

        while self._data[self._index: self._index + 1] != b'e':
            key = self.decode()
            value = self.decode()
            result[key] = value
        self._index += 1
        return result

    def _decode_string(self):
        colon = self._data.index(b':', self._index)
        length_str = int(self._data[self._index:colon])
        start = colon + 1
        end = start + length_str
        value = self._data[start:end]
        self._index = end
        return value

class Encoder:
    def __init__(self, data):
        self._data = data

    def encode(self):
        return self._encode_value(self._data)

    def _encode_value(self, value):
        if isinstance(value, int):
            return f'i{value}e'.encode()

        elif isinstance(value, bytes):
            return f'{len(value)}:'.encode() + value

        elif isinstance(value, str):
            encoded = value.encode('utf-8')
            return f'{len(encoded)}:'.encode() + encoded

        elif isinstance(value, (list, tuple)):
            parts = b''.join(self._encode_value(item) for item in value)
            return b'l' + parts + b'e'

        elif isinstance(value, dict):
            parts = b''
            for k, v in value.items():
                parts += self._encode_value(k)
                parts += self._encode_value(v)
            return b'd' + parts + b'e'

        else:
            raise TypeError(f"Cannot bencode type: {type(value)}")