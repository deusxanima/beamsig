"""Minimal SSH wire-format (RFC 4251) reader/writer."""
import struct


class Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def remaining(self) -> bytes:
        return self.d[self.i:]

    def eof(self) -> bool:
        return self.i >= len(self.d)

    def u8(self) -> int:
        v = self.d[self.i]
        self.i += 1
        return v

    def u32(self) -> int:
        v = struct.unpack_from(">I", self.d, self.i)[0]
        self.i += 4
        return v

    def u64(self) -> int:
        v = struct.unpack_from(">Q", self.d, self.i)[0]
        self.i += 8
        return v

    def string(self) -> bytes:
        n = self.u32()
        v = self.d[self.i:self.i + n]
        if len(v) != n:
            raise ValueError("truncated string")
        self.i += n
        return v

    def cstring(self) -> str:
        return self.string().decode("utf-8", "replace")

    def mpint(self) -> int:
        return int.from_bytes(self.string(), "big")

    def namelist(self) -> list:
        """A string containing a sequence of embedded strings."""
        inner = Reader(self.string())
        out = []
        while not inner.eof():
            out.append(inner.cstring())
        return out


class Writer:
    def __init__(self):
        self.b = bytearray()

    def u8(self, v):
        self.b.append(v)
        return self

    def u32(self, v):
        self.b += struct.pack(">I", v)
        return self

    def u64(self, v):
        self.b += struct.pack(">Q", v)
        return self

    def string(self, v):
        if isinstance(v, str):
            v = v.encode()
        self.b += struct.pack(">I", len(v)) + v
        return self

    def raw(self, v):
        self.b += v
        return self

    def mpint(self, v: int):
        """SSH mpint: minimal big-endian two's complement, i.e. ceil((bits+1)/8)."""
        if v == 0:
            return self.string(b"")
        if v < 0:
            raise ValueError("negative mpint not supported")
        n = (v.bit_length() + 8) // 8  # == ceil((bit_length+1)/8)
        return self.string(v.to_bytes(n, "big"))

    def bytes(self) -> bytes:
        return bytes(self.b)
