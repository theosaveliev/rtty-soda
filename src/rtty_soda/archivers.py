from collections.abc import Callable
from compression import bz2, lzma, zlib, zstd

__all__ = ["ARCHIVERS", "UNARCHIVERS", "Archiver"]


type Archiver = Callable[[bytes], bytes]


def compress_zstd(data: bytes) -> bytes:
    return zstd.compress(data, level=20)


def compress_zlib(data: bytes) -> bytes:
    return zlib.compress(data, level=9)


def compress_bz2(data: bytes) -> bytes:
    return bz2.compress(data, compresslevel=9)


def compress_lzma(data: bytes) -> bytes:
    return lzma.compress(
        data,
        format=lzma.FORMAT_ALONE,
        check=lzma.CHECK_NONE,
        preset=lzma.PRESET_EXTREME,
    )


def decompress_zstd(data: bytes) -> bytes:
    return zstd.decompress(data)


def decompress_zlib(data: bytes) -> bytes:
    return zlib.decompress(data)


def decompress_bz2(data: bytes) -> bytes:
    return bz2.decompress(data)


def decompress_lzma(data: bytes) -> bytes:
    return lzma.decompress(data, format=lzma.FORMAT_ALONE)


def noop(data: bytes) -> bytes:
    return data


ARCHIVERS: dict[str, Archiver] = {
    "zstd": compress_zstd,
    "zlib": compress_zlib,
    "bz2": compress_bz2,
    "lzma": compress_lzma,
    "raw": noop,
}

UNARCHIVERS: dict[str, Archiver] = {
    "zstd": decompress_zstd,
    "zlib": decompress_zlib,
    "bz2": decompress_bz2,
    "lzma": decompress_lzma,
    "raw": noop,
}
