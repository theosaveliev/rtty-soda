from collections.abc import Callable
from compression import bz2, lzma, zlib, zstd

import brotli

__all__ = ["ARCHIVERS", "UNARCHIVERS", "Archiver"]


type Archiver = Callable[[bytes], bytes]


def compress_brotli(data: bytes) -> bytes:
    return brotli.compress(data, quality=11)


def compress_zstd(data: bytes) -> bytes:
    param = zstd.CompressionParameter
    _, upper = param.compression_level.bounds()
    options = {
        param.compression_level: upper,
        param.checksum_flag: 0,
        param.content_size_flag: 0,
        param.dict_id_flag: 0,
    }
    return zstd.compress(data, options=options)  # type: ignore[arg-type]


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


def decompress_brotli(data: bytes) -> bytes:
    return brotli.decompress(data)


def decompress_zstd(data: bytes) -> bytes:
    return zstd.decompress(data)


def decompress_zlib(data: bytes) -> bytes:
    return zlib.decompress(data)


def decompress_bz2(data: bytes) -> bytes:
    return bz2.decompress(data)


def decompress_lzma(data: bytes) -> bytes:
    return lzma.decompress(data, format=lzma.FORMAT_ALONE)


ARCHIVERS: dict[str, Archiver] = {
    "brotli": compress_brotli,
    "zstd": compress_zstd,
    "zlib": compress_zlib,
    "bz2": compress_bz2,
    "lzma": compress_lzma,
}

UNARCHIVERS: dict[str, Archiver] = {
    "brotli": decompress_brotli,
    "zstd": decompress_zstd,
    "zlib": decompress_zlib,
    "bz2": decompress_bz2,
    "lzma": decompress_lzma,
}
