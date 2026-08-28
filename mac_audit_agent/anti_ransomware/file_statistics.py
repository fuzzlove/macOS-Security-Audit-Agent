from __future__ import annotations

import math
from collections import Counter

from .models import FileStatistics

IMAGE_HEADERS = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"RIFF")
BASE64_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def chi_square_uniform(data: bytes) -> float:
    if not data:
        return math.inf
    expected = len(data) / 256.0
    counts = Counter(data)
    return sum(((counts.get(value, 0) - expected) ** 2) / expected for value in range(256))


def monte_carlo_pi_error(data: bytes) -> float:
    pairs = len(data) // 2
    if pairs < 16:
        return math.inf
    inside = 0
    for index in range(0, pairs * 2, 2):
        x = data[index] / 255.0
        y = data[index + 1] / 255.0
        inside += int(x * x + y * y <= 1.0)
    estimate = 4.0 * inside / pairs
    return abs(estimate - math.pi) / math.pi * 100.0


def analyze_bytes(data: bytes, *, original_size: int | None = None) -> FileStatistics:
    meaningful = sum(byte in BASE64_BYTES for byte in data)
    return FileStatistics(
        size=len(data) if original_size is None else original_size,
        entropy=shannon_entropy(data),
        chi_square=chi_square_uniform(data),
        monte_carlo_pi_error=monte_carlo_pi_error(data),
        base64_ratio=meaningful / len(data) if data else 0.0,
        recognized_image=any(data.startswith(header) for header in IMAGE_HEADERS),
        gzip_header=data.startswith(b"\x1f\x8b"),
        bytes_sampled=len(data),
    )
