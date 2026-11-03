# Krystal's part.

from typing import Optional

from contracts import GeneratedKeyCase


def generate_close_prime_key(modulus_bits: int = 2048, e: int = 65537, *,
                             target_gap: Optional[int] = None) -> GeneratedKeyCase:
    raise NotImplementedError("Krystal's close-prime generator has not been integrated")
