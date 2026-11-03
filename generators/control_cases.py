"""Van's library-generated controls for common dataset assembly."""

from Crypto.PublicKey import RSA

from contracts import GeneratedKeyCase

def generate_control_key(modulus_bits: int = 2048, e: int = 65537) -> GeneratedKeyCase:
    """Return a library-generated key with separate public/private records.

    Requires at least 1024 bits; the default is 2048. No weakness is deliberately
    inserted. Shared-prime scenarios enforce their own cross-key factor uniqueness.
    """
    if type(modulus_bits) is not int or type(e) is not int:
        raise TypeError("modulus_bits and e must be integers")
    if modulus_bits < 1024:
        raise ValueError("modulus_bits must be at least 1024 for library RSA generation")
    if e <= 1 or e % 2 == 0:
        raise ValueError("e must be an odd integer greater than one")
    key = RSA.generate(modulus_bits, e=e)
    return {
        "public_key": {"key_id": "key_001", "n": int(key.n), "e": int(key.e)},
        "private_truth": {"p": int(key.p), "q": int(key.q), "case_type": "control"},
    }
