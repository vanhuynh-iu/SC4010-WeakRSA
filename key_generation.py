from Crypto.Util.number import getPrime, isPrime, inverse, GCD

def generate_close_prime_key(bits, gap_bits, e=65537):
    prime_bits = bits // 2

    while True:
        p = getPrime(prime_bits)

        candidate = p + (2 ** gap_bits)

        if candidate % 2 == 0:
            candidate += 1

        while not isPrime(candidate):
            candidate += 2

        q = candidate
        
        if p == q:
            continue

        n = p*q
        if n.bit_length() != bits: 
            continue
        phi = (p-1)*(q-1)

        if GCD(e, phi) != 1:
            continue

        d = inverse(e, phi)

        return {
            "p": p,
            "q": q,
            "n": n,
            "e": e,
            "d": d,
            "phi": phi,
            "gap": abs(q - p),
        }
    
def generate_prime_key(bits, e=65537):
    prime_bits = bits // 2
    while True:
        p = getPrime(prime_bits)
        q = getPrime(prime_bits)
        if p == q:
            continue
        n = p*q
        if n.bit_length() != bits: 
            continue
        phi = (p-1)*(q-1)

        if GCD(e, phi) != 1:
            continue

        d = inverse(e, phi)

        return {
            "p": p,
            "q": q,
            "n": n,
            "e": e,
            "d": d,
            "phi": phi,
            "gap": abs(q - p),
        }

        
if __name__ == "__main__":
    key = generate_close_prime_key(
        bits=2048,
        gap_bits=20,
        e = 65537
    )

    print("p =", key["p"])
    print("q =", key["q"])
    print("n =", key["n"])
    print("e =", key["e"])
    print("d =", key["d"])
    print("|p - q| =", key["gap"])
    print("n bit length =", key["n"].bit_length())

    print("p is prime:", isPrime(key["p"]))
    print("q is prime:", isPrime(key["q"]))
    print("p != q:", key["p"] != key["q"])
    print("n == p*q:", key["n"] == key["p"] * key["q"])
    print("n bit length:", key["n"].bit_length())
    print("|p - q|:", key["gap"])
    print("gcd(e, phi):", GCD(key["e"], key["phi"]))