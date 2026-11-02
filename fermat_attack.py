import math
from bisect import bisect_left 
import time

perfect_square_remainders_64= {
    (x * x) % 64 for x in range(64)
}

def fermat_attack(N, max_iterations):
    p = -1
    q = -1
    
    i = 1
    a = math.isqrt(N)
    if a*a < N:
        a += 1

    while (i<=max_iterations):
        result = a**2 - N 
        potential_b = math.isqrt(result)
        if potential_b**2 == result:
            p = a-potential_b
            q = a+potential_b
            return p, q, i
        a += 1
        i += 1

    return None

def improved_fermat_attack(N, max_iterations):
    p = -1
    q = -1
    
    i = 1
    a = math.isqrt(N)
    if a*a < N:
        a += 1 

    perfect_square_checks = 0

    while (i<=max_iterations):
        result = a**2 - N 

        #checking remainder before square root
        if result%64 in perfect_square_remainders_64:
            perfect_square_checks+=1

            potential_b = math.isqrt(result)
            if potential_b**2 == result:
                p = a-potential_b
                q = a+potential_b
                return p, q, i, perfect_square_checks
        a += 1
        i += 1
    
    return None, None, i - 1, perfect_square_checks      


def fermat_sieved(N,max_iterations,moduli=(64, 3, 5, 7)):

    if N <= 1 or N % 2 == 0:
        raise ValueError("N must be an odd integer greater than 1")

    if max_iterations < 1:
        raise ValueError("max_iterations must be positive")

    if not moduli or any(m < 2 for m in moduli):
        raise ValueError("moduli must contain integers >= 2")

    if any(
        math.gcd(moduli[i], moduli[j]) != 1
        for i in range(len(moduli))
        for j in range(i + 1, len(moduli))
    ):
        raise ValueError("Wheel moduli must be pairwise coprime")

    #start at ceil(sqrt(N))
    a0 = math.isqrt(N)
    if a0 * a0 < N:
        a0 += 1

    preprocessing_start = time.perf_counter()
    modulus = math.prod(moduli)

    square_residues = {
        m: {(x * x) % m for x in range(m)}
        for m in moduli
    }

    #valid residues r=a mod M
    valid = [
        r for r in range(modulus)
        if all(
            (r * r - N) % m in square_residues[m]
            for m in moduli
        )
    ]

    preprocessing_time = time.perf_counter() - preprocessing_start

    if not valid:
        return None, None, max_iterations, 0, preprocessing_time

    remainder = a0 % modulus
    pos = bisect_left(valid, remainder)

    if pos < len(valid):
        a = a0 + valid[pos] - remainder
    else:
        a = a0 + modulus - remainder + valid[0]
        pos = 0

    square_checks = 0

    end = a0 + max_iterations

    #fermat attack 
    while a < end:
        difference = a * a - N
        square_checks += 1

        b = math.isqrt(difference)

        if b * b == difference:
            p = a - b
            q = a + b

            positions_examined = a - a0 + 1

            return (
                p,
                q,
                positions_examined,
                square_checks,
                preprocessing_time
            )

        #move to next allowed residue
        pos += 1

        if pos == len(valid):
            a += modulus - valid[-1] + valid[0]
            pos = 0

        else:
            a += valid[pos] - valid[pos - 1]

    return (
        None,
        None,
        max_iterations,
        square_checks,
        preprocessing_time
    )

        
if __name__ == "__main__":
    result = fermat_attack(
       N = 14207782315160918623871043509678586595304964610227736731297832723161616629184354986429019744017171603482317021436613372916616116426608606003253854406130192349041922215606597631519792191740569683704894713450595680727939345832007069451214236963298726887390645239996061019796350608207558068405266399182619682647245701459491554585669558903270253932297819012167278193043969739679702377868031581334883489052115542218180796879428328922957479628783125150327105256074611313466763220714882650169072412633815040097876236633771904052994202491103911742980417348778957104173341502240615319695874417653869715073141375659310308086047,
       max_iterations = 1000000
    )
    if result is not None:
        p,q,i = result
        print(f"Prime numbers are {p} and {q}")
        print(f"Number of iterations to get answer is {i}")
    else:
        print("Unable to find prime numbers")


    





