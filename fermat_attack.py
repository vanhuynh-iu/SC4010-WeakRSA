import math

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


    





