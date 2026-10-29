from key_generation import generate_prime_key
from fermat_attack import fermat_attack
import time
import csv
import os

startingOfEntireExperiment = time.perf_counter()
results = []
for i in range(6):
    success = True
    key = generate_prime_key(bits = 2048)
    n = key["n"]
    e = key["e"]
    
    actual_gap = key["gap"]
    gap_bits = actual_gap.bit_length() - 1

    start = time.perf_counter()
    result = fermat_attack(n, max_iterations= 100000000)

    if result is None:
        success = False
        final_end = time.perf_counter()
        print("Fermat attack failed")
        results.append({
                    "trial": i,
                    "gap_bits": gap_bits,
                    "actual_gap": key["gap"],
                    "n_bits": key["n"].bit_length(),
                    "iterations": 100000000,
                    "runtime_seconds": final_end-start,
                    "success": success
                })
        continue

    p_found, q_found, iterations = result
    # print(f"Fermat attack succeeded, iterations: {iterations}")
    end = time.perf_counter()
    print(f"Fermat attack succeeded for {gap_bits}bits - number {i}, iterations: {iterations}")
    results.append({
        "trial": i,
        "gap_bits": gap_bits,
        "actual_gap": key["gap"],
        "n_bits": key["n"].bit_length(),
        "iterations": iterations,
        "runtime_seconds": end-start,
        "success": success
    })
        
        
EndingOfExperiment = time.perf_counter()
print(f"total experiment took {EndingOfExperiment-startingOfEntireExperiment}s ")

os.makedirs("results", exist_ok=True)

# Save results to CSV
with open(
    "results/rsa_control.csv",
    "w",
    newline=""
) as file:

    fieldnames = [
        "trial",
        "gap_bits",
        "actual_gap",
        "n_bits",
        "iterations",
        "runtime_seconds",
        "success"
    ]

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(results)