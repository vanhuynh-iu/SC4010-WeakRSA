from key_generation import generate_close_prime_key
from fermat_attack import fermat_attack, improved_fermat_attack
import time
import csv
import os, sys
import argparse

gap_ranges = {
    1024: {"detailed": (254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270)},
    2048: {"pilot": (50, 100, 150, 200, 250, 300, 350, 400, 450, 500, 520),
           "detailed": (510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526) },
    3072: {"detailed": (768, 769, 770, 771, 772, 773, 774, 775, 776, 777, 778, 779, 780, 781, 782)}
}

def run_experiment(bits, attack_type, experiment_type, trials=15):
    selected_gap_bits = gap_ranges[bits][experiment_type]
    
    startingOfEntireExperiment = time.perf_counter()
    
    results = []

    if attack_type =="original":
        for gap_bits in selected_gap_bits:
            for i in range(trials):
                success = True
                key = generate_close_prime_key(bits = bits, gap_bits = gap_bits) # 2048, 3072
                n = key["n"]
                e = key["e"]

                start = time.perf_counter()
                result = fermat_attack(n, max_iterations= 1000000000)
                
                if result is None: 
                    # print("Fermat attack failed")
                    success = False
                    final_end = time.perf_counter()
                    results.append({
                                "trial": i,
                                "gap_bits": gap_bits,
                                "actual_gap": key["gap"],
                                "n_bits": key["n"].bit_length(),
                                "iterations": 1000000000,
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
        output_file = f"results/{attack_type}_fermat_{experiment_type}_results_{bits}.csv"
        # Save results to CSV
        with open(output_file, "w", newline="") as file:
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
                
    elif attack_type =="improved":
        for gap_bits in selected_gap_bits:
            for i in range(trials):
                success = True
                key = generate_close_prime_key(bits = bits, gap_bits = gap_bits) # 2048, 3072
                n = key["n"]
                e = key["e"]

                start = time.perf_counter()
                result = improved_fermat_attack(n, max_iterations= 1000000000)
                p_found, q_found, iterations, perfect_square_checks = result
                
                if p_found is None: #if result is None
                    # print("Fermat attack failed")
                    success = False
                    final_end = time.perf_counter()
                    results.append({
                                "trial": i,
                                "gap_bits": gap_bits,
                                "actual_gap": key["gap"],
                                "n_bits": key["n"].bit_length(),
                                "iterations": iterations,
                                "perfect_square_checks": perfect_square_checks,
                                "checks_skipped": iterations - perfect_square_checks,
                                "checks_skipped_percentage": (
                                    (iterations - perfect_square_checks) / iterations * 100
                                    if iterations > 0 else 0
                                ),
                                "runtime_seconds": final_end - start,
                                "success": success
                            })
                    continue

                end = time.perf_counter()
                print(f"Fermat attack succeeded for {gap_bits}bits - number {i}, iterations: {iterations}, perfect_square_checks: {perfect_square_checks}, checks_skipped: {iterations-perfect_square_checks}")

                results.append({
                    "trial": i,
                    "gap_bits": gap_bits,
                    "actual_gap": key["gap"],
                    "n_bits": key["n"].bit_length(),
                    "iterations": iterations,
                    "perfect_square_checks": perfect_square_checks,
                    "checks_skipped": iterations - perfect_square_checks,
                    "checks_skipped_percentage": (
                        (iterations - perfect_square_checks) / iterations * 100
                    ),
                    "runtime_seconds": end - start,
                    "success": success
                })
                    
                    
        EndingOfExperiment = time.perf_counter()
        print(f"total experiment took {EndingOfExperiment-startingOfEntireExperiment}s ")

        os.makedirs("results", exist_ok=True)
        output_file = f"results/{attack_type}_fermat_{experiment_type}_results_{bits}.csv"
        # Save results to CSV
        with open(output_file,"w", newline="") as file:
            fieldnames = [
                    "trial",
                    "gap_bits",
                    "actual_gap",
                    "n_bits",
                    "iterations",
                    "perfect_square_checks",
                    "checks_skipped",
                    "checks_skipped_percentage",
                    "runtime_seconds",
                    "success"
                ]
            writer = csv.DictWriter(
                file,
                fieldnames=fieldnames
            )

            writer.writeheader()
            writer.writerows(results)
    else: raise ValueError("invalid attack") 

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Run RSA Fermat factorisation experiments"
    )

    parser.add_argument("--bits", type=int, choices=[1024, 2048, 3072], required=True)
    parser.add_argument("--attack", choices=["original", "improved"], required=True)
    parser.add_argument("--experiment", choices=["pilot", "detailed"], required = True)
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    args = parser.parse_args()

    if args.experiment not in gap_ranges[args.bits]:
        parser.error(
            f"{args.experiment} experiment is not available "
            f"for RSA-{args.bits}"
        )

    run_experiment(
        bits=args.bits,
        attack_type=args.attack,
        experiment_type=args.experiment
    )




