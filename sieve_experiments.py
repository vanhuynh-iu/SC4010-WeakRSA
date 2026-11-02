
from key_generation import generate_close_prime_key
from fermat_attack import fermat_attack, improved_fermat_attack, fermat_sieved

import time
import csv
import os
import argparse


BITS = 2048

GAP_BITS = (510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 526)

TRIALS = 15
MAX_ITERATIONS = 1000000000

EXTENDED_GAP_BITS = (527, 528, 529)
EXTENDED_MAX_ITERATIONS = 5000000000
EXTENDED_MODULI = (64, 3, 5, 7)

WHEEL_CONFIGS = {
    "wheel_15": (3, 5),
    "wheel_105": (3, 5, 7),
    "wheel_1155": (3, 5, 7, 11),
    "wheel_960": (64, 3, 5),
    "wheel_6720": (64, 3, 5, 7)
}


def run_sieve_experiments():

    os.makedirs("results", exist_ok=True)

    output_file = "results/sieve_comparison_2048.csv"

    fieldnames = [
        "trial",
        "gap_bits",
        "actual_gap",
        "n_bits",
        "algorithm",
        "iterations",
        "square_checks",
        "preprocessing_seconds",
        "runtime_seconds",
        "success"
    ]

    with open(output_file, "w", newline="") as file:

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for gap_bits in GAP_BITS:

            for trial in range(TRIALS):

                key = generate_close_prime_key(
                    bits=BITS,
                    gap_bits=gap_bits
                )

                n = key["n"]

             
                #original fermat
                start = time.perf_counter()

                result = fermat_attack(n, MAX_ITERATIONS)

                runtime = time.perf_counter() - start

                if result is None:
                    p, q = None, None
                    iterations = MAX_ITERATIONS
                else:
                    p, q, iterations = result

                baseline_result = (p, q, iterations)

                rows = [{
                    "trial": trial,
                    "gap_bits": gap_bits,
                    "actual_gap": key["gap"],
                    "n_bits": n.bit_length(),
                    "algorithm": "original",
                    "iterations": iterations,
                    "square_checks": iterations,
                    "preprocessing_seconds": 0,
                    "runtime_seconds": runtime,
                    "success": p is not None
                }]


                #improved fermat (mod 64)
                start = time.perf_counter()

                p, q, iterations, checks = improved_fermat_attack(
                    n,
                    MAX_ITERATIONS
                )

                runtime = time.perf_counter() - start

                rows.append({
                    "trial": trial,
                    "gap_bits": gap_bits,
                    "actual_gap": key["gap"],
                    "n_bits": n.bit_length(),
                    "algorithm": "mod64",
                    "iterations": iterations,
                    "square_checks": checks,
                    "preprocessing_seconds": 0,
                    "runtime_seconds": runtime,
                    "success": p is not None
                })

                assert (p, q, iterations) == baseline_result

                #sieve fermat
                for name, moduli in WHEEL_CONFIGS.items():

                    start = time.perf_counter()

                    p, q, iterations, checks, prep_time = fermat_sieved(
                        n,
                        max_iterations=MAX_ITERATIONS,
                        moduli=moduli
                    )

                    runtime = time.perf_counter() - start

                    assert (p, q, iterations) == baseline_result

                    rows.append({
                        "trial": trial,
                        "gap_bits": gap_bits,
                        "actual_gap": key["gap"],
                        "n_bits": n.bit_length(),
                        "algorithm": name,
                        "iterations": iterations,
                        "square_checks": checks,
                        "preprocessing_seconds": prep_time,
                        "runtime_seconds": runtime,
                        "success": p is not None
                    })

                for row in rows:

                    writer.writerow(row)
                    file.flush()

                    print(
                        f"gap={gap_bits} | "
                        f"trial={trial + 1} | "
                        f"{row['algorithm']} | "
                        f"iterations={row['iterations']} | "
                        f"sqrt_checks={row['square_checks']} | "
                        f"runtime={row['runtime_seconds']:.4f}s"
                    )

    print(f"\nSaved results to {output_file}")

def run_extended_experiments():
    #extended wheel-6720 experiment (527-529)
    os.makedirs("results", exist_ok=True)

    output_file = "results/wheel_6720_extended_2048.csv"

    fieldnames = [
        "trial",
        "gap_bits",
        "actual_gap",
        "n_bits",
        "algorithm",
        "iterations",
        "square_checks",
        "preprocessing_seconds",
        "runtime_seconds",
        "success"
    ]

    file_exists = os.path.exists(output_file)

    with open(output_file, "a", newline="") as file:

        writer = csv.DictWriter(file, fieldnames=fieldnames)

        if not file_exists or os.path.getsize(output_file) == 0:
            writer.writeheader()

        for gap_bits in EXTENDED_GAP_BITS:

            for trial in range(TRIALS):

                with open(output_file, "r", newline="") as read_file:
                    completed = {
                        (int(row["gap_bits"]), int(row["trial"]))
                        for row in csv.DictReader(read_file)
                    }

                if (gap_bits, trial) in completed:
                    print(f"Skipping gap={gap_bits}, trial={trial + 1}")
                    continue

                key = generate_close_prime_key(
                    bits=BITS,
                    gap_bits=gap_bits
                )

                n = key["n"]

                start = time.perf_counter()

                p, q, iterations, checks, prep_time = fermat_sieved(
                    n,
                    max_iterations=EXTENDED_MAX_ITERATIONS,
                    moduli=EXTENDED_MODULI
                )

                runtime = time.perf_counter() - start

                success = p is not None

                if success:
                    assert p * q == n

                row = {
                    "trial": trial,
                    "gap_bits": gap_bits,
                    "actual_gap": key["gap"],
                    "n_bits": n.bit_length(),
                    "algorithm": "wheel_6720",
                    "iterations": iterations,
                    "square_checks": checks,
                    "preprocessing_seconds": prep_time,
                    "runtime_seconds": runtime,
                    "success": success
                }

                writer.writerow(row)
                file.flush()

                print(
                    f"gap={gap_bits} | "
                    f"trial={trial + 1}/{TRIALS} | "
                    f"wheel_6720 | "
                    f"iterations={iterations} | "
                    f"sqrt_checks={checks} | "
                    f"runtime={runtime:.4f}s | "
                    f"success={success}"
                )

    print(f"\nSaved results to {output_file}")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Run Fermat modular sieving experiments"
    )

    parser.add_argument(
        "--experiment",
        choices=["comparison", "extended"],
        required=True
    )

    args = parser.parse_args()

    if args.experiment == "comparison":
        run_sieve_experiments()

    elif args.experiment == "extended":
        run_extended_experiments()
