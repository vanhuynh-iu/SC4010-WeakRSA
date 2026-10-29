import pandas as pd
import argparse
import os

def summarise_results(bits, attack_type, experiment_type):
    file = f"results/{attack_type}_fermat_{experiment_type}_results_{bits}.csv"
    df = pd.read_csv(file)

    if attack_type == "improved":

        summary = df.groupby("gap_bits").agg(
            trials=("trial", "count"),
            success_rate=("success", "mean"),
            mean_iterations=("iterations", "mean"),
            mean_perfect_square_checks=("perfect_square_checks", "mean"),
            mean_checks_skipped=("checks_skipped", "mean"),
            mean_checks_skipped_percentage=(
                "checks_skipped_percentage", "mean"
            ),
            mean_runtime=("runtime_seconds", "mean"),
        ).reset_index()

        summary["success_rate"] *= 100

        summary["iteration_growth_ratio"] = (
            summary["mean_iterations"]
            / summary["mean_iterations"].shift(1)
        )

        summary["runtime_growth_ratio"] = (
            summary["mean_runtime"]
            / summary["mean_runtime"].shift(1)
        )

        output_file = f"results/{attack_type}_fermat_{experiment_type}_summary_{bits}.csv"
        summary.to_csv(output_file, index=False)

        print(summary.to_string(index=False))

    elif attack_type == "original":
        summary = df.groupby("gap_bits").agg(
            mean_iterations=("iterations", "mean"),
            mean_runtime=("runtime_seconds", "mean"),
        ).reset_index()

        summary["iteration_growth_ratio"] = (
            summary["mean_iterations"]
            / summary["mean_iterations"].shift(1)
        )


        summary["runtime_growth_ratio"] = (
            summary["mean_runtime"]
            / summary["mean_runtime"].shift(1)
        )

        print(summary)

        output_file = f"results/{attack_type}_fermat_{experiment_type}_summary_{bits}.csv"
        summary.to_csv(output_file, index=False)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Summarise RSA Fermat experiment results"
    )

    parser.add_argument("--bits", type=int, choices=[1024, 2048, 3072], required=True)
    parser.add_argument("--attack", choices=["original", "improved"], required=True)
    parser.add_argument("--experiment", choices=["pilot", "detailed"], default="detailed")

    args = parser.parse_args()

    summarise_results(
        bits=args.bits,
        attack_type=args.attack,
        experiment_type=args.experiment
    )