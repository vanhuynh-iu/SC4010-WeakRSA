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


def summarise_sieve_results():
    os.makedirs("results", exist_ok=True)

    df = pd.read_csv("results/sieve_comparison_2048.csv")

    summary = df.groupby(["gap_bits", "algorithm"]).agg(
        trials=("trial", "count"),
        success_rate=("success", "mean"),
        mean_iterations=("iterations", "mean"),
        mean_square_checks=("square_checks", "mean"),
        mean_preprocessing=("preprocessing_seconds", "mean"),
        mean_runtime=("runtime_seconds", "mean")
    ).reset_index()

    summary["success_rate"] *= 100

    baseline = summary[
        summary["algorithm"] == "original"
    ][["gap_bits", "mean_runtime", "mean_square_checks"]].rename(
        columns={
            "mean_runtime": "baseline_runtime",
            "mean_square_checks": "baseline_checks"
        }
    )

    summary = summary.merge(baseline, on="gap_bits")

    summary["speedup"] = (
        summary["baseline_runtime"] / summary["mean_runtime"]
    )

    summary["checks_eliminated_pct"] = (
        1 - summary["mean_square_checks"] / summary["baseline_checks"]
    ) * 100

    summary.to_csv(
        "results/sieve_comparison_summary_2048.csv",
        index=False
    )


    algorithm_order = [
        "original",
        "mod64",
        "wheel_15",
        "wheel_105",
        "wheel_1155",
        "wheel_960",
        "wheel_6720"
    ]


    def create_table(value_column, output_file, decimals=4):

        table = summary.pivot(
            index="gap_bits",
            columns="algorithm",
            values=value_column
        )

        table = table.reindex(columns=algorithm_order)
        table = table.round(decimals)

        table.to_csv(f"results/{output_file}.csv")

        print(f"\n===== {output_file} =====")
        print(table.to_string())

        return table


    runtime_table = create_table(
        "mean_runtime",
        "sieve_runtime_comparison_2048",
        decimals=6
    )

    speedup_table = create_table(
        "speedup",
        "sieve_speedup_comparison_2048",
        decimals=2
    )

    checks_table = create_table(
        "checks_eliminated_pct",
        "sieve_checks_eliminated_2048",
        decimals=2
    )

    iteration_table = summary[
        summary["algorithm"] == "original"
    ][["gap_bits", "mean_iterations"]].copy()

    iteration_table = iteration_table.sort_values("gap_bits")

    iteration_table["iteration_growth_ratio"] = (
        iteration_table["mean_iterations"]
        / iteration_table["mean_iterations"].shift(1)
    )

    iteration_table.to_csv(
        "results/sieve_iteration_growth_2048.csv",
        index=False
    )

    print("Original Fermat Iteration Growth")
    print(iteration_table.to_string(index=False))

def summarise_extended_sieve_results():
    os.makedirs("results", exist_ok=True)

    df_comparison = pd.read_csv("results/sieve_comparison_2048.csv")

    df_comparison = df_comparison[
        df_comparison["algorithm"] == "wheel_6720"
    ]

    df_extended = pd.read_csv("results/wheel_6720_extended_2048.csv")

    df = pd.concat(
        [df_comparison, df_extended],
        ignore_index=True
    )

    summary = df.groupby(["gap_bits", "algorithm"]).agg(
        trials=("trial", "count"),
        success_rate=("success", "mean"),
        mean_iterations=("iterations", "mean"),
        mean_square_checks=("square_checks", "mean"),
        mean_preprocessing=("preprocessing_seconds", "mean"),
        mean_runtime=("runtime_seconds", "mean")
    ).reset_index()

    summary["success_rate"] *= 100

    summary["checks_eliminated_pct"] = (
        1 - summary["mean_square_checks"] / summary["mean_iterations"]
    ) * 100

    summary["iteration_growth_ratio"] = (
        summary["mean_iterations"]
        / summary["mean_iterations"].shift(1)
    )

    summary["runtime_growth_ratio"] = (
        summary["mean_runtime"]
        / summary["mean_runtime"].shift(1)
    )

    summary.to_csv(
        "results/wheel_6720_summary_2048.csv",
        index=False
    )

    print("Wheel-6720 Summary (510–529)")
    print(summary.to_string(index=False))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Summarise RSA Fermat experiment results"
    )
    parser.add_argument("--analysis", choices=["prime_gap", "sieve_comparison", "wheel_6720"], required=True)
    parser.add_argument("--bits", type=int, choices=[1024, 2048, 3072])
    parser.add_argument("--attack", choices=["original", "improved"])
    parser.add_argument("--experiment", choices=["pilot", "detailed"], default="detailed")

    args = parser.parse_args()
    
    if args.analysis =="prime_gap":
        if args.bits is None or args.attack is None:
            parser.error("--bits and --attack are required for prime_gap")

        summarise_results(
            bits=args.bits,
            attack_type=args.attack,
            experiment_type=args.experiment
        )

    elif args.analysis == "sieve_comparison":
        summarise_sieve_results()

    elif args.analysis == "wheel_6720":
        summarise_extended_sieve_results()