
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

os.makedirs("results/graphs", exist_ok=True)

df = pd.read_csv("results/sieve_comparison_summary_2048.csv")

GAP_BITS = [520, 523, 526]
ALGORITHMS = ["original", "mod64", "wheel_6720"]

LABELS = {
    "original": "Original Fermat",
    "mod64": "Mod-64 Filtering",
    "wheel_6720": "Wheel-6720"
}

df = df[
    df["gap_bits"].isin(GAP_BITS) &
    df["algorithm"].isin(ALGORITHMS)
].copy()

def plot_comparison(column, xlabel, title, filename):

    fig, ax = plt.subplots(figsize=(10, 5))
    y = np.arange(len(GAP_BITS))
    height = 0.23

    for i, algorithm in enumerate(ALGORITHMS):
        values = [
            df[
                (df["gap_bits"] == gap) &
                (df["algorithm"] == algorithm)
            ][column].iloc[0]
            for gap in GAP_BITS
        ]

        bars = ax.barh(
            y + (i - 1) * height,
            values,
            height,
            label=LABELS[algorithm]
        )

        if column == "mean_runtime":
            labels = [f"{v:.3f}s" for v in values]
        else:
            labels = [f"{v:,.0f}" for v in values]

        ax.bar_label(
            bars,
            labels=labels,
            padding=3,
            fontsize=9
        )
    
    ax.set_yticks(y)
    ax.set_yticklabels([f"Gap exponent {gap}" for gap in GAP_BITS])
    ax.set_xlabel(xlabel)
    ax.set_title(title)
    ax.legend()
    ax.set_xscale("log")
    ax.set_xlim(right=df[column].max() * 3)
    ax.invert_yaxis()
    plt.tight_layout()
    plt.savefig(f"results/graphs/{filename}", dpi=300)
    plt.close()

    print(f"Saved: results/graphs/{filename}")


plot_comparison(
    column="mean_square_checks",
    xlabel="Mean Square-Root Checks (log scale)",
    title="Square-Root Checks: Original vs Mod-64 vs Wheel-6720",
    filename="sieve_checks_3gaps.png"
)

plot_comparison(
    column="mean_runtime",
    xlabel="Mean Runtime (seconds, log scale)",
    title="Runtime: Original vs Mod-64 vs Wheel-6720",
    filename="sieve_runtime_3gaps.png"
)
