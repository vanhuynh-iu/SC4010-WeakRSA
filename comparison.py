import pandas as pd
import matplotlib.pyplot as plt
import os

os.makedirs("results/graphs", exist_ok=True)

original = pd.read_csv("results/original_fermat_detailed_summary_2048.csv")
improved = pd.read_csv("results/improved_fermat_detailed_summary_2048.csv")

comparison = pd.merge(
    original[["gap_bits", "mean_iterations", "mean_runtime"]],
    improved[["gap_bits", "mean_perfect_square_checks", "mean_runtime"]],
    on="gap_bits",
    suffixes=("_original", "_improved")
)

comparison = comparison.sort_values("gap_bits")

# iteration comparison
plt.figure(figsize=(10, 6))

plt.plot(
    comparison["gap_bits"],
    comparison["mean_iterations"],
    marker="o",
    label="Original Fermat"
)

plt.plot(
    comparison["gap_bits"],
    comparison["mean_perfect_square_checks"],
    marker="s",
    label="Improved Fermat (Mod 64)"
)

# plt.yscale("log")
plt.xlabel("Prime Gap Exponent (bits)")
plt.ylabel("Mean Iterations")
plt.title("Fermat Factorisation: Iterations Comparison")
plt.legend()
plt.grid(True, which="both", alpha=0.3)
plt.tight_layout()

plt.savefig("results/graphs/iterations_comparison.png", dpi=300)
plt.close()

# runtime comparison
plt.figure(figsize=(10, 6))

plt.plot(
    comparison["gap_bits"],
    comparison["mean_runtime_original"],
    marker="o",
    label="Original Fermat"
)

plt.plot(
    comparison["gap_bits"],
    comparison["mean_runtime_improved"],
    marker="s",
    label="Improved Fermat (Mod 64)"
)

# plt.yscale("log")
plt.xlabel("Prime Gap Exponent (bits)")
plt.ylabel("Mean Runtime (seconds)")
plt.title("Fermat Factorisation: Runtime Comparison")
plt.legend()
plt.grid(True, which="both", alpha=0.3)
plt.tight_layout()

plt.savefig("results/graphs/runtime_comparison.png", dpi=300)
plt.close()

print("Graphs saved successfully!")
