import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

df = pd.read_csv("results/original_fermat_detailed_summary_2048.csv")

measured_gap = df["gap_bits"]
measured_runtime = df["mean_runtime"]

runtime_526 = df.loc[df["gap_bits"] == 526, "mean_runtime"].iloc[0]

future_gap = np.arange(526, 532)

future_runtime = runtime_526 * (4 ** (future_gap - 526))

plt.figure(figsize=(9, 6))

plt.plot(
    measured_gap,
    measured_runtime,
    marker="o",
    label="Measured runtime"
)

plt.plot(
    future_gap,
    future_runtime,
    marker="o",
    linestyle="--",
    label="Extrapolated runtime (~4x per gap bit)"
)

plt.axhline(3600, linestyle=":", label="1 hour")
plt.axhline(8 * 3600, linestyle="--", label="8 hours")
plt.axhline(24 * 3600, linestyle="-.", label="24 hours")

plt.yscale("log")

plt.xlabel("Prime Separation (gap bits)")
plt.ylabel("Runtime (seconds)")
plt.title("Fermat Factorisation Runtime vs Prime Separation")

plt.legend()
plt.grid(True, which="both", alpha=0.3)

plt.tight_layout()
plt.savefig("results/fermat_runtime_extrapolation.png", dpi=300)
plt.close()