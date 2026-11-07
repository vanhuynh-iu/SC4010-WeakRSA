import pandas as pd
import matplotlib.pyplot as plt

#update summary csv file and output file names

summary = pd.read_csv("results/original_fermat_detailed_summary_2048.csv")

plt.figure()

plt.plot(
    summary["gap_bits"],
    summary["mean_iterations"],
    marker="o"
)

plt.yscale("log")

plt.xlabel("Prime Gap (bits)")
plt.ylabel("Mean Fermat Iterations")
plt.title("Effect of Prime Separation on Fermat Factorisation (log)")

plt.grid(True)
plt.tight_layout()
plt.savefig("results/2048_meaniterations_vs_gap_detailed_log.png")

plt.figure()

plt.plot(
    summary["gap_bits"],
    summary["mean_runtime"],
    marker="o"
)

plt.yscale("log")

plt.xlabel("Prime Gap (bits)")
plt.ylabel("Mean Runtime (seconds)")
plt.title("Fermat Runtime vs Prime Separation (log)")

plt.grid(True)
plt.tight_layout()
plt.savefig("results/2048_meanruntime_vs_gap_detailed_log.png")

