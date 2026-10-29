import pandas as pd
from key_generation import generate_prime_key
results = []

num_trials = 100

for trial in range(num_trials):
    key = generate_prime_key(bits=2048)

    gap = key["gap"]
    gap_bits = gap.bit_length() - 1

    results.append({
        "trial": trial + 1,
        "gap_bits": gap_bits,
        "gap": gap,
        "n_bits": key["n"].bit_length()
    })
    if trial % 10 == 0:
        print(trial)

df = pd.DataFrame(results)

df.to_csv("results/normal_rsa_gap_distribution.csv", index=False)


print(df.head())

print("\nSummary:")
print("Number of trials:", len(df))
print("Minimum gap bits:", df["gap_bits"].min())
print("Maximum gap bits:", df["gap_bits"].max())
print("Mean gap bits:", df["gap_bits"].mean())
print("Median gap bits:", df["gap_bits"].median())