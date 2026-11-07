"""Run RSA comparisons, GCD checks, benchmarks and plots.

Importing this module runs no experiments; Matplotlib loads only for plots.
"""

import argparse
import json

from .gcd_scalability import prepare_scalability_datasets, run_scalability_experiment
from .gcd_checks import run_shared_prime_correctness, run_coverage_experiment
from .plots import generate_figures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("scalability", "correctness", "coverage", "plot", "compare"), default="scalability")
    parser.add_argument("--dataset", default="data/public/auditor_demo", help="saved public fixture for compare mode")
    parser.add_argument("--private-directory", help="optional evaluator truth directory for compare mode")
    parser.add_argument("--budgets", nargs="+", type=int, default=[16, 256], help="per-modulus Fermat budgets for compare mode")
    parser.add_argument("--gcd-backend", choices=("pairwise", "batch"), default="batch", help="GCD scanner for compare mode")
    parser.add_argument("--dataset-dirs", nargs="+", default=["data/public/van_mixed"])
    parser.add_argument("--before", default="data/public/van_coverage/before")
    parser.add_argument("--after", default="data/public/van_coverage/after")
    parser.add_argument("--target-key-id", default="key_001")
    parser.add_argument("--sizes", nargs="+", type=int, default=[20, 50, 100])
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--bits", type=int, default=2048)
    parser.add_argument("--dataset-root", default="data/public/scalability")
    parser.add_argument("--output", help="result directory, or optional figure directory in plot mode")
    parser.add_argument("--input", help="existing result directory for plot mode")
    parser.add_argument("--overwrite-figures", action="store_true")
    parser.add_argument("--skip-memory", action="store_true")
    parser.add_argument("--backend", choices=("euclidean", "math"), default="euclidean")
    args = parser.parse_args(argv)
    if args.mode == "plot" and args.input is None:
        parser.error("--input RESULTS_DIR is required for --mode plot")
    output = args.output or ("results/auditor_comparison" if args.mode == "compare" else "results/van_batch_pilot")
    try:
        if args.mode == "plot":
            metadata = generate_figures(args.input, args.output, args.overwrite_figures)
            for name, source in metadata["sources"].items():
                print("{}: {} rows included; {} excluded".format(name, source["included_rows"], source["excluded_rows"]))
                for reason, count in source["exclusion_reasons"].items():
                    print("  {}: {}".format(reason, count))
            for chart in metadata["charts"]:
                for path in chart["paths"]:
                    print(path)
            return 0
        if args.mode == "compare":
            from .comparison import run_mode_comparison
            summary = run_mode_comparison(args.dataset, output, args.budgets, args.trials,
                                          args.gcd_backend, args.private_directory)
        elif args.mode == "correctness":
            summary = run_shared_prime_correctness(args.dataset_dirs, output)
        elif args.mode == "coverage":
            summary = run_coverage_experiment(args.before, args.after, args.target_key_id, output)
        else:
            directories = prepare_scalability_datasets(args.sizes, args.dataset_root, args.bits)
            summary = run_scalability_experiment(directories, output, args.trials, args.warmups,
                                                 args.backend, not args.skip_memory)
    except (ValueError, TypeError, OSError, RuntimeError) as error:
        parser.exit(1, "Error: {}\n".format(error))
    print(json.dumps(summary, indent=2))
    return 0 if summary["all_runs_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
