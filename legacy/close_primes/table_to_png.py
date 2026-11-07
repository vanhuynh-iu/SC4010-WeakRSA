import pandas as pd
import dataframe_image as dfi

df = pd.read_csv("results/original_fermat_detailed_summary_2048.csv")

dfi.export(df, "results/summary_table.png", table_conversion="matplotlib")
