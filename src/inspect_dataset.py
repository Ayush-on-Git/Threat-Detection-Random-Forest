import pandas as pd

# Load dataset
df = pd.read_csv("data/Final_Raw_Malicious_Url_Dataset.csv")

print("Columns:")
print(df.columns)

print("\nShape:")
print(df.shape)

print("\nFirst 5 rows:")
print(df.head())

print("\nLabel distribution:")
print(df["target"].value_counts())