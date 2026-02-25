import pandas as pd
from urllib.parse import urlparse

df = pd.read_csv("data/Final_Raw_Malicious_Url_Dataset.csv")

# Convert to binary
df["label"] = df["target"].apply(lambda x: 0 if x == 0 else 1)

# Extract domain
df["domain"] = df["url"].apply(
    lambda x: urlparse(str(x)).netloc.lower().replace("www.", "")
)

# Keep required columns
domain_df = df[["domain", "label"]]

# Remove duplicates
domain_df = domain_df.drop_duplicates()

print("After conversion:")
print(domain_df.shape)
print("\nBinary distribution:")
print(domain_df["label"].value_counts())

domain_df.to_csv("data/domain_binary_dataset.csv", index=False)