import pandas as pd

# Load datasets
benign = pd.read_csv("data/benign_domains.csv")
domain_binary = pd.read_csv("data/domain_binary_dataset.csv")

# Keep only malicious from big dataset
malicious = domain_binary[domain_binary["label"] == 1]

print("Total malicious available:", len(malicious))
print("Total benign available:", len(benign))

# ------------------------------
# BALANCING STRATEGY
# ------------------------------

TARGET_SIZE = 5000   # you can change to 8000 later

malicious_sample = malicious.sample(n=TARGET_SIZE, random_state=42)
benign_sample = benign.sample(n=TARGET_SIZE, random_state=42)

# Merge
final_df = pd.concat([benign_sample, malicious_sample])

# Shuffle
final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)

print("\nFinal dataset distribution:")
print(final_df["label"].value_counts())

# Save
final_df.to_csv("data/final_balanced_dataset.csv", index=False)

print("\nFinal dataset shape:", final_df.shape)