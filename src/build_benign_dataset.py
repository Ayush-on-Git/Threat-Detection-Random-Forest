import pandas as pd

# Load datasets
umbrella = pd.read_csv("data/top-1m.csv", header=None)
majestic = pd.read_csv("data/majestic_million.csv")

# Extract domain column
umbrella_domains = umbrella[1]
majestic_domains = majestic["Domain"]

# Combine
combined = pd.concat([umbrella_domains, majestic_domains])

# Clean
combined = combined.str.lower()
combined = combined.str.replace("www.", "", regex=False)
combined = combined.str.strip()

# Remove duplicates
combined = combined.drop_duplicates()

# Remove very long domains
combined = combined[combined.str.len() < 60]

# Take only top 5000
benign_domains = combined.head(5000)

# Create dataframe
benign_df = pd.DataFrame({
    "domain": benign_domains,
    "label": 0
})

# 🔥 NOW DO BIAS CHECK (after dataframe creation)

print("Average length:", benign_df["domain"].str.len().mean())
print("Dot count avg:", benign_df["domain"].str.count(r"\.").mean())
print(
    "Digit ratio avg:",
    benign_df["domain"].str.count(r"\d").sum()
    / benign_df["domain"].str.len().sum()
)

print("\nSample domains:")
print(benign_df.head())

# Save
benign_df.to_csv("data/benign_domains.csv", index=False)

print("Benign dataset created:", benign_df.shape)