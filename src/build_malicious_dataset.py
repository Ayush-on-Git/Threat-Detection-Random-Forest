import pandas as pd
from urllib.parse import urlparse
import re

# Load OpenPhish feed
with open("data/feed.txt", "r") as f:
    urls = f.read().splitlines()

df = pd.DataFrame({"url": urls})

# Extract domain
def extract_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain = domain.replace("www.", "")
        return domain
    except:
        return None

df["domain"] = df["url"].apply(extract_domain)

# Remove empty
df = df.dropna()

# Remove duplicates
df = df.drop_duplicates(subset=["domain"])

# Remove very long domains
df = df[df["domain"].str.len() < 60]

# Remove pure IP domains (limit bias)
def is_ip(domain):
    return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", domain))

df["is_ip"] = df["domain"].apply(is_ip)

# Keep max 10% IP-based
ip_df = df[df["is_ip"]]
non_ip_df = df[~df["is_ip"]]

max_ip = int(len(non_ip_df) * 0.1)
ip_df = ip_df.head(max_ip)

df = pd.concat([non_ip_df, ip_df])

# Take top 5000
malicious_df = df.head(5000)[["domain"]]
malicious_df["label"] = 1

# Distribution check
print("Malicious Avg Length:", malicious_df["domain"].str.len().mean())
print("Dot count avg:", malicious_df["domain"].str.count(r"\.").mean())
print(
    "Digit ratio avg:",
    malicious_df["domain"].str.count(r"\d").sum()
    / malicious_df["domain"].str.len().sum()
)

print("\nSample malicious domains:")
print(malicious_df.head())

malicious_df.to_csv("data/malicious_domains.csv", index=False)

print("Malicious dataset created:", malicious_df.shape)