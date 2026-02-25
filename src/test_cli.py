from threat_engine import analyze_url

print("\n--- URL Threat Analyzer ---\n")

while True:
    url = input("Enter URL (type 'exit' to quit): ")

    if url.lower() == "exit":
        print("Exiting...")
        break

    try:
        result = analyze_url(url)

        print("\nResult:")
        print("Domain       :", result["domain"])
        print("Probability  :", result["probability"])
        print("Prediction   :", "Malicious" if result["prediction"] == 1 else "Safe")
        print("Threat Score :", result["threat_score"], "/ 100")
        print("Risk Level   :", result["risk_level"])
        print("-" * 40)

    except Exception as e:
        print("Error occurred:", e)