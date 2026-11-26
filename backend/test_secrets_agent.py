from backend.agents.secrets_agent import SecretsDetectionAgent


agent = SecretsDetectionAgent()

test_directory = "uploads"

findings = agent.scan_directory(test_directory)


print("\n")
print("=" * 50)
print("SENTINELAI SECRETS DETECTION AGENT")
print("=" * 50)


if findings:

    print("\nFindings detected:\n")

    for finding in findings:

        print("Vulnerability:", finding["title"])
        print("Severity:", finding["severity"])
        print("File:", finding["file_path"])
        print("Line:", finding["line_number"])
        print("Description:", finding["description"])
        print("Recommendation:", finding["recommendation"])
        print("-" * 50)


else:

    print("No potential secrets detected.")


print("\nTotal findings:", len(findings))