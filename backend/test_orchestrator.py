from backend.agents.orchestrator import ScanOrchestrator


orchestrator = ScanOrchestrator()

project_directory = "uploads"

result = orchestrator.scan_project(
    project_directory
)


print("\n")
print("=" * 50)
print("SENTINELAI SECURITY SCAN")
print("=" * 50)

print("\nStatus:", result["status"])

print("Files scanned:", result["files_scanned"])

print("Total findings:", result["total_findings"])


print("\nSeverity Distribution:")

for severity, count in result["severity_counts"].items():

    print(severity, ":", count)


print("\n" + "=" * 50)

print("DETECTED VULNERABILITIES")

print("=" * 50)


for finding in result["findings"]:

    print("\nTitle:", finding["title"])

    print("Severity:", finding["severity"])

    print("File:", finding["file_path"])

    print("Line:", finding["line_number"])

    print("Description:", finding["description"])

    print("Recommendation:", finding["recommendation"])

    print("-" * 50)