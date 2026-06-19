import os

files_to_scan = ['s3.tf', 'iam.tf', 'main.tf']
vulnerabilities = {
    '"0.0.0.0/0"': "CRITICAL: Port exposed to the public internet (F-05)",
    '"*"': "HIGH: Wildcard administrative permissions granted (F-02)",
    "block_public_acls       = false": "CRITICAL: S3 Public Access Block disabled (F-01)"
}

print("=== STARTING SIMULATED COMPLIANCE AUDIT ===")
for file_name in files_to_scan:
    if os.path.exists(file_name):
        print(f"\nScanning {file_name}...")
        with open(file_name, 'r') as f:
            lines = f.readlines()
            for line_num, line in enumerate(lines, 1):
                for flaw, message in vulnerabilities.items():
                    if flaw in line:
                        print(f" [!] {message} on line {line_num}: {line.strip()}")
print("\n=== SCAN COMPLETE ===")
