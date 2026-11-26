
import re
from pathlib import Path


class SecretsDetectionAgent:

    def __init__(self):

        self.agent_name = "Secrets Detection Agent"

        self.supported_extensions = {
            ".py", ".js", ".ts", ".java", ".php",
            ".env", ".json", ".yaml", ".yml",
            ".xml", ".config", ".properties"
        }

        self.secret_patterns = [

            {
                "name": "Hardcoded Password",
                "pattern": re.compile(
                    r"""(?:password|passwd|pwd)\s*[:=]\s*(?:["']([^"']+)["']|([^\s,;#]+))""",
                    re.IGNORECASE
                ),
                "severity": "HIGH"
            },

            {
                "name": "Hardcoded API Key",
                "pattern": re.compile(
                    r"""(?:api_key|apikey|api-key)\s*[:=]\s*(?:["']([^"']+)["']|([^\s,;#]+))""",
                    re.IGNORECASE
                ),
                "severity": "HIGH"
            },

            {
                "name": "Hardcoded Secret",
                "pattern": re.compile(
                    r"""(?:secret|secret_key|client_secret)\s*[:=]\s*(?:["']([^"']+)["']|([^\s,;#]+))""",
                    re.IGNORECASE
                ),
                "severity": "HIGH"
            },

            {
                "name": "Hardcoded Access Token",
                "pattern": re.compile(
                    r"""(?:access_token|auth_token|token)\s*[:=]\s*(?:["']([^"']+)["']|([^\s,;#]+))""",
                    re.IGNORECASE
                ),
                "severity": "HIGH"
            },

            {
                "name": "Hardcoded Database Credential",
                "pattern": re.compile(
                    r"""(?:db_password|database_password|db_pass)\s*[:=]\s*(?:["']([^"']+)["']|([^\s,;#]+))""",
                    re.IGNORECASE
                ),
                "severity": "CRITICAL"
            }

        ]

        self.placeholder_values = {
            "example",
            "placeholder",
            "your_api_key",
            "your_password",
            "your_secret",
            "change_me",
            "changeme",
            "dummy",
            "test",
            "none",
            "null",
            "xxxx",
            "12345",
            "demo",
            "sample",
            "redacted",
            "replace_me",
            "insert_key_here"
        }

        self.skipped_directories = {
            "venv",
            ".venv",
            "__pycache__",
            "node_modules",
            ".git",
            "site-packages",
            "dist",
            "build"
        }


    def is_placeholder(self, value):

        cleaned_value = value.strip().lower()

        if cleaned_value in self.placeholder_values:
            return True

        if len(cleaned_value) < 4:
            return True

        return False


    def redact_secrets(self, line):

        redacted_line = line

        for rule in self.secret_patterns:

            matches = list(rule["pattern"].finditer(redacted_line))

            for match in reversed(matches):

                secret_value = match.group(1) or match.group(2)

                if not secret_value:
                    continue

                start = match.start(1) if match.group(1) else match.start(2)
                end = match.end(1) if match.group(1) else match.end(2)

                redacted_line = (
                    redacted_line[:start]
                    + "[REDACTED]"
                    + redacted_line[end:]
                )

        return redacted_line.strip()


    def scan_file(self, file_path):

        findings = []

        try:

            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                lines = file.readlines()

        except Exception:

            return findings


        for line_number, line in enumerate(lines, start=1):

            for rule in self.secret_patterns:

                matches = rule["pattern"].finditer(line)

                for match in matches:

                    secret_value = match.group(1) or match.group(2)

                    if not secret_value:
                        continue

                    if self.is_placeholder(secret_value):
                        continue

                    findings.append({

                        "agent": self.agent_name,

                        "title": rule["name"],

                        "severity": rule["severity"],

                        "file_path": str(file_path),

                        "line_number": line_number,

                        "description":
                            "Potential hardcoded credential detected. "
                            "The sensitive value has been redacted.",

                        "recommendation":
                            "Move credentials into environment variables "
                            "or a secure secrets manager. Rotate exposed "
                            "credentials if they have been used.",

                        "code_snippet":
                            self.redact_secrets(line),

                        "confidence": "MEDIUM"

                    })


        return findings


    def scan_directory(self, directory):

        directory = Path(directory)

        findings = []

        if not directory.exists():
            return findings


        for file_path in directory.rglob("*"):

            if not file_path.is_file():
                continue

            if any(
                folder in self.skipped_directories
                for folder in file_path.parts
            ):
                continue

            if file_path.suffix.lower() not in self.supported_extensions:
                continue


            try:

                if file_path.stat().st_size > 1_000_000:
                    continue

            except Exception:

                continue


            file_findings = self.scan_file(file_path)

            findings.extend(file_findings)


        return findings
