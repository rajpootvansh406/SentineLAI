
import re
from pathlib import Path


class CodeSecurityAgent:

    def __init__(self):

        self.agent_name = "Code Security Agent"

        self.supported_extensions = {
            ".py",
            ".js",
            ".ts",
            ".java",
            ".php"
        }

        self.security_patterns = [

            {
                "name": "Potential SQL Injection",
                "pattern": re.compile(
                    r"""(?:execute|executemany)\s*\(\s*(?:f["']|["'][^"']*["']\s*\+)""",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "description":
                    "Potentially unsafe SQL query construction detected.",
                "recommendation":
                    "Use parameterized queries instead of dynamically "
                    "building SQL statements."
            },

            {
                "name": "Unsafe Code Evaluation",
                "pattern": re.compile(
                    r"\b(?:eval|exec)\s*\(",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "description":
                    "Dynamic code evaluation detected.",
                "recommendation":
                    "Avoid evaluating untrusted input as executable code."
            },

            {
                "name": "Unsafe Command Execution",
                "pattern": re.compile(
                    r"""subprocess\.(?:run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True""",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "description":
                    "Command execution with shell mode enabled detected.",
                "recommendation":
                    "Avoid shell execution with untrusted input. "
                    "Prefer argument lists and shell=False."
            },

            {
                "name": "Debug Mode Enabled",
                "pattern": re.compile(
                    r"\bdebug\s*=\s*True\b",
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "description":
                    "Debug mode appears to be enabled.",
                "recommendation":
                    "Disable debug mode in production environments."
            },

            {
                "name": "Insecure HTTP URL",
                "pattern": re.compile(
                    r"""https?://(?!localhost|127\.0\.0\.1)[^\s"'<>]+""",
                    re.IGNORECASE
                ),
                "severity": "LOW",
                "description":
                    "An HTTP URL was detected which may transmit "
                    "data without encryption.",
                "recommendation":
                    "Use HTTPS for communication with external services."
            },

            {
                "name": "SSL Verification Disabled",
                "pattern": re.compile(
                    r"""(?:verify\s*=\s*False|CERT_NONE)""",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "description":
                    "SSL certificate verification appears to be disabled.",
                "recommendation":
                    "Enable certificate verification to prevent "
                    "insecure connections."
            },

            {
                "name": "Unsafe YAML Loading",
                "pattern": re.compile(
                    r"\byaml\.load\s*\(",
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "description":
                    "Potentially unsafe YAML loading detected.",
                "recommendation":
                    "Use yaml.safe_load() when loading untrusted YAML data."
            },

            {
                "name": "Unsafe Pickle Deserialization",
                "pattern": re.compile(
                    r"\bpickle\.loads?\s*\(",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "description":
                    "Pickle deserialization detected. "
                    "Untrusted serialized data can be unsafe.",
                "recommendation":
                    "Avoid deserializing untrusted pickle data. "
                    "Use safer data formats where possible."
            }

        ]

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


    def scan_file(self, file_path, secrets_agent=None):

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

            for rule in self.security_patterns:

                if not rule["pattern"].search(line):
                    continue

                code_snippet = line.strip()

                if secrets_agent:
                    code_snippet = secrets_agent.redact_secrets(
                        code_snippet
                    )

                findings.append({

                    "agent": self.agent_name,

                    "title": rule["name"],

                    "severity": rule["severity"],

                    "file_path": str(file_path),

                    "line_number": line_number,

                    "description": rule["description"],

                    "recommendation": rule["recommendation"],

                    "code_snippet": code_snippet,

                    "confidence": "MEDIUM"

                })


        return findings


    def scan_directory(self, directory, secrets_agent=None):

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


            findings.extend(
                self.scan_file(file_path, secrets_agent)
            )


        return findings
