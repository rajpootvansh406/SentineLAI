
import re
from pathlib import Path


class ConfigurationAnalysisAgent:

    def __init__(self):

        self.agent_name = "Configuration Analysis Agent"

        self.supported_files = {
            ".py",
            ".js",
            ".ts",
            ".json",
            ".yaml",
            ".yml",
            ".toml",
            ".ini",
            ".cfg",
            ".env"
        }

        self.patterns = [

            {
                "name": "Debug Mode Enabled",
                "pattern": re.compile(
                    r"\bDEBUG\s*=\s*True\b|debug\s*:\s*true",
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "description":
                    "Debug mode appears to be enabled.",
                "recommendation":
                    "Disable debug mode in production."
            },

            {
                "name": "Permissive CORS Configuration",
                "pattern": re.compile(
                    r"""(?:allow_origins\s*=\s*\[\s*["']\*["']|Access-Control-Allow-Origin\s*[:=]\s*["']\*["'])""",
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "description":
                    "A permissive cross-origin configuration was detected.",
                "recommendation":
                    "Restrict cross-origin access to trusted origins."
            },

            {
                "name": "SSL Verification Disabled",
                "pattern": re.compile(
                    r"verify\s*=\s*False|CERT_NONE",
                    re.IGNORECASE
                ),
                "severity": "HIGH",
                "description":
                    "SSL certificate verification appears disabled.",
                "recommendation":
                    "Enable SSL certificate verification."
            },

            {
                "name": "Insecure Cookie Configuration",
                "pattern": re.compile(
                    r"""(?:secure\s*[:=]\s*False|httponly\s*[:=]\s*False)""",
                    re.IGNORECASE
                ),
                "severity": "MEDIUM",
                "description":
                    "A cookie security setting may be disabled.",
                "recommendation":
                    "Enable Secure and HttpOnly cookie attributes where appropriate."
            },

            {
                "name": "Potentially Exposed Environment File",
                "pattern": re.compile(
                    r"\.env",
                    re.IGNORECASE
                ),
                "severity": "LOW",
                "description":
                    "An environment file reference was detected.",
                "recommendation":
                    "Ensure environment files containing secrets are not publicly accessible or committed to source control."
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

        file_path = Path(file_path)

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


        for line_number, line in enumerate(
            lines,
            start=1
        ):

            for rule in self.patterns:

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

                    "code_snippet": code_snippet[:200],

                    "confidence": "MEDIUM"

                })


        return findings


    def scan_directory(self, directory, secrets_agent=None):

        directory = Path(directory)

        findings = []

        scanned_files = []

        if not directory.exists():
            return findings, scanned_files


        for file_path in directory.rglob("*"):

            if not file_path.is_file():
                continue

            if any(
                folder in self.skipped_directories
                for folder in file_path.parts
            ):
                continue

            if file_path.suffix.lower() not in self.supported_files:
                continue

            if file_path.name not in {
                ".env",
                ".env.example",
                ".env.template"
            } and file_path.suffix.lower() not in self.supported_files:
                continue


            try:

                if file_path.stat().st_size > 1_000_000:
                    continue

            except Exception:

                continue


            relative_path = file_path.relative_to(
                directory
            ).as_posix()

            scanned_files.append(relative_path)


            findings.extend(
                self.scan_file(
                    file_path,
                    secrets_agent
                )
            )


        return findings, scanned_files
