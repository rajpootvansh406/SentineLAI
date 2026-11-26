
import hashlib
from pathlib import Path

from backend.agents.secrets_agent import SecretsDetectionAgent
from backend.agents.code_security_agent import CodeSecurityAgent
from backend.agents.dependency_agent import DependencyAnalysisAgent
from backend.agents.configuration_agent import ConfigurationAnalysisAgent
from backend.agents.security_review_agent import SecurityReviewAgent


class ScanOrchestrator:

    def __init__(self):

        self.agent_name = "Orchestrator Agent"

        self.secrets_agent = SecretsDetectionAgent()

        self.code_security_agent = CodeSecurityAgent()

        self.dependency_agent = DependencyAnalysisAgent()

        self.configuration_agent = ConfigurationAnalysisAgent()

        self.security_review_agent = SecurityReviewAgent()


    def scan_project(self, project_directory):

        project_directory = Path(project_directory)

        all_findings = []

        scanned_files = []

        scanned_paths = set()


        supported_extensions = (
            self.secrets_agent.supported_extensions
            | self.code_security_agent.supported_extensions
        )


        skipped_directories = {
            "venv",
            ".venv",
            "__pycache__",
            "node_modules",
            ".git",
            "site-packages",
            "dist",
            "build"
        }


        if not project_directory.exists():

            return {
                "status": "failed",
                "message": "Project directory does not exist",
                "files": [],
                "findings": []
            }


        # SOURCE CODE SCANNING

        for file_path in project_directory.rglob("*"):

            if not file_path.is_file():
                continue


            if any(
                folder in skipped_directories
                for folder in file_path.parts
            ):
                continue


            if file_path.suffix.lower() not in supported_extensions:
                continue


            try:

                file_size = file_path.stat().st_size

                if file_size > 1_000_000:
                    continue

            except Exception:

                continue


            try:

                with open(file_path, "rb") as file:

                    file_hash = hashlib.sha256(
                        file.read()
                    ).hexdigest()

            except Exception:

                file_hash = None


            # Secrets Detection Agent

            secrets_findings = self.secrets_agent.scan_file(
                file_path
            )


            # Code Security Agent

            code_findings = self.code_security_agent.scan_file(
                file_path,
                self.secrets_agent
            )


            file_findings = (
                secrets_findings + code_findings
            )


            relative_path = file_path.relative_to(
                project_directory
            ).as_posix()


            scanned_files.append({

                "file_path": relative_path,

                "file_name": file_path.name,

                "extension": file_path.suffix.lower(),

                "file_size": file_size,

                "file_hash": file_hash,

                "status": "SCANNED",

                "findings_count": len(file_findings)

            })


            scanned_paths.add(relative_path)


            for finding in file_findings:

                finding["file_path"] = relative_path

                finding["fingerprint"] = hashlib.sha256(
                    (
                        relative_path
                        + str(finding["line_number"])
                        + finding["title"]
                    ).encode("utf-8")
                ).hexdigest()


            all_findings.extend(
                file_findings
            )


        # DEPENDENCY ANALYSIS AGENT

        dependency_findings, dependency_files = (
            self.dependency_agent.scan_directory(
                project_directory
            )
        )


        for finding in dependency_findings:

            relative_path = Path(
                finding["file_path"]
            ).relative_to(
                project_directory
            ).as_posix()


            finding["file_path"] = relative_path


            finding["fingerprint"] = hashlib.sha256(
                (
                    relative_path
                    + str(finding["line_number"])
                    + finding["title"]
                ).encode("utf-8")
            ).hexdigest()


        all_findings.extend(
            dependency_findings
        )


        # CONFIGURATION ANALYSIS AGENT

        configuration_findings, configuration_files = (
            self.configuration_agent.scan_directory(
                project_directory,
                self.secrets_agent
            )
        )


        for finding in configuration_findings:

            relative_path = Path(
                finding["file_path"]
            ).relative_to(
                project_directory
            ).as_posix()


            finding["file_path"] = relative_path


            finding["fingerprint"] = hashlib.sha256(
                (
                    relative_path
                    + str(finding["line_number"])
                    + finding["title"]
                ).encode("utf-8")
            ).hexdigest()


        all_findings.extend(
            configuration_findings
        )


        # ADD ADDITIONAL SCANNED FILES

        additional_files = (
            dependency_files + configuration_files
        )


        for relative_path in additional_files:

            if relative_path in scanned_paths:
                continue


            file_path = project_directory / relative_path


            try:

                file_size = file_path.stat().st_size

                with open(file_path, "rb") as file:

                    file_hash = hashlib.sha256(
                        file.read()
                    ).hexdigest()

            except Exception:

                file_size = 0

                file_hash = None


            file_findings_count = sum(
                1
                for finding in all_findings
                if finding["file_path"] == relative_path
            )


            scanned_files.append({

                "file_path": relative_path,

                "file_name": file_path.name,

                "extension": file_path.suffix.lower(),

                "file_size": file_size,

                "file_hash": file_hash,

                "status": "SCANNED",

                "findings_count": file_findings_count

            })


            scanned_paths.add(relative_path)


        # SEVERITY DISTRIBUTION

        severity_counts = {

            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0

        }


        for finding in all_findings:

            severity = finding.get("severity", "INFO")

            if severity in severity_counts:

                severity_counts[severity] += 1


        # SECURITY SCORE

        score = 100

        score -= severity_counts["CRITICAL"] * 25

        score -= severity_counts["HIGH"] * 15

        score -= severity_counts["MEDIUM"] * 8

        score -= severity_counts["LOW"] * 3

        score = max(0, min(100, score))


        # SECURITY REVIEW AGENT

        security_review = (
            self.security_review_agent.review_findings(
                all_findings,
                severity_counts
            )
        )


        # FINAL RESULTS

        return {

            "status": "completed",

            "agent": self.agent_name,

            "files_scanned": len(scanned_files),

            "total_findings": len(all_findings),

            "security_score": score,

            "severity_counts": severity_counts,

            "security_review": security_review,

            "files": scanned_files,

            "findings": all_findings

        }
