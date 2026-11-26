import json
from pathlib import Path


class DependencyAnalysisAgent:

    def __init__(self):

        self.agent_name = "Dependency Analysis Agent"

        self.dependency_files = {
            "requirements.txt",
            "package.json",
            "Pipfile",
            "pyproject.toml"
        }


    def scan_file(self, file_path):

        findings = []

        file_path = Path(file_path)

        try:

            content = file_path.read_text(
                encoding="utf-8",
                errors="ignore"
            )

        except Exception:

            return findings


        if file_path.name == "requirements.txt":

            for line_number, line in enumerate(
                content.splitlines(),
                start=1
            ):

                dependency = line.strip()

                if not dependency or dependency.startswith("#"):
                    continue

                if dependency.startswith("-"):
                    continue

                if "==" not in dependency:

                    findings.append({

                        "agent": self.agent_name,

                        "title": "Unpinned Dependency",

                        "severity": "MEDIUM",

                        "file_path": str(file_path),

                        "line_number": line_number,

                        "description":
                            "Dependency version is not strictly pinned.",

                        "recommendation":
                            "Specify an exact dependency version "
                            "and regularly review updates.",

                        "code_snippet": dependency[:200],

                        "confidence": "MEDIUM"

                    })


        elif file_path.name == "package.json":

            try:

                data = json.loads(content)

            except Exception:

                return findings


            dependencies = {}

            dependencies.update(
                data.get("dependencies", {})
            )

            dependencies.update(
                data.get("devDependencies", {})
            )


            for package_name, version in dependencies.items():

                if (
                    version == "*"
                    or version == "latest"
                    or version.startswith("^")
                    or version.startswith("~")
                ):

                    findings.append({

                        "agent": self.agent_name,

                        "title": "Flexible Dependency Version",

                        "severity": "LOW",

                        "file_path": str(file_path),

                        "line_number": 1,

                        "description":
                            "Dependency uses a flexible version "
                            "specifier.",

                        "recommendation":
                            "Review dependency versions and consider "
                            "using a lockfile for reproducible builds.",

                        "code_snippet":
                            f"{package_name}: {version}",

                        "confidence": "MEDIUM"

                    })


        return findings


    def scan_directory(self, directory):

        directory = Path(directory)

        findings = []

        scanned_files = []

        if not directory.exists():
            return findings, scanned_files


        skipped_directories = {
            "venv",
            ".venv",
            "node_modules",
            ".git",
            "__pycache__",
            "dist",
            "build"
        }


        for file_path in directory.rglob("*"):

            if not file_path.is_file():
                continue

            if any(
                folder in skipped_directories
                for folder in file_path.parts
            ):
                continue

            if file_path.name not in self.dependency_files:
                continue


            scanned_files.append(
                file_path.relative_to(directory).as_posix()
            )


            findings.extend(
                self.scan_file(file_path)
            )


        return findings, scanned_files