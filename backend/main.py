import os
import shutil
import zipfile
import hashlib
import io
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

from backend.database import get_connection
from backend.agents.orchestrator import ScanOrchestrator


load_dotenv()

app = FastAPI(title="SentinelAI")

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
UPLOAD_DIR = BASE_DIR / "uploads"

UPLOAD_DIR.mkdir(exist_ok=True)

app.mount(
    "/static",
    StaticFiles(directory=FRONTEND_DIR / "static"),
    name="static"
)


# =========================================================
# HOME PAGE
# =========================================================

@app.get("/", response_class=HTMLResponse)
def home():
    html_file = FRONTEND_DIR / "templates" / "index.html"

    with open(html_file, "r", encoding="utf-8") as file:
        return file.read()


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "message": "SentinelAI backend is running"
    }


# =========================================================
# DATABASE CHECK
# =========================================================

@app.get("/api/database")
def database_check():

    connection = None

    try:
        connection = get_connection()

        return {
            "status": "connected",
            "message": "MySQL database connected successfully"
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Database connection failed: {str(error)}"
        )

    finally:

        if connection:
            connection.close()


# =========================================================
# DASHBOARD STATISTICS
# =========================================================

@app.get("/api/dashboard/stats")
def dashboard_stats():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT COUNT(*) FROM scans")
        total_scans = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM projects")
        total_projects = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total_vulnerabilities = cursor.fetchone()[0]

        cursor.execute("""
            SELECT security_score
            FROM scans
            WHERE scan_status = 'COMPLETED'
            ORDER BY scan_id DESC
            LIMIT 1
        """)

        latest_scan = cursor.fetchone()

        security_score = (
            latest_scan[0]
            if latest_scan and latest_scan[0] is not None
            else None
        )

        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM vulnerabilities
            WHERE status = 'OPEN'
            GROUP BY severity
        """)

        severity_results = cursor.fetchall()

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        for row in severity_results:

            severity_counts[row[0]] = row[1]

        return {
            "total_scans": total_scans,
            "total_projects": total_projects,
            "total_vulnerabilities": total_vulnerabilities,
            "security_score": security_score,
            "severity_counts": severity_counts
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Dashboard statistics error: {str(error)}"
        )

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================================
# RECENT SCANS
# =========================================================

@app.get("/api/dashboard/recent-scans")
def recent_scans():

    connection = None
    cursor = None

    try:

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                s.scan_id,
                p.project_name,
                s.scan_status,
                s.files_scanned,
                s.total_findings,
                s.security_score,
                s.critical_count,
                s.high_count,
                s.medium_count,
                s.low_count,
                s.created_at
            FROM scans s
            JOIN projects p
                ON s.project_id = p.project_id
            ORDER BY s.scan_id DESC
            LIMIT 5
        """)

        results = cursor.fetchall()

        scans = []

        for row in results:

            scans.append({
                "scan_id": row[0],
                "project_name": row[1],
                "scan_status": row[2],
                "files_scanned": row[3],
                "total_findings": row[4],
                "security_score": row[5],
                "critical_count": row[6],
                "high_count": row[7],
                "medium_count": row[8],
                "low_count": row[9],
                "created_at": str(row[10]) if row[10] else None
            })

        return {
            "recent_scans": scans
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Recent scans error: {str(error)}"
        )

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================================
# ZIP VALIDATION
# =========================================================

def validate_zip_file(zip_file):

    MAX_UPLOAD_SIZE = 50 * 1024 * 1024
    MAX_EXTRACTED_SIZE = 100 * 1024 * 1024
    MAX_FILES = 2000

    if len(zip_file) > MAX_UPLOAD_SIZE:

        raise HTTPException(
            status_code=400,
            detail="ZIP file exceeds the 50 MB upload limit"
        )

    try:

        zip_buffer = io.BytesIO(zip_file)

        with zipfile.ZipFile(zip_buffer, "r") as archive:

            file_list = archive.infolist()

            if len(file_list) > MAX_FILES:

                raise HTTPException(
                    status_code=400,
                    detail="ZIP contains too many files"
                )

            total_size = 0

            for file_info in file_list:

                file_path = Path(file_info.filename)

                if file_path.is_absolute():

                    raise HTTPException(
                        status_code=400,
                        detail="Invalid ZIP file path"
                    )

                if ".." in file_path.parts:

                    raise HTTPException(
                        status_code=400,
                        detail="ZIP contains unsafe paths"
                    )

                if file_info.filename.startswith("/"):

                    raise HTTPException(
                        status_code=400,
                        detail="ZIP contains unsafe paths"
                    )

                unix_mode = file_info.external_attr >> 16

                if (unix_mode & 0o170000) == 0o120000:

                    raise HTTPException(
                        status_code=400,
                        detail="ZIP contains symbolic links"
                    )

                total_size += file_info.file_size

                if total_size > MAX_EXTRACTED_SIZE:

                    raise HTTPException(
                        status_code=400,
                        detail="ZIP extracted size exceeds 100 MB"
                    )

            return True

    except zipfile.BadZipFile:

        raise HTTPException(
            status_code=400,
            detail="Uploaded file is not a valid ZIP archive"
        )


# =========================================================
# ZIP EXTRACTION
# =========================================================

def extract_zip_safely(zip_file, destination):

    destination = Path(destination).resolve()

    zip_buffer = io.BytesIO(zip_file)

    with zipfile.ZipFile(zip_buffer, "r") as archive:

        for file_info in archive.infolist():

            target_path = (
                destination / file_info.filename
            ).resolve()

            if (
                not str(target_path).startswith(
                    str(destination) + os.sep
                )
                and target_path != destination
            ):

                raise HTTPException(
                    status_code=400,
                    detail="Unsafe file path detected"
                )

        archive.extractall(destination)


# =========================================================
# FILE HASH
# =========================================================

def calculate_file_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# =========================================================
# UPLOAD AND SCAN PROJECT
# =========================================================

@app.post("/api/upload")
async def upload_project(file: UploadFile = File(...)):

    connection = None
    cursor = None

    project_id = None
    scan_id = None
    extracted_folder = None

    try:

        # -------------------------------------------------
        # CHECK FILE TYPE
        # -------------------------------------------------

        if not file.filename or not file.filename.lower().endswith(".zip"):

            raise HTTPException(
                status_code=400,
                detail="Please upload a ZIP file"
            )

        zip_content = await file.read()

        validate_zip_file(zip_content)

        project_name = Path(file.filename).stem

        # -------------------------------------------------
        # DATABASE CONNECTION
        # -------------------------------------------------

        connection = get_connection()
        cursor = connection.cursor()

        # -------------------------------------------------
        # CREATE PROJECT
        # -------------------------------------------------

        cursor.execute("""
            INSERT INTO projects (
                project_name,
                project_description,
                project_type,
                source_type
            )
            VALUES (%s, %s, %s, %s)
        """, (
            project_name,
            "Uploaded project for security analysis",
            "SOURCE_CODE",
            "ZIP_UPLOAD"
        ))

        project_id = cursor.lastrowid

        connection.commit()

        # -------------------------------------------------
        # CREATE SCAN RECORD
        # -------------------------------------------------

        cursor.execute("""
            INSERT INTO scans (
                project_id,
                scan_name,
                scan_status,
                started_at
            )
            VALUES (%s, %s, %s, NOW())
        """, (
            project_id,
            f"Scan of {project_name}",
            "RUNNING"
        ))

        scan_id = cursor.lastrowid

        connection.commit()

        # -------------------------------------------------
        # EXTRACT PROJECT
        # -------------------------------------------------

        extracted_folder = (
            UPLOAD_DIR / f"project_{project_id}_scan_{scan_id}"
        )

        extracted_folder.mkdir(
            parents=True,
            exist_ok=True
        )

        extract_zip_safely(
            zip_content,
            extracted_folder
        )

        # -------------------------------------------------
        # RUN ORCHESTRATOR
        # -------------------------------------------------

        orchestrator = ScanOrchestrator()

        scan_result = orchestrator.scan_project(
            str(extracted_folder)
        )

        if scan_result.get("status") != "completed":

            raise Exception(
                scan_result.get(
                    "message",
                    "Security scan did not complete successfully"
                )
            )

        # -------------------------------------------------
        # GET SCAN RESULTS
        # -------------------------------------------------

        files = scan_result.get("files", [])
        findings = scan_result.get("findings", [])

        severity_counts = scan_result.get(
            "severity_counts",
            {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0
            }
        )

        files_scanned = scan_result.get(
            "files_scanned",
            0
        )

        total_findings = scan_result.get(
            "total_findings",
            len(findings)
        )

        security_score = scan_result.get(
            "security_score",
            100
        )

        # -------------------------------------------------
        # SAVE SCANNED FILES
        # -------------------------------------------------

        file_id_map = {}

        for scanned_file in files:

            if isinstance(scanned_file, dict):

                file_path = scanned_file.get(
                    "file_path",
                    scanned_file.get("path", "")
                )

            else:

                file_path = str(scanned_file)

            full_path = extracted_folder / file_path

            if not full_path.exists() or not full_path.is_file():
                continue

            file_extension = full_path.suffix

            file_size = full_path.stat().st_size

            file_hash = calculate_file_hash(full_path)

            cursor.execute("""
                INSERT INTO scan_files (
                    scan_id,
                    file_path,
                    file_extension,
                    file_size,
                    file_hash,
                    scan_status,
                    findings_count,
                    scanned_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (
                scan_id,
                str(file_path),
                file_extension,
                file_size,
                file_hash,
                "SCANNED",
                0
            ))

            file_id = cursor.lastrowid

            file_id_map[str(file_path)] = file_id

        connection.commit()

        # -------------------------------------------------
        # SAVE VULNERABILITIES
        # -------------------------------------------------

        file_findings_count = {}

        saved_fingerprints = set()

        saved_findings = []

        for finding in findings:

            file_path = finding.get("file_path", "")

            file_id = file_id_map.get(str(file_path))

            severity = finding.get(
                "severity",
                "LOW"
            ).upper()

            if severity not in [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
                "INFO"
            ]:

                severity = "LOW"

            title = finding.get(
                "title",
                "Security Finding"
            )

            vulnerability_type = finding.get(
                "vulnerability_type",
                title
            )

            description = finding.get(
                "description",
                "Potential security issue detected."
            )

            recommendation = finding.get(
                "recommendation",
                "Review this code and apply appropriate security practices."
            )

            line_number = finding.get("line_number")

            code_snippet = finding.get(
                "code_snippet",
                ""
            )

            impact = finding.get(
                "impact",
                description
            )

            confidence = finding.get(
                "confidence",
                "MEDIUM"
            ).upper()

            if confidence not in ["HIGH", "MEDIUM", "LOW"]:

                confidence = "MEDIUM"

            fingerprint = finding.get(
                "fingerprint",
                ""
            )

            # Generate fingerprint if missing
            if not fingerprint:

                fingerprint = hashlib.sha256(
                    (
                        str(file_path)
                        + str(line_number)
                        + str(title)
                    ).encode("utf-8")
                ).hexdigest()

            # Prevent duplicate fingerprints
            # within the same scan
            if fingerprint in saved_fingerprints:
                continue

            saved_fingerprints.add(fingerprint)

            owasp_category = finding.get(
                "owasp_category",
                "Unclassified"
            )

            owasp_id = finding.get(
                "owasp_id",
                ""
            )

            # INSERT IGNORE prevents database duplicate errors
            cursor.execute("""
                INSERT IGNORE INTO vulnerabilities (
                    scan_id,
                    file_id,
                    title,
                    vulnerability_type,
                    severity,
                    owasp_category,
                    owasp_id,
                    file_path,
                    line_number,
                    code_snippet,
                    description,
                    impact,
                    recommendation,
                    confidence,
                    status,
                    fingerprint
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """, (
                scan_id,
                file_id,
                title,
                vulnerability_type,
                severity,
                owasp_category,
                owasp_id,
                file_path,
                line_number,
                code_snippet,
                description,
                impact,
                recommendation,
                confidence,
                "OPEN",
                fingerprint
            ))

            # Only count findings actually inserted
            if cursor.rowcount > 0:

                file_findings_count[file_path] = (
                    file_findings_count.get(file_path, 0) + 1
                )

                saved_findings.append(finding)

        connection.commit()

        # -------------------------------------------------
        # RECALCULATE FINDING COUNTS
        # -------------------------------------------------

        total_findings = len(saved_findings)

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

        for finding in saved_findings:

            severity = finding.get(
                "severity",
                "LOW"
            ).upper()

            if severity in severity_counts:

                severity_counts[severity] += 1

        # -------------------------------------------------
        # UPDATE FILE FINDING COUNTS
        # -------------------------------------------------

        for file_path, findings_count in file_findings_count.items():

            file_id = file_id_map.get(file_path)

            if file_id:

                cursor.execute("""
                    UPDATE scan_files
                    SET findings_count = %s
                    WHERE file_id = %s
                """, (
                    findings_count,
                    file_id
                ))

        connection.commit()

        # -------------------------------------------------
        # UPDATE SCAN SUMMARY
        # -------------------------------------------------

        cursor.execute("""
            UPDATE scans
            SET
                scan_status = 'COMPLETED',
                security_score = %s,
                total_files = %s,
                files_scanned = %s,
                total_findings = %s,
                critical_count = %s,
                high_count = %s,
                medium_count = %s,
                low_count = %s,
                info_count = %s,
                completed_at = NOW()
            WHERE scan_id = %s
        """, (
            security_score,
            files_scanned,
            files_scanned,
            total_findings,
            severity_counts["CRITICAL"],
            severity_counts["HIGH"],
            severity_counts["MEDIUM"],
            severity_counts["LOW"],
            severity_counts["INFO"],
            scan_id
        ))

        connection.commit()

        # -------------------------------------------------
        # RETURN RESULT
        # -------------------------------------------------

        return {
            "status": "success",
            "message": "Project scanned successfully",
            "project_id": project_id,
            "project_name": project_name,
            "scan_id": scan_id,
            "files_scanned": files_scanned,
            "total_findings": total_findings,
            "security_score": security_score,
            "severity_counts": severity_counts,
            "findings": saved_findings
        }

    except HTTPException:

        raise

    except Exception as error:

        print("UPLOAD AND SCAN ERROR:", error)

        if connection and scan_id:

            try:

                cursor.execute("""
                    UPDATE scans
                    SET scan_status = 'FAILED',
                        completed_at = NOW()
                    WHERE scan_id = %s
                """, (scan_id,))

                connection.commit()

            except Exception:

                pass

        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(error)}"
        )

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# =========================================================
# VULNERABILITY REPORTS
# =========================================================

@app.get("/api/dashboard/vulnerabilities")
def get_vulnerability_reports(scan_id: int | None = None):

    connection = None
    cursor = None

    try:

        connection = get_connection()

        cursor = connection.cursor(dictionary=True)

        query = """
            SELECT
                v.vulnerability_id,
                v.scan_id,
                p.project_name,
                v.title,
                v.vulnerability_type,
                v.severity,
                v.owasp_category,
                v.owasp_id,
                v.file_path,
                v.line_number,
                v.code_snippet,
                v.description,
                v.impact,
                v.recommendation,
                v.confidence,
                v.status,
                v.detected_at
            FROM vulnerabilities v
            JOIN scans s
                ON v.scan_id = s.scan_id
            JOIN projects p
                ON s.project_id = p.project_id
        """

        if scan_id is not None:

            query += " WHERE v.scan_id = %s"

        query += """
            ORDER BY v.vulnerability_id DESC
            LIMIT 100
        """

        if scan_id is not None:

            cursor.execute(query, (scan_id,))

        else:

            cursor.execute(query)

        vulnerabilities = cursor.fetchall()

        return {
            "success": True,
            "total_findings": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }

    except Exception as error:

        print("Vulnerability Report Error:", error)

        return {
            "success": False,
            "message": str(error),
            "total_findings": 0,
            "vulnerabilities": []
        }

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()