# SentinelAI – Agentic AI Security Scanner

SentinelAI is a Python-based security scanning platform designed to analyze source code and identify potential security vulnerabilities based on common OWASP security risks.

The project uses multiple specialized scanning agents to examine uploaded code, detect security issues, and generate vulnerability reports through a web-based dashboard.

## Features

- **Secrets Detection:** Identifies potential hardcoded passwords, API keys, and sensitive credentials.
- **Code Security Analysis:** Scans source code for common security weaknesses.
- **Dependency Analysis:** Checks project dependencies for potential security concerns.
- **Configuration Analysis:** Identifies potentially insecure configuration settings.
- **Security Review:** Combines security findings to provide an overall review.
- **Multi-Agent Architecture:** Uses an orchestrator to coordinate different security scanning agents.
- **Web Dashboard:** Displays scan statistics, recent scans, and detected vulnerabilities.
- **Vulnerability Reports:** Provides details about findings, severity levels, and recommendations.
- **ZIP File Upload:** Allows users to upload project files for security analysis.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development |
| FastAPI | REST API and application backend |
| MySQL | Database management |
| HTML | Frontend structure |
| CSS | Frontend styling |
| JavaScript | Frontend functionality |
| Uvicorn | ASGI server |
| Git & GitHub | Version control |

## Project Structure

```text
SentinelAI/
│
├── backend/
│   ├── agents/
│   │   ├── code_security_agent.py
│   │   ├── configuration_agent.py
│   │   ├── dependency_agent.py
│   │   ├── orchestrator.py
│   │   ├── secrets_agent.py
│   │   └── security_review_agent.py
│   │
│   ├── database.py
│   ├── main.py
│   └── __init__.py
│
├── frontend/
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css
│   │   └── js/
│   │       └── app.js
│   │
│   └── templates/
│       └── index.html
│
├── .gitignore
├── requirements.txt
└── README.md
```

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/rajpootvansh406/SentineLAI.git
```

### 2. Open the Project Folder

```bash
cd SentinaLAI
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure Environment Variables

Create a `.env` file in the project root directory.

Add your local MySQL database configuration:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=sentinelai_db
```

Replace the example password with your own local MySQL password.

**Important:** Never upload your `.env` file or actual database credentials to GitHub.

### 6. Configure the Database

Make sure MySQL is installed and running, and create the database:

```sql
CREATE DATABASE sentinelai_db;
```

Ensure the required application tables are created before running scans.

### 7. Start the Application

Run the following command from the project root:

```bash
uvicorn backend.main:app --reload
```

### 8. Open the Dashboard

Visit:

```text
http://127.0.0.1:8000
```

## How It Works

1. The user uploads a project ZIP file through the dashboard.
2. The backend extracts and processes the uploaded project files.
3. The scanning orchestrator coordinates the specialized security agents.
4. Each agent examines the relevant files for potential security issues.
5. Findings are stored in the MySQL database.
6. The dashboard displays scan results, severity levels, and recommendations.

## Security Focus

SentinelAI focuses on identifying potential vulnerabilities associated with common application security risks, including:

- Hardcoded credentials and exposed secrets.
- Insecure coding practices.
- Dependency-related security concerns.
- Unsafe configuration settings.
- Other common application security weaknesses.

## Current Project Status

**Development Status:** Working Local MVP

SentinelAI currently provides a multi-agent, rule-based security scanning workflow with a FastAPI backend, MySQL database, and interactive web dashboard.

The project is under active development, with further improvements planned for detection accuracy, reporting, and security analysis.

## Future Improvements

- Integration of AI-powered code analysis.
- Improved vulnerability detection accuracy.
- Expanded OWASP vulnerability coverage.
- PDF report generation.
- Additional programming language support.
- Improved dependency vulnerability intelligence.

## Disclaimer

SentinelAI is an educational and defensive security project. Its findings are intended to assist developers in identifying potential security weaknesses. Results should be manually reviewed and validated before making security decisions.

## Authors

**Vansh Ranot**  
**Ritika Sharma**

B.Tech Computer Science and Engineering (AI)  
Shoolini University

GitHub: [@rajpootvansh406](https://github.com/rajpootvansh406)

---

*SentinelAI – Making application security analysis more accessible to developers.*
