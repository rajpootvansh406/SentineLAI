
class SecurityReviewAgent:

    def __init__(self):

        self.agent_name = "Security Review Agent"


    def review_findings(self, findings, severity_counts):

        total = len(findings)

        high_risk = (
            severity_counts.get("CRITICAL", 0)
            + severity_counts.get("HIGH", 0)
        )

        medium_risk = severity_counts.get("MEDIUM", 0)

        low_risk = severity_counts.get("LOW", 0)


        if total == 0:

            summary = (
                "No security findings were detected during this scan. "
                "This does not guarantee that the project is completely secure."
            )

            priority = "LOW"


        elif high_risk > 0:

            summary = (
                f"The scan detected {total} potential security issues, "
                f"including {high_risk} critical or high severity findings. "
                "These should be reviewed and addressed first."
            )

            priority = "HIGH"


        elif medium_risk > 0:

            summary = (
                f"The scan detected {total} potential security issues. "
                "Medium severity findings should be reviewed and fixed "
                "before deploying the project."
            )

            priority = "MEDIUM"


        else:

            summary = (
                f"The scan detected {total} low severity findings. "
                "Review the recommendations to improve security."
            )

            priority = "LOW"


        recommendations = []

        seen = set()


        for finding in findings:

            recommendation = finding.get(
                "recommendation",
                "Review this finding manually."
            )

            if recommendation not in seen:

                recommendations.append(recommendation)

                seen.add(recommendation)


        return {

            "agent": self.agent_name,

            "summary": summary,

            "priority": priority,

            "total_findings": total,

            "high_risk_findings": high_risk,

            "medium_risk_findings": medium_risk,

            "low_risk_findings": low_risk,

            "recommendations": recommendations[:10],

            "disclaimer":
                "Automated analysis may produce false positives "
                "or miss vulnerabilities. Manual review is recommended."

        }
