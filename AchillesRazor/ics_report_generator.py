import json
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

class ICSReportGenerator:
    """
    AchillesRazor Report Generator
    Produces reports in multiple formats: JSON, HTML, Markdown, Console
    """

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "pass": 4, "info": 5}

    SEVERITY_COLORS = {
        "critical": "\033[41m\033[1m",  # Red background, bold
        "high": "\033[31m",            # Red
        "medium": "\033[33m",          # Yellow
        "low": "\033[34m",             # Blue
        "pass": "\033[32m",            # Green
        "info": "\033[36m",            # Cyan
        "error": "\033[91m",           # Bright Red
        "reset": "\033[0m",            # Reset
    }

    def __init__(self, target: str, checks: List[str] = None):
        self.target = target
        self.checks = checks or []
        self.results = []
        self.start_time = time.time()
        self.end_time = None

    def add_result(self, result: Dict[str, Any]) -> None:
        """Add a check result to the report"""
        self.results.append(result)

    def finish(self) -> None:
        """Mark the report as complete"""
        self.end_time = time.time()

    def _get_duration(self) -> float:
        """Get the total scan duration in seconds"""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    def _get_summary_stats(self) -> Dict[str, int]:
        """Get summary statistics of results"""
        stats = {
            "total": len(self.results),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "pass": 0,
            "error": 0,
            "warn": 0,
        }

        for result in self.results:
            severity = result.get("severity", "low")
            status = result.get("status", "info")

            if severity in stats:
                stats[severity] += 1

            # Track warnings/failures separately
            if status == "warn" or status == "fail":
                stats["warn"] += 1
            elif status == "error":
                stats["error"] += 1

        return stats

    def _get_severity_color(self, severity: str) -> str:
        """Get ANSI color code for a severity level"""
        return self.SEVERITY_COLORS.get(severity, self.SEVERITY_COLORS["reset"])

    def _format_details(self, details: str, max_length: int = 100) -> str:
        """Truncate details for console output"""
        if len(details) > max_length:
            return details[:max_length] + "..."
        return details

    # ======================================================================
    # Console Report
    # ======================================================================

    def to_console(self) -> str:
        """Generate a formatted console report"""
        stats = self._get_summary_stats()

        lines = []
        lines.append("=" * 80)
        lines.append("  OT/ICS SECURITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append(f"  Target:      {self.target}")
        lines.append(f"  Checks run:  {len(self.results)}")
        lines.append(f"  Duration:    {self._get_duration():.2f} seconds")
        lines.append(f"  Completed:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("-" * 80)
        lines.append("  SUMMARY")
        lines.append("-" * 80)
        lines.append(f"  {self.SEVERITY_COLORS['critical']}Critical{self.SEVERITY_COLORS['reset']}: {stats['critical']:>6}")
        lines.append(f"  {self.SEVERITY_COLORS['high']}High{self.SEVERITY_COLORS['reset']}:     {stats['high']:>6}")
        lines.append(f"  {self.SEVERITY_COLORS['medium']}Medium{self.SEVERITY_COLORS['reset']}:   {stats['medium']:>6}")
        lines.append(f"  {self.SEVERITY_COLORS['low']}Low{self.SEVERITY_COLORS['reset']}:      {stats['low']:>6}")
        lines.append(f"  {self.SEVERITY_COLORS['pass']}Pass{self.SEVERITY_COLORS['reset']}:      {stats['pass']:>6}")
        lines.append(f"  {self.SEVERITY_COLORS['info']}Info{self.SEVERITY_COLORS['reset']}:      {stats.get('info', 0):>6}")
        lines.append(f"  Errors:      {stats.get('error', 0):>6}")
        lines.append(f"  Warnings:    {stats.get('warn', 0):>6}")
        lines.append("-" * 80)

        # Detailed results
        if self.results:
            # Sort by severity (critical first)
            sorted_results = sorted(
                self.results,
                key=lambda x: self.SEVERITY_ORDER.get(x.get("severity", "low"), 99)
            )

            for result in sorted_results:
                severity = result.get("severity", "low")
                status = result.get("status", "info")
                name = result.get("name", "Unknown Check")
                details = result.get("details", "")
                recommendation = result.get("recommendation", "")

                # Color the severity
                color = self._get_severity_color(severity)
                status_icon = "✓" if status == "pass" else "✗" if status == "fail" else "⚠"

                lines.append(f"{color}[{severity.upper():<8}]{self.SEVERITY_COLORS['reset']} {status_icon} {name}")
                lines.append(f"    {self._format_details(details, 120)}")

                if recommendation and status in ("warn", "fail", "error"):
                    lines.append(f"    → {recommendation[:80]}{'...' if len(recommendation) > 80 else ''}")

                lines.append("")

        lines.append("=" * 80)
        lines.append("  End of Report")
        lines.append("=" * 80)

        return "\n".join(lines)

    # ======================================================================
    # JSON Report
    # ======================================================================

    def to_json(self, indent: int = 2) -> str:
        """Generate a JSON report"""
        stats = self._get_summary_stats()

        report = {
            "metadata": {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "duration": self._get_duration(),
                "checks_run": len(self.results),
            },
            "summary": stats,
            "results": self.results,
        }

        return json.dumps(report, indent=indent)

    # ======================================================================
    # Markdown Report
    # ======================================================================

    def to_markdown(self) -> str:
        """Generate a Markdown report"""
        stats = self._get_summary_stats()

        lines = []
        lines.append("# OT/ICS Security Scan Report")
        lines.append("")
        lines.append(f"**Target:** `{self.target}`")
        lines.append(f"**Completed:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Duration:** {self._get_duration():.2f} seconds")
        lines.append(f"**Checks Run:** {len(self.results)}")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Critical | {stats['critical']} |")
        lines.append(f"| High     | {stats['high']} |")
        lines.append(f"| Medium   | {stats['medium']} |")
        lines.append(f"| Low      | {stats['low']} |")
        lines.append(f"| Pass     | {stats['pass']} |")
        lines.append(f"| Errors   | {stats.get('error', 0)} |")
        lines.append(f"| Warnings | {stats.get('warn', 0)} |")
        lines.append("")
        lines.append("## Detailed Results")
        lines.append("")

        for result in self.results:
            severity = result.get("severity", "low")
            status = result.get("status", "info")
            name = result.get("name", "Unknown")
            details = result.get("details", "")
            recommendation = result.get("recommendation", "")

            status_icon = "✅" if status == "pass" else "❌" if status == "fail" else "⚠️"
            lines.append(f"### {status_icon} {name}")
            lines.append("")
            lines.append(f"- **Status:** `{status}`")
            lines.append(f"- **Severity:** `{severity}`")
            lines.append(f"- **Details:** {details}")
            if recommendation and status in ("warn", "fail", "error"):
                lines.append(f"- **Recommendation:** {recommendation}")
            lines.append("")

        return "\n".join(lines)

    # ======================================================================
    # HTML Report
    # ======================================================================

    def to_html(self) -> str:
        """Generate an HTML report"""
        stats = self._get_summary_stats()

        # Build results table rows
        rows = []
        for result in self.results:
            severity = result.get("severity", "low")
            status = result.get("status", "info")
            name = result.get("name", "Unknown")
            details = result.get("details", "")
            recommendation = result.get("recommendation", "")

            status_class = "pass" if status == "pass" else "fail" if status == "fail" else "warn"

            rows.append(f"""
                <tr class="severity-{severity} status-{status_class}">
                    <td class="severity">{severity.upper()}</td>
                    <td class="status">{status}</td>
                    <td class="name">{name}</td>
                    <td class="details">{details}</td>
                    <td class="recommendation">{recommendation if status in ('warn', 'fail', 'error') else ''}</td>
                </tr>
            """)

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OT/ICS Security Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 40px;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #1a1a2e;
            border-bottom: 3px solid #007acc;
            padding-bottom: 10px;
        }}
        .metadata {{
            background: #f0f4f8;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .summary-item {{
            padding: 15px;
            border-radius: 4px;
            text-align: center;
            font-weight: bold;
        }}
        .summary-item .count {{
            font-size: 28px;
        }}
        .summary-item.critical {{ background: #ffebee; color: #c62828; }}
        .summary-item.high {{ background: #ffcdd2; color: #e53935; }}
        .summary-item.medium {{ background: #fff3e0; color: #ef6c00; }}
        .summary-item.low {{ background: #e3f2fd; color: #0d47a1; }}
        .summary-item.pass {{ background: #e8f5e9; color: #2e7d32; }}
        .summary-item.errors {{ background: #fce4ec; color: #880e4f; }}
        .summary-item.warnings {{ background: #fff8e1; color: #f57f17; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th {{
            background: #1a1a2e;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        td {{
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .severity-critical {{ border-left: 4px solid #c62828; }}
        .severity-high {{ border-left: 4px solid #e53935; }}
        .severity-medium {{ border-left: 4px solid #ef6c00; }}
        .severity-low {{ border-left: 4px solid #0d47a1; }}
        .severity-pass {{ border-left: 4px solid #2e7d32; }}
        .status-pass .status {{ color: #2e7d32; font-weight: bold; }}
        .status-fail .status {{ color: #c62828; font-weight: bold; }}
        .status-warn .status {{ color: #ef6c00; font-weight: bold; }}
        .status-pass .status::before {{ content: "✅ "; }}
        .status-fail .status::before {{ content: "❌ "; }}
        .status-warn .status::before {{ content: "⚠️ "; }}
        .details {{ max-width: 400px; word-break: break-word; }}
        .recommendation {{ max-width: 350px; color: #0d47a1; font-style: italic; }}
        .footer {{
            margin-top: 30px;
            text-align: center;
            color: #888;
            font-size: 12px;
            border-top: 1px solid #ddd;
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 OT/ICS Security Scan Report</h1>

        <div class="metadata">
            <strong>Target:</strong> <code>{self.target}</code><br>
            <strong>Completed:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Duration:</strong> {self._get_duration():.2f} seconds<br>
            <strong>Checks Run:</strong> {len(self.results)}
        </div>

        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-item critical"><div class="count">{stats['critical']}</div>Critical</div>
            <div class="summary-item high"><div class="count">{stats['high']}</div>High</div>
            <div class="summary-item medium"><div class="count">{stats['medium']}</div>Medium</div>
            <div class="summary-item low"><div class="count">{stats['low']}</div>Low</div>
            <div class="summary-item pass"><div class="count">{stats['pass']}</div>Pass</div>
            <div class="summary-item errors"><div class="count">{stats.get('error', 0)}</div>Errors</div>
            <div class="summary-item warnings"><div class="count">{stats.get('warn', 0)}</div>Warnings</div>
        </div>

        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Check</th>
                    <th>Details</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>

        <div class="footer">
            AchillesRazor v1.0.0 | Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
</body>
</html>
        """

        return html

    # ======================================================================
    # Save Methods
    # ======================================================================

    def save_console(self, filepath: str) -> None:
        """Save console report to file"""
        with open(filepath, "w") as f:
            f.write(self.to_console())

    def save_json(self, filepath: str) -> None:
        """Save JSON report to file"""
        with open(filepath, "w") as f:
            f.write(self.to_json())

    def save_markdown(self, filepath: str) -> None:
        """Save Markdown report to file"""
        with open(filepath, "w") as f:
            f.write(self.to_markdown())

    def save_html(self, filepath: str) -> None:
        """Save HTML report to file"""
        with open(filepath, "w") as f:
            f.write(self.to_html())


# ======================================================================
# Convenience Functions
# ======================================================================

def create_report(target: str, results: List[Dict[str, Any]], output_format: str = "console") -> str:
    """
    Quick helper to create a report from a list of results
    """
    generator = ICSReportGenerator(target)
    for result in results:
        generator.add_result(result)
    generator.finish()

    if output_format == "json":
        return generator.to_json()
    elif output_format == "markdown":
        return generator.to_markdown()
    elif output_format == "html":
        return generator.to_html()
    else:
        return generator.to_console()


def save_report(target: str, results: List[Dict[str, Any]], filepath: str, format: str = "console") -> None:
    """
    Quick helper to save a report to file
    """
    generator = ICSReportGenerator(target)
    for result in results:
        generator.add_result(result)
    generator.finish()

    if format == "json":
        generator.save_json(filepath)
    elif format == "markdown":
        generator.save_markdown(filepath)
    elif format == "html":
        generator.save_html(filepath)
    else:
        generator.save_console(filepath)