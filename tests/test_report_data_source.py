"""
Tests for report data source labeling.
"""

import json

from libp2p_privacy_poc.privacy_analyzer import PrivacyReport
from libp2p_privacy_poc.report_generator import ReportGenerator


def test_console_report_includes_data_source():
    report = PrivacyReport(timestamp=0.0, overall_risk_score=0.0)
    report_gen = ReportGenerator()

    console = report_gen.generate_console_report(
        report,
        data_source="SIMULATED",
    )

    assert "Data Source: SIMULATED" in console


def test_json_report_includes_data_source():
    report = PrivacyReport(timestamp=0.0, overall_risk_score=0.0)
    report_gen = ReportGenerator()

    json_report = report_gen.generate_json_report(
        report,
        data_source="REAL",
    )
    data = json.loads(json_report)

    assert data["data_source"] == "REAL"


def test_html_report_includes_data_source():
    report = PrivacyReport(timestamp=0.0, overall_risk_score=0.0)
    report_gen = ReportGenerator()

    html_report = report_gen.generate_html_report(
        report,
        data_source="SIMULATED",
    )

    assert "Data Source:" in html_report
    assert "SIMULATED" in html_report
