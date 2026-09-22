"""Offline forensic PDF report generator using ReportLab."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import HRFlowable, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from aegis_wm.schemas.alert import AlertRecord
from aegis_wm.schemas.explanation import ExplanationResult
from aegis_wm.schemas.forecast import ForecastTrajectory
from aegis_wm.schemas.job import AnalysisJob
from aegis_wm.schemas.labels import AttackStageEnum


class ForensicReportGenerator:
    """Generates comprehensive offline PDF forensic analysis reports."""

    def __init__(self, output_dir: Path | str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        job: AnalysisJob,
        trajectory: Optional[ForecastTrajectory] = None,
        explanation: Optional[ExplanationResult] = None,
        alerts: Optional[List[AlertRecord]] = None,
        output_filename: Optional[str] = None,
    ) -> Path:
        """Assembles and renders complete PDF report from stored analysis records."""
        fname = output_filename or f"AEGIS_Report_{job.job_id}.pdf"
        report_path = self.output_dir / fname

        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
            spaceAfter=12,
        )
        heading_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodyText",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
        badge_style = ParagraphStyle(
            "Badge",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.white,
            alignment=1,
        )

        elements = []

        # 1. Header & Metadata
        elements.append(Paragraph("AEGIS-WM: Anticipatory Forensic Analysis Report", title_style))
        elements.append(
            Paragraph(
                f"Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | "
                f"Analysis Identifier: <b>{job.job_id}</b>",
                subtitle_style,
            )
        )
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))

        # Provenance Summary Table
        provenance_data = [
            [Paragraph("<b>Source Telemetry</b>", body_style), Paragraph(job.filename, body_style)],
            [Paragraph("<b>File SHA-256 Hash</b>", body_style), Paragraph(f"<font size=7>{job.source_file_sha256}</font>", body_style)],
            [Paragraph("<b>Extraction Status</b>", body_style), Paragraph(job.status.value.upper(), body_style)],
            [Paragraph("<b>Extracted Flows</b>", body_style), Paragraph(str(job.total_flows_extracted), body_style)],
            [Paragraph("<b>Temporal Windows</b>", body_style), Paragraph(str(job.total_windows_generated), body_style)],
            [Paragraph("<b>Alerts Triggered</b>", body_style), Paragraph(str(job.total_alerts_generated), body_style)],
        ]
        prov_table = Table(provenance_data, colWidths=[150, 390])
        prov_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        elements.append(prov_table)
        elements.append(Spacer(1, 10))

        # 2. Anticipatory Risk Forecast
        if trajectory and trajectory.points:
            elements.append(Paragraph("Anticipatory Attack Forecast & Rollout Trajectory", heading_style))
            forecast_data = [
                [
                    Paragraph("<b>Horizon</b>", body_style),
                    Paragraph("<b>Timestamp</b>", body_style),
                    Paragraph("<b>Infiltration Risk</b>", body_style),
                    Paragraph("<b>95% CI</b>", body_style),
                    Paragraph("<b>Predicted Stage</b>", body_style),
                    Paragraph("<b>Risk Velocity</b>", body_style),
                ]
            ]
            for pt in trajectory.points:
                stg_name = AttackStageEnum.get_display_name(int(pt.predicted_stage))
                forecast_data.append([
                    Paragraph(f"T + {pt.horizon_step} ({pt.horizon_step * 5}s)", body_style),
                    Paragraph(datetime.fromtimestamp(pt.target_timestamp, timezone.utc).strftime("%H:%M:%S"), body_style),
                    Paragraph(f"<b>{pt.infiltration_probability * 100:.1f}%</b>", body_style),
                    Paragraph(f"[{pt.uncertainty_lower*100:.0f}% - {pt.uncertainty_upper*100:.0f}%]", body_style),
                    Paragraph(stg_name, body_style),
                    Paragraph(f"{pt.risk_velocity:+.2f}/s", body_style),
                ])

            fc_table = Table(forecast_data, colWidths=[80, 70, 95, 95, 120, 80])
            fc_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ])
            )
            elements.append(fc_table)
            elements.append(Spacer(1, 10))

        # 3. Explainability & Evidence
        if explanation:
            elements.append(Paragraph("Evidence-Based Attribution & Driving Telemetry", heading_style))

            # Top Features
            if explanation.top_features:
                feat_data = [
                    [
                        Paragraph("<b>Rank</b>", body_style),
                        Paragraph("<b>Telemetry Feature</b>", body_style),
                        Paragraph("<b>Attribution Weight</b>", body_style),
                        Paragraph("<b>Direction</b>", body_style),
                    ]
                ]
                for r_idx, f in enumerate(explanation.top_features[:5], start=1):
                    dir_color = "#dc2626" if f.direction == "increases_risk" else "#16a34a"
                    feat_data.append([
                        Paragraph(str(r_idx), body_style),
                        Paragraph(f.feature_name, body_style),
                        Paragraph(f"{f.relative_importance*100:.1f}% ({f.contribution:+.3f})", body_style),
                        Paragraph(f"<font color='{dir_color}'>{f.direction}</font>", body_style),
                    ])
                feat_table = Table(feat_data, colWidths=[40, 240, 130, 130])
                feat_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ])
                )
                elements.append(feat_table)
                elements.append(Spacer(1, 8))

            # Supporting Flows
            if explanation.supporting_flows:
                elements.append(Paragraph("Authentic Supporting Telemetry Flows (Driving Window)", heading_style))
                flow_data = [
                    [
                        Paragraph("<b>Source</b>", body_style),
                        Paragraph("<b>Destination</b>", body_style),
                        Paragraph("<b>Port</b>", body_style),
                        Paragraph("<b>Proto</b>", body_style),
                        Paragraph("<b>Packets</b>", body_style),
                        Paragraph("<b>Bytes</b>", body_style),
                    ]
                ]
                for fl in explanation.supporting_flows[:6]:
                    flow_data.append([
                        Paragraph(fl.src_ip_pseudo, body_style),
                        Paragraph(fl.dst_ip_pseudo, body_style),
                        Paragraph(str(fl.dst_port), body_style),
                        Paragraph("TCP" if fl.protocol == 6 else ("UDP" if fl.protocol == 17 else str(fl.protocol)), body_style),
                        Paragraph(str(fl.packets), body_style),
                        Paragraph(str(fl.bytes), body_style),
                    ])
                flow_table = Table(flow_data, colWidths=[120, 120, 60, 60, 80, 100])
                flow_table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ])
                )
                elements.append(flow_table)
                elements.append(Spacer(1, 10))

        # 4. Triggered Alerts
        if alerts:
            elements.append(Paragraph("Anticipatory Detection Alerts", heading_style))
            alert_data = [
                [
                    Paragraph("<b>Alert ID</b>", body_style),
                    Paragraph("<b>Severity</b>", body_style),
                    Paragraph("<b>Lead Time</b>", body_style),
                    Paragraph("<b>Risk</b>", body_style),
                    Paragraph("<b>Triggered Policy Rule</b>", body_style),
                ]
            ]
            for alt in alerts:
                sev_color = "#dc2626" if alt.severity.value == "critical" else "#d97706"
                alert_data.append([
                    Paragraph(alt.alert_id, body_style),
                    Paragraph(f"<font color='{sev_color}'><b>{alt.severity.value.upper()}</b></font>", body_style),
                    Paragraph(f"{alt.forecast_horizon_seconds:.0f}s ahead", body_style),
                    Paragraph(f"{alt.infiltration_probability * 100:.1f}%", body_style),
                    Paragraph(alt.policy_rule_triggered, body_style),
                ])
            alt_table = Table(alert_data, colWidths=[110, 80, 80, 70, 200])
            alt_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ])
            )
            elements.append(alt_table)
            elements.append(Spacer(1, 10))

        # 5. Limitations & Confidence Statement
        elements.append(Paragraph("Forensic Limitations & Methodological Safeguards", heading_style))
        limitation_text = (
            "<b>Scientific Methodology Notice:</b> AEGIS-WM provides probabilistic anticipatory decision support "
            "derived from temporal state-transition modeling. Forecasts reflect behavioral consistency based on "
            "observed telemetry and do not constitute absolute guarantees of zero-day exploitation. Network operators "
            "must correlate these findings with endpoint host logs before executing defensive remediation."
        )
        elements.append(Paragraph(limitation_text, body_style))

        doc.build(elements)
        logger.info(f"Generated Forensic PDF Report: {report_path}")
        return report_path
