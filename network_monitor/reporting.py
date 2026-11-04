from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import HostSummary


def export_pdf(
    summaries: list[HostSummary],
    output_path: str | Path,
    period_hours: int = 24,
) -> None:
    if not 1 <= period_hours <= 720:
        raise ValueError("period_hours must be between 1 and 720.")
    document = SimpleDocTemplate(
        str(output_path),
        pagesize=landscape(letter),
        title="Network Monitor Report",
        author="Network Monitor",
    )
    styles = getSampleStyleSheet()
    elements = [
        Paragraph("Network Monitor Report", styles["Title"]),
        Paragraph(
            f"Generated {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} "
            f"(last {period_hours} hour(s))",
            styles["Normal"],
        ),
        Spacer(1, 16),
    ]
    rows = [
        [
            "Host",
            "Port",
            "Samples",
            "Successes",
            "Loss",
            "Avg latency",
            "Min latency",
            "Max latency",
        ]
    ]
    for summary in summaries:
        rows.append(
            [
                summary.address,
                str(summary.port),
                str(summary.samples),
                str(summary.successes),
                f"{summary.loss_percent:.1f}%",
                _format_ms(summary.average_ms),
                _format_ms(summary.minimum_ms),
                _format_ms(summary.maximum_ms),
            ]
        )
    table = Table(rows, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#18324b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d6dee7")),
                ("PADDING", (0, 0), (-1, -1), 7),
                ("ALIGN", (1, 1), (-1, -1), "RIGHT"),
            ]
        )
    )
    elements.append(table)
    if not summaries:
        elements.append(Paragraph("No hosts have been added yet.", styles["Normal"]))
    document.build(elements)


def _format_ms(value: float | None) -> str:
    return f"{value:.2f} ms" if value is not None else "N/A"
