from app.ai.validation import ValidationRow, render_validation_table, summarize_validation


def test_summarize_validation_counts_matches_and_accuracy():
    rows = [
        ValidationRow(
            domain="example.com",
            check="TLS certificate",
            our_result="pass",
            external_tool="SSL Labs",
            external_result="pass",
            matches=True,
        ),
        ValidationRow(
            domain="example.com",
            check="HSTS",
            our_result="missing",
            external_tool="securityheaders.com",
            external_result="pass",
            matches=False,
        ),
        ValidationRow(
            domain="example.com",
            check="DMARC",
            our_result="pass",
            external_tool="MXToolbox",
            external_result="missing",
            matches=False,
        ),
    ]

    summary = summarize_validation(rows)

    assert summary.total == 3
    assert summary.matches == 1
    assert summary.mismatches == 2
    assert summary.accuracy == 0.333
    assert summary.false_positives == 1
    assert summary.false_negatives == 1


def test_render_validation_table_outputs_markdown():
    rows = [
        ValidationRow(
            domain="example.com",
            check="TLS certificate",
            our_result="pass",
            external_tool="SSL Labs",
            external_result="pass",
            matches=True,
            notes="Both tools agree.",
        )
    ]

    table = render_validation_table(rows)

    assert "| Domain | Check | Our Result | External Tool | External Result | Match? | Notes |" in table
    assert "| example.com | TLS certificate | pass | SSL Labs | pass | yes | Both tools agree. |" in table
