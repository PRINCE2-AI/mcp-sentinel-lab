from __future__ import annotations

from dataclasses import asdict

from app.demo import run_demo


def main() -> None:
    try:
        import streamlit as st
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("Streamlit is not installed. Run: pip install -r requirements.txt") from exc

    st.set_page_config(page_title="MCP Sentinel Lab", layout="wide")
    st.title("MCP Sentinel Lab")
    st.caption("Runtime security gateway and evaluation bench for tool-using AI agents.")

    data = run_demo()
    summary = data["summary"]
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Baseline attack success", f"{summary.baseline_attack_success_rate:.0%}")
    col2.metric("Protected attack success", f"{summary.protected_attack_success_rate:.0%}")
    col3.metric("Leakage block rate", f"{summary.leakage_block_rate:.0%}")
    col4.metric("Policy coverage", f"{summary.policy_coverage:.0%}")

    st.subheader("Case Results")
    st.dataframe([asdict(case) for case in summary.case_results], use_container_width=True)

    st.subheader("Manifest Scan Reports")
    scan_rows = []
    for name, report in data["scan_reports"].items():
        scan_rows.append(
            {
                "tool": name,
                "risk_score": report.risk_score,
                "risk_level": report.risk_level.value,
                "findings": ", ".join(f.rule_id for f in report.findings),
            }
        )
    st.dataframe(scan_rows, use_container_width=True)


if __name__ == "__main__":
    main()
