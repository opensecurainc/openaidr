"""Pinned scanner subprocess: unpaid local static checks and final scoring."""

import json
import socket
import sys


def main():
    import skillspector

    if skillspector.__version__ != "2.12.0":
        raise ValueError("Unsupported scanner interface")

    def no_network(*_args, **_kwargs):
        raise RuntimeError("Local static preparation has no network access")

    socket.socket.connect = socket.socket.connect_ex = socket.create_connection = no_network
    if sys.argv[1:] == ["score"]:
        from skillspector.models import Finding
        from skillspector.nodes.report import _compute_risk_score

        value = json.loads(sys.stdin.buffer.read((16 << 20) + 1))
        findings = []
        for issue in value["issues"]:
            location = issue.get("location") or {}
            findings.append(Finding(rule_id=issue["id"], finding_id=issue["finding_id"],
                message=issue.get("explanation") or issue.get("finding") or issue["id"],
                severity=issue["severity"], confidence=issue.get("confidence", .5),
                file=location.get("file") or "", start_line=location.get("start_line") or 1,
                end_line=location.get("end_line"), evidence=issue.get("evidence") or {},
                source_identity=issue.get("source_identity"), source_url=issue.get("source_url"),
                source_digest=issue.get("source_digest")))
        components = value["components"]
        score, _, _ = _compute_risk_score(findings, any(item.get("executable") for item in components), components)
        print(json.dumps({"score": score}))
        return

    from skillspector.inspection_ledger import LedgerReason
    from skillspector.nodes.analyzers import osv_client as osv, static_patterns_supply_chain as supply

    def deferred(packages, ecosystem, *, timeout_seconds=None, budget=None):
        limitation = osv.OsvQueryLimitation(reason=LedgerReason.ANALYZER_RUNTIME_ERROR,
                                           error_class="IntelligenceDeferredToSkillService")
        return osv.QueryBatchResults([[] for _ in packages], limitations=[limitation])

    osv.query_batch = supply.query_batch = deferred
    from skillspector.nodes import report as report_node

    original = report_node.report

    def report(state):
        result = original(state)
        sources = {}
        for event in state.get("inspection_ledger", []):
            if event.get("phase") == "static":
                for ident in event.get("emitted_finding_ids", []):
                    sources.setdefault(ident, set()).add(event.get("analyzer_id"))
        raw = json.loads(result["report_body"])
        raw["_local_sources"] = {ident: next(iter(values)) for ident, values in sources.items() if len(values) == 1}
        result["report_body"] = json.dumps(raw)
        return result

    report_node.report = report
    from skillspector.cli import app

    app()


if __name__ == "__main__":
    main()
