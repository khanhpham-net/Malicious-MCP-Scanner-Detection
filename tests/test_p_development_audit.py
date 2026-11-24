"""Audit gates: preserve partial denominators and reject duplicate identities."""
import json

import pytest

from scripts.p_development_audit import read_jsonl, summary


def report(hit=False, partial=False):
    return {
        "input_provenance":{"snapshot_sha256":"same"},
        "scan_status":"partial" if partial else "complete",
        "scanner":{"engines":[{"name":"python_ast","status":"complete"}]},
        "coverage":{"surfaces":{"p_tool_result":"partial" if partial else "scanned"}},
        "findings":[{"category":"P","finding_id":"p"}] if hit else [],
        "diagnostics":[],
    }


def test_partial_cases_are_not_removed_from_observed_denominator():
    specs=[("P_WITH_GAP",True,True,True),("P_MISS",True,False,True),("BEN_CLEAR",False,False,True)]
    rows=[{"corpus":"fixture","sample_id":sid,"report":report(hit,gap)} for sid,_,hit,gap in specs]
    labels={("fixture",sid):(positive,"P" if positive else "BEN") for sid,positive,_,_ in specs}
    result=summary(rows,rows,labels)
    assert result["observed_confusion_against_fixture_labels"]=={"tp":1,"fn":1,"fp":0,"tn":1}
    assert result["families"]["P"]["p_partial"]==2
    assert result["overall_scan_status"]=={"partial":3}
    assert not result["hash_mismatches"] and not result["non_p_finding_changes"]


def test_non_p_sim_does_not_become_a_p_negative():
    rows=[{"corpus":"SIM","sample_id":"M01","report":report(hit=True)}]
    result=summary(rows,rows,{("SIM","M01"):(None,"M01")})
    assert sum(result["observed_confusion_against_fixture_labels"].values())==0


def test_duplicate_baseline_identity_is_rejected(tmp_path):
    row={"corpus":"fixture","sample_id":"same","report":report()}
    p=tmp_path/"baseline.jsonl"
    p.write_text(json.dumps(row)+"\n"+json.dumps(row)+"\n")
    with pytest.raises(ValueError,match="duplicate"):
        read_jsonl(p)
