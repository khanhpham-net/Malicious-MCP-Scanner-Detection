"""Replay a development baseline and audit P coverage without running servers.

This is a development audit, not an official benchmark runner or blind-set
evaluator. SIM P mechanism fixtures and BEN labels are read from manifests.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
from importlib.metadata import version, PackageNotFoundError
import json
from pathlib import Path
import time

from mcp_scanner.models import ScanReport
from mcp_scanner.scanner import run_scan


def read_jsonl(path):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    keys = [(row["corpus"],row["sample_id"]) for row in rows]
    if len(keys)!=len(set(keys)):
        raise ValueError("Baseline contains duplicate corpus/sample identities.")
    return rows


def source_state():
    root = Path(__file__).resolve().parents[1]
    files = sorted((root/"src").rglob("*.py")) + [root/"pyproject.toml"]
    hashes = {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    dependencies = {}
    for name in ("tree-sitter","tree-sitter-javascript","tree-sitter-typescript","packaging"):
        try:
            dependencies[name]=version(name)
        except PackageNotFoundError:
            dependencies[name]=None
    return {"files":hashes,"dependencies":dependencies}


def summary(rows, baseline, labels):
    old = {(r["corpus"],r["sample_id"]):r["report"] for r in baseline}
    engines = defaultdict(Counter)
    codes = defaultdict(set)
    examples = defaultdict(list)
    fields = Counter()
    components = Counter()
    statuses = Counter()
    hashes, non_p, errors = [], [], []
    confusion = Counter({"tp":0,"fn":0,"fp":0,"tn":0})
    families = defaultdict(lambda: Counter({"samples":0,"flagged":0,"p_partial":0}))
    positive_misses, negative_flags = [], []
    for row in rows:
        key = row["corpus"],row["sample_id"]
        report = row["report"]
        prior = old[key]
        statuses[report["scan_status"]]+=1
        if report["input_provenance"]["snapshot_sha256"]!=prior["input_provenance"]["snapshot_sha256"]:
            hashes.append(list(key))
        ids = lambda r:sorted(f["finding_id"] for f in r["findings"] if f["category"]!="P")
        if ids(report)!=ids(prior):
            non_p.append(list(key))
        for engine in report["scanner"]["engines"]:
            engines[engine["name"]][engine["status"]]+=1
        for diagnostic in report["diagnostics"]:
            code = diagnostic.get("code","")
            if code.startswith("P_") and code!="P_OUTPUT_COVERAGE_SUMMARY":
                codes[code].add(key)
                if len(examples[code])<4:
                    examples[code].append({"sample_id":key[1],"location":diagnostic.get("location")})
            if code in {"P_ANALYSIS_ERROR","P_JS_ANALYSIS_ERROR"}:
                errors.append({"sample_id":key[1],"code":code})
            if code=="P_OUTPUT_COVERAGE_SUMMARY":
                for component in diagnostic.get("components",[]):
                    components[component["status"]]+=1
                    for issue in component["unresolved_fields"]:
                        fields[(issue["code"],issue["field_path"])]+=1
        hit = any(f["category"]=="P" for f in report["findings"])
        positive,family = labels[key]
        incomplete = any(v in {"partial","failed","unmeasured"} for k,v in report["coverage"]["surfaces"].items() if k.startswith("p_"))
        families[family]["samples"]+=1
        families[family]["flagged"]+=int(hit)
        families[family]["p_partial"]+=int(incomplete)
        if positive is True:
            confusion["tp" if hit else "fn"]+=1
            if not hit:
                positive_misses.append(key[1])
        elif positive is False:
            confusion["fp" if hit else "tn"]+=1
            if hit:
                negative_flags.append(key[1])
    return {
        "purpose":"development replay; not blind or paper-grade benchmark",
        "samples":len(rows),"overall_scan_status":dict(statuses),"engines":dict(engines),
        "hash_mismatches":hashes,"non_p_finding_changes":non_p,"p_analysis_errors":errors,
        "gap_sample_counts":{k:len(v) for k,v in sorted(codes.items())},
        "gap_examples":dict(examples),"component_status":dict(components),
        "gap_field_counts":[{"code":k[0],"field_path":k[1],"count":v} for k,v in fields.most_common()],
        "observed_confusion_against_fixture_labels":dict(confusion),
        "positive_misses":positive_misses,"negative_flags":negative_flags,"families":dict(families),
        "interpretation":[
            "P-positive SIM mechanism fixtures and BEN author labels are development expectations, not independently proven real-world intent.",
            "Non-P SIM families are excluded from the P confusion table.",
            "Partial samples stay in the denominator; no finding does not establish benignness.",
            "The confusion table is provisional where P coverage is incomplete.",
            "English rules remain the declared language scope; misses require manual review.",
            "Semgrep and OSV SCA are disabled to match the development baseline.",
        ],
    }


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline",type=Path,required=True)
    parser.add_argument("--dataset-root",type=Path,required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        baseline=read_jsonl(args.baseline)
        labels={}
        for corpus in ("MCP-SIM-100","MCP-BENIGN-160"):
            manifest=json.loads((args.dataset_root/corpus/"manifest.json").read_text(encoding="utf-8-sig"))
            samples=manifest["samples"]
            if len(samples)!=manifest["count"]:
                raise ValueError("Manifest count mismatch.")
            for item in samples:
                key=(corpus,item["sample_id"])
                if key in labels:
                    raise ValueError("Duplicate manifest sample.")
                family=item.get("family_id","BEN")
                positive=True if corpus=="MCP-SIM-100" and family.startswith("P") else (
                    False if corpus=="MCP-BENIGN-160" and item.get("label")=="benign" else None)
                labels[key]=(positive,family)
        expected=set(labels)
        if {(r["corpus"],r["sample_id"]) for r in baseline}!=expected:
            raise ValueError("Baseline and manifests must contain exactly the same sample identities.")
        paths={}
        for corpus,sid in expected:
            if Path(sid).name!=sid or sid in {".",".."}:
                raise ValueError("Invalid sample ID.")
            path=(args.dataset_root/corpus/"samples"/sid).resolve()
            root=(args.dataset_root/corpus/"samples").resolve()
            if root not in path.parents or not path.is_dir():
                raise ValueError("Sample path is missing or outside corpus.")
            paths[(corpus,sid)]=path
        output=args.output_dir.resolve()
        dataset=args.dataset_root.resolve()
        if output==dataset or dataset in output.parents:
            raise ValueError("Audit artifacts must be outside the dataset.")
        output.mkdir(parents=True,exist_ok=False)
        state=source_state()
        rows=[]
        started=time.monotonic()
        (output/"source-state.json").write_text(json.dumps(state,indent=2),encoding="utf-8")
        with (output/"results.jsonl").open("x",encoding="utf-8") as stream:
            for i,row in enumerate(baseline,1):
                key=row["corpus"],row["sample_id"]
                report=run_scan(paths[key],server_id=key[1],enable_semgrep=False,enable_sca=False).to_dict()
                ScanReport.from_dict(report)
                result={"corpus":key[0],"sample_id":key[1],"report":report}
                rows.append(result)
                stream.write(json.dumps(result,ensure_ascii=True)+"\n")
                stream.flush()
                if i%25==0:
                    print(f"Scanned {i}/{len(baseline)}",flush=True)
        report=summary(rows,baseline,labels)
        report.update(elapsed_seconds=time.monotonic()-started,baseline=str(args.baseline.resolve()),
                      source_unchanged=source_state()==state)
        (output/"audit-summary.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
        print(json.dumps({k:report[k] for k in ("samples","overall_scan_status","hash_mismatches",
            "non_p_finding_changes","p_analysis_errors","source_unchanged",
            "observed_confusion_against_fixture_labels")},indent=2))
        print(f"Saved audit: {output}",flush=True)
        return 2 if (report["hash_mismatches"] or report["non_p_finding_changes"] or
                     report["p_analysis_errors"] or not report["source_unchanged"]) else 0
    except (ValueError,OSError,KeyError,TypeError) as error:
        parser.error(str(error))


if __name__=="__main__":
    raise SystemExit(main())
