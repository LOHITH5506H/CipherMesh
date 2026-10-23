import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from crypto_protocol import execute_private_query, load_hospital_data
from query_engine import parse_natural_language_query, local_rule_parser, evaluate_custom_local_contribution, format_custom_result

DATA = Path(__file__).resolve().parents[1] / "data"

def datasets():
    d, e = load_hospital_data(DATA)
    assert not e
    return d

def test_natural_language_fallback_parser():
    q1 = local_rule_parser("What is the average age of patients with diabetes?")
    assert q1["aggregation"] == "average"
    assert q1["target_field"] == "Age"
    assert any(f["field"] == "Diabetes" and f["value"] == "Yes" for f in q1["filters"])

    q2 = local_rule_parser("How many patients have systolic blood pressure over 140?")
    assert q2["aggregation"] == "count"
    assert any(f["field"] == "SystolicBP" and f["op"] == ">=" and f["value"] == 140 for f in q2["filters"])

    q3 = local_rule_parser("What is the average cholesterol for patients older than 50?")
    assert q3["aggregation"] == "average"
    assert q3["target_field"] == "Cholesterol"
    assert any(f["field"] == "Age" and f["value"] == 50 for f in q3["filters"])

    q4 = local_rule_parser("Prevalence of diabetes in patients with high blood pressure")
    assert q4["aggregation"] == "rate"
    assert q4["rate_condition"]["field"] == "Diabetes"

def test_custom_query_across_all_cryptographic_protocols():
    d = datasets()
    prompt = "Average age of diabetic patients"
    spec = local_rule_parser(prompt)

    results = [execute_private_query("custom", d, p, custom_spec=spec) for p in ("additive", "shamir", "paillier")]

    # Verification: all 3 protocols must compute the exact same aggregate
    assert results[0]["result"]["display"] == results[1]["result"]["display"] == results[2]["result"]["display"]
    assert results[0]["result"]["components"] == results[1]["result"]["components"] == results[2]["result"]["components"]
    assert len(results[0]["packet_summary"]) == 9
    assert len(results[1]["packet_summary"]) == 9
    assert len(results[2]["packet_summary"]) == 3

def test_custom_count_query_across_protocols():
    d = datasets()
    spec = local_rule_parser("Count patients with systolic blood pressure >= 140")
    res_add = execute_private_query("custom", d, "additive", custom_spec=spec)
    res_sha = execute_private_query("custom", d, "shamir", custom_spec=spec)
    res_pai = execute_private_query("custom", d, "paillier", custom_spec=spec)

    assert res_add["result"]["display"] == res_sha["result"]["display"] == res_pai["result"]["display"]
    assert "patients" in res_add["result"]["display"]

def test_sanitization_and_bounds():
    from query_engine import validate_and_sanitize_spec
    bad_spec = {
        "aggregation": "unknown_agg",
        "target_field": "NonExistentField",
        "filters": [{"field": "Hacked", "op": "==", "value": "x"}],
        "bounds": [-50, 1000]
    }
    sanitized = validate_and_sanitize_spec(bad_spec)
    assert sanitized["aggregation"] == "count"
    assert sanitized["filters"] == []
