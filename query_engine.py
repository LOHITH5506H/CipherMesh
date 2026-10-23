from __future__ import annotations
import json, os, re, urllib.request, urllib.error
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
VALID_FIELDS = {"PatientRef", "Age", "Cholesterol", "Diabetes", "SystolicBP"}
NUMERIC_FIELDS = {"Age": (18, 100, "years"), "Cholesterol": (110, 360, "mg/dL"), "SystolicBP": (80, 240, "mmHg")}

def load_env():
    for name in (".env", ".ENV"):
        p = ROOT / name
        if p.is_file():
            try:
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k, v = k.strip(), v.strip().strip('"').strip("'")
                        if k and k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass

load_env()

SYSTEM_PROMPT = """You are the Privacy Query Compiler for CipherMesh, a secure collaborative analytics system.
Participating hospitals hold synthetic patient datasets with the following schema:
- PatientRef (string, e.g. "PT-A-001")
- Age (integer, years, valid clinical bounds: 18 to 100)
- Cholesterol (integer, mg/dL, valid clinical bounds: 110 to 360)
- Diabetes (string, either "Yes" or "No")
- SystolicBP (integer, mmHg systolic blood pressure, valid clinical bounds: 80 to 240)

CipherMesh computes privacy-preserving aggregates across hospitals using Additive Secret Sharing, Shamir Secret Sharing, or Paillier Homomorphic Encryption.
Because cryptographic protocols can only add integer vectors across institutions, your job is to convert the user's natural language question into a structured JSON query plan.

Return a JSON object conforming strictly to this specification:
{
  "label": "Short human-readable query title (e.g. 'Average age of diabetic patients')",
  "result_label": "Label for the final combined aggregate (e.g. 'Combined average age')",
  "question": "Clarified query question",
  "context": "Short explanation of how local sites contribute protected values without sharing raw rows",
  "rule": "Summary of filters and clipping applied (e.g. 'Age clipped to 18-100; Diabetes == Yes')",
  "fields": ["List of dataset fields used, e.g. ['Age', 'Diabetes']"],
  "aggregation": "count" | "average" | "sum" | "rate",
  "target_field": "Age" | "Cholesterol" | "SystolicBP" | null,
  "bounds": [min_int, max_int] or null,
  "filters": [
    {
      "field": "Age" | "Cholesterol" | "Diabetes" | "SystolicBP",
      "op": "==" | "!=" | ">" | ">=" | "<" | "<=",
      "value": number or "Yes" or "No"
    }
  ],
  "rate_condition": {
    "field": "...",
    "op": "...",
    "value": "..."
  } or null,
  "unit": "years" | "mg/dL" | "mmHg" | "patients" | "%" | ""
}

Rules:
1. For 'count', target_field should be null. Unit is 'patients'.
2. For 'average' or 'sum', target_field MUST be one of 'Age', 'Cholesterol', 'SystolicBP'. Set appropriate bounds.
3. For 'rate', target_field is null, unit is '%', and rate_condition specifies which subset of the filtered cohort counts as positive.
4. ONLY reference the 5 allowed fields. Never hallucinate other columns.
5. Output ONLY valid raw JSON. No markdown code blocks, no explanations outside JSON.
"""

def compile_with_gemini(user_prompt: str, api_key: str | None = None) -> dict[str, Any]:
    """Compiles a user's natural language question into a structured query plan via Gemini API."""
    key = api_key or os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        raise ValueError("No Gemini API key provided. Set GEMINI_API_KEY or enter your key.")

    models = ["gemini-flash-latest"]
    last_err = None
    
    for model in models:
        endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": SYSTEM_PROMPT},
                        {"text": f"User question: {user_prompt}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json"
            }
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(endpoint, data=data, headers={"Content-Type": "application/json"})
        
        try:
            with urllib.request.urlopen(req, timeout=4) as resp:
                res_json = json.loads(resp.read().decode("utf-8"))
                candidates = res_json.get("candidates", [])
                if not candidates:
                    raise ValueError("No response candidate returned by Gemini.")
                text = candidates[0]["content"]["parts"][0]["text"].strip()
                if text.startswith("```"):
                    text = re.sub(r"^```(?:json)?\s*", "", text)
                    text = re.sub(r"\s*```$", "", text)
                spec = json.loads(text)
                spec["source"] = f"Gemini API ({model})"
                return validate_and_sanitize_spec(spec)
        except Exception as e:
            last_err = e
            continue

    raise RuntimeError(f"Gemini API call failed: {last_err}")

def local_rule_parser(prompt: str) -> dict[str, Any]:
    """Smart fallback NLP parser for clinical queries when no API key is available."""
    p = prompt.strip().lower()
    filters = []
    fields = []
    
    # 1. Detect Diabetes filters
    if any(w in p for w in ["non-diabetic", "without diabetes", "no diabetes", "diabetes=no", "diabetes: no"]):
        filters.append({"field": "Diabetes", "op": "==", "value": "No"})
        fields.append("Diabetes")
    elif any(w in p for w in ["diabetic", "with diabetes", "has diabetes", "have diabetes", "diabetes=yes", "diabetes: yes"]):
        if not ("prevalence of diabetes" in p or "diabetes rate" in p or "percentage of" in p):
            filters.append({"field": "Diabetes", "op": "==", "value": "Yes"})
            fields.append("Diabetes")


    # 2. Detect Age filters
    age_over = re.search(r"(?:age|older than|over|above|>=|>)\s*(\d{2})\s*(?:years|yrs|yo)?", p)
    age_under = re.search(r"(?:younger than|under|below|<=|<)\s*(\d{2})\s*(?:years|yrs|yo)?", p)
    if "seniors" in p or "elderly" in p:
        filters.append({"field": "Age", "op": ">=", "value": 60})
        fields.append("Age")
    elif age_over and not any(k in p for k in ["average age", "mean age"]):
        val = int(age_over.group(1))
        filters.append({"field": "Age", "op": ">=", "value": val})
        fields.append("Age")
    elif age_under and not any(k in p for k in ["average age", "mean age"]):
        val = int(age_under.group(1))
        filters.append({"field": "Age", "op": "<=", "value": val})
        fields.append("Age")

    # 3. Detect BP filters
    bp_over = re.search(r"(?:bp|blood pressure|systolic)\s*(?:>=|>|over|above|at or above)?\s*(\d{3})", p)
    if bp_over and not ("average bp" in p or "average systolic" in p):
        val = int(bp_over.group(1))
        filters.append({"field": "SystolicBP", "op": ">=", "value": val})
        fields.append("SystolicBP")
    elif "elevated bp" in p or "high blood pressure" in p or "hypertension" in p:
        filters.append({"field": "SystolicBP", "op": ">=", "value": 140})
        fields.append("SystolicBP")
    elif "normal bp" in p or "normal blood pressure" in p:
        filters.append({"field": "SystolicBP", "op": "<", "value": 120})
        fields.append("SystolicBP")

    # 4. Detect Cholesterol filters
    chol_over = re.search(r"(?:cholesterol)\s*(?:>=|>|over|above)?\s*(\d{3})", p)
    if chol_over and not ("average cholesterol" in p or "mean cholesterol" in p):
        val = int(chol_over.group(1))
        filters.append({"field": "Cholesterol", "op": ">=", "value": val})
        fields.append("Cholesterol")
    elif "high cholesterol" in p or "hypercholesterolemia" in p:
        filters.append({"field": "Cholesterol", "op": ">=", "value": 200})
        fields.append("Cholesterol")

    # 5. Determine Aggregation & Target Field
    if any(w in p for w in ["average", "mean", "avg"]):
        if any(w in p for w in ["cholesterol", "chol"]):
            target = "Cholesterol"
            fields.append("Cholesterol")
            unit = "mg/dL"
            bounds = [110, 360]
            label = "Average cholesterol"
        elif any(w in p for w in ["bp", "systolic", "blood pressure"]):
            target = "SystolicBP"
            fields.append("SystolicBP")
            unit = "mmHg"
            bounds = [80, 240]
            label = "Average systolic blood pressure"
        else:
            target = "Age"
            fields.append("Age")
            unit = "years"
            bounds = [18, 100]
            label = "Average age"
        
        spec = {
            "label": f"{label} (custom)",
            "result_label": f"Combined {label.lower()}",
            "question": prompt,
            "context": f"Sites compute bounded sum of {target} and matching patient count locally before collaborative aggregation.",
            "rule": f"{target} clipped to {bounds[0]}-{bounds[1]}; filters: {format_filters_rule(filters)}",
            "fields": list(dict.fromkeys(fields)),
            "aggregation": "average",
            "target_field": target,
            "bounds": bounds,
            "filters": filters,
            "rate_condition": None,
            "unit": unit,
            "source": "Local Natural Language Parser"
        }
        return validate_and_sanitize_spec(spec)

    elif any(w in p for w in ["rate", "prevalence", "percentage", "proportion", "%"]):
        if "bp" in p or "systolic" in p or "hypertension" in p:
            rate_cond = {"field": "SystolicBP", "op": ">=", "value": 140}
            name = "Elevated blood pressure"
        else:
            rate_cond = {"field": "Diabetes", "op": "==", "value": "Yes"}
            name = "Diabetes"
        fields.append(rate_cond["field"])
        spec = {
            "label": f"{name} prevalence (custom)",
            "result_label": f"Combined {name.lower()} prevalence",
            "question": prompt,
            "context": "Sites compute local positive matches and cohort size; protected counts are combined securely.",
            "rule": f"Rate of {name} in cohort; filters: {format_filters_rule(filters)}",
            "fields": list(dict.fromkeys(fields)),
            "aggregation": "rate",
            "target_field": None,
            "bounds": None,
            "filters": filters,
            "rate_condition": rate_cond,
            "unit": "%",
            "source": "Local Natural Language Parser"
        }
        return validate_and_sanitize_spec(spec)

    else:
        spec = {
            "label": "Custom patient count",
            "result_label": "Matching patients",
            "question": prompt,
            "context": "Sites locally count records matching criteria; protected counts are combined through privacy protocol.",
            "rule": f"Record count matching filters: {format_filters_rule(filters)}",
            "fields": list(dict.fromkeys(fields or ["PatientRef"])),
            "aggregation": "count",
            "target_field": None,
            "bounds": None,
            "filters": filters,
            "rate_condition": None,
            "unit": "patients",
            "source": "Local Natural Language Parser"
        }
        return validate_and_sanitize_spec(spec)

def format_filters_rule(filters: list[dict]) -> str:
    if not filters:
        return "All cohort records"
    return " AND ".join(f"{f['field']} {f['op']} {f['value']}" for f in filters)

def validate_and_sanitize_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Ensures that the compiled query spec is strictly safe and adheres to valid bounds and fields."""
    agg = spec.get("aggregation", "count")
    if agg not in {"count", "average", "sum", "rate"}:
        agg = "count"
    spec["aggregation"] = agg
    
    target = spec.get("target_field")
    if target and target not in NUMERIC_FIELDS:
        target = "Age"
    if agg in {"average", "sum"} and not target:
        target = "Age"
    spec["target_field"] = target
    
    if target:
        default_min, default_max, default_unit = NUMERIC_FIELDS[target]
        b = spec.get("bounds")
        if not b or not isinstance(b, (list, tuple)) or len(b) != 2:
            spec["bounds"] = [default_min, default_max]
        else:
            spec["bounds"] = [max(0, int(b[0])), max(int(b[0]) + 1, int(b[1]))]
        if not spec.get("unit"):
            spec["unit"] = default_unit
    elif agg == "rate":
        spec["unit"] = "%"
    elif not spec.get("unit"):
        spec["unit"] = "patients"

    sanitized_filters = []
    for f in spec.get("filters", []):
        field = f.get("field")
        op = f.get("op", "==")
        val = f.get("value")
        if field in VALID_FIELDS and op in {"==", "!=", ">", ">=", "<", "<="}:
            if field in NUMERIC_FIELDS:
                try: val = int(val)
                except (ValueError, TypeError): continue
            else:
                val = str(val).strip()
            sanitized_filters.append({"field": field, "op": op, "value": val})
    spec["filters"] = sanitized_filters

    rc = spec.get("rate_condition")
    if rc and isinstance(rc, dict):
        r_field = rc.get("field")
        r_op = rc.get("op", "==")
        r_val = rc.get("value")
        if r_field in VALID_FIELDS and r_op in {"==", "!=", ">", ">=", "<", "<="}:
            if r_field in NUMERIC_FIELDS:
                try: r_val = int(r_val)
                except (ValueError, TypeError): r_val = 0
            else:
                r_val = str(r_val).strip()
            spec["rate_condition"] = {"field": r_field, "op": r_op, "value": r_val}
        else:
            spec["rate_condition"] = None
    else:
        spec["rate_condition"] = None

    if not spec.get("label"): spec["label"] = "Custom Query"
    if not spec.get("result_label"): spec["result_label"] = spec["label"]
    if not spec.get("rule"): spec["rule"] = format_filters_rule(spec["filters"])
    if not spec.get("fields"):
        spec["fields"] = [f["field"] for f in spec["filters"]]
        if target and target not in spec["fields"]: spec["fields"].append(target)
    
    return spec

def check_condition(row: dict[str, str], cond: dict[str, Any]) -> bool:
    field = cond["field"]
    op = cond["op"]
    target_val = cond["value"]
    row_val = row.get(field, "").strip()

    if field in NUMERIC_FIELDS:
        try:
            num_row = int(row_val)
            num_target = int(target_val)
            if op == "==": return num_row == num_target
            if op == "!=": return num_row != num_target
            if op == ">": return num_row > num_target
            if op == ">=": return num_row >= num_target
            if op == "<": return num_row < num_target
            if op == "<=": return num_row <= num_target
        except ValueError:
            return False
    else:
        if field == "Diabetes":
            is_yes = row_val.lower() in {"yes", "1", "true"}
            target_is_yes = str(target_val).lower() in {"yes", "1", "true"}
            if op in {"==", "="}: return is_yes == target_is_yes
            if op in {"!=", "<>"}: return is_yes != target_is_yes
        else:
            if op == "==": return row_val == str(target_val)
            if op == "!=": return row_val != str(target_val)
    return False

def row_matches_filters(row: dict[str, str], filters: list[dict[str, Any]]) -> bool:
    return all(check_condition(row, f) for f in filters)

def evaluate_custom_local_contribution(spec: dict[str, Any], rows: list[dict[str, str]]) -> list[int]:
    """Evaluates the custom query spec locally at a hospital node, returning an integer vector for the MPC layer."""
    filtered = [r for r in rows if row_matches_filters(r, spec.get("filters", []))]
    agg = spec.get("aggregation", "count")

    if agg == "count":
        return [len(filtered)]

    elif agg == "average":
        target = spec["target_field"]
        low, high = spec.get("bounds", [0, 1000])
        val_sum = sum(min(high, max(low, int(r[target]))) for r in filtered)
        return [val_sum, len(filtered)]

    elif agg == "sum":
        target = spec["target_field"]
        low, high = spec.get("bounds", [0, 100000])
        val_sum = sum(min(high, max(low, int(r[target]))) for r in filtered)
        return [val_sum]

    elif agg == "rate":
        rc = spec.get("rate_condition")
        if rc:
            positive = sum(1 for r in filtered if check_condition(r, rc))
        else:
            positive = len(filtered)
        return [positive, len(filtered)]

    raise ValueError(f"Unsupported custom aggregation '{agg}'")

def format_custom_result(spec: dict[str, Any], vec: list[int]) -> dict[str, Any]:
    """Formats the reconstructed aggregate vector into display values and UI components."""
    agg = spec.get("aggregation", "count")
    unit = spec.get("unit", "")

    if agg == "count":
        cnt = int(vec[0])
        label = "patients" if cnt != 1 else "patient"
        return {
            "display": f"{cnt} {label}",
            "components": {"Aggregate count": cnt}
        }

    elif agg == "average":
        val_sum, count = vec[0], vec[1]
        avg = (val_sum / count) if count > 0 else 0.0
        return {
            "display": f"{avg:.1f} {unit}".strip(),
            "components": {
                f"Aggregate {spec.get('target_field', 'value')} sum": val_sum,
                "Cohort record count": count
            }
        }

    elif agg == "sum":
        val_sum = vec[0]
        return {
            "display": f"{val_sum:,} {unit}".strip(),
            "components": {f"Aggregate {spec.get('target_field', 'value')} total": val_sum}
        }

    elif agg == "rate":
        pos, total = vec[0], vec[1]
        pct = (100.0 * pos / total) if total > 0 else 0.0
        return {
            "display": f"{pct:.1f}%",
            "components": {
                "Positive matches": pos,
                "Cohort denominator": total
            }
        }

    return {"display": str(vec), "components": {"Vector": str(vec)}}

def parse_natural_language_query(prompt: str, api_key: str | None = None) -> dict[str, Any]:
    """Attempts to parse using Gemini API if key is available, else gracefully falls back to local NLP parser."""
    key = api_key or os.environ.get("GEMINI_API_KEY", "").strip()
    if key:
        try:
            return compile_with_gemini(prompt, key)
        except Exception as e:
            fallback = local_rule_parser(prompt)
            fallback["warning"] = f"Gemini API error ({e}). Successfully fell back to built-in local parser."
            return fallback
    return local_rule_parser(prompt)
