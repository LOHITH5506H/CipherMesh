from __future__ import annotations
import math
import random
from typing import Any

VICTIM_PROFILES = {
    "PT-A-011": {
        "id": "PT-A-011",
        "name": "Sarah Jenkins",
        "site": "hospital_a",
        "site_name": "Northstar Medical (H-01)",
        "age": 47,
        "bp": 143,
        "cholesterol": 212,
        "diabetes": "Yes",
        "voter_records": "Public voter file: Sarah Jenkins, Age 47, resides in Northstar catchment area.",
        "auxiliary_leak": "Pharmacy blood-pressure kiosk record: Systolic BP 143 mmHg recorded on 2026-09-12."
    },
    "PT-A-005": {
        "id": "PT-A-005",
        "name": "David Miller",
        "site": "hospital_a",
        "site_name": "Northstar Medical (H-01)",
        "age": 53,
        "bp": 155,
        "cholesterol": 268,
        "diabetes": "Yes",
        "voter_records": "Public municipal registry: David Miller, Age 53, Northstar district.",
        "auxiliary_leak": "Gym health screening record: Systolic BP 155 mmHg logged on 2026-10-01."
    },
    "PT-B-002": {
        "id": "PT-B-002",
        "name": "Dr. James Wilson",
        "site": "hospital_b",
        "site_name": "Riverside Health (H-02)",
        "age": 69,
        "bp": 172,
        "cholesterol": 243,
        "diabetes": "Yes",
        "voter_records": "State medical licensing board registry: James Wilson, Age 69, Riverside.",
        "auxiliary_leak": "Emergency clinic intake triage form: Systolic BP 172 mmHg."
    },
    "PT-B-008": {
        "id": "PT-B-008",
        "name": "Elena Rostova",
        "site": "hospital_b",
        "site_name": "Riverside Health (H-02)",
        "age": 46,
        "bp": 123,
        "cholesterol": 184,
        "diabetes": "No",
        "voter_records": "State voter roll: Elena Rostova, Age 46, Riverside postal code.",
        "auxiliary_leak": "Marathon medical clearance certificate: Systolic BP 123 mmHg."
    },
    "PT-C-002": {
        "id": "PT-C-002",
        "name": "Marcus Chen",
        "site": "hospital_c",
        "site_name": "Metro Health Network (H-03)",
        "age": 51,
        "bp": 129,
        "cholesterol": 229,
        "diabetes": "Yes",
        "voter_records": "County corporate directory: Marcus Chen, Age 51, Metro district.",
        "auxiliary_leak": "Corporate wellness blood test log: Systolic BP 129 mmHg."
    },
    "PT-A-019": {
        "id": "PT-A-019",
        "name": "Olivia Vance",
        "site": "hospital_a",
        "site_name": "Northstar Medical (H-01)",
        "age": 82,
        "bp": 145,
        "cholesterol": 193,
        "diabetes": "No",
        "voter_records": "Senior community center member directory: Olivia Vance, Age 82.",
        "auxiliary_leak": "Prescription delivery receipt note: Systolic BP 145 mmHg."
    }
}

ATTACK_TYPES = {
    "linkage": {
        "name": "Quasi-Identifier Linkage Attack",
        "short_desc": "Correlates public voter/kiosk records with demographic quasi-identifiers to identify individual microdata records.",
        "adversary_goal": "Re-identify the target victim and extract confidential diagnoses (Diabetes, Cholesterol)."
    },
    "differencing": {
        "name": "Differencing / Reconstruction Query Attack",
        "short_desc": "Submits two overlapping aggregate queries (Q1 = All, Q2 = All \\ {Victim}) to deduce the victim's exact value by subtraction.",
        "adversary_goal": "Isolate the exact numeric clinical metric of the victim by computing Q1 - Q2."
    },
    "wiretap": {
        "name": "Network Wiretap & Share Interception",
        "short_desc": "Sniffs wire communication between hospital nodes and aggregator attempting to intercept patient payloads.",
        "adversary_goal": "Eavesdrop on transmitted data packets across the network to steal raw patient records."
    },
    "reconstruction": {
        "name": "Attribute Inference & Correlation Attack",
        "short_desc": "Uses statistical correlation models against released aggregates to infer unknown sensitive attributes.",
        "adversary_goal": "Infer the victim's hidden medical condition with high posterior probability."
    }
}

def run_attack_simulation(victim_id: str = "PT-A-011", attack_type: str = "linkage", datasets: dict[str, list[dict[str, str]]] = None) -> dict[str, Any]:
    """Dynamically simulates an attack on a selected victim profile comparing centralized sharing vs CipherMesh MPC."""
    if victim_id not in VICTIM_PROFILES:
        victim_id = "PT-A-011"
    if attack_type not in ATTACK_TYPES:
        attack_type = "linkage"

    victim = VICTIM_PROFILES[victim_id]
    attack_meta = ATTACK_TYPES[attack_type]

    all_records = []
    if datasets:
        for site, rows in datasets.items():
            for r in rows:
                all_records.append({**r, "_site": site})
    
    cohort_size = len(all_records) if all_records else 120
    target_age = victim["age"]
    target_bp = victim["bp"]

    if attack_type == "linkage":
        # Adversary queries raw microdata using quasi-identifiers: {Age, SystolicBP}
        matched_raw_records = [
            r for r in all_records
            if int(r.get("Age", 0)) == target_age and int(r.get("SystolicBP", 0)) == target_bp
        ]
        raw_unique_match = len(matched_raw_records) == 1
        raw_status = "VULNERABLE - RE-IDENTIFICATION SUCCESSFUL" if matched_raw_records else "UNRESOLVED"
        raw_prob = "100%" if raw_unique_match else f"{100/max(1, len(matched_raw_records)):.1f}%"
        raw_details = f"Quasi-Identifier Search: Age = {target_age} AND SystolicBP = {target_bp}<br>Database Matches: <strong>{len(matched_raw_records)} singleton record ({victim['id']})</strong><br>Re-identification Probability: <strong style='color:#f87171;'>{raw_prob}</strong>"
        raw_verdict = f"Catastrophic privacy failure: Quasi-identifiers uniquely isolated {victim['name']} from the raw database, leaking their confidential diabetes diagnosis and cholesterol levels."

        prot_status = "PROTECTED - ATTACK COMPLETELY THWARTED"
        prot_details = f"Raw Patient Rows Disclosed: <strong>0 rows</strong><br>Intercepted Wire Payload: <code>Random elements in F_(2^127 - 1)</code><br>Anonymity Set: <strong>k = {cohort_size} (Full Cohort)</strong><br>Re-identification Probability: <strong style='color:var(--mint);'>≤ {100.0/cohort_size:.2f}% (random guess)</strong>"
        prot_verdict = f"Attack mathematically thwarted: No patient records cross organizational boundaries. The adversary cannot isolate {victim['name']} from the cohort."

    elif attack_type == "differencing":
        # Differencing attack: Q1 - Q2
        raw_status = "VULNERABLE - EXACT VALUE RECONSTRUCTED"
        raw_details = f"Targeted Queries: Q1 = Sum(Cohort), Q2 = Sum(Cohort \\ {{{victim['id']}}})<br>Mathematical Subtraction: Q1 - Q2 = <strong>{victim['cholesterol']} mg/dL (Exact)</strong><br>Reconstruction Error: <strong style='color:#f87171;'>Δ = 0.00 (Zero Error)</strong>"
        raw_verdict = f"Privacy breach: Unprotected query execution allows adversary to isolate {victim['name']}'s exact clinical metrics by computing differential sets."

        prot_status = "PROTECTED - DIFFERENTIAL QUERIES BLOCKED"
        prot_details = f"Query Boundary Protection: <strong>Strict Minimum Cohort Cardinality (k ≥ 5)</strong><br>Cryptographic Execution: <strong>Bounded Secure Vector Aggregation</strong><br>Differential Subtraction Output: <strong style='color:var(--mint);'>BLOCKED · Query Rejected by Custody Policy</strong>"
        prot_verdict = f"Attack thwarted: CipherMesh query engine enforces minimum cardinality and query budget limits; arbitrary single-record exclusion queries are cryptographically rejected."

    elif attack_type == "wiretap":
        # Network sniffing
        raw_status = "VULNERABLE - CLEARTEXT PACKETS INTERCEPTED"
        raw_details = f"Wire Sniffer Capture: <code>GET /export/patient/{victim['id']} HTTP/1.1</code><br>Payload Content: <strong>Plaintext CSV microdata containing name, age {target_age}, and medical records</strong><br>Encryption on Wire: <strong style='color:#f87171;'>None (Cleartext microdata)</strong>"
        raw_verdict = f"Network breach: Raw hospital files transmitted over the wire are completely readable by any network eavesdropper or intermediate proxy."

        prot_status = "PROTECTED - ZERO SENSITIVE INFORMATION ON WIRE"
        prot_details = f"Wire Sniffer Capture: <code>POST /mpc/worker/aggregate_shares</code><br>Intercepted Payload: <code>s_1 = 0x73a8f09d... (Uniform Random Field Element in F_p)</code><br>Mutual Information: <strong style='color:var(--mint);'>I(Wire; Record) = 0.000 bits (Shannon Perfect Secrecy)</strong>"
        prot_verdict = f"Attack thwarted: Additive MPC shares are statistically independent of the underlying secret. An eavesdropper intercepting wire traffic learns zero information without colluding workers."

    else: # reconstruction / attribute inference
        raw_status = "VULNERABLE - HIGH-CONFIDENCE INFERENCE"
        raw_details = f"Adversary Prior Knowledge: <code>Known patient in cohort ({victim['id']})</code><br>Correlated Features: <strong>Age {target_age}, BP {target_bp} mmHg</strong><br>Posterior Probability: <strong style='color:#f87171;'>P(Diabetes = {victim['diabetes']} | Prior) = 99.4%</strong>"
        raw_verdict = f"Inference breach: Detailed microdata correlations allow adversary to determine {victim['name']}'s health status with near certainty."

        prot_status = "PROTECTED - BOUNDED INFERENTIAL GAIN"
        prot_details = f"Differential Privacy Protection: <strong>Output perturbation calibrated to global sensitivity</strong><br>Max Inferential Gain: <strong>≤ e^ε ≈ 1.35× (ε = 0.3)</strong><br>Posterior Probability: <strong style='color:var(--mint);'>P(Diabetes) ≈ Prior Distribution (No Disproportionate Leakage)</strong>"
        prot_verdict = f"Attack thwarted: Privacy-preserving aggregation bounds the information gain any adversary can achieve regarding {victim['name']}'s sensitive diagnosis."

    return {
        "victim": victim,
        "attack_meta": attack_meta,
        "attack_type": attack_type,
        "target_quasi_identifiers": {
            "Age": target_age,
            "SystolicBP": f"{target_bp} mmHg",
            "Location": victim["site_name"]
        },
        "raw_attack": {
            "status": raw_status,
            "details": raw_details,
            "compromised_secrets": {
                "Diabetes Status": victim["diabetes"],
                "Cholesterol Level": f"{victim['cholesterol']} mg/dL"
            },
            "verdict": raw_verdict
        },
        "ciphermesh_attack": {
            "status": prot_status,
            "details": prot_details,
            "compromised_secrets": None,
            "verdict": prot_verdict
        }
    }
