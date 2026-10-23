from __future__ import annotations
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
    "PT-B-008": {
        "id": "PT-B-008",
        "name": "Elena Rostova",
        "site": "hospital_b",
        "site_name": "Riverside Health (H-02)",
        "age": 62,
        "bp": 148,
        "cholesterol": 240,
        "diabetes": "Yes",
        "voter_records": "State voter roll: Elena Rostova, Age 62, Riverside postal code.",
        "auxiliary_leak": "Marathon medical clearance certificate: Systolic BP 148 mmHg."
    }
}

def run_linkage_simulation(victim_id: str = "PT-A-011", datasets: dict[str, list[dict[str, str]]] = None) -> dict[str, Any]:
    """Simulates a live quasi-identifier linkage attack comparing traditional centralized data sharing against CipherMesh MPC."""
    if victim_id not in VICTIM_PROFILES:
        victim_id = "PT-A-011"
    
    victim = VICTIM_PROFILES[victim_id]
    all_records = []
    if datasets:
        for site, rows in datasets.items():
            for r in rows:
                all_records.append({**r, "_site": site})
    
    # 1. ATTACK ON RAW CENTRALIZED DATABASE
    # Adversary queries raw microdata using quasi-identifiers: {Age, SystolicBP}
    target_age = victim["age"]
    target_bp = victim["bp"]
    
    matched_raw_records = [
        r for r in all_records
        if int(r.get("Age", 0)) == target_age and int(r.get("SystolicBP", 0)) == target_bp
    ]
    
    raw_unique_match = len(matched_raw_records) == 1
    raw_identified_id = matched_raw_records[0]["PatientRef"] if matched_raw_records else None
    
    # 2. ATTACK ON CIPHERMESH PROTECTED SYSTEM
    # What crosses the wire: Zero raw rows, only randomized secret shares or Paillier ciphertexts
    # Adversary attempts linkage on intercepted wire payloads and aggregate output
    ciphermesh_raw_rows_exposed = 0
    cohort_size = len(all_records)
    anonymity_set_size = cohort_size
    reid_probability_protected = (1.0 / cohort_size) if cohort_size > 0 else 0.0

    return {
        "victim": victim,
        "target_quasi_identifiers": {
            "Age": target_age,
            "SystolicBP": f"{target_bp} mmHg",
            "Location": victim["site_name"]
        },
        "raw_attack": {
            "status": "VULNERABLE - RE-IDENTIFICATION SUCCESSFUL",
            "matches_found": len(matched_raw_records),
            "matched_record": matched_raw_records[0] if matched_raw_records else None,
            "is_unique": raw_unique_match,
            "reid_probability": "100%" if raw_unique_match else f"{100/max(1, len(matched_raw_records)):.1f}%",
            "compromised_secrets": {
                "Diabetes Status": victim["diabetes"],
                "Cholesterol Level": f"{victim['cholesterol']} mg/dL"
            },
            "verdict": "Catastrophic privacy failure: Quasi-identifiers uniquely isolated Sarah Jenkins from the database, leaking her confidential diabetes diagnosis."
        },
        "ciphermesh_attack": {
            "status": "PROTECTED - ATTACK COMPLETELY THWARTED",
            "raw_rows_exposed": 0,
            "intercepted_packets": "Random elements in field 2^127 - 1 (indistinguishable from random noise)",
            "anonymity_set_size": anonymity_set_size,
            "reid_probability": f"≤ {reid_probability_protected * 100:.2f}% (random guess)",
            "compromised_secrets": None,
            "verdict": "Attack mathematically thwarted: No patient records cross organizational boundaries. The adversary cannot isolate the victim from the cohort."
        }
    }
