import io, sys, urllib.parse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import app

def make_environ(path="/", method="GET", form_data=None):
    body = b""
    if form_data:
        body = urllib.parse.urlencode(form_data).encode("utf-8")
    environ = {
        "PATH_INFO": path,
        "REQUEST_METHOD": method,
        "CONTENT_LENGTH": str(len(body)),
        "wsgi.input": io.BytesIO(body),
    }
    return environ

def start_response(status, headers):
    pass

def test_home_page():
    res = app(make_environ("/"), start_response)
    html = b"".join(res).decode("utf-8")
    assert "CipherMesh" in html
    assert "Ask in Plain English" in html
    assert "Standard Preset Queries" in html

def test_static_css():
    res = app(make_environ("/static/style.css"), start_response)
    css = b"".join(res).decode("utf-8")
    assert "mode-tabs" in css

def test_run_natural_language_query_post():
    form = {
        "mode": "nl",
        "prompt": "What is the average age of patients with diabetes?",
        "protocol": "additive",
        "integrity": "yes",
    }
    res = app(make_environ("/run", method="POST", form_data=form), start_response)
    html = b"".join(res).decode("utf-8")
    assert "RUN COMPLETE" in html
    assert "PRIVACY COMPILATION PLAN" in html
    assert "mg/dL" in html or "years" in html or "patients" in html


def test_run_preset_query_post():
    form = {
        "mode": "preset",
        "query": "elevated_bp_count",
        "protocol": "shamir",
        "integrity": "yes",
    }
    res = app(make_environ("/run", method="POST", form_data=form), start_response)
    html = b"".join(res).decode("utf-8")
    assert "RUN COMPLETE" in html
    assert "Shamir threshold sharing" in html

def test_tabs_presence():
    res = app(make_environ("/"), start_response)
    html = b"".join(res).decode("utf-8")
    assert "id=\"nav-landing\"" in html
    assert "id=\"nav-custody\"" in html
    assert "id=\"nav-compute\"" in html
    assert "id=\"nav-attack\"" in html
    assert "id=\"nav-integrity\"" in html
    assert "id=\"nav-security\"" in html
    assert "id=\"sec-landing\"" in html
    assert "id=\"sec-custody\"" in html
    assert "id=\"sec-compute\"" in html
    assert "id=\"sec-attack\"" in html
    assert "id=\"sec-integrity\"" in html
    assert "id=\"sec-security\"" in html

def test_diff_and_fidelity_table():
    res = app(make_environ("/"), start_response)
    html = b"".join(res).decode("utf-8")
    assert "diff-wrap" in html
    assert "STATISTICAL UTILITY ANALYSIS" in html
    assert "Query Fidelity:" in html
    assert "Absolute Difference" in html
    assert "Response With Cryptography" in html
    assert "Same Query Output Without Cryptography" in html

def test_query_diff_on_custom_query_post():
    form = {
        "mode": "nl",
        "prompt": "What is the average age of patients with diabetes?",
        "protocol": "additive",
        "integrity": "yes",
    }
    res = app(make_environ("/run", method="POST", form_data=form), start_response)
    html = b"".join(res).decode("utf-8")
    assert "Response With Cryptography (CipherMesh)" in html
    assert "Same Query Output Without Cryptography" in html
    assert "53.2 years" in html


def test_attack_simulation_standby_and_execution():
    # 1. Standby state before user triggers
    res = app(make_environ("/"), start_response)
    html = b"".join(res).decode("utf-8")
    assert "attack-box" in html
    assert "Sarah Jenkins" in html
    assert "David Miller" in html
    assert "Elena Rostova" in html
    assert "Dr. James Wilson" in html
    assert "Marcus Chen" in html
    assert "Olivia Vance" in html
    assert "Execute Live Attack Simulation" in html
    assert "Simulation Standby" in html

    # 2. Execution when user triggers simulation
    form = {
        "victim": "PT-A-011",
        "attack_type": "linkage"
    }
    res_sim = app(make_environ("/simulate-attack", method="POST", form_data=form), start_response)
    html_sim = b"".join(res_sim).decode("utf-8")
    assert "LIVE SIMULATION COMPLETED" in html_sim
    assert "VULNERABLE - RE-IDENTIFICATION SUCCESSFUL" in html_sim
    assert "PROTECTED - ATTACK COMPLETELY THWARTED" in html_sim
    assert "Sarah Jenkins" in html_sim

def test_data_custody_shows_20_rows_by_default():
    res = app(make_environ("/"), start_response)
    html = b"".join(res).decode("utf-8")
    assert "20 records displayed by default" in html
    assert "PT-A-020" in html
    assert "PT-B-020" in html
    assert "PT-C-020" in html

def test_security_model_tab_removed_previous_section():
    res = app(make_environ("/"), start_response)
    html = b"".join(res).decode("utf-8")
    assert "What this prototype does and does not promise" not in html
    assert "CRYPTOGRAPHIC ARCHITECTURE VERIFICATION" in html
    assert "Additive Secret Sharing MPC" in html
    assert "Shamir (2-of-3) Threshold Sharing" in html
    assert "Paillier Additive Homomorphic Encryption" in html



