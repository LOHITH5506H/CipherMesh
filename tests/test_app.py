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
    assert "Privacy Query Plan" in html
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
