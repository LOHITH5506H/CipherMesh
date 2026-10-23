from __future__ import annotations
import html, json, os, urllib.parse
from pathlib import Path
from wsgiref.simple_server import make_server
from crypto_protocol import HOSPITALS, QUERY_SPECS, PROTOCOLS, execute_private_query, load_hospital_data, dataset_fingerprints
from query_engine import parse_natural_language_query, format_filters_rule

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"

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

def esc(v): return html.escape(str(v), quote=True)
def tag(t, cls=""): return f'<span class="tag {esc(cls)}">{esc(t)}</span>'

def render_site(k, records):
    m = HOSPITALS[k]
    colors = {"hospital_a": "blue", "hospital_b": "purple", "hospital_c": "mint"}
    cols = [("Patient ref.", "PatientRef"), ("Age", "Age"), ("Cholesterol", "Cholesterol"), ("Diabetes", "Diabetes"), ("Systolic BP", "SystolicBP")]
    head = "".join(f"<th>{esc(a)}</th>" for a, b in cols)
    rows = "".join("<tr>" + "".join(f"<td>{esc(r[b])}</td>" for a, b in cols) + "</tr>" for r in records[:5])
    return f'''<article class="site-card"><div class="site-head"><span class="site-icon {colors[k]}">✚</span><div><h3>{esc(m["name"])}</h3><p>{m["code"]} · {len(records)} synthetic records</p></div>{tag("Local source","local")}</div><div class="field-tags">{tag("Age")}{tag("Cholesterol")}{tag("Diabetes")}{tag("Blood pressure")}</div><details><summary>Inspect local sample records <span>⌄</span></summary><div class="table-scroll"><table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div><p class="small">Synthetic rows only. The demo server can access these files, so this is not a real multi-organization deployment.</p></details></article>'''

def render_result(r):
    result = r["result"]
    comps = "".join(f'<div class="component"><span>{esc(k)}</span><strong>{esc(v)}</strong></div>' for k, v in result["components"].items())
    packets = "".join(f'<tr><td>{esc(p["from"])}</td><td>{esc(p["to"])}</td><td>{esc(p["kind"])}</td><td>{esc(p["payload"])}</td><td>{esc(p["status"])}</td></tr>' for p in r["packet_summary"])
    trace = "".join(f"<li>{esc(x)}</li>" for x in r["trace"])
    audits = "".join(f'<tr><td>{esc(a["site"])}</td><td><code>{esc(a["digest"])}</code></td><td>{esc(a["status"])}</td></tr>' for a in r["audit"])
    schema = {
        "protocol": r["protocol_key"],
        "query_id": r["query_id"],
        "sender": "site_node",
        "recipient": "computation_party",
        "payload": "randomized share or encrypted contribution (values omitted)",
        "raw_patient_rows_included": False
    }

    is_custom = "custom_spec" in r and r["custom_spec"]
    if is_custom:
        spec = r["custom_spec"]
        result_title = spec.get("result_label", spec.get("label", "Custom Collaborative Query"))
        filters_str = format_filters_rule(spec.get("filters", []))
        ai_plan_html = f'''<div class="ai-plan-card">
            <div class="ai-plan-head">
                <h4><span>✨</span> Privacy Query Plan ({esc(spec.get("source", "Query Engine"))})</h4>
                {tag("Compiled to MPC Vector", "local")}
            </div>
            <p class="small" style="margin:0 0 10px 0; font-size: 11px;"><strong>User question:</strong> "{esc(spec.get("question", ""))}"</p>
            <div class="ai-plan-grid">
                <div class="ai-plan-item"><span>Aggregation Primitive</span><strong>{esc(spec.get("aggregation", "count").upper())}</strong></div>
                <div class="ai-plan-item"><span>Target Field</span><strong>{esc(str(spec.get("target_field") or "Cohort Count"))}</strong></div>
                <div class="ai-plan-item"><span>Clinical Privacy Bounds</span><strong>{esc(str(spec.get("bounds") or "N/A"))}</strong></div>
                <div class="ai-plan-item"><span>Filters Applied</span><strong>{esc(filters_str)}</strong></div>
            </div>
            <p class="small" style="margin-top:10px;">{esc(spec.get("context", ""))}</p>
        </div>'''
    else:
        result_title = QUERY_SPECS[r["query_key"]]["result_label"]
        ai_plan_html = ""

    return f'''<section class="result section" id="result">
        <div class="section-top">
            <div>
                <div class="kicker">RUN COMPLETE · {esc(r["query_id"])}</div>
                <h2>{esc(result_title)}</h2>
            </div>
            {tag("Aggregate released", "success")}
        </div>
        {ai_plan_html}
        <div class="result-number">{esc(result["display"])}</div>
        <p class="result-caption">Exact aggregate for this educational run. No differential privacy is applied.</p>
        <div class="metrics">
            <div><span>Participating sites</span><strong>3</strong></div>
            <div><span>Raw rows in modeled payload</span><strong>0</strong></div>
            <div><span>Protocol messages</span><strong>{len(r["packet_summary"])}</strong></div>
            <div><span>Integrity commitments</span><strong>{len(r["audit"])}</strong></div>
        </div>
        <div class="component-grid">{comps}</div>
        <details open class="inspect">
            <summary>Cryptographic execution trace</summary>
            <ol class="trace">{trace}</ol>
            <h3>Message exchange log</h3>
            <p class="small">Metadata only. Actual share and ciphertext values are deliberately not rendered.</p>
            <div class="table-scroll">
                <table>
                    <thead><tr><th>From</th><th>To</th><th>Message type</th><th>Payload description</th><th>Status</th></tr></thead>
                    <tbody>{packets}</tbody>
                </table>
            </div>
        </details>
        <details class="inspect">
            <summary>Integrity audit · SHA-256 commitments</summary>
            <p class="small">Hashes are over local contribution metadata, not raw rows. Hashing is not encryption and does not establish authenticity by itself.</p>
            <div class="table-scroll">
                <table>
                    <thead><tr><th>Site</th><th>SHA-256 digest</th><th>Status</th></tr></thead>
                    <tbody>{audits}</tbody>
                </table>
            </div>
        </details>
        <details class="inspect">
            <summary>Example protocol message schema</summary>
            <pre>{esc(json.dumps(schema, indent=2))}</pre>
        </details>
        <div class="warning"><strong>Security note:</strong> this is an educational simulation. All parties run in one server process. The Paillier option uses tiny insecure primes. Use synthetic data only.</div>
    </section>'''

def render_page(mode="nl", prompt="", q="average_cholesterol", p="additive", result=None, error=None, integrity=True, gemini_key=""):
    datasets, errors = load_hospital_data(DATA_DIR)
    if q not in QUERY_SPECS: q = "average_cholesterol"
    query = QUERY_SPECS[q]
    if p not in PROTOCOLS: p = "additive"
    proto = PROTOCOLS[p]

    sites = "".join(render_site(k, datasets.get(k, [])) for k in HOSPITALS)
    qopts = "".join(f'<option value="{esc(k)}" {"selected" if k==q else ""}>{esc(v["label"])}</option>' for k, v in QUERY_SPECS.items())
    popts = "".join(f'<option value="{esc(k)}" {"selected" if k==p else ""}>{esc(v["label"])}</option>' for k, v in PROTOCOLS.items())

    error_html = f'<div class="error">{esc(error)}</div>' if error else ""
    if errors: error_html += '<div class="error">Dataset problem: ' + esc("; ".join(errors)) + '</div>'

    fps = dataset_fingerprints(DATA_DIR)
    fp_rows = "".join(f'<tr><td>{esc(x["site"])}</td><td>{x["records"]}</td><td>{x["bytes"]:,}</td><td><code>{esc(x["sha256"][:24])}…</code></td></tr>' for x in fps)
    result_html = render_result(result) if result else ""

    qjs = json.dumps({k: {"question": v["question"], "context": v["context"], "fields": v["fields"], "rule": v["rule"]} for k, v in QUERY_SPECS.items()})
    pjs = json.dumps({k: {"label": v["label"], "summary": v["summary"], "security": v["security"]} for k, v in PROTOCOLS.items()})

    default_prompt = prompt or "What is the average age of patients with diabetes?"

    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CipherMesh | Secure Collaborative Analytics</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="shell">
<header class="topbar"><a class="brand" href="/"><span class="brand-icon">C<span>⌁</span></span><span><strong>CipherMesh</strong><small>SECURE COLLABORATIVE ANALYTICS</small></span></a><div class="status"><i></i> LOCAL RESEARCH BUILD</div></header>
<section class="hero"><div class="kicker">PRIVACY ENGINEERING · RESEARCH PROTOTYPE</div><h1>Collaborate on the insight.<br><em>Not on the raw records.</em></h1><p>Explore how multiple data custodians can compute shared statistics while limiting what crosses the data boundary. Ask questions in simple English, switch cryptographic protocols, and inspect the message flow.</p><div class="hero-tags">{tag("Natural Language AI")}{tag("3 data custodians")}{tag("3 aggregation protocols")}{tag("SHA-256 audit")}</div><div class="hero-note"><span class="pulse"></span><span><strong>Built for experiments</strong><small>Synthetic clinical data · Natural Language Querying via Gemini API · Zero raw patient rows shared</small></span></div></section>
<section class="section"><div class="section-head"><div><div class="kicker">01 / DATA CUSTODY</div><h2>Three data holders</h2><p>Each institution owns a separate dataset. Open a card to inspect a few synthetic records.</p></div><span class="section-count">3 SITES · {sum(len(v) for v in datasets.values())} RECORDS</span></div><div class="site-grid">{sites}</div></section>
<section class="section"><div class="section-head"><div><div class="kicker">02 / SECURE COMPUTATION</div><h2>Configure a collaborative query</h2><p>Ask in plain English or select a preset research question, then compare how cryptographic primitives protect local contributions.</p></div></div>
<form method="post" action="/run#result" class="run-form">
    <input type="hidden" name="mode" id="mode" value="{esc(mode)}">
    <div class="mode-tabs">
        <button type="button" class="tab-btn {"active" if mode=="nl" else ""}" id="tab-nl" onclick="switchMode('nl')">✨ Ask in Plain English (AI)</button>
        <button type="button" class="tab-btn {"active" if mode=="preset" else ""}" id="tab-preset" onclick="switchMode('preset')">📋 Standard Preset Queries</button>
    </div>

    <!-- Natural Language Query Box -->
    <div id="nl-panel" style="display: {'block' if mode=='nl' else 'none'};">
        <label>Your research question in simple English
            <div class="nl-input-wrap">
                <input type="text" name="prompt" id="prompt" class="nl-input" value="{esc(default_prompt)}" placeholder="e.g. What is the average age of patients with diabetes?">
            </div>
        </label>
        <p class="small" style="margin-top: 10px;">Enter clinical research questions naturally — the privacy compiler translates them into bounded MPC vectors.</p>
    </div>

    <!-- Preset Query Box -->
    <div id="preset-panel" style="display: {'block' if mode=='preset' else 'none'};">
        <div class="form-grid">
            <label>Pre-built research question
                <select name="query" id="query">{qopts}</select>
            </label>
            <div class="query-info" style="margin-top:0;">
                <div class="query-symbol">⌁</div>
                <div>
                    <strong id="query-label">{esc(query["question"])}</strong>
                    <p id="query-context">{esc(query["context"])}</p>
                    <div class="field-tags">{''.join(tag(f) for f in query["fields"])}{tag(query["rule"])}</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Protocol Selection (Common to both) -->
    <div style="margin-top: 20px;">
        <label>Aggregation protocol
            <select name="protocol" id="protocol">{popts}</select>
        </label>
        <div class="protocol-info">
            <div class="protocol-symbol">⌘</div>
            <div>
                <strong id="protocol-label">{esc(proto["label"])}</strong>
                <p id="protocol-summary">{esc(proto["summary"])}</p>
                <span class="assumption">{esc(proto["security"])}</span>
            </div>
        </div>
    </div>

    <label class="check-row">
        <input type="checkbox" name="integrity" value="yes" {"checked" if integrity else ""}>
        <span><strong>Generate SHA-256 audit commitments</strong><small>Records a digest for each site's local query-contribution metadata. Hashes do not encrypt data.</small></span>
    </label>

    <button type="submit" {"disabled" if errors else ""}>Run secure aggregation <span>↗</span></button>
</form>{error_html}</section>
{result_html}
<section class="section"><div class="section-head"><div><div class="kicker">03 / DATA INTEGRITY</div><h2>Dataset fingerprint registry</h2><p>SHA-256 fingerprints can help detect file changes between experiments. They do not prove who created a file.</p></div></div><div class="audit-table"><table><thead><tr><th>Data holder</th><th>Rows</th><th>File size</th><th>SHA-256 fingerprint (prefix)</th></tr></thead><tbody>{fp_rows}</tbody></table></div></section>
<section class="section"><div class="section-head"><div><div class="kicker">04 / SECURITY MODEL</div><h2>What this prototype does and does not promise</h2></div></div><div class="security-grid"><article><span class="security-num">A</span><h3>Demonstrates</h3><ul><li>Natural language queries compiled to privacy-preserving vectors</li><li>Local query evaluation on separate synthetic CSVs</li><li>Additive secret-sharing MPC</li><li>Shamir threshold sharing (2-of-3)</li><li>Paillier additive homomorphic encryption</li><li>SHA-256 fingerprints and contribution commitments</li></ul></article><article class="risk"><span class="security-num">!</span><h3>Not production security</h3><ul><li>All parties run in one Python process</li><li>The server operator can read all CSV files</li><li>No independent network isolation, authentication or key management</li><li>Paillier demo primes are deliberately tiny and insecure</li><li>Exact aggregate outputs can still leak information</li></ul></article></div><p class="security-foot"><strong>Use synthetic data only.</strong> This is a research/teaching prototype, not a deployable healthcare system. A real deployment needs audited libraries, independent services, secure transport, access control, key management and independent security review.</p></section>
<footer><strong>CipherMesh</strong><span>Privacy-preserving collaborative analytics · educational prototype</span></footer></main>
<script>
const queries = {qjs}; const protocols = {pjs};
const q = document.getElementById('query'), p = document.getElementById('protocol');
if (q) {{
    q.addEventListener('change', () => {{
        const v = queries[q.value];
        document.getElementById('query-label').textContent = v.question;
        document.getElementById('query-context').textContent = v.context;
        document.querySelector('.query-info .field-tags').innerHTML = [...v.fields, v.rule].map(x => '<span class="tag">' + x.replaceAll('&','&amp;').replaceAll('<','&lt;') + '</span>').join('');
    }});
}}
if (p) {{
    p.addEventListener('change', () => {{
        const v = protocols[p.value];
        document.getElementById('protocol-label').textContent = v.label;
        document.getElementById('protocol-summary').textContent = v.summary;
        document.querySelector('.assumption').textContent = v.security;
    }});
}}
function switchMode(m) {{
    document.getElementById('mode').value = m;
    document.getElementById('nl-panel').style.display = m === 'nl' ? 'block' : 'none';
    document.getElementById('preset-panel').style.display = m === 'preset' ? 'block' : 'none';
    document.getElementById('tab-nl').className = 'tab-btn' + (m === 'nl' ? ' active' : '');
    document.getElementById('tab-preset').className = 'tab-btn' + (m === 'preset' ? ' active' : '');
}}
</script></body></html>'''

def app(environ, start_response):
    path = environ.get("PATH_INFO", "/"); method = environ.get("REQUEST_METHOD", "GET").upper()
    mode = "nl"; prompt = "What is the average age of patients with diabetes?"
    q = "average_cholesterol"; p = "additive"; result = None; error = None; integrity = True

    if path.startswith("/static/"):
        name = path.removeprefix("/static/")
        if name != "style.css":
            start_response("404 Not Found", [("Content-Type", "text/plain")]); return [b"Not found"]
        body = (ROOT / "static" / name).read_bytes()
        start_response("200 OK", [("Content-Type", "text/css; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [body]

    if method == "POST" and path == "/run":
        length = int(environ.get("CONTENT_LENGTH") or 0)
        form = urllib.parse.parse_qs(environ["wsgi.input"].read(length).decode("utf-8", "replace"))
        mode = form.get("mode", ["nl"])[0]
        prompt = form.get("prompt", [""])[0].strip()
        q = form.get("query", ["average_cholesterol"])[0]
        p = form.get("protocol", ["additive"])[0]
        integrity = form.get("integrity", [""])[0] == "yes"

        if p not in PROTOCOLS: p = "additive"; error = "Unsupported protocol."

        if not error:
            data, errs = load_hospital_data(DATA_DIR)
            if errs:
                error = "Cannot run: " + "; ".join(errs)
            else:
                try:
                    if mode == "nl" and prompt:
                        spec = parse_natural_language_query(prompt)
                        result = execute_private_query("custom", data, protocol=p, integrity=integrity, custom_spec=spec)
                    else:
                        if q not in QUERY_SPECS: q = "average_cholesterol"
                        result = execute_private_query(q, data, protocol=p, integrity=integrity)
                except Exception as exc:
                    error = str(exc)

    page = render_page(mode=mode, prompt=prompt, q=q, p=p, result=result, error=error, integrity=integrity).encode("utf-8")
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(page)))])
    return [page]

if __name__ == "__main__":
    host = os.environ.get("CIPHERMESH_HOST", "127.0.0.1")
    port = int(os.environ.get("CIPHERMESH_PORT", "5000"))
    print(f"CipherMesh running at http://{host}:{port}")
    print("Synthetic data only. Educational cryptography simulation, not production security.")
    with make_server(host, port, app) as server:
        server.serve_forever()
