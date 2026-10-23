from __future__ import annotations
import html, json, os, urllib.parse
from pathlib import Path
from wsgiref.simple_server import make_server
from crypto_protocol import HOSPITALS, QUERY_SPECS, PROTOCOLS, execute_private_query, load_hospital_data, dataset_fingerprints
from query_engine import parse_natural_language_query, format_filters_rule
from attack_simulator import VICTIM_PROFILES, ATTACK_TYPES, run_attack_simulation
from data_diff import compute_data_fidelity_diff, compute_query_difference


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
    sample_records = records[:20]
    rows = "".join("<tr>" + "".join(f"<td>{esc(r[b])}</td>" for a, b in cols) + "</tr>" for r in sample_records)
    return f'''<article class="site-card">
        <div class="site-head">
            <span class="site-icon {colors[k]}">✚</span>
            <div>
                <h3>{esc(m["name"])}</h3>
                <p>{m["code"]} · {len(records)} synthetic records</p>
            </div>
            {tag("Active Local Node","local")}
        </div>
        <div class="field-tags">{tag("Age")}{tag("Cholesterol")}{tag("Diabetes")}{tag("Blood pressure")}</div>
        <div class="site-table-open">
            <details open>
                <summary>Microdata Repository ({len(sample_records)} records displayed by default) <span>⌄</span></summary>
                <div class="site-scroll">
                    <table>
                        <thead><tr>{head}</tr></thead>
                        <tbody>{rows}</tbody>
                    </table>
                </div>
            </details>
            <p class="small" style="margin-top:8px;">Local institution records. Microdata rows stay within this boundary and are never transmitted cleartext.</p>
        </div>
    </article>'''

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
        ai_plan_html = f'''<div class="ai-plan-box" style="margin-bottom:18px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <strong style="color:var(--mint);font-size:12px;letter-spacing:0.5px;">NATURAL LANGUAGE PRIVACY COMPILATION PLAN</strong>
                <span class="tag local">Validated AST</span>
            </div>
            <div class="ai-plan-grid">
                <div class="ai-plan-item"><span>Target Field</span><strong>{esc(spec.get("target_field", "N/A"))}</strong></div>
                <div class="ai-plan-item"><span>Aggregation Rule</span><strong>{esc(spec.get("aggregation", "SUM").upper())}</strong></div>
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
        <p class="result-caption">Exact aggregate for this educational run. Local contributions bounded before sharing.</p>
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
        <div class="warning"><strong>Security note:</strong> this is an educational simulation. All parties run in one server process. The Paillier option uses tiny demonstration primes. Use synthetic data only.</div>
    </section>'''

def render_diff_section(datasets, mode="nl", prompt="", q="average_cholesterol", p="additive", result=None):
    query_diff = compute_query_difference(datasets, mode=mode, prompt=prompt, q=q, p=p, result=result)
    diff_data = compute_data_fidelity_diff(datasets)

    rows = "".join(f'''<tr>
        <td><strong>{esc(m["name"])}</strong></td>
        <td><code>{esc(m["original"])}</code></td>
        <td><code>{esc(m["protected"])}</code></td>
        <td><strong style="color:var(--cyan);">{esc(m["diff"])}</strong></td>
        <td><span class="diff-badge">{esc(m["fidelity"])}</span></td>
        <td><span class="tag local">{esc(m["status"])}</span></td>
    </tr>''' for m in diff_data["metrics"])
    
    return f'''<div class="diff-wrap">
        <div class="section-head" style="margin-bottom:14px;">
            <div>
                <div class="kicker">DYNAMIC STATISTICAL UTILITY ANALYSIS · FEATURE 03</div>
                <h2>Difference Between Original and Protected Data</h2>
                <p>Direct comparison for the current query: Output with CipherMesh collaborative cryptography vs. what the exact same query would yield in a traditional centralized database without cryptography.</p>
            </div>
            <div style="display:flex;align-items:center;gap:10px;">
                <span class="diff-badge" style="font-size:12px;padding:6px 12px;">Query Fidelity: {esc(query_diff["fidelity"])}</span>
                <span class="tag success" style="padding:6px 10px;">0 Rows Disclosed</span>
            </div>
        </div>

        <!-- 1. LIVE QUERY COMPARISON (WITH CRYPTO VS WITHOUT CRYPTO) -->
        <div class="query-diff-card" style="margin-bottom:20px;padding:18px 20px;background:#ffffff04;border:1px solid #ffffff12;border-radius:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:14px;">
                <div>
                    <span class="small" style="color:var(--muted);text-transform:uppercase;letter-spacing:1px;font-weight:700;">Active Evaluated Query:</span>
                    <div style="font-size:15px;font-weight:700;color:#fff;margin-top:3px;">"{esc(query_diff['question'])}"</div>
                </div>
                <span class="tag local">{'Natural Language AI Query' if query_diff['is_custom'] else 'Standard Preset Query'}</span>
            </div>

            <div class="attack-grid" style="margin-top:12px;">
                <!-- 1> RESPONSE WITH CRYPTOGRAPHY -->
                <div class="attack-card safe">
                    <div class="attack-head">
                        <h3>🛡️ 1> Response With Cryptography (CipherMesh)</h3>
                        <span class="badge-safe">Protected · 0 Rows Shared</span>
                    </div>
                    <div style="margin:14px 0 10px;">
                        <span class="small" style="color:#bbf7d0;text-transform:uppercase;letter-spacing:0.5px;font-weight:700;">CipherMesh Cryptographic Output:</span>
                        <div style="font-size:26px;font-weight:800;color:var(--mint);margin-top:4px;letter-spacing:-0.5px;">{esc(query_diff['ciphermesh_output'])}</div>
                    </div>
                    <div class="attack-stat">
                        <strong>Protocol &amp; Custody Pipeline:</strong>
                        {esc(query_diff['crypto_methodology'])}<br>
                        Raw Patient Rows Disclosed: <strong style="color:var(--mint);">0 rows (Zero Row Disclosure)</strong><br>
                        Institutional Boundary: <strong>Strict local custody · No cleartext records leave hospitals</strong>
                    </div>
                    <p class="small" style="color:#bbf7d0;margin-top:8px;">{esc(query_diff['crypto_verdict'])}</p>
                </div>

                <!-- 2> RESPONSE WITHOUT CRYPTOGRAPHY -->
                <div class="attack-card breach">
                    <div class="attack-head">
                        <h3>❌ 2> Same Query Output Without Cryptography</h3>
                        <span class="badge-breach">Exposed · 120 Rows in Cleartext</span>
                    </div>
                    <div style="margin:14px 0 10px;">
                        <span class="small" style="color:#fca5a5;text-transform:uppercase;letter-spacing:0.5px;font-weight:700;">Unprotected Plaintext Output:</span>
                        <div style="font-size:26px;font-weight:800;color:#f87171;margin-top:4px;letter-spacing:-0.5px;">{esc(query_diff['unprotected_output'])}</div>
                    </div>
                    <div class="attack-stat">
                        <strong>Protocol &amp; Custody Pipeline:</strong>
                        Direct plaintext aggregation on pooled centralized database<br>
                        Raw Patient Rows Disclosed: <strong style="color:#f87171;">{query_diff['raw_rows_exposed']} rows transmitted in cleartext</strong><br>
                        Institutional Boundary: <strong>None · All hospital microdata pooled into central server</strong>
                    </div>
                    <p class="small" style="color:#fca5a5;margin-top:8px;">{esc(query_diff['unprotected_verdict'])}</p>
                </div>
            </div>

            <!-- FIDELITY & DIFFERENCE DELTA BAR -->
            <div style="margin-top:14px;padding:12px 16px;background:#ffffff06;border-radius:10px;border:1px solid #ffffff10;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
                <div>
                    <strong style="color:#fff;font-size:12px;">Query Absolute Difference (Δ):</strong>
                    <span style="font-family:'DM Mono',monospace;color:var(--cyan);font-weight:700;margin-left:6px;font-size:13px;">{esc(query_diff['diff_str'])}</span>
                    <span class="small" style="color:var(--muted);margin-left:10px;">(Utility Fidelity: <strong style="color:var(--mint);">{esc(query_diff['fidelity'])}</strong>)</span>
                </div>
                <div>
                    <span class="tag success" style="background:#9af5d014;color:var(--mint);border-color:#9af5d033;">Identical Research Insight · 0 Patient Rows Leaked</span>
                </div>
            </div>
        </div>

        <!-- 2. COHORT-WIDE CLINICAL FIDELITY BENCHMARK TABLE -->
        <div style="margin-bottom:10px;">
            <span class="small" style="color:var(--muted);text-transform:uppercase;letter-spacing:1px;font-weight:700;">Cohort-Wide Ground Truth vs. Collaborative Protected Benchmarks:</span>
        </div>
        <div class="table-scroll">
            <table>
                <thead>
                    <tr><th>Clinical Metric</th><th>Original Centralized Data</th><th>CipherMesh Output</th><th>Absolute Difference (Δ)</th><th>Utility Fidelity</th><th>Status</th></tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        <div style="margin-top:16px;padding:12px 14px;background:#ffffff04;border-radius:10px;border:1px solid #ffffff10;font-size:11px;color:var(--muted);line-height:1.7;">
            <strong style="color:var(--mint);">Data Transformation Takeaway:</strong> In traditional analytics, calculating <code>{esc(query_diff['unprotected_output'])}</code> requires transmitting and pooling <strong>{query_diff['raw_rows_exposed']} raw patient medical files</strong> in cleartext. Under CipherMesh, researchers obtain the exact same result (<code>{esc(query_diff['ciphermesh_output'])}</code>) with <strong>0 raw patient records ever leaving hospital boundaries</strong>.
        </div>
    </div>'''


def render_attack_section(datasets, current_victim="PT-A-011", current_attack="linkage", attack_simulated=False):
    if current_victim not in VICTIM_PROFILES:
        current_victim = "PT-A-011"
    if current_attack not in ATTACK_TYPES:
        current_attack = "linkage"

    # Victim Selector Buttons (6 victims)
    victim_buttons = "".join(f'''<button type="button" class="victim-btn {"active" if vid==current_victim else ""}" id="vbtn-{vid}" onclick="selectVictim('{vid}')">
        👤 {esc(v["name"])} ({esc(v["id"])}) · {v["age"]}y/o
    </button>''' for vid, v in VICTIM_PROFILES.items())

    # Attack Type Selector (4 attack types)
    attack_buttons = "".join(f'''<div class="attack-type-btn {"active" if at_id==current_attack else ""}" id="atbtn-{at_id}" onclick="selectAttack('{at_id}')">
        <strong>⚔ {esc(at["name"])}</strong>
        <p>{esc(at["short_desc"])}</p>
    </div>''' for at_id, at in ATTACK_TYPES.items())

    curr_v = VICTIM_PROFILES[current_victim]
    curr_at = ATTACK_TYPES[current_attack]

    # Previews for each victim
    victim_previews = []
    for vid, v in VICTIM_PROFILES.items():
        victim_previews.append(f'''<div id="victim-preview-{vid}" class="victim-preview-box" style="display:{'block' if vid==current_victim else 'none'};margin-bottom:18px;padding:14px 16px;background:#ffffff04;border:1px solid #ffffff12;border-radius:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
                <div>
                    <strong style="font-size:14px;color:#fff;">Target Subject: {esc(v["name"])} (Patient Ref: {esc(v["id"])})</strong>
                    <p class="small" style="margin:4px 0 0 0;">Institution: {esc(v["site_name"])} · Baseline: Age {v["age"]} | Systolic BP {v["bp"]} mmHg | Cholesterol {v["cholesterol"]} mg/dL | Diabetes {esc(v["diabetes"])}</p>
                </div>
                <span class="tag local">Auxiliary Source Profile</span>
            </div>
            <div style="margin-top:10px;font-size:11px;color:#b2c0cc;line-height:1.6;">
                <div>🔍 <strong>Public External Dossier:</strong> {esc(v["voter_records"])}</div>
                <div>📡 <strong>Correlated Out-of-Band Leakage:</strong> {esc(v["auxiliary_leak"])}</div>
            </div>
        </div>''')
    previews_html = "".join(victim_previews)

    if attack_simulated:
        sim = run_attack_simulation(current_victim, current_attack, datasets)
        v = sim["victim"]
        raw = sim["raw_attack"]
        prot = sim["ciphermesh_attack"]
        compromised_tags = "".join(f'<span class="compromised-item">⚠️ {esc(k)}: {esc(val)}</span>' for k, val in raw["compromised_secrets"].items())

        sim_output_html = f'''<div class="sim-results" style="margin-top:20px;">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;padding:12px 16px;background:#15222e;border:1px solid #78d9ed44;border-radius:10px;margin-bottom:16px;">
                <div style="display:flex;align-items:center;gap:10px;">
                    <span class="pulse" style="background:#78d9ed;"></span>
                    <strong style="font-size:12px;color:var(--cyan);letter-spacing:0.5px;">LIVE SIMULATION COMPLETED</strong>
                    <span class="small" style="color:#c9d7e3;">Target: <strong>{esc(v["name"])} ({esc(v["id"])})</strong> · Vector: <strong>{esc(curr_at["name"])}</strong></span>
                </div>
                <span class="diff-badge" style="background:#78d9ed18;border-color:#78d9ed44;color:var(--cyan);">Evaluated 120 Patients Across 3 Hospitals</span>
            </div>

            <div class="attack-grid">
                <!-- BEFORE DATA CHANGE (TRADITIONAL) -->
                <div class="attack-card breach">
                    <div class="attack-head">
                        <h3>❌ BEFORE: Centralized Data Sharing</h3>
                        <span class="badge-breach">{esc(raw["status"])}</span>
                    </div>
                    <div class="attack-stat">
                        <strong>Adversary Execution &amp; Exploitation:</strong>
                        <div>{raw["details"]}</div>
                    </div>
                    <div class="attack-stat">
                        <strong>Exposed Private Medical Record:</strong>
                        <div style="margin-top:6px;">{compromised_tags}</div>
                    </div>
                    <p class="small" style="color:#fca5a5;margin-top:10px;">{esc(raw["verdict"])}</p>
                </div>

                <!-- AFTER DATA CHANGE (CIPHERMESH) -->
                <div class="attack-card safe">
                    <div class="attack-head">
                        <h3>🛡️ AFTER: CipherMesh Protection</h3>
                        <span class="badge-safe">{esc(prot["status"])}</span>
                    </div>
                    <div class="attack-stat">
                        <strong>Cryptographic Defense Mechanism:</strong>
                        <div>{prot["details"]}</div>
                    </div>
                    <div class="attack-stat">
                        <strong>Exposed Private Medical Record:</strong>
                        <div style="margin-top:6px;"><span class="tag success" style="background:#9af5d012;color:var(--mint);border-color:#9af5d033;">🔒 ZERO SECRETS LEAKED — Identity Protected</span></div>
                    </div>
                    <p class="small" style="color:#bbf7d0;margin-top:10px;">{esc(prot["verdict"])}</p>
                </div>
            </div>
        </div>'''
    else:
        sim_output_html = f'''<div style="margin-top:20px;padding:24px;border:1px dashed #ffffff22;border-radius:12px;text-align:center;background:#ffffff02;">
            <div style="font-size:24px;margin-bottom:8px;">⚔</div>
            <strong style="color:#fff;font-size:14px;display:block;margin-bottom:6px;">Simulation Standby · Awaiting Trigger</strong>
            <p class="small" style="max-width:540px;margin:0 auto 18px;color:#a0b0be;">
                Target: <strong>{esc(curr_v["name"])} ({esc(curr_v["id"])})</strong> · Vector: <strong>{esc(curr_at["name"])}</strong>.<br>
                Click the execution button below when you are ready to simulate the comparative attack.
            </p>
        </div>'''

    return f'''<section class="section">
        <div class="section-head">
            <div>
                <div class="kicker">03 / LIVE ATTACK SIMULATION LAB</div>
                <h2>Live Privacy &amp; Linkage Attack Simulation</h2>
                <p>Configure a targeted adversarial attack against a specific patient using external auxiliary files (voter registers, pharmacy kiosks, differential queries, or wiretap sniffing). Then execute the simulation to compare vulnerability before vs. after CipherMesh protection.</p>
            </div>
            <span class="tag local">Interactive Adversarial Lab</span>
        </div>
        <div class="attack-box">
            <form method="post" action="/simulate-attack#sec-attack" id="attack-form">
                <input type="hidden" name="victim" id="selected-victim" value="{esc(current_victim)}">
                <input type="hidden" name="attack_type" id="selected-attack" value="{esc(current_attack)}">
                <input type="hidden" name="active_tab" value="attack">

                <span class="small" style="color:var(--muted);text-transform:uppercase;letter-spacing:1px;font-weight:700;">1. Select Target Victim:</span>
                <div class="victim-row">{victim_buttons}</div>

                {previews_html}

                <span class="small" style="color:var(--muted);text-transform:uppercase;letter-spacing:1px;font-weight:700;">2. Select Adversarial Attack Vector:</span>
                <div class="attack-type-grid">{attack_buttons}</div>

                <div style="display:flex;align-items:center;gap:14px;margin-top:8px;">
                    <button type="submit" class="sim-trigger-btn">⚡ Execute Live Attack Simulation ↗</button>
                    <span class="small" style="color:#8ba0b2;">Simulates live adversary query against all 120 cohort records.</span>
                </div>
            </form>

            {sim_output_html}
        </div>
    </section>'''

def render_crypto_verification():
    return f'''<div style="border:1px solid #78d9ed33;background:linear-gradient(145deg,#0e1e24,#0b1419);border-radius:var(--radius);padding:24px;">
        <div class="section-head" style="margin-bottom:14px;">
            <div>
                <div class="kicker">05 / CRYPTOGRAPHIC ARCHITECTURE VERIFICATION</div>
                <h2>Meaningful Backend Cryptographic Implementations</h2>
                <p>Verification of the mathematical primitives executing on the server in <code>crypto_protocol.py</code>.</p>
            </div>
            <span class="tag local">Audit Status: Verified Authentic</span>
        </div>
        <div class="security-grid">
            <article style="border-color:#9af5d033;">
                <span class="security-num" style="background:#9af5d018;color:var(--mint);">1</span>
                <h3>Additive Secret Sharing MPC</h3>
                <p class="small" style="color:#d5dee7;line-height:1.7;">
                    Implemented over the Mersenne prime field <strong>F_p</strong> where <code>p = 2^127 - 1</code>.
                    For any value <code>v</code>, sites sample <code>n-1</code> random field elements via <code>secrets.randbelow(FIELD)</code>.
                    Workers compute component-wise sums: <code>W_w = ∑ s_w,h mod p</code>.
                    <strong>Security:</strong> Information-theoretically secure against up to <code>n-1</code> colluding workers. Individual shares are statistically indistinguishable from uniform random noise.
                </p>
            </article>
            <article style="border-color:#c7b4ff33;">
                <span class="security-num" style="background:#c7b4ff18;color:var(--violet);">2</span>
                <h3>Shamir (2-of-3) Threshold Sharing</h3>
                <p class="small" style="color:#d5dee7;line-height:1.7;">
                    Encodes values as the constant term of a degree-1 polynomial: <code>P(x) = v + a·x mod p</code>.
                    Evaluations at <code>x ∈ {{1, 2, 3}}</code> are distributed to three workers.
                    Workers sum evaluations, preserving the combined polynomial.
                    Any 2 workers reconstruct the sum via <strong>Lagrange basis interpolation</strong>: <code>v = ∑ y_i ∏ ((-x_j)/(x_i - x_j)) mod p</code>.
                    <strong>Security:</strong> Any single share provides exactly 0 bits of information about the secret.
                </p>
            </article>
            <article style="border-color:#78d9ed33;">
                <span class="security-num" style="background:#78d9ed18;color:var(--cyan);">3</span>
                <h3>Paillier Additive Homomorphic Encryption</h3>
                <p class="small" style="color:#d5dee7;line-height:1.7;">
                    Public key <code>(n, g)</code> with private Carmichael totient <code>λ = lcm(p-1, q-1)</code>.
                    Ciphertexts: <code>c = g^m · r^n mod n^2</code>.
                    The aggregator multiplies ciphertexts: <code>∏ c_i ≡ g^(∑ m_i) · (∏ r_i)^n mod n^2</code>, which homomorphically yields an encryption of the sum.
                    <strong>Educational parameter note:</strong> Uses small fixed demonstration primes (p=499, q=547) for rapid teaching demonstration rather than 2048-bit production RSA keys.
                </p>
            </article>
            <article style="border-color:#f1cb8a33;">
                <span class="security-num" style="background:#f1cb8a18;color:var(--amber);">4</span>
                <h3>SHA-256 Commitments &amp; Audit</h3>
                <p class="small" style="color:#d5dee7;line-height:1.7;">
                    Each local site computes a SHA-256 commitment: <code>H(site || query || vector)</code> before dispatching shares.
                    Prevents sites from altering their contribution retrospectively without detection.
                    Dataset fingerprints ensure that CSV files have not been modified between experimental runs.
                </p>
            </article>
        </div>
    </div>'''

def render_page(mode="nl", prompt="", q="average_cholesterol", p="additive", result=None, error=None, integrity=True, active_tab="landing", current_victim="PT-A-011", current_attack="linkage", attack_simulated=False):
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
    diff_html = render_diff_section(datasets, mode=mode, prompt=prompt, q=q, p=p, result=result)

    attack_html = render_attack_section(datasets, current_victim=current_victim, current_attack=current_attack, attack_simulated=attack_simulated)
    crypto_verif_html = render_crypto_verification()

    qjs = json.dumps({k: {"question": v["question"], "context": v["context"], "fields": v["fields"], "rule": v["rule"]} for k, v in QUERY_SPECS.items()})
    pjs = json.dumps({k: {"label": v["label"], "summary": v["summary"], "security": v["security"]} for k, v in PROTOCOLS.items()})

    default_prompt = prompt or "What is the average age of patients with diabetes?"
    total_records = sum(len(v) for v in datasets.values())

    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CipherMesh | Secure Collaborative Analytics</title><link rel="stylesheet" href="/static/style.css"></head><body><main class="shell">
<header class="topbar"><a class="brand" href="/" onclick="showMainTab('landing');return false;"><span class="brand-icon">C<span>⌁</span></span><span><strong>CipherMesh</strong><small>SECURE COLLABORATIVE ANALYTICS</small></span></a><div class="status"><i></i> LOCAL RESEARCH BUILD</div></header>

<nav class="nav-bar-wrap">
    <div class="nav-bar">
        <button type="button" class="nav-tab {"active" if active_tab=="landing" else ""}" id="nav-landing" onclick="showMainTab('landing')">
            <span class="nav-num">00</span> Landing Page
        </button>
        <button type="button" class="nav-tab {"active" if active_tab=="custody" else ""}" id="nav-custody" onclick="showMainTab('custody')">
            <span class="nav-num">01</span> Data Custody
        </button>
        <button type="button" class="nav-tab {"active" if active_tab=="compute" else ""}" id="nav-compute" onclick="showMainTab('compute')">
            <span class="nav-num">02</span> Secure Computation
        </button>
        <button type="button" class="nav-tab {"active" if active_tab=="attack" else ""}" id="nav-attack" onclick="showMainTab('attack')">
            <span class="nav-num">03</span> Attack Simulation
        </button>
        <button type="button" class="nav-tab {"active" if active_tab=="integrity" else ""}" id="nav-integrity" onclick="showMainTab('integrity')">
            <span class="nav-num">04</span> Data Integrity
        </button>
        <button type="button" class="nav-tab {"active" if active_tab=="security" else ""}" id="nav-security" onclick="showMainTab('security')">
            <span class="nav-num">05</span> Security Model
        </button>
    </div>
</nav>

<!-- 00. LANDING PAGE TAB -->
<section id="sec-landing" class="tab-content {"active" if active_tab=="landing" else ""}">
    <section class="hero"><div class="kicker">PRIVACY ENGINEERING · RESEARCH PROTOTYPE</div><h1>Collaborate on the insight.<br><em>Not on the raw records.</em></h1><p>Explore how multiple data custodians can compute shared statistics while limiting what crosses the data boundary. Ask research questions in simple English, simulate live linkage attacks, and inspect cryptographic proofs.</p><div class="hero-tags">{tag("Natural Language AI")}{tag("3 data custodians")}{tag("3 aggregation protocols")}{tag("Live Linkage Attack Simulation")}{tag("SHA-256 audit")}</div><div class="hero-note"><span class="pulse"></span><span><strong>Built for experiments</strong><small>Synthetic clinical data · Natural Language Querying via Gemini API · Zero raw patient rows shared</small></span></div></section>

    <div class="landing-grid">
        <article class="landing-card">
            <div>
                <div class="landing-card-top"><span class="site-icon mint">✚</span><div><h3>01 / Data Custody</h3><p>Three independent hospital nodes holding synthetic clinical records. Inspect local patient records safely.</p></div></div>
            </div>
            <button type="button" class="landing-card-btn" onclick="showMainTab('custody')">Explore Data Holders →</button>
        </article>
        <article class="landing-card">
            <div>
                <div class="landing-card-top"><span class="site-icon">⌁</span><div><h3>02 / Secure Computation</h3><p>Ask in simple English or select preset queries. Compare original vs protected data fidelity.</p></div></div>
            </div>
            <button type="button" class="landing-card-btn" onclick="showMainTab('compute')">Open Computation Console →</button>
        </article>
        <article class="landing-card">
            <div>
                <div class="landing-card-top"><span class="site-icon" style="background:#ff000018;color:#f87171;">⚔</span><div><h3>03 / Live Attack Simulation</h3><p>Target a victim and compare how re-identification succeeds before data change vs. how it fails after CipherMesh.</p></div></div>
            </div>
            <button type="button" class="landing-card-btn" onclick="showMainTab('attack')">Launch Attack Simulator →</button>
        </article>
        <article class="landing-card">
            <div>
                <div class="landing-card-top"><span class="site-icon purple">#</span><div><h3>04 / Data Integrity</h3><p>Verify SHA-256 dataset fingerprints and per-query local contribution commitments across all sites.</p></div></div>
            </div>
            <button type="button" class="landing-card-btn" onclick="showMainTab('integrity')">Inspect Fingerprints →</button>
        </article>
    </div>

    <div class="cta-banner">
        <div>
            <h3>Ready to run a privacy-preserving query?</h3>
            <p>Compile natural language questions into secure MPC vectors without sharing patient records.</p>
        </div>
        <button type="button" class="cta-btn" onclick="showMainTab('compute')">Launch Secure Computation ↗</button>
    </div>
</section>

<!-- 01. DATA CUSTODY TAB -->
<section id="sec-custody" class="tab-content {"active" if active_tab=="custody" else ""}">
    <section class="section">
        <div class="section-head">
            <div><div class="kicker">01 / DATA CUSTODY</div><h2>Three data holders</h2><p>Each institution owns a separate dataset with microdata visible below. All raw records stay inside their institutional node.</p></div>
            <span class="section-count">3 SITES · {total_records} RECORDS</span>
        </div>
        <div class="site-grid">{sites}</div>
    </section>
</section>

<!-- 02. SECURE COMPUTATION TAB -->
<section id="sec-compute" class="tab-content {"active" if active_tab=="compute" else ""}">
    <section class="section">
        <div class="section-head"><div><div class="kicker">02 / SECURE COMPUTATION</div><h2>Configure a collaborative query</h2><p>Ask in plain English or select a preset research question, then compare how cryptographic primitives protect local contributions.</p></div></div>
        <form method="post" action="/run#sec-compute" class="run-form">
            <input type="hidden" name="mode" id="mode" value="{esc(mode)}">
            <input type="hidden" name="active_tab" id="active_tab" value="compute">
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
        </form>
        {error_html}
    </section>
    {result_html}
    {diff_html}
</section>

<!-- 03. ATTACK SIMULATION TAB -->
<section id="sec-attack" class="tab-content {"active" if active_tab=="attack" else ""}">
    {attack_html}
</section>

<!-- 04. DATA INTEGRITY TAB -->
<section id="sec-integrity" class="tab-content {"active" if active_tab=="integrity" else ""}">
    <section class="section">
        <div class="section-head"><div><div class="kicker">04 / DATA INTEGRITY</div><h2>Dataset fingerprint registry</h2><p>SHA-256 fingerprints can help detect file changes between experiments. They do not prove who created a file.</p></div></div>
        <div class="audit-table"><table><thead><tr><th>Data holder</th><th>Rows</th><th>File size</th><th>SHA-256 fingerprint (prefix)</th></tr></thead><tbody>{fp_rows}</tbody></table></div>
    </section>
</section>

<!-- 05. SECURITY MODEL TAB -->
<section id="sec-security" class="tab-content {"active" if active_tab=="security" else ""}">
    <section class="section">
        {crypto_verif_html}
    </section>
</section>

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

function selectVictim(vid) {{
    document.querySelectorAll('.victim-btn').forEach(btn => btn.classList.remove('active'));
    const btn = document.getElementById('vbtn-' + vid);
    if (btn) btn.classList.add('active');
    const input = document.getElementById('selected-victim');
    if (input) input.value = vid;
    document.querySelectorAll('.victim-preview-box').forEach(el => el.style.display = 'none');
    const target = document.getElementById('victim-preview-' + vid);
    if (target) target.style.display = 'block';
}}

function selectAttack(att) {{
    document.querySelectorAll('.attack-type-btn').forEach(btn => btn.classList.remove('active'));
    const btn = document.getElementById('atbtn-' + att);
    if (btn) btn.classList.add('active');
    const input = document.getElementById('selected-attack');
    if (input) input.value = att;
}}

function showMainTab(tabId) {{
    const tabs = ['landing', 'custody', 'compute', 'attack', 'integrity', 'security'];
    tabs.forEach(t => {{
        const sec = document.getElementById('sec-' + t);
        const btn = document.getElementById('nav-' + t);
        if (sec) sec.className = 'tab-content' + (t === tabId ? ' active' : '');
        if (btn) btn.className = 'nav-tab' + (t === tabId ? ' active' : '');
    }});
    const tabInput = document.getElementById('active_tab');
    if (tabInput) tabInput.value = tabId;
    if (history.replaceState) history.replaceState(null, '', '#' + tabId);
    else location.hash = tabId;
}}

window.addEventListener('DOMContentLoaded', () => {{
    let hash = window.location.hash.replace('#', '').replace('sec-', '');
    if (hash === 'result') hash = 'compute';
    const valid = ['landing', 'custody', 'compute', 'attack', 'integrity', 'security'];
    if (valid.includes(hash)) {{
        showMainTab(hash);
    }}
}});
</script></body></html>'''

def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()
    mode = "nl"
    prompt = "What is the average age of patients with diabetes?"
    q = "average_cholesterol"
    p = "additive"
    result = None
    error = None
    integrity = True
    active_tab = "landing"
    current_victim = "PT-A-011"
    current_attack = "linkage"
    attack_simulated = False

    if path.startswith("/static/"):
        name = path.removeprefix("/static/")
        if name != "style.css":
            start_response("404 Not Found", [("Content-Type", "text/plain")])
            return [b"Not found"]
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
        active_tab = "compute"

        if p not in PROTOCOLS:
            p = "additive"
            error = "Unsupported protocol."

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
                        if q not in QUERY_SPECS:
                            q = "average_cholesterol"
                        result = execute_private_query(q, data, protocol=p, integrity=integrity)
                except Exception as exc:
                    error = str(exc)

    elif method == "POST" and (path == "/simulate-attack" or path == "/attack"):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        form = urllib.parse.parse_qs(environ["wsgi.input"].read(length).decode("utf-8", "replace"))
        current_victim = form.get("victim", ["PT-A-011"])[0]
        current_attack = form.get("attack_type", ["linkage"])[0]
        active_tab = "attack"
        attack_simulated = True

    page = render_page(
        mode=mode,
        prompt=prompt,
        q=q,
        p=p,
        result=result,
        error=error,
        integrity=integrity,
        active_tab=active_tab,
        current_victim=current_victim,
        current_attack=current_attack,
        attack_simulated=attack_simulated
    ).encode("utf-8")
    start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(page)))])
    return [page]

if __name__ == "__main__":
    host = os.environ.get("CIPHERMESH_HOST", "127.0.0.1")
    port = int(os.environ.get("CIPHERMESH_PORT", "5000"))
    print(f"CipherMesh running at http://{host}:{port}")
    print("Synthetic data only. Educational cryptography simulation, not production security.")
    with make_server(host, port, app) as server:
        server.serve_forever()
