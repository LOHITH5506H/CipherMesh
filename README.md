# CipherMesh: Secure Collaborative Analytics

A polished research/teaching prototype demonstrating collaborative aggregate queries across three synthetic data holders.

## Features
- **Natural Language Custom Queries (AI Compiler)**: Ask arbitrary clinical questions in plain English (e.g. *"What is the average age of diabetic patients?"* or *"How many patients have systolic BP over 140?"*).
- **Gemini API & Offline Fallback**: Translates natural language into a sandboxed, schema-bounded MPC query plan via Gemini (`gemini-2.5-flash`), with a zero-dependency intelligent local NLP fallback.
- **Zero Raw Data to Cloud**: Only column names and the user's question are compiled into a query plan; raw patient rows never leave local hospital nodes.
- Three separate synthetic hospital CSVs and local sample previews.
- Pre-built research queries: average cholesterol, diabetes count, elevated blood-pressure count, average age, total cohort size, diabetes prevalence, and blood-pressure bands.
- Three selectable aggregation techniques:
  1. Additive secret sharing / simulated MPC.
  2. Shamir threshold sharing (2-of-3).
  3. Paillier additive homomorphic encryption.
- SHA-256 dataset fingerprints and optional local-contribution metadata commitments.
- Execution traces, message logs, protocol payload schema, and clear security assumptions.
- Tests that compare every query across all three protocols.

## Run (Windows PowerShell)
Python 3.10+ recommended. Runtime uses the standard library. Tests use pytest.

```powershell
git clone https://github.com/LOHITH5506H/CipherMesh.git
cd CipherMesh
python -m pip install pytest
python -m pytest -v
python app.py
```

Open http://127.0.0.1:5000.

To use another port:
```powershell
$env:CIPHERMESH_PORT = "5050"
python app.py
```

## Structure
- `app.py`: WSGI web app, natural language interface, and dashboard
- `query_engine.py`: Gemini API compiler, natural language parser, safe AST, bounded vector evaluator
- `crypto_protocol.py`: secret sharing, Shamir, Paillier, audit hashes, query logic
- `data/`: synthetic hospital CSVs
- `static/style.css`: visual design
- `tests/`: protocol, query compiler, and web app tests

## Important security limitations
This is an **educational simulation**, not a production privacy system.
- All hospitals, workers, aggregation service, and decryptor execute in one Python process. The process operator can read every CSV.
- Paillier uses tiny fixed demonstration primes and is cryptographically insecure.
- No independent networked parties, authenticated channels, malicious-party defenses, real key lifecycle, production access controls, or formal protocol verification are included.
- SHA-256 fingerprints can help detect file changes when compared with a trusted digest; hashes are not encryption and do not establish source authenticity. Contribution commitments are not digital signatures.
- Outputs are exact aggregates. No differential privacy is applied; small cohorts and repeated queries may reveal information.
- “Zero raw rows in modeled payload” refers to generated protocol messages, not the server's ability to access source CSVs.
- All data is synthetic. Never use real patient or personal data.

A serious deployment would require audited cryptographic libraries, independent services, authenticated encrypted transport, identity and key management, query authorization, leakage controls, and an independent security review.
