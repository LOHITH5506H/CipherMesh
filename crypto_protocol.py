from __future__ import annotations
import csv, hashlib, secrets, uuid, math
from pathlib import Path

FIELD = 2**127 - 1
HOSPITALS = {
 "hospital_a":{"name":"Northstar Medical","code":"H-01","file":"hospital_a.csv"},
 "hospital_b":{"name":"Riverside Health","code":"H-02","file":"hospital_b.csv"},
 "hospital_c":{"name":"Cedar Research Hospital","code":"H-03","file":"hospital_c.csv"},
}
QUERY_SPECS = {
 "average_cholesterol":{"label":"Average cholesterol","result_label":"Combined average cholesterol","question":"What is the average cholesterol level across all participating hospitals?","context":"Sites calculate bounded local sums and counts, then combine protected contributions.","rule":"Cholesterol clipped to 110-360 mg/dL","fields":["Cholesterol"]},
 "diabetes_count":{"label":"Diabetes prevalence count","result_label":"Patients with diabetes","question":"How many patients in the combined cohort have diabetes?","context":"Each site counts positive records locally; only protected counts are combined.","rule":"Diabetes = Yes","fields":["Diabetes"]},
 "elevated_bp_count":{"label":"Elevated blood pressure count","result_label":"Patients with elevated blood pressure","question":"How many patients have systolic blood pressure at or above 140 mmHg?","context":"Each site applies the same threshold locally, then protects the count.","rule":"Systolic BP >= 140 mmHg","fields":["SystolicBP"]},
 "average_age":{"label":"Average age","result_label":"Combined average age","question":"What is the average age across the participating cohort?","context":"Local age sums and counts are protected before aggregation.","rule":"Age clipped to 18-100 years","fields":["Age"]},
 "patient_count":{"label":"Total cohort size","result_label":"Combined patient count","question":"How many synthetic records are held across all participating sites?","context":"Sites contribute protected counts, not patient rows.","rule":"Count of records","fields":["PatientRef"]},
 "diabetes_rate":{"label":"Diabetes prevalence (%)","result_label":"Combined diabetes prevalence","question":"What percentage of the combined cohort has diabetes?","context":"Positive counts and total counts are aggregated through the selected protocol.","rule":"Positive count / total records x 100","fields":["Diabetes"]},
 "bp_band_counts":{"label":"Blood pressure bands","result_label":"Systolic blood pressure distribution","question":"How many records fall into three systolic blood-pressure bands?","context":"Sites bin measurements locally, then share a vector of bin counts.","rule":"Low <120 / Elevated 120-139 / High >=140 mmHg","fields":["SystolicBP"]},
}
PROTOCOLS = {
 "additive":{"label":"Additive secret sharing MPC","summary":"Each local contribution is split into random shares. Workers add shares and reconstruct only the combined aggregate.","security":"One isolated share is designed not to reveal its contribution; collusion and deployment boundaries matter."},
 "shamir":{"label":"Shamir threshold sharing (2-of-3)","summary":"A random polynomial encodes each contribution. Any two shares reconstruct the value; one share alone does not.","security":"Threshold-sharing demonstration over a finite field; all workers are simulated in one process."},
 "paillier":{"label":"Paillier additive homomorphic encryption","summary":"Sites encrypt numeric contributions. Ciphertexts are multiplied to obtain an encryption of the sum, then the authorized demo decryptor recovers the aggregate.","security":"Uses intentionally tiny demonstration primes. Never use this implementation or keys for real data."},
}

def load_hospital_data(data_dir: Path):
 data, errors = {}, []
 required={"PatientRef","Age","Cholesterol","Diabetes","SystolicBP"}
 for key, meta in HOSPITALS.items():
  try:
   with open(Path(data_dir)/meta["file"],newline="",encoding="utf-8") as f: rows=list(csv.DictReader(f))
   if not rows: errors.append(f'{meta["name"]}: no records found'); continue
   missing=required-set(rows[0])
   if missing: errors.append(f'{meta["name"]}: missing columns {sorted(missing)}'); continue
   data[key]=rows
  except OSError: errors.append(f'{meta["name"]}: missing file {meta["file"]}')
 return data,errors

def dataset_fingerprints(data_dir: Path):
 out=[]
 for key,meta in HOSPITALS.items():
  raw=(Path(data_dir)/meta["file"]).read_bytes()
  out.append({"site":meta["code"],"name":meta["name"],"records":max(0,len(raw.decode().splitlines())-1),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()})
 return out

def local_contribution(q, rows):
 yes=lambda r:r["Diabetes"].strip().lower() in {"yes","1","true"}
 if q=="average_cholesterol": return [sum(min(360,max(110,int(r["Cholesterol"]))) for r in rows),len(rows)]
 if q=="diabetes_count": return [sum(yes(r) for r in rows)]
 if q=="elevated_bp_count": return [sum(int(r["SystolicBP"])>=140 for r in rows)]
 if q=="average_age": return [sum(min(100,max(18,int(r["Age"]))) for r in rows),len(rows)]
 if q=="patient_count": return [len(rows)]
 if q=="diabetes_rate": return [sum(yes(r) for r in rows),len(rows)]
 if q=="bp_band_counts": return [sum(int(r["SystolicBP"])<120 for r in rows),sum(120<=int(r["SystolicBP"])<140 for r in rows),sum(int(r["SystolicBP"])>=140 for r in rows)]
 raise ValueError("Unsupported research query.")

def additive_share(v,n=3):
 if not isinstance(v,int) or v<0 or v>=FIELD: raise ValueError("Invalid field contribution.")
 a=[secrets.randbelow(FIELD) for _ in range(n-1)]
 return a+[(v-sum(a))%FIELD]
def additive_compute(locals_):
 width=len(next(iter(locals_.values()))); workers=[[0]*width for _ in range(3)]; packets=[]
 for site,vec in locals_.items():
  shares=[additive_share(v) for v in vec]
  for w in range(3):
   for j in range(width): workers[w][j]=(workers[w][j]+shares[j][w])%FIELD
   packets.append({"from":HOSPITALS[site]["code"],"to":f"Worker {w+1}","kind":"Random secret share","payload":f"{width} field element(s); values hidden","status":"Accepted"})
 result=[sum(workers[w][j] for w in range(3))%FIELD for j in range(width)]
 trace=["Each site evaluates the query locally.","Each local contribution is split into three random field shares.","Nine share packets are sent to three simulated workers.","Workers add shares component-wise modulo the field.","The combined aggregate vector is reconstructed from worker totals."]
 return result,packets,trace

def shamir_split(value):
 a=secrets.randbelow(FIELD)
 return [(x,(value+a*x)%FIELD) for x in (1,2,3)]
def shamir_reconstruct(shares):
 result=0
 for i,(xi,yi) in enumerate(shares):
  num=den=1
  for j,(xj,_) in enumerate(shares):
   if i!=j: num=num*(-xj)%FIELD; den=den*(xi-xj)%FIELD
  result=(result+yi*num*pow(den,-1,FIELD))%FIELD
 return result
def shamir_compute(locals_):
 width=len(next(iter(locals_.values()))); worker=[[0]*width for _ in range(3)]; packets=[]
 for site,vec in locals_.items():
  shares=[shamir_split(v) for v in vec]
  for w in range(3):
   for j in range(width): worker[w][j]=(worker[w][j]+shares[j][w][1])%FIELD
   packets.append({"from":HOSPITALS[site]["code"],"to":f"Worker {w+1}","kind":"Shamir threshold share","payload":f"{width} evaluation(s); values hidden","status":"Accepted"})
 result=[shamir_reconstruct([(1,worker[0][j]),(2,worker[1][j])]) for j in range(width)]
 trace=["Each site computes its local contribution.","A fresh random degree-1 polynomial encodes each value in a finite field.","Each worker receives one polynomial evaluation from each site.","Worker evaluations are added, preserving the combined polynomial.","Two worker totals reconstruct the combined value with Lagrange interpolation (2-of-3 threshold)."]
 return result,packets,trace

def paillier_keys():
 # Fixed tiny primes are intentionally insecure and for algebra demonstration only.
 p,q=499,547; n=p*q; n2=n*n; lam=(p-1)*(q-1)//math.gcd(p-1,q-1); g=n+1
 L=lambda u:(u-1)//n
 mu=pow(L(pow(g,lam,n2)),-1,n)
 return (n,g,n2),(lam,mu)
def paillier_encrypt(m,pub):
 n,g,n2=pub
 if not 0<=m<n: raise ValueError("Contribution exceeds demo Paillier plaintext range.")
 r=secrets.randbelow(n-1)+1
 while math.gcd(r,n)!=1: r=secrets.randbelow(n-1)+1
 return pow(g,m,n2)*pow(r,n,n2)%n2
def paillier_decrypt(c,pub,priv):
 n,g,n2=pub; lam,mu=priv
 return (((pow(c,lam,n2)-1)//n)*mu)%n
def paillier_compute(locals_):
 pub,priv=paillier_keys(); n,g,n2=pub; width=len(next(iter(locals_.values()))); encrypted=[1]*width; packets=[]
 for site,vec in locals_.items():
  for j,v in enumerate(vec): encrypted[j]=encrypted[j]*paillier_encrypt(v,pub)%n2
  packets.append({"from":HOSPITALS[site]["code"],"to":"Aggregation service","kind":"Paillier ciphertext","payload":f"{width} encrypted value(s); ciphertexts hidden","status":"Accepted"})
 result=[paillier_decrypt(c,pub,priv) for c in encrypted]
 trace=["A demonstration Paillier key pair is initialized.","Each site encrypts its local numeric contribution.","The aggregation service multiplies ciphertexts modulo n squared; the result encrypts the sum.","The demo decryptor recovers only the aggregate vector.","The small fixed demo primes are intentionally insecure and are not suitable for deployment."]
 return result,packets,trace

def format_result(q,v):
 if q=="average_cholesterol": return {"display":f"{v[0]/v[1]:.1f} mg/dL","components":{"Aggregate sum":v[0],"Record count":v[1]}}
 if q=="average_age": return {"display":f"{v[0]/v[1]:.1f} years","components":{"Aggregate age sum":v[0],"Record count":v[1]}}
 if q=="diabetes_rate": return {"display":f"{100*v[0]/v[1]:.1f}%","components":{"Positive count":v[0],"Record count":v[1]}}
 if q=="bp_band_counts": return {"display":f"Low {v[0]} · Elevated {v[1]} · High {v[2]}","components":{"Low (<120)":v[0],"Elevated (120-139)":v[1],"High (>=140)":v[2]}}
 label="records" if q=="patient_count" else "patients"
 return {"display":f"{int(v[0])} {label}","components":{"Aggregate count":int(v[0])}}

def execute_private_query(q,datasets,protocol="additive",integrity=True):
 if q not in QUERY_SPECS: raise ValueError("Unsupported query.")
 if protocol not in PROTOCOLS: raise ValueError("Unsupported cryptographic protocol.")
 if any(k not in datasets for k in HOSPITALS): raise ValueError("All three synthetic datasets must be loaded.")
 local={k:local_contribution(q,datasets[k]) for k in HOSPITALS}
 if protocol=="additive": vec,packets,trace=additive_compute(local)
 elif protocol=="shamir": vec,packets,trace=shamir_compute(local)
 else: vec,packets,trace=paillier_compute(local)
 audit=[]
 if integrity:
  for site,v in local.items():
   msg=(site+"|"+q+"|"+",".join(map(str,v))).encode()
   audit.append({"site":HOSPITALS[site]["code"],"digest":hashlib.sha256(msg).hexdigest(),"status":"Commitment recorded"})
  trace.append("SHA-256 commitments were generated for local contribution metadata. Hashing is not encryption and does not prove source authenticity.")
 return {"query_id":"CM-"+uuid.uuid4().hex[:10].upper(),"query_key":q,"protocol_key":protocol,"protocol":PROTOCOLS[protocol]["label"],"result":format_result(q,vec),"packet_summary":packets,"trace":trace,"audit":audit,"raw_rows_sent":0}

def protocol_summary():
 return {"name":"CipherMesh Secure Collaborative Analytics","workers":3,"security_note":"Educational simulation only; no independent servers."}
