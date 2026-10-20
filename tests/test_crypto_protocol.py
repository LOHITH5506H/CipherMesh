import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from crypto_protocol import FIELD,additive_share,shamir_split,shamir_reconstruct,execute_private_query,load_hospital_data,QUERY_SPECS
DATA=Path(__file__).resolve().parents[1]/"data"
def datasets():
 d,e=load_hospital_data(DATA); assert not e; return d
def test_additive_reconstructs():
 for v in (0,1,12345,999999): assert sum(additive_share(v))%FIELD==v
def test_shamir_any_two_reconstruct():
 for v in (0,1,98765,999999):
  s=shamir_split(v)
  assert shamir_reconstruct(s[:2])==v
  assert shamir_reconstruct([s[0],s[2]])==v
  assert shamir_reconstruct(s[1:])==v
def test_all_queries_match_across_protocols():
 d=datasets()
 for q in QUERY_SPECS:
  results=[execute_private_query(q,d,p) for p in ("additive","shamir","paillier")]
  assert results[0]["result"]["display"]==results[1]["result"]["display"]==results[2]["result"]["display"]
  assert len(results[0]["packet_summary"])==9 and len(results[1]["packet_summary"])==9
def test_integrity_toggle():
 d=datasets()
 assert len(execute_private_query("patient_count",d,integrity=True)["audit"])==3
 assert execute_private_query("patient_count",d,integrity=False)["audit"]==[]
def test_invalid_inputs():
 d=datasets()
 for args in [("bad",d),("patient_count",d,"unknown")]:
  try: execute_private_query(*args)
  except ValueError: pass
  else: assert False
