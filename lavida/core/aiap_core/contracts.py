"""Offline validation and stable local encoding. Wang Lu."""
from pathlib import Path
import json,base64,hashlib
import rfc3339_validator
from jsonschema import Draft202012Validator,FormatChecker
from referencing import Registry,Resource
ROOT=Path(__file__).resolve().parents[1]
REGISTRY=Registry()
SCHEMAS={}
for p in sorted((ROOT/'profile').rglob('*.schema.json')):
    s=json.loads(p.read_text(encoding='utf-8'));Draft202012Validator.check_schema(s)
    if s['$id'] in SCHEMAS and SCHEMAS[s['$id']]!=s:raise RuntimeError('Conflicting schema')
    SCHEMAS[s['$id']]=s;REGISTRY=REGISTRY.with_resource(s['$id'],Resource.from_contents(s))
CHECKER=FormatChecker()
class Fault(Exception):
    def __init__(self,code,status=400):self.code=code;self.status=status;super().__init__(code)
def require(condition,code='E_SCHEMA',status=400):
    if not condition:raise Fault(code,status)
def validate(name,data):
    uri='https://schemas.aiap.invalid/core-profile/0.1-draft/'+name+'.schema.json'
    if next(Draft202012Validator(SCHEMAS[uri],registry=REGISTRY,format_checker=CHECKER).iter_errors(data),None):raise Fault('E_SCHEMA')
def canonical(data):return json.dumps(data,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
def digest(data):return hashlib.sha256(canonical(data)).hexdigest()
def b64(data):return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
def unb64(value):return base64.urlsafe_b64decode(value+'='*(-len(value)%4))
def exact(data,required,optional=()):
    require(isinstance(data,dict) and set(required)<=set(data) and set(data)<=set(required)|set(optional))
def names(values):return isinstance(values,list) and 0<len(values)<=16 and all(isinstance(x,str) and 0<len(x)<=200 for x in values) and len(set(values))==len(values)
