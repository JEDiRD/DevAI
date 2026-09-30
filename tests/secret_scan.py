"""Report only paths/kinds, never secret values, matching lines or request URLs."""
import json
import os
from pathlib import Path
import re
import sys


def scan(root,known_secrets=()):
    known=[value.encode() if isinstance(value,str) else value for value in known_secrets if len(value)>=16]
    patterns=[('worker_token',re.compile(rb'devai_wkr_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])')),
        ('telegram_token',re.compile(rb'\b[0-9]{8,12}:[A-Za-z0-9_-]{35}\b')),
        ('private_key',re.compile(rb'(?m)^-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----\r?$')),
        ('database_password',re.compile(rb'postgres(?:ql)?://[^\s/:]+:[^\s/@]+@'))]
    findings=[];checked=0
    for file in Path(root).rglob('*'):
        if not file.is_file() or any(part in ('.git','__pycache__','.venv') for part in file.parts):continue
        data=file.read_bytes();checked+=1
        kinds=[kind for kind,pattern in patterns if pattern.search(data)]
        if any(value in data for value in known):kinds.append('runtime_secret')
        if kinds:findings.append({'path':str(file.relative_to(root)),'kinds':kinds})
    return {'checked_files':checked,'findings':findings,'clean':not findings}


if __name__=='__main__':
    secrets=[value for key,value in os.environ.items() if re.search(r'(?:TOKEN|PASSWORD|DATABASE_URL|API_KEY)$',key)]
    result=scan(sys.argv[1] if len(sys.argv)>1 else Path(__file__).parent.parent,secrets)
    print(json.dumps(result))
    sys.exit(0 if result['clean'] else 1)
