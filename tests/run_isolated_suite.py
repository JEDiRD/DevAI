"""VPS acceptance suite against a newly created, disposable empty database.

Credentials stay in the inherited runtime environment. Existing databases and
applied migrations are never modified by this command.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4
import psycopg
from psycopg.conninfo import make_conninfo


def main():
    base=os.environ['DEVAI_DATABASE_URL']
    with psycopg.connect(base) as conn:
        role=conn.execute('SELECT current_user').fetchone()[0]
    if not re.fullmatch(r'[a-z][a-z0-9_]*',role): raise RuntimeError('UNSUPPORTED_TEST_ROLE')
    name='devai_hardening_test_'+uuid4().hex
    root=Path(__file__).absolute().parent.parent
    subprocess.run(['sudo','-n','-u','postgres','createdb','-O',role,name],check=True)
    result=1
    try:
        test_url=make_conninfo(base,dbname=name)
        with psycopg.connect(test_url) as conn:
            for migration in sorted((root/'migrations').glob('*.sql')):
                conn.execute(migration.read_text())
        env={**os.environ,'DEVAI_DATABASE_URL':test_url,'DEVAI_TEST_DATABASE_URL':test_url,
            'PYTHONPATH':str(root/'controller')+os.pathsep+str(root),
            'PYTHONDONTWRITEBYTECODE':'1'}
        result=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-v'],cwd=root,env=env).returncode
    finally:
        subprocess.run(['sudo','-n','-u','postgres','dropdb','--force',name],check=True)
        print('DISPOSABLE_DATABASE_REMOVED',flush=True)
    return result

if __name__=='__main__': sys.exit(main())
