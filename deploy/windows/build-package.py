"""Build a private service package, encrypting the existing token only in memory."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

root=Path(__file__).absolute().parents[2]
sys.path.insert(0,str(root))
from worker_agent.agent import AgentConfig
from worker_agent.credential_store import WindowsDpapiCredentialStore
from worker_agent.service_credentials import ServiceCredentialStore
from worker_agent.windows_security import no_reparse,set_directory_acl

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--destination',type=Path,required=True)
    parser.add_argument('--existing-config',type=Path,required=True)
    args=parser.parse_args()
    destination=args.destination.absolute()
    if destination.exists():raise RuntimeError('PACKAGE_DESTINATION_EXISTS')
    no_reparse(destination.parent)
    owner=re.search(r'S-1-5-\d+(?:-\d+)+',subprocess.check_output(['whoami.exe','/user','/fo','csv','/nh'],text=True)).group()
    destination.mkdir();set_directory_acl(destination,owner)
    config=AgentConfig.load(args.existing_config)
    personal_fixture=config.credential_path.parent/'service-access-denial.fixture'
    if personal_fixture.exists():
        raise RuntimeError('PERSONAL_TEST_FIXTURE_ALREADY_EXISTS')
    personal_fixture.write_text('Non-secret DevAI dedicated-service ACL acceptance fixture.\n')
    set_directory_acl(personal_fixture,owner)
    token=WindowsDpapiCredentialStore(config.credential_path).load(config.worker_id)
    (destination/'worker.dpapi').write_bytes(ServiceCredentialStore.encrypted(config.worker_id,token))
    del token
    control=destination/'control';control.mkdir()
    shutil.copytree(root/'worker_agent',control/'worker_agent',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(root/'deploy'/'windows'/'install-worker.ps1',destination/'install-worker.ps1')
    base=Path(sys.base_prefix)
    for name in ('host-runtime','sandbox-runtime'):
        runtime=destination/name;runtime.mkdir()
        for file in ('python.exe','python313.dll','python3.dll','vcruntime140.dll','vcruntime140_1.dll'):
            if (base/file).exists():shutil.copy2(base/file,runtime/file)
        shutil.copytree(base/'DLLs',runtime/'DLLs')
        shutil.copytree(base/'Lib',runtime/'Lib',ignore=shutil.ignore_patterns('site-packages','__pycache__','tests','test','tkinter','idlelib','ensurepip'))
        (runtime/'python313._pth').write_text('Lib\nDLLs\n'+('../control\n' if name=='host-runtime' else ''))
    shutil.copy2(root/'worker_agent'/'synthetic_process.py',destination/'sandbox-runtime'/'synthetic_process.py')
    manifest={str(file.relative_to(destination)).replace('\\','/'):hashlib.sha256(file.read_bytes()).hexdigest()
        for file in destination.rglob('*') if file.is_file()}
    (destination/'package.json').write_text(json.dumps({'worker_id':str(config.worker_id),
        'api_base_url':config.api_base_url,'personal_denial_fixture':str(personal_fixture),'files':manifest},indent=2))
    print(json.dumps({'package_ready':True,'files':len(manifest),'package_manifest_sha256':hashlib.sha256((destination/'package.json').read_bytes()).hexdigest()}))

if __name__=='__main__':main()
