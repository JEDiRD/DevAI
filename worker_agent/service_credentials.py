"""Machine DPAPI is usable by a virtual service identity; protected ACL is mandatory."""
import json
from pathlib import Path

from .credential_store import _dpapi


class ServiceCredentialStore:
    def __init__(self, path):
        self.path = Path(path)

    def load(self, worker_id):
        # Service bootstrap validates SYSTEM ownership and allowlisted ACLs before
        # constructing this store. AppContainer never receives access to its directory.
        data = json.loads(_dpapi(self.path.read_bytes(), protect=False))
        if data.get('worker_id') != str(worker_id) or not data.get('token','').startswith('devai_wkr_'):
            raise ValueError('Invalid service credential')
        return data['token']

    @staticmethod
    def encrypted(worker_id, token):
        if not token.startswith('devai_wkr_'):
            raise ValueError('Invalid Worker credential')
        return _dpapi(json.dumps({'worker_id':str(worker_id),'token':token}).encode(),
                      protect=True, machine=True)
