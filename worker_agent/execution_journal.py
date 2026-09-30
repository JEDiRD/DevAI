"""Crash-safe at-most-once local execution; uncertain work is never rerun."""
import hashlib
import json
from pathlib import Path
import sqlite3
from .adapters import AdapterError,AdapterResult


class ExecutionJournal:
    def __init__(self,path):
        if str(path) != ':memory:':
            Path(path).parent.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(str(path))
        self.db.execute('CREATE TABLE IF NOT EXISTS executions (key TEXT PRIMARY KEY, dispatch_id TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL, state TEXT NOT NULL, content TEXT, error TEXT, prompt_tokens INTEGER, completion_tokens INTEGER)')
        self.db.commit()

    def begin(self,dispatch):
        fingerprint=hashlib.sha256(json.dumps([str(dispatch.id),str(dispatch.connection_id),dispatch.adapter_key,dispatch.adapter_version,dispatch.gateway_model,dispatch.prompt,dispatch.spec_version,dispatch.execution_timeout_seconds,dispatch.deadline_at.isoformat()],separators=(',',':')).encode()).hexdigest()
        key=str(dispatch.idempotency_key)
        row=self.db.execute('SELECT dispatch_id,fingerprint,state,content,error,prompt_tokens,completion_tokens FROM executions WHERE key=?',(key,)).fetchone()
        if row:
            if row[0]!=str(dispatch.id) or row[1]!=fingerprint:
                raise AdapterError('IDEMPOTENCY_CONFLICT')
            if row[2]=='done':
                return AdapterResult(row[3],row[5],row[6])
            raise AdapterError(row[4] or 'EXECUTION_OUTCOME_UNKNOWN')
        self.db.execute("INSERT INTO executions(key,dispatch_id,fingerprint,state) VALUES (?,?,?,'running')",(key,str(dispatch.id),fingerprint))
        self.db.commit()  # Durable BEFORE adapter execution, including crash window.
        return None

    def finish(self,dispatch,result=None,error=None):
        self.db.execute("UPDATE executions SET state=?,content=?,error=?,prompt_tokens=?,completion_tokens=? WHERE key=? AND state='running'",('done' if result else 'failed',result.content if result else None,error,result.prompt_tokens if result else None,result.completion_tokens if result else None,str(dispatch.idempotency_key)))
        self.db.commit()
