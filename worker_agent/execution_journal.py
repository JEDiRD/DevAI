"""Crash-safe at-most-once local execution; uncertain work is never rerun."""
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from dataclasses import dataclass
from uuid import UUID
from .adapters import AdapterError,AdapterResult

@dataclass(frozen=True)
class TerminationReceipt:
    id: UUID
    claim_version: int


class ExecutionJournal:
    def __init__(self,path):
        if str(path) != ':memory:':
            Path(path).parent.mkdir(parents=True,exist_ok=True)
        self.db=sqlite3.connect(str(path))
        self.db.execute('PRAGMA page_size=4096')
        self.db.execute('PRAGMA max_page_count=4096')  # 16 MiB at the default 4 KiB page size.
        self.db.execute('CREATE TABLE IF NOT EXISTS executions (key TEXT PRIMARY KEY, dispatch_id TEXT UNIQUE NOT NULL, fingerprint TEXT NOT NULL, state TEXT NOT NULL, content TEXT, error TEXT, prompt_tokens INTEGER, completion_tokens INTEGER)')
        self.db.commit()
        if 'created_at' not in {row[1] for row in self.db.execute('PRAGMA table_info(executions)')}:
            self.db.execute('ALTER TABLE executions ADD COLUMN created_at REAL NOT NULL DEFAULT 0')
            self.db.commit()
        columns = {row[1] for row in self.db.execute('PRAGMA table_info(executions)')}
        for column, definition in (('claim_version','INTEGER NOT NULL DEFAULT 0'),
                ('termination_confirmed','INTEGER NOT NULL DEFAULT 0'),('termination_reported','INTEGER NOT NULL DEFAULT 0')):
            if column not in columns:
                self.db.execute(f'ALTER TABLE executions ADD COLUMN {column} {definition}')
        self.db.commit()
        self.maintain()

    def maintain(self):
        self.db.execute("DELETE FROM executions WHERE state<>'running' AND (termination_reported=1 OR claim_version=0) AND created_at<?", (time.time()-90*86400,))
        self.db.commit()

    def recover_after_containment(self):
        """Only called AFTER WorkspaceManager has confirmed all old jobs stopped."""
        self.db.execute("UPDATE executions SET state='failed',error='EXECUTION_OUTCOME_UNKNOWN' WHERE state='running'")
        self.db.execute('UPDATE executions SET termination_confirmed=1 WHERE claim_version>0')
        self.db.commit()

    def pending_terminations(self):
        return [TerminationReceipt(UUID(row[0]),row[1]) for row in self.db.execute(
            'SELECT dispatch_id,claim_version FROM executions WHERE termination_confirmed=1 AND termination_reported=0 AND claim_version>0 ORDER BY created_at LIMIT 100')]

    def termination_reported(self,dispatch):
        self.db.execute('UPDATE executions SET termination_reported=1 WHERE dispatch_id=? AND claim_version=? AND termination_confirmed=1',(str(dispatch.id),dispatch.claim_version))
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
        self.maintain()
        self.db.execute("INSERT INTO executions(key,dispatch_id,fingerprint,state,created_at,claim_version) VALUES (?,?,?,'running',?,?)",(key,str(dispatch.id),fingerprint,time.time(),dispatch.claim_version))
        self.db.commit()  # Durable BEFORE adapter execution, including crash window.
        return None

    def finish(self,dispatch,result=None,error=None,termination_confirmed=True):
        self.db.execute("UPDATE executions SET state=?,content=?,error=?,prompt_tokens=?,completion_tokens=?,termination_confirmed=? WHERE key=? AND state='running'",('done' if result else 'failed',result.content if result else None,error,result.prompt_tokens if result else None,result.completion_tokens if result else None,int(termination_confirmed),str(dispatch.idempotency_key)))
        self.db.commit()
