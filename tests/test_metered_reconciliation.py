"""Evidence recovery, not execution retry. Every fixture is rolled back."""
from decimal import Decimal
import os
import unittest
import psycopg
from uuid import uuid4
from devai import ledger,budget,reconciliation as rec
from devai.budgeted_observer import BudgetedLedgerObserver,UsageMissing
from devai.types import ModelCandidate,Capability,ExecutionAttempt
import test_adapter_foundation as foundation


@unittest.skipUnless(os.environ.get('DEVAI_TEST_DATABASE_URL'),'PostgreSQL integration URL required')
class MeteredReconciliationTests(unittest.TestCase):
    setUp=foundation.AdapterFoundationTests.setUp
    sql=foundation.AdapterFoundationTests.sql
    def _case(self):
        job=ledger.create_job('reconciliation test',self.tenant)
        task=ledger.create_task(job,'a','a','a','basic','low',False,tenant_id=self.tenant)
        budget.configure_budget(job,Decimal('.02'),tenant_id=self.tenant)
        key=str(uuid4())
        self.sql('INSERT INTO model_pricing(pricing_key,version,input_per_million_usd,output_per_million_usd,active) VALUES (%s,1,2,3,TRUE)',(key,))
        route=ModelCandidate(key,'test',Capability.BASIC,'standard',1,pricing_key=key,billing_mode='metered')
        observer=BudgetedLedgerObserver(job,task,{'standard':Decimal('.01')},tenant_id=self.tenant)
        observer.attempt_started(1,route,'model')
        with self.assertRaises(UsageMissing):
            observer.attempt_finished(1,ExecutionAttempt(key,'test','model',True))
        case=self.sql('SELECT id FROM metered_reconciliations WHERE attempt_id=%s',(observer._state[1][0],))[0][0]
        return job,case,observer._state[1][0]

    def test_recoverable_review_final_without_inventing_cost(self):
        job,case,attempt=self._case()
        self.assertEqual(budget.get_budget(job,tenant_id=self.tenant)[1:],(Decimal(0),Decimal(0)))
        self.assertEqual(self.sql('SELECT recovery_exposure_usd FROM job_budgets WHERE job_id=%s',(job,))[0][0],Decimal('.01'))
        with self.assertRaises(budget.BudgetExceeded):budget.reserve_budget(job,Decimal('.02'),tenant_id=self.tenant)
        self.sql("UPDATE metered_reconciliations SET recover_until=clock_timestamp()-interval '1 second' WHERE id=%s",(case,))
        self.assertEqual(rec.sweep()['review_required'],1)
        self.sql("UPDATE metered_reconciliations SET resolve_by=clock_timestamp()-interval '1 second' WHERE id=%s",(case,))
        self.assertEqual(rec.sweep()['resolved_unpriced'],1)
        self.assertEqual(rec.sweep()['resolved_unpriced'],0)
        self.assertEqual(self.sql('SELECT recovery_exposure_usd,unpriced_exposure_usd,spent_usd FROM job_budgets WHERE job_id=%s',(job,))[0],(Decimal(0),Decimal('.01'),Decimal(0)))
        self.assertIsNone(self.sql('SELECT reconciled_cost_usd FROM execution_attempts WHERE id=%s',(attempt,))[0][0])
        self.assertEqual([row[0] for row in self.sql('SELECT action FROM metered_reconciliation_events WHERE case_id=%s ORDER BY id',(case,))],['opened','review_required','unrecoverable_exposure'])
        self.assertTrue(rec.resolve_case(tenant_id=self.tenant,case_id=case,actor='operator',usage=(1000,500),evidence_sha256='2'*64))
        self.assertEqual(self.sql('SELECT unpriced_exposure_usd,spent_usd FROM job_budgets WHERE job_id=%s',(job,))[0],(Decimal(0),Decimal('.0035')))
        self.assertFalse(rec.resolve_case(tenant_id=self.tenant,case_id=case,actor='operator',usage=(1000,500),evidence_sha256='2'*64))

    def test_cross_tenant_and_unsubstantiated_statement_rejected(self):
        job,case,attempt=self._case()
        with self.assertRaises(rec.ReconciliationError):
            rec.resolve_case(tenant_id=uuid4(),case_id=case,actor='operator',usage=(1,1),evidence_sha256='2'*64)
        with self.assertRaises(rec.ReconciliationError):
            rec.resolve_case(tenant_id=self.tenant,case_id=case,actor='operator',statement_cost=Decimal('.005'))
        self.assertTrue(rec.resolve_case(tenant_id=self.tenant,case_id=case,actor='operator',statement_cost=Decimal('.005'),evidence_sha256='3'*64))
        self.assertEqual(budget.get_budget(job,tenant_id=self.tenant)[2],Decimal('.005'))

    def test_controller_crash_reservation_expires_to_recovery(self):
        job=ledger.create_job('crash test',self.tenant)
        task=ledger.create_task(job,'a','a','a','basic','low',False,tenant_id=self.tenant)
        budget.configure_budget(job,Decimal('.02'),tenant_id=self.tenant)
        key=str(uuid4())
        self.sql('INSERT INTO model_pricing(pricing_key,version,input_per_million_usd,output_per_million_usd,active) VALUES (%s,1,2,3,TRUE)',(key,))
        route=ModelCandidate(key,'test',Capability.BASIC,'standard',1,pricing_key=key,billing_mode='metered')
        observer=BudgetedLedgerObserver(job,task,{'standard':Decimal('.01')},tenant_id=self.tenant)
        observer.attempt_started(1,route,'model')
        self.sql("UPDATE execution_attempts SET accounting_due_at=clock_timestamp()-interval '1 second' WHERE id=%s",(observer._state[1][0],))
        self.assertEqual(rec.sweep()['opened'],1)
        self.assertEqual(budget.get_budget(job,tenant_id=self.tenant)[1],Decimal(0))

    def test_audit_events_are_append_only_and_actor_rejects_secrets(self):
        job,case,_=self._case()
        for statement in ('UPDATE metered_reconciliation_events SET actor=%s WHERE case_id=%s',
                'DELETE FROM metered_reconciliation_events WHERE actor=%s AND case_id=%s'):
            with self.assertRaises(psycopg.Error),self.conn.transaction():
                self.sql(statement,('controller',case))
        with self.assertRaises(rec.ReconciliationError),self.conn.transaction():
            rec.resolve_case(tenant_id=self.tenant,case_id=case,actor='devai_wkr_synthetic_secret',
                usage=(1,1),evidence_sha256='2'*64)
        self.assertEqual(self.sql('SELECT count(*) FROM metered_reconciliation_events WHERE case_id=%s',(case,))[0][0],1)
