"""Operator-only real Windows E2E; no credentials accepted as arguments."""
import json
import os
from pathlib import Path
import re
from uuid import UUID,uuid4

from devai.db import connect
from devai.provider_registry import upsert_route,list_available_routes,set_route_enabled
from devai.transport import build_gateway_for_route
from devai.worker_dispatch import create_dispatch


TENANT=UUID('00000000-0000-4000-8000-000000000001')
WORKER=UUID('20000000-0000-4000-8000-000000000001')


def run():
    with connect() as conn,conn.cursor() as cur:
        cur.execute("SELECT status,last_seen_at>clock_timestamp()-interval '90 seconds',capabilities FROM worker_nodes WHERE tenant_id=%s AND id=%s",(TENANT,WORKER))
        status,fresh,caps=cur.fetchone()
        assert status=='online' and fresh and caps==['synthetic_test'],'WINDOWS_WORKER_NOT_READY'
        cur.execute("SELECT id FROM provider_connections WHERE tenant_id=%s AND name='Execution Adapter Synthetic Fixture'",(TENANT,))
        previous=cur.fetchone()
        connection=previous[0] if previous else uuid4()
        if previous:
            cur.execute('UPDATE provider_connections SET enabled=TRUE WHERE tenant_id=%s AND id=%s',(TENANT,connection))
        else:
            cur.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'Execution Adapter Synthetic Fixture','local_cli','local_none',%s,'synthetic_test')",(connection,TENANT,WORKER))
    assert 'codex/frontier' not in [r.key for r in list_available_routes(TENANT)],'UNSUPPORTED_CODEX_ELIGIBLE'
    upsert_route(tenant_id=TENANT,connection_id=connection,route_key='synthetic/local',
        provider='synthetic',gateway_model='synthetic/local',capability='basic',
        cost_class='free',priority=9999,pricing_key='synthetic/no-price',billing_mode='local')
    try:
        gateway=build_gateway_for_route(TENANT,'synthetic/local')
        result=gateway.complete('synthetic/local','Controlled remote adapter acceptance')
        assert result.content=='REMOTE_ADAPTER_OK','INVALID_SYNTHETIC_RESULT'
        ident=gateway.last_dispatch_id
        with connect() as conn,conn.cursor() as cur:
            cur.execute("SELECT status,claim_version,idempotency_key,spec_version,adapter_version,completed_at<deadline_at,row_to_json(d)::text FROM worker_dispatches d WHERE tenant_id=%s AND id=%s",(TENANT,ident))
            state,claim,key,spec,version,before_deadline,payload=cur.fetchone()
        assert (state,claim,spec,version,before_deadline)==('succeeded',1,1,'1.0',True),'EXECUTION_INVARIANT_FAILED'
        duplicate=create_dispatch(tenant_id=TENANT,worker_node_id=WORKER,
            route_key='synthetic/local',gateway_model='synthetic/local',
            prompt='Controlled remote adapter acceptance',idempotency_key=key)
        assert duplicate==ident,'DUPLICATE_LOGICAL_EXECUTION'
        for name in ('command','executable','shell','powershell','environment','arbitrary_args','credential_ref','token'):
            assert name not in json.loads(payload),'UNSAFE_EXECUTION_FIELD'
        secrets=[v for k,v in os.environ.items() if re.search(r'token|api.?key|password|secret|database_url|master_key',k,re.I) and len(v)>8]
        assert not any(value in payload for value in secrets),'ENVIRONMENT_SECRET_IN_DISPATCH'
        assert 'devai_wkr_' not in payload,'WORKER_TOKEN_IN_DISPATCH'
        report={'dispatch_id':str(ident),'worker_id':str(WORKER),'status':state,
            'claim_version':claim,'spec_version':spec,'adapter_version':version,
            'result':result.content,'idempotency_duplicate_same_dispatch':True,
            'capabilities':caps,'codex_route_ineligible':True,'completed_before_deadline':True,
            'controller_environment_secrets_absent':True,'unsafe_fields_absent':True}
        Path('/tmp/devai-foundation-e2e.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report,indent=2))
    finally:
        # Synthetic fixtures must not serve real production model tasks.
        set_route_enabled(TENANT,'synthetic/local',False)
        with connect() as conn,conn.cursor() as cur:
            cur.execute('UPDATE provider_connections SET enabled=FALSE WHERE tenant_id=%s AND id=%s',(TENANT,connection))


if __name__=='__main__':
    run()
