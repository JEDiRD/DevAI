import asyncio
import hashlib
import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import psycopg
import httpx

from devai import worker_api, worker_dispatch, worker_identity, worker_registry
from devai.worker_api import app


class ApiClient:
    def get(self, path, **kwargs):
        async def send():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://worker-api.test",
            ) as client:
                return await client.get(path, **kwargs)

        return asyncio.run(send())

    def post(self, path, **kwargs):
        async def send():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://worker-api.test",
            ) as client:
                return await client.post(path, **kwargs)

        return asyncio.run(send())


class SharedTransaction:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_):
        return False


@unittest.skipUnless(
    os.environ.get("DEVAI_TEST_DATABASE_URL"),
    "set DEVAI_TEST_DATABASE_URL to run PostgreSQL integration tests",
)
class WorkerControlApiTests(unittest.TestCase):
    def setUp(self):
        self.connection = psycopg.connect(
            os.environ["DEVAI_TEST_DATABASE_URL"]
        )
        self.addCleanup(self.connection.close)
        self.addCleanup(self.connection.rollback)
        shared = SharedTransaction(self.connection)
        for module in (
            worker_api,
            worker_identity,
            worker_registry,
            worker_dispatch,
        ):
            patcher = patch.object(module, "connect", return_value=shared)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.client = ApiClient()
        self.tenant_a, self.tenant_b = uuid4(), uuid4()
        self.worker_a1, self.worker_a2, self.worker_b = (
            uuid4(), uuid4(), uuid4()
        )
        with self.connection.cursor() as cur:
            for tenant_id in (self.tenant_a, self.tenant_b):
                cur.execute(
                    "INSERT INTO tenants(id, slug, name) VALUES (%s, %s, %s)",
                    (tenant_id, str(tenant_id), "Worker API test"),
                )
            for worker_id, tenant_id in (
                (self.worker_a1, self.tenant_a),
                (self.worker_a2, self.tenant_a),
                (self.worker_b, self.tenant_b),
            ):
                cur.execute(
                    """
                    INSERT INTO worker_nodes(id, tenant_id, name)
                    VALUES (%s, %s, %s)
                    """,
                    (worker_id, tenant_id, str(worker_id)),
                )

    def auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    def route(self, tenant_id, route_key):
        connection_id = uuid4()
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO provider_connections (
                    id, tenant_id, name, transport, auth_type
                ) VALUES (%s, %s, %s, 'local_cli', 'subscription_session')
                """,
                (connection_id, tenant_id, str(connection_id)),
            )
            cur.execute(
                """
                INSERT INTO provider_routes (
                    tenant_id, connection_id, route_key, provider,
                    gateway_model, capability, cost_class, pricing_key
                ) VALUES (
                    %s, %s, %s, 'test', 'model', 'basic', 'free', 'test'
                )
                """,
                (tenant_id, connection_id, route_key),
            )

    def test_token_hash_authentication_and_revocation(self):
        issued = worker_identity.issue_worker_token(
            self.tenant_a, self.worker_a1
        )
        self.assertNotIn(issued.token, repr(issued))
        with self.connection.cursor() as cur:
            cur.execute(
                "SELECT token_hash FROM worker_tokens WHERE id = %s",
                (issued.id,),
            )
            self.assertEqual(
                bytes(cur.fetchone()[0]),
                hashlib.sha256(issued.token.encode()).digest(),
            )

        path = "/v1/worker/heartbeat"
        self.assertEqual(
            self.client.get("/healthz").json(), {"status": "ok"}
        )
        self.assertEqual(self.client.post(path, json={}).status_code, 401)
        self.assertEqual(
            self.client.post(path, headers=self.auth("invalid"), json={}).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                path,
                headers=self.auth(issued.token),
                json={"platform": "windows", "architecture": "x64"},
            ).status_code,
            204,
        )
        self.assertEqual(
            self.client.post(
                path,
                headers={
                    **self.auth(issued.token),
                    "X-Worker-Id": str(self.worker_a2),
                },
                json={},
            ).status_code,
            403,
        )
        with self.connection.cursor() as cur:
            cur.execute(
                "SELECT status, platform FROM worker_nodes WHERE id = %s",
                (self.worker_a1,),
            )
            self.assertEqual(cur.fetchone(), ("online", "windows"))

        worker_identity.revoke_worker_token(
            self.tenant_a, self.worker_a1, issued.id
        )
        self.assertEqual(
            self.client.post(
                path, headers=self.auth(issued.token), json={}
            ).status_code,
            401,
        )

    def test_rotation_rejects_old_token_and_scopes_admin_action(self):
        old = worker_identity.issue_worker_token(
            self.tenant_a, self.worker_a1
        )
        with self.assertRaises(worker_identity.WorkerTokenNotFound):
            worker_identity.revoke_worker_token(
                self.tenant_b, self.worker_b, old.id
            )

        new = worker_identity.rotate_worker_token(
            self.tenant_a, self.worker_a1, old.id
        )
        self.assertNotEqual(old.token, new.token)
        path = "/v1/worker/heartbeat"
        self.assertEqual(
            self.client.post(
                path, headers=self.auth(old.token), json={}
            ).status_code,
            401,
        )
        self.assertEqual(
            self.client.post(
                path, headers=self.auth(new.token), json={}
            ).status_code,
            204,
        )

    def test_expired_and_disabled_worker_tokens_are_rejected(self):
        issued = worker_identity.issue_worker_token(
            self.tenant_a,
            self.worker_a1,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        path = "/v1/worker/heartbeat"
        with self.connection.cursor() as cur:
            cur.execute(
                """
                UPDATE worker_tokens
                SET expires_at = now() - interval '1 second'
                WHERE id = %s
                """,
                (issued.id,),
            )
        self.assertEqual(
            self.client.post(
                path, headers=self.auth(issued.token), json={}
            ).status_code,
            401,
        )

        active = worker_identity.issue_worker_token(
            self.tenant_a, self.worker_a1
        )
        worker_registry.set_worker_status(
            self.tenant_a, self.worker_a1, "disabled"
        )
        self.assertEqual(
            self.client.post(
                path, headers=self.auth(active.token), json={}
            ).status_code,
            401,
        )

        another = worker_identity.issue_worker_token(
            self.tenant_a, self.worker_a2
        )
        with self.connection.cursor() as cur:
            cur.execute(
                "UPDATE tenants SET status = 'suspended' WHERE id = %s",
                (self.tenant_a,),
            )
        self.assertEqual(
            self.client.post(
                path, headers=self.auth(another.token), json={}
            ).status_code,
            401,
        )
        with self.assertRaises(worker_identity.WorkerTokenProvisioningError):
            worker_identity.issue_worker_token(
                self.tenant_a, self.worker_a2
            )

    def test_claim_complete_fail_are_scoped_to_tenant_and_worker(self):
        token_a1 = worker_identity.issue_worker_token(
            self.tenant_a, self.worker_a1
        ).token
        token_a2 = worker_identity.issue_worker_token(
            self.tenant_a, self.worker_a2
        ).token
        token_b = worker_identity.issue_worker_token(
            self.tenant_b, self.worker_b
        ).token
        for token in (token_a1, token_a2, token_b):
            self.assertEqual(
                self.client.post(
                    "/v1/worker/heartbeat",
                    headers=self.auth(token),
                    json={},
                ).status_code,
                204,
            )

        self.route(self.tenant_a, "test/a")
        self.route(self.tenant_b, "test/b")
        a1 = worker_dispatch.create_dispatch(
            tenant_id=self.tenant_a,
            worker_node_id=self.worker_a1,
            route_key="test/a",
            gateway_model="model",
            prompt="a1 prompt",
        )
        a2 = worker_dispatch.create_dispatch(
            tenant_id=self.tenant_a,
            worker_node_id=self.worker_a2,
            route_key="test/a",
            gateway_model="model",
            prompt="a2 prompt",
        )
        b = worker_dispatch.create_dispatch(
            tenant_id=self.tenant_b,
            worker_node_id=self.worker_b,
            route_key="test/b",
            gateway_model="model",
            prompt="b prompt",
        )

        claims = {}
        for token, expected in (
            (token_a1, a1), (token_a2, a2), (token_b, b)
        ):
            response = self.client.post(
                "/v1/worker/claim", headers=self.auth(token)
            )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["id"], str(expected))
            claims[expected] = response.json()["claim_version"]
            self.assertEqual(
                self.client.post(
                    "/v1/worker/claim", headers=self.auth(token)
                ).status_code,
                204,
            )

        for foreign in (a2, b):
            response = self.client.post(
                f"/v1/worker/dispatches/{foreign}/complete",
                headers=self.auth(token_a1),
                json={"claim_version": claims[foreign], "content": "wrong"},
            )
            self.assertEqual(response.status_code, 409)

        self.assertEqual(
            self.client.post(
                f"/v1/worker/dispatches/{a1}/complete",
                headers=self.auth(token_a1),
                json={
                    "claim_version": claims[a1] + 1,
                    "content": "wrong version",
                },
            ).status_code,
            409,
        )

        self.assertEqual(
            self.client.post(
                f"/v1/worker/dispatches/{a1}/complete",
                headers=self.auth(token_a1),
                json={"claim_version": claims[a1], "content": "done"},
            ).status_code,
            204,
        )
        self.assertEqual(
            self.client.post(
                f"/v1/worker/dispatches/{a2}/fail",
                headers=self.auth(token_a2),
                json={"claim_version": claims[a2], "error": "failed"},
            ).status_code,
            204,
        )
        self.assertEqual(
            self.client.post(
                f"/v1/worker/dispatches/{b}/complete",
                headers=self.auth(token_b),
                json={"claim_version": claims[b], "content": "done"},
            ).status_code,
            204,
        )
        with self.connection.cursor() as cur:
            cur.execute(
                """
                SELECT status FROM worker_dispatches
                WHERE id IN (%s, %s, %s)
                ORDER BY id
                """,
                (a1, a2, b),
            )
            self.assertEqual(
                sorted(row[0] for row in cur.fetchall()),
                ["failed", "succeeded", "succeeded"],
            )
