"""Bounded dispatch polling; model fallback belongs solely to Executor."""
import random
import time
from uuid import uuid4
from .gateway import GatewayError, GatewayResult, GatewayConnectionError, ExecutionSafetyError
from .worker_dispatch import (create_dispatch,get_dispatch_result,cancel_dispatch,termination_confirmed,
                              DispatchUnavailable,MAX_TIMEOUT_SECONDS)


class RemoteWorkerError(GatewayError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class RemoteWorkerGateway:
    def __init__(self, *, tenant_id, worker_node_id, connection_id, route_key,
                 maximum_wait_seconds=MAX_TIMEOUT_SECONDS+5):
        if not 1 <= maximum_wait_seconds <= MAX_TIMEOUT_SECONDS+5:
            raise ValueError('INVALID_POLLING_LIMIT')
        self.tenant_id,self.worker_node_id = tenant_id,worker_node_id
        self.connection_id,self.route_key = connection_id,route_key
        self.maximum_wait_seconds = maximum_wait_seconds
        self.last_dispatch_id = None

    def complete(self, model, prompt):
        try:
            dispatch_id = create_dispatch(tenant_id=self.tenant_id,
                worker_node_id=self.worker_node_id, connection_id=self.connection_id,
                route_key=self.route_key, gateway_model=model,prompt=prompt,
                idempotency_key=uuid4())
        except DispatchUnavailable:
            raise RemoteWorkerError('REMOTE_ROUTE_UNAVAILABLE') from None
        except Exception:
            raise GatewayConnectionError('REMOTE_DISPATCH_CREATION_UNAVAILABLE') from None
        self.last_dispatch_id = dispatch_id
        end = time.monotonic()+self.maximum_wait_seconds
        delay = 0.1
        while time.monotonic()<end:
            try:
                status,content,pt,ct,request_id,error = get_dispatch_result(dispatch_id,tenant_id=self.tenant_id)
            except DispatchUnavailable:
                raise ExecutionSafetyError('REMOTE_TERMINATION_UNCONFIRMED') from None
            except Exception:
                # Polling reconnect only: never create a second execution.
                time.sleep(min(1.5,delay*random.uniform(.8,1.2),max(0,end-time.monotonic())))
                delay=min(1.5,delay*1.5)
                continue
            if status in ('succeeded','failed','expired','cancelled'):
                try:
                    confirmed=termination_confirmed(tenant_id=self.tenant_id,dispatch_id=dispatch_id)
                except Exception:
                    confirmed=False  # Unknown containment never permits fallback.
                if not confirmed:
                    time.sleep(min(.2,max(0,end-time.monotonic())))
                    continue
            if status=='succeeded':
                return GatewayResult(content,pt,ct,request_id)
            if status in ('failed','expired','cancelled'):
                raise RemoteWorkerError({'failed':'REMOTE_EXECUTION_FAILED',
                    'expired':'REMOTE_DEADLINE_EXCEEDED','cancelled':'REMOTE_CANCELLED'}[status])
            time.sleep(min(1.5,delay*random.uniform(.8,1.2),max(0,end-time.monotonic())))
            delay=min(1.5,delay*1.5)
        try:
            cancel_dispatch(tenant_id=self.tenant_id,dispatch_id=dispatch_id)
        except Exception:
            pass  # Absolute immutable deadline still fences execution/results.
        try:
            if termination_confirmed(tenant_id=self.tenant_id,dispatch_id=dispatch_id):
                raise RemoteWorkerError('REMOTE_POLL_TIMEOUT')
        except RemoteWorkerError:
            raise
        except Exception:
            pass
        raise ExecutionSafetyError('REMOTE_TERMINATION_UNCONFIRMED')
