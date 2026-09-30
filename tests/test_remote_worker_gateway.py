import unittest
from unittest.mock import patch
from uuid import uuid4
from devai.remote_worker_gateway import RemoteWorkerGateway,RemoteWorkerError


class RemoteWorkerGatewayTests(unittest.TestCase):
    def gateway(self,wait=65):
        return RemoteWorkerGateway(tenant_id=uuid4(),worker_node_id=uuid4(),
            connection_id=uuid4(),route_key='test',maximum_wait_seconds=wait)

    def test_poll_connectivity_retries_do_not_create_another_dispatch(self):
        ident=uuid4()
        with patch('devai.remote_worker_gateway.create_dispatch',return_value=ident) as create,patch('devai.remote_worker_gateway.get_dispatch_result',side_effect=[OSError('FAKE_SECRET'),('pending',None,None,None,None,None),('succeeded','REMOTE_ADAPTER_OK',None,None,None,None)]),patch('devai.remote_worker_gateway.time.sleep'):
            self.assertEqual(self.gateway().complete('model','test').content,'REMOTE_ADAPTER_OK')
        create.assert_called_once()

    def test_terminal_errors_are_typed_without_worker_detail_or_fallback(self):
        for state,code in (('expired','REMOTE_DEADLINE_EXCEEDED'),('failed','REMOTE_EXECUTION_FAILED'),('cancelled','REMOTE_CANCELLED')):
            with patch('devai.remote_worker_gateway.create_dispatch',return_value=uuid4()) as create,patch('devai.remote_worker_gateway.get_dispatch_result',return_value=(state,None,None,None,None,'FAKE_SECRET')):
                with self.assertRaises(RemoteWorkerError) as found:self.gateway().complete('model','test')
                self.assertEqual(str(found.exception),code)
                create.assert_called_once()

    def test_bounded_poll_timeout_cancels_without_retrying_model(self):
        with patch('devai.remote_worker_gateway.create_dispatch',return_value=uuid4()) as create,patch('devai.remote_worker_gateway.time.monotonic',side_effect=[0,2]),patch('devai.remote_worker_gateway.cancel_dispatch') as cancel:
            with self.assertRaises(RemoteWorkerError):self.gateway(1).complete('model','test')
        create.assert_called_once();cancel.assert_called_once()
