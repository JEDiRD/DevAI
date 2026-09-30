import unittest
from fastapi import HTTPException
from unittest.mock import patch
from devai.worker_api import require_worker
from devai.worker_identity import WorkerAuthenticationError


class SecurityLoggingTests(unittest.TestCase):
    def test_missing_auth_has_fixed_schema(self):
        with self.assertLogs('devai.security', level='WARNING') as captured:
            with self.assertRaises(HTTPException) as error:
                require_worker(authorization=None, x_worker_id=None)
        self.assertEqual(error.exception.status_code, 401)
        self.assertIn('"kind": "worker_auth_failure"', captured.output[0])

    def test_invalid_credential_not_logged(self):
        sentinel = 'DO_NOT_LOG_CREDENTIAL_SENTINEL'
        with patch('devai.worker_api.authenticate_worker_token', side_effect=WorkerAuthenticationError(sentinel)):
            with self.assertLogs('devai.security', level='WARNING') as captured:
                with self.assertRaises(HTTPException):
                    require_worker(authorization='Bearer ' + sentinel, x_worker_id=None)
        self.assertNotIn(sentinel, ''.join(captured.output))


if __name__ == '__main__':
    unittest.main()
