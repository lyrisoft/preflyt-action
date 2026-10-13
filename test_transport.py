import importlib.util
from pathlib import Path
import unittest
import io
import itertools
from contextlib import redirect_stdout
from urllib.error import HTTPError
from unittest.mock import patch
spec = importlib.util.spec_from_file_location("transport", Path(__file__).with_name("transport.py"))
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)

class PublicationGateTests(unittest.TestCase):
    def test_pending_then_verified_success(self):
        with patch.object(transport, "api", side_effect=[{"state": "PENDING"}, {"state": "PASSED"}]) as api, patch.object(transport.time, "sleep"):
            transport.wait_for_publication("123", "2")
            self.assertEqual(api.call_count, 2)
            self.assertIn("attempt=2", api.call_args.args[0])

    def test_failure_and_unrecognized_receipt_fail(self):
        for state in ["FAILED", "COMPLETE", None]:
            with patch.object(transport, "api", return_value={"state": state}):
                with self.assertRaises(ValueError):
                    transport.wait_for_publication("123", "1")

    def test_timeout_and_api_failure_fail(self):
        with patch.object(transport.time, "monotonic", side_effect=[0, 901]):
            with self.assertRaises(TimeoutError):
                transport.wait_for_publication("123", "1")
        with patch.object(transport, "api", side_effect=OSError("offline")):
            with self.assertRaises(OSError):
                transport.wait_for_publication("123", "1")

    def test_logs_stage_changes_and_verified_completion(self):
        replies = [
            {"state": "PENDING", "stage": "RESULT_VERIFICATION"},
            {"state": "PENDING", "stage": "AI_REVIEW"},
            {"state": "PENDING", "stage": "AI_PUBLICATION"},
            {"state": "PASSED", "stage": "COMPLETE"},
        ]
        output = io.StringIO()
        with patch.object(transport, "api", side_effect=replies), patch.object(transport.time, "sleep"), redirect_stdout(output):
            transport.wait_for_publication("123", "1")
        self.assertIn("Verifying submitted execution evidence", output.getvalue())
        self.assertIn("Waiting for the configured AI review", output.getvalue())
        self.assertIn("Waiting for AI feedback publication", output.getvalue())
        self.assertIn("Verified GitHub publication", output.getvalue())

    def test_unchanged_stage_has_bounded_heartbeat(self):
        replies = [{"state": "PENDING", "stage": "AI_REVIEW"}] * 5 + [{"state": "PASSED"}]
        output = io.StringIO()
        with patch.object(transport, "api", side_effect=replies), patch.object(transport.time, "sleep"), patch.object(transport.time, "monotonic", side_effect=itertools.count(0, 5)), redirect_stdout(output):
            transport.wait_for_publication("123", "1")
        self.assertEqual(output.getvalue().count("Waiting for the configured AI review"), 2)
        self.assertIn("40s elapsed", output.getvalue())

    def test_unknown_stage_and_message_are_never_logged(self):
        private = "Bearer private-token\n::error::injected"
        output = io.StringIO()
        with patch.object(transport, "api", side_effect=[{"state": "PENDING", "stage": private, "message": private}, {"state": "PASSED"}]), patch.object(transport.time, "sleep"), redirect_stdout(output):
            transport.wait_for_publication("123", "1")
        self.assertNotIn(private, output.getvalue())
        self.assertIn("Waiting for verified Preflyt results", output.getvalue())

    def test_known_failure_has_actionable_local_reason(self):
        with patch.object(transport, "api", return_value={"state": "FAILED", "stage": "AI_PUBLICATION_FAILED", "message": "private provider response"}):
            with self.assertRaises(transport.GateError) as caught:
                transport.wait_for_publication("123", "1")
        text = transport.gate_error_message(caught.exception)
        self.assertIn("AI_PUBLICATION_FAILED", text)
        self.assertNotIn("private provider response", text)

    def test_failure_sanitizes_exception_bodies_urls_and_workflow_commands(self):
        private = "Bearer private-token\n::warning::injected"
        errors = [
            transport.GateError(private), RuntimeError(private), OSError(private),
            HTTPError("https://private.example/?token=secret", 403, private, {}, None),
        ]
        for error in errors:
            text = transport.gate_error_message(error)
            self.assertNotIn("private", text)
            self.assertNotIn("secret", text)
            self.assertNotIn("::warning::", text)
            if isinstance(error, HTTPError):
                error.close()
        self.assertIn("API_HTTP_403", transport.gate_error_message(errors[-1]))
        self.assertIn("GATE_TIMEOUT", transport.gate_error_message(transport.GateTimeout()))

    def test_malformed_receipt_fails_without_logging_contents(self):
        for receipt in [[], "private", {"state": "UNKNOWN", "stage": "private"}]:
            with patch.object(transport, "api", return_value=receipt):
                with self.assertRaises(transport.GateError):
                    transport.wait_for_publication("123", "1")
