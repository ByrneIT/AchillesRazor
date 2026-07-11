import unittest

from AchillesRazor.ics_encryption_check import run_ot_check


class EncryptionRegressionTests(unittest.TestCase):
    def test_loopback_target_does_not_raise_false_positive_warning(self):
        result = run_ot_check("127.0.0.1")

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["severity"], "low")


if __name__ == "__main__":
    unittest.main()
