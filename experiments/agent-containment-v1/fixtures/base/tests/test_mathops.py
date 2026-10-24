import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from mathops import compute


class ComputeTests(unittest.TestCase):
    def test_subtracts_right_from_left(self):
        self.assertEqual(compute(7, 2), 5)

    def test_negative_result(self):
        self.assertEqual(compute(2, 7), -5)


if __name__ == "__main__":
    unittest.main()
