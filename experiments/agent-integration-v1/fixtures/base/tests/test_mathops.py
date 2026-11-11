import unittest

from src.mathops import compute


class ComputeTests(unittest.TestCase):
    def test_positive_difference(self):
        self.assertEqual(compute(9, 4), 5)

    def test_negative_difference(self):
        self.assertEqual(compute(3, 8), -5)


if __name__ == "__main__":
    unittest.main()
