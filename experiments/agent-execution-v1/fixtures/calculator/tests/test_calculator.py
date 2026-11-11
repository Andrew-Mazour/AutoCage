import unittest

from src.calculator import add, multiply, subtract


class CalculatorTests(unittest.TestCase):
    def test_addition(self):
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(-2, 3), 1)

    def test_subtraction(self):
        self.assertEqual(subtract(8, 3), 5)

    def test_multiplication(self):
        self.assertEqual(multiply(4, 3), 12)


if __name__ == "__main__":
    unittest.main()
