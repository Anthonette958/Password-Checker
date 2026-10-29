import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import tricky


class TestWordlist(unittest.TestCase):
    def test_missing_wordlist_returns_empty(self):
        self.assertEqual(tricky.load_wordlist("/no/such/file.txt"), set())

    def test_load_wordlist(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        with open(path, "w") as f:
            f.write("password\nfoo\n# comment\n\nbar\n")
        try:
            wl = tricky.load_wordlist(path)
            self.assertEqual(wl, {"password", "foo", "bar"})
        finally:
            os.remove(path)


class TestEntropy(unittest.TestCase):
    def test_pool_size(self):
        self.assertEqual(tricky.char_pool_size(""), 0)
        self.assertEqual(tricky.char_pool_size("abc"), 26)
        self.assertEqual(tricky.char_pool_size("ABC"), 26)
        self.assertEqual(tricky.char_pool_size("abcABC"), 52)
        self.assertEqual(tricky.char_pool_size("abc123"), 36)
        self.assertEqual(tricky.char_pool_size("aB1!"), 26 + 26 + 10 + 32)

    def test_theoretical_entropy(self):
        self.assertEqual(tricky.theoretical_entropy(""), 0.0)
        # 'aaaa' has lowercase only -> 4*log2(26)
        self.assertAlmostEqual(tricky.theoretical_entropy("aaaa"), 4 * __import__("math").log2(26), places=5)


class TestCommon(unittest.TestCase):
    def test_common_match(self):
        wl = {"password", "qwerty"}
        self.assertTrue(tricky.is_common_password("password", wl)[0])
        self.assertTrue(tricky.is_common_password("PASSWORD", wl)[0])
        self.assertFalse(tricky.is_common_password("xYz!9q", wl)[0])

    def test_substitution_common(self):
        wl = {"password"}
        self.assertTrue(tricky.is_common_password("p@ssw0rd", wl)[0])


class TestPatterns(unittest.TestCase):
    def test_repeated(self):
        self.assertEqual(tricky.detect_repeated("aaabbb"), ["a", "b"])
        self.assertEqual(tricky.detect_repeated("abc"), [])

    def test_sequences(self):
        seqs = tricky.detect_sequences("abc123")
        self.assertIn("abc", seqs)
        self.assertIn("123", seqs)

    def test_predictable(self):
        wl = set()
        found = tricky.detect_predictable_words("mypassword1", wl)
        self.assertIn("password", found)


class TestAssess(unittest.TestCase):
    def test_common_very_weak(self):
        wl = {"password123"}
        r = tricky.assess("password123", wl)
        self.assertEqual(r["rating"], "Very Weak")
        self.assertTrue(r["common_password"])

    def test_empty(self):
        r = tricky.assess("", set())
        self.assertEqual(r["rating"], "Very Weak")

    def test_has_recommendations(self):
        r = tricky.assess("abc", set())
        self.assertTrue(len(r["recommendations"]) > 0)

    def test_zxcvbn_score_range(self):
        r = tricky.assess("Xk9#mP2$vLqR7!nQ", set())
        self.assertGreaterEqual(r["zxcvbn_score"], 0)
        self.assertLessEqual(r["zxcvbn_score"], 4)


if __name__ == "__main__":
    unittest.main()
