"""Tests for tiny_input_sanitize v0.1.0."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tiny_input_sanitize as tis
from tiny_input_sanitize import (
    SanitizationContext,
    SanitizationResult,
    is_safe,
    sanitize_for_filename,
    sanitize_for_html,
    sanitize_for_jsonpath,
    sanitize_for_log,
    sanitize_for_shell_arg,
    sanitize_for_sql_literal,
    sanitize_text,
)


class TestResultDataclass(unittest.TestCase):
    def test_clean_input_has_full_confidence(self):
        r = sanitize_for_html("hello world")
        self.assertTrue(r.is_clean)
        self.assertEqual(r.confidence, 1.0)
        self.assertEqual(r.value, "hello world")
        self.assertEqual(r.applied_rules, [])

    def test_to_dict_shape(self):
        r = sanitize_for_html("<b>x</b>")
        d = r.to_dict()
        self.assertEqual(d["context"], "html")
        self.assertIn("html_chars", d["applied_rules"])
        self.assertEqual(d["is_clean"], False)
        self.assertEqual(d["original_length"], len("<b>x</b>"))

    def test_was_truncated_property(self):
        r = sanitize_text("abcdefghij", max_length=3)
        self.assertTrue(r.was_truncated)
        self.assertEqual(r.value, "abc")


class TestTypeErrors(unittest.TestCase):
    def test_non_string_raises(self):
        with self.assertRaises(TypeError):
            sanitize_text(123)
        with self.assertRaises(TypeError):
            sanitize_text(None)


class TestHTML(unittest.TestCase):
    def test_basic_tags_stripped(self):
        r = sanitize_for_html("<script>alert(1)</script>")
        self.assertEqual(r.value, "&lt;script&gt;alert(1)&lt;/script&gt;")
        self.assertIn("html_chars", r.applied_rules)

    def test_ampersand_escaped(self):
        r = sanitize_for_html("AT&T")
        self.assertEqual(r.value, "AT&amp;T")

    def test_quotes_escaped(self):
        r = sanitize_for_html('he said "hi"')
        self.assertEqual(r.value, "he said &quot;hi&quot;")

    def test_javascript_uri_blocked(self):
        r = sanitize_for_html("javascript:alert(1)")
        self.assertIn("html_uri_scheme", r.applied_rules)
        self.assertNotIn("javascript:", r.value)

    def test_data_uri_blocked(self):
        r = sanitize_for_html("data:text/html,<h1>x</h1>")
        self.assertNotIn("data:", r.value)

    def test_safe_text_passes_through(self):
        r = sanitize_for_html("Hello, World!")
        self.assertTrue(r.is_clean)
        self.assertEqual(r.value, "Hello, World!")

    def test_normal_text_confidence_one(self):
        r = sanitize_for_html("plain text")
        self.assertEqual(r.confidence, 1.0)


class TestSQL(unittest.TestCase):
    def test_single_quote_doubled(self):
        r = sanitize_for_sql_literal("O'Reilly")
        self.assertEqual(r.value, "O''Reilly")
        self.assertIn("sql_quote", r.applied_rules)

    def test_backslash_doubled(self):
        # In Python, "a\\b" is a string of length 4: a, backslash, backslash, b.
        r = sanitize_for_sql_literal("a\\b")
        # SQL transform doubles each backslash -> 2 become 4
        self.assertEqual(r.value, "a\\\\b")
        self.assertIn("sql_quote", r.applied_rules)

    def test_nul_byte_stripped(self):
        r = sanitize_for_sql_literal("abc" + chr(0) + "def")
        self.assertNotIn(chr(0), r.value)
        self.assertIn("sql_nul", r.applied_rules)

    def test_safe_value_clean(self):
        r = sanitize_for_sql_literal("plain_identifier_42")
        self.assertTrue(r.is_clean)


class TestShell(unittest.TestCase):
    def test_metachars_stripped(self):
        r = sanitize_for_shell_arg("foo; rm -rf /")
        self.assertNotIn(";", r.value)
        self.assertNotIn("|", r.value)
        self.assertIn("shell_meta", r.applied_rules)

    def test_dollar_stripped(self):
        r = sanitize_for_shell_arg("$(whoami)")
        self.assertNotIn("$", r.value)

    def test_safe_filename_clean(self):
        r = sanitize_for_shell_arg("report.pdf")
        self.assertTrue(r.is_clean)


class TestFilename(unittest.TestCase):
    def test_path_separators_stripped(self):
        r = sanitize_for_filename("../../../etc/passwd")
        self.assertNotIn("/", r.value)
        self.assertEqual(r.value, "passwd")

    def test_windows_path(self):
        r = sanitize_for_filename("C:\\Windows\\System32\\evil.exe")
        self.assertNotIn("\\", r.value)
        self.assertEqual(r.value, "evil.exe")

    def test_reserved_name_prefixed(self):
        r = sanitize_for_filename("CON")
        self.assertEqual(r.value, "_CON")
        self.assertIn("filename_reserved", r.applied_rules)

    def test_leading_dot_stripped(self):
        r = sanitize_for_filename(".hidden")
        self.assertFalse(r.value.startswith("."))
        self.assertIn("filename_leading_dot", r.applied_rules)

    def test_trailing_space_stripped(self):
        r = sanitize_for_filename("name   ")
        self.assertEqual(r.value, "name")
        self.assertIn("filename_trailing_space", r.applied_rules)

    def test_empty_input_replaced(self):
        r = sanitize_for_filename("")
        self.assertEqual(r.value, "untitled")
        self.assertIn("filename_empty", r.applied_rules)

    def test_bad_chars_replaced_with_underscore(self):
        r = sanitize_for_filename("a:b*c?d|e")
        self.assertEqual(r.value, "a_b_c_d_e")


class TestLog(unittest.TestCase):
    def test_ansi_stripped(self):
        r = sanitize_for_log("" + chr(0x1b) + "[31mRED" + chr(0x1b) + "[0m")
        self.assertNotIn(chr(0x1b), r.value)
        self.assertEqual(r.value, "RED")
        self.assertIn("log_ansi", r.applied_rules)

    def test_control_chars_replaced(self):
        r = sanitize_for_log("a" + chr(1) + "b" + chr(2) + "c")
        self.assertEqual(r.value, "a?b?c")
        self.assertIn("log_control", r.applied_rules)

    def test_newline_preserved(self):
        r = sanitize_for_log("line1\nline2")
        self.assertIn("\n", r.value)
        self.assertNotIn("strip_control", r.applied_rules)

    def test_tab_preserved(self):
        r = sanitize_for_log("col1\tcol2")
        self.assertIn("\t", r.value)


class TestJSONPath(unittest.TestCase):
    def test_dots_replaced(self):
        r = sanitize_for_jsonpath("foo.bar")
        self.assertEqual(r.value, "foo_bar")

    def test_brackets_replaced(self):
        r = sanitize_for_jsonpath("foo[0]")
        self.assertNotIn("[", r.value)
        self.assertNotIn("]", r.value)

    def test_dollar_replaced(self):
        r = sanitize_for_jsonpath("$.root")
        self.assertNotIn("$", r.value)


class TestAllowDeny(unittest.TestCase):
    def test_deny_strips_individual_chars(self):
        r = sanitize_text("hello world", deny="lo")
        self.assertNotIn("l", r.value)
        self.assertNotIn("o", r.value)
        self.assertIn("deny_char", r.applied_rules)

    def test_allow_keeps_only_listed(self):
        r = sanitize_text("abc123", allow="abc")
        self.assertEqual(r.value, "abc")
        self.assertIn("allow_filter", r.applied_rules)


class TestMaxLength(unittest.TestCase):
    def test_truncation(self):
        r = sanitize_text("abcdefghij", max_length=5)
        self.assertEqual(r.value, "abcde")
        self.assertTrue(r.was_truncated)

    def test_no_truncation_when_short(self):
        r = sanitize_text("abc", max_length=10)
        self.assertEqual(r.value, "abc")
        self.assertFalse(r.was_truncated)


class TestUnicodeNormalization(unittest.TestCase):
    def test_compatibility_decomposition(self):
        r = sanitize_text("Ａ", normalize_unicode=True)
        self.assertEqual(r.value, "A")
        self.assertIn("normalize_unicode", r.applied_rules)

    def test_no_normalize_keeps_input(self):
        r = sanitize_text("Ａ", normalize_unicode=False)
        self.assertEqual(r.value, "Ａ")
        self.assertNotIn("normalize_unicode", r.applied_rules)


class TestIsSafe(unittest.TestCase):
    def test_safe_passes(self):
        self.assertTrue(is_safe("hello", context="html"))

    def test_dangerous_fails(self):
        self.assertFalse(is_safe("<script>", context="html"))

    def test_threshold_adjustable(self):
        self.assertFalse(is_safe("<><><><>", context="html", threshold=0.5))


class TestConfidenceScoring(unittest.TestCase):
    def test_identical_strings_score_one(self):
        r = sanitize_for_html("hello")
        self.assertEqual(r.confidence, 1.0)

    def test_reserved_name_keeps_all_chars(self):
        r = sanitize_for_filename("CON")
        self.assertEqual(r.confidence, 1.0)

    def test_partial_mutation_partial_score(self):
        r = sanitize_for_html("a<b>c")
        self.assertAlmostEqual(r.confidence, 0.4, places=2)

    def test_completely_replaced_scores_low(self):
        r = sanitize_for_filename("../../../etc/passwd")
        self.assertLess(r.confidence, 0.5)


class TestContextEnum(unittest.TestCase):
    def test_string_aliases(self):
        for ctx in ["html", "sql", "shell", "filename", "log", "jsonpath"]:
            r = sanitize_text("test", context=ctx)
            self.assertIsInstance(r.context, SanitizationContext)
            self.assertEqual(r.context.value, ctx)

    def test_invalid_context_raises(self):
        with self.assertRaises(ValueError):
            sanitize_text("test", context="unknown")


class TestContextObjects(unittest.TestCase):
    def test_passing_enum_works(self):
        r = sanitize_text("hi", context=SanitizationContext.SHELL)
        self.assertEqual(r.context, SanitizationContext.SHELL)

    def test_result_dataclass_fields(self):
        r = sanitize_text("x")
        self.assertIsInstance(r, SanitizationResult)
        self.assertTrue(hasattr(r, "value"))
        self.assertTrue(hasattr(r, "applied_rules"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
