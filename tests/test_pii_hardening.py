from __future__ import annotations

import unittest

from ticket_automation.pii import detect_pii, is_snils_valid, redact_pii


class PiiHardeningTests(unittest.TestCase):
    def test_passport_requires_explicit_context(self) -> None:
        passport = "12 34 567890"
        self.assertIn("russian_passport", detect_pii(f"Паспорт РФ: {passport}"))
        self.assertEqual(redact_pii(f"Паспорт РФ: {passport}"), "[RUSSIAN_PASSPORT]")
        self.assertNotIn("russian_passport", detect_pii(f"номер заказа {passport}"))

    def test_passport_series_and_number_form_is_redacted(self) -> None:
        text = "серия 12 34, номер 567890"
        self.assertIn("russian_passport", detect_pii(text))
        self.assertNotIn("567890", redact_pii(text))

    def test_checksum_valid_snils_is_detected_without_label(self) -> None:
        # Deliberately synthetic digits; the final pair only exercises the checksum rule.
        snils = "123-456-789 64"
        self.assertTrue(is_snils_valid(snils))
        self.assertIn("snils", detect_pii(f"идентификатор {snils}"))
        self.assertEqual(redact_pii(snils), "[SNILS]")

    def test_invalid_unlabelled_snils_shape_is_not_a_false_positive(self) -> None:
        synthetic_invalid = "123-456-789 00"
        self.assertFalse(is_snils_valid(synthetic_invalid))
        self.assertNotIn("snils", detect_pii(synthetic_invalid))
        self.assertEqual(redact_pii(synthetic_invalid), synthetic_invalid)

    def test_labelled_snils_is_redacted_even_after_a_typo(self) -> None:
        text = "СНИЛС: 123-456-789 00"
        self.assertIn("snils", detect_pii(text))
        self.assertEqual(redact_pii(text), "[SNILS]")

    def test_english_password_shorthand_and_symbol_value_are_redacted(self) -> None:
        for label in ("pass", "password"):
            with self.subTest(label=label):
                text = f"{label}: synthetic!42"
                self.assertIn("credential", detect_pii(text))
                self.assertEqual(redact_pii(text), "[CREDENTIAL]")

    def test_password_substring_without_assignment_is_ignored(self) -> None:
        text = "The password reset page is unavailable"
        self.assertNotIn("credential", detect_pii(text))
        self.assertEqual(redact_pii(text), text)

    def test_natural_numeric_password_is_treated_as_a_credential(self) -> None:
        for text in ("Мой пароль 12345678", "пароль 000000", "password hunter2"):
            with self.subTest(text=text):
                self.assertIn("credential", detect_pii(text))
                self.assertNotRegex(redact_pii(text), r"\d{6,}|hunter2")

    def test_one_time_code_is_typed_and_redacted(self) -> None:
        for text in (
            "код подтверждения 123456",
            "код подтверждения — 123456",
            "код подтверждения это 123456",
            "код подтверждения 123 456",
        ):
            with self.subTest(text=text):
                self.assertIn("one_time_code", detect_pii(text))
                self.assertEqual(redact_pii(text), "[ONE_TIME_CODE]")

    def test_unformatted_and_context_labeled_phone_are_redacted(self) -> None:
        for text in ("Телефон 79991234567", "телефон: 9991234567"):
            with self.subTest(text=text):
                self.assertIn("phone", detect_pii(text))
                self.assertNotRegex(redact_pii(text), r"\d{10,11}")

    def test_card_with_repeated_space_or_dot_separators_is_redacted(self) -> None:
        for value in (
            "4111  1111  1111  1111",
            "4111.1111.1111.1111",
            "4111–1111–1111–1111",
            "4111—1111—1111—1111",
        ):
            with self.subTest(value=value):
                self.assertIn("card_number", detect_pii(value))
                self.assertEqual(redact_pii(value), "[CARD_NUMBER]")


if __name__ == "__main__":
    unittest.main()
