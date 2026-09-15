"""Тесты нормализации: гомоглифы, punycode, leet, Левенштейн."""
import pytest

from normalize import (canonical, decode_punycode, fold_homoglyphs,
                       fold_leet, has_non_ascii, levenshtein, mixed_scripts)


def test_punycode_decoded():
    assert decode_punycode("xn--80ak6aa92e.com").endswith(".com")
    assert decode_punycode("xn--80ak6aa92e.com") != "xn--80ak6aa92e.com"


def test_punycode_broken_label_survives():
    """Битый ACE не должен ронять анализатор."""
    assert decode_punycode("xn--!!!.com") == "xn--!!!.com"


def test_punycode_passthrough():
    assert decode_punycode("example.com") == "example.com"


@pytest.mark.parametrize("raw,expected", [
    ("аmazon", "amazon"),      # кириллическая а
    ("gоogle", "google"),      # кириллическая о
    ("рaypal", "paypal"),      # кириллическая р
])
def test_homoglyphs_folded(raw, expected):
    assert fold_homoglyphs(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("paypa1", "paypal"), ("g00gle", "google"), ("micr0s0ft", "microsoft"),
])
def test_leet_folded(raw, expected):
    assert fold_leet(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("arnazon", "amazon"),          # rn → m
    ("vvhatsapp", "whatsapp"),      # vv → w
    ("pay-pal", "paypal"),          # разделители выкидываются
])
def test_canonical_sequences(raw, expected):
    assert canonical(raw) == expected


def test_mixed_scripts_detects_cyrillic_in_latin():
    assert mixed_scripts("аmazon") is True
    assert mixed_scripts("amazon") is False
    assert mixed_scripts("амазон") is False  # чистая кириллица — не смешение


def test_levenshtein_basics():
    assert levenshtein("google", "google") == 0
    assert levenshtein("gogle", "google") == 1
    assert levenshtein("arnazon", "amazon") == 2


def test_levenshtein_early_exit():
    """При превышении порога возвращается max_distance+1, а не точное значение."""
    assert levenshtein("a" * 30, "b" * 30, max_distance=2) == 3


def test_has_non_ascii():
    assert has_non_ascii("аmazon.com") is True
    assert has_non_ascii("amazon.com") is False
