from __future__ import annotations

import unicodedata

RULE_SET_VERSION = "1.0.0"
DATA_VERSIONS = {
    "unicode": unicodedata.unidata_version,
    "uts39_profile": "MSAA-audited-subset-1",
    "confusables": "MSAA-audited-subset-2026-07",
    "cldr": "generic-keyboard-subset-2026-07",
    "normalization": "Python-unicodedata-NFC-NFD",
    "rule_set": RULE_SET_VERSION,
}

KEYBOARDS = {
    "en-US-qwerty": ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
    "en-GB-qwerty": ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
    "fr-FR-azerty": ["azertyuiop", "qsdfghjklm", "wxcvbn"],
    "de-DE-qwertz": ["qwertzuiop", "asdfghjkl", "yxcvbnm"],
    "es-ES-qwerty": ["qwertyuiop", "asdfghjklñ", "zxcvbnm"],
    "it-IT-qwerty": ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
    "pt-BR-qwerty": ["qwertyuiop", "asdfghjklç", "zxcvbnm"],
    "pl-PL-qwerty": ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
    "tr-TR-qwerty": ["qwertyuıopğü", "asdfghjklşi", "zxcvbnmöç"],
    "generic-qwerty": ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
}

SERVICE_WORDS = ("account", "login", "portal", "secure", "support", "update", "verification")
COMMON_TLDS = ("com", "net", "org", "co", "io")

SCORE_WEIGHTS = {
    "one_edit": 25, "omission": 28, "repeat": 24, "transposition": 38,
    "adjacent_key": 34, "separator": 24, "phonetic": 22, "unicode_confusable": 58,
    "mixed_script": 20, "normalization_collision": 55, "service_word": 32, "tld_confusion": 25,
}
