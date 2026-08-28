# RCE rule authoring

Rules are trusted, versioned Python predicates in `rce_monitor/rules.py`; remote or user-supplied executable rules are not accepted. Each rule returns only an identifier, version, weight, and evidence-grounded signal. A high-sensitivity threshold preserves one strong or qualifying weak signal. Multiple signals add confidence but never produce `CONFIRMED_REMOTE_CODE_EXECUTION`.

Changes require code review, synthetic positive/negative fixtures, a version increment, configuration/rule audit evidence, and deployment through the signed application release. ATT&CK identifiers may be attached only after validation against an administrator-supplied, versioned STIX source. Missing data fails visibly and no identifier is invented.
