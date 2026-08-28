# Process Injection Rules

Templates are versioned detection-as-code records containing rule ID/version, author/reviewer state, platform, required and optional primitives, contradictions, ordering, correlation interval, required sensors, confidence/severity contribution, expected benign sources, and a provisional ATT&CK external identifier that must validate against configured STIX.

Rules never match only a process name. Promotion requires preserved observations, analyst review, authorized lab reproduction where needed, synthetic regression fixtures, false-positive/performance/security review, versioned deployment, monitoring, and rollback. Generated research candidates never become production rules automatically. `msaa process-injection rules-validate` checks structural requirements; human reviewer fields remain mandatory release gates.
