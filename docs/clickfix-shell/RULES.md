# Rules

Stable primary rule IDs are `network_to_interpreter`, `decoded_content_to_interpreter`, `clipboard_to_interpreter`, `download_stage_execute`, `applescript_shell_execution`, `security_control_weakening`, `persistence_creation`, and `sensitive_data_access`. Supporting rules cover Unicode/control anomalies, escaped names, reconstruction, static decoded content, and history/output evasion.

Scores 0–3 allow, 4–6 warn, and 7+ block. High-confidence pasted execution relationships hard block. Executable names alone are not malicious. Disabled rules and exceptions must be narrowly governed; command exceptions are exact SHA-256 hashes.
