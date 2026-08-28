# Apple Endpoint Security Entitlement

The `com.apple.developer.endpoint-security.client` entitlement requires Apple approval. An entitlement plist in source is not evidence of approval. Production requires an approved provisioning/distribution configuration, matching Developer ID-signed host and extension, expected Team ID and signing identifier, notarization, activation approval, and successful `es_new_client` evidence.

MSAA must not fabricate approval or replace Endpoint Security with polling while claiming equivalent enforcement. Without approval it remains degraded observation.
