# Anti-Ransomware Managed Deployment

Templates under `packaging/anti_ransomware/mdm` contain explicit Team ID, bundle ID, code-requirement, organization, and UUID placeholders. They are not deployable until an administrator replaces and signs them. Use SystemExtensions/SMAppService where supported; MDM may preapprove system extension, privacy access, background items, and notifications. No profile fabricates a Team ID or silently grants TCC.
