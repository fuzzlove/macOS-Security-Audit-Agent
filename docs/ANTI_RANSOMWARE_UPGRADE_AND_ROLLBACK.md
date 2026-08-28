# Anti-Ransomware Upgrade and Rollback

Upgrade must stage and verify native/protocol/Python/policy compatibility, preserve the incident vault and approved rules, stop intake, drain bounded queues, atomically activate components, restart health checks, and retain the last-known-good signed set. Failure restores the prior signed components and reconciles active leases before intake resumes. These steps are designed but not live installer-tested.
