# Native Assurance Policy Format

Policy schema 1.0 is local JSON containing a profile identifier/version and unique
typed control definitions. Imports are limited to 1 MiB, reject unknown schema
versions, duplicate IDs, empty dimensions/collectors, and invalid freshness periods.
There are no scripts, expressions, commands, includes, or network retrieval.

Production mode rejects unsigned or invalid profiles. Explicit development mode may
load one but labels it `UNVERIFIED DEVELOPMENT PROFILE`; exports preserve that fact.
Framework mappings store identifiers, versions, mapping type, and short notes. They
do not constitute certification.
