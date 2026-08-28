# RCE false-positive review

MSAA never autonomously declares an RCE candidate false positive. Reviewers use `msaa rce-monitor events-show` to inspect facts, rules, missing evidence, CVE criteria, and immutable raw-evidence hashes. `events-disposition` requires an allowed local UID, protected reviewer reference, and non-empty reason. The decision is stored separately and the event/raw evidence remains.

Suppression requires an owner, reason, expiration, audit record, and authorization. Broad wildcard suppression additionally requires elevated approval. Matching activity remains counted; health, loss, and tamper events are not ordinary suppressible detections.
