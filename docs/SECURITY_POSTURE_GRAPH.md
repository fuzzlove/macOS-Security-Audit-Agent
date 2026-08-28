# Security Posture Graph Engine

The Security Posture Graph Engine adds temporal and contextual risk-path analysis to MSAA's existing `EvidenceGraph`. It does not replace the evidence graph, security timeline, intrusion correlation, CSAE, or module-specific detectors.

## Correlation contract

An accepted event requires an event ID, parseable timestamp, source module, and at least one evidence reference. Entities must have an explicit type and stable identifier. Sensitive fields such as passwords, tokens, secrets, credentials, and private keys are removed from entity attributes.

Events receive a temporal relationship only when they share an explicit entity identifier and occur within the configured window. ATT&CK mappings, severity, text similarity, or close timestamps alone do not establish a relationship.

A risk path requires at least three temporally connected events from at least two source modules. Every path separates:

- observed facts: timestamped source events;
- analyst interpretation: why the connected activity may warrant investigation;
- limitations: proximity and shared entities do not prove causation, compromise, attribution, or maliciousness.

## Risk scoring

Graph risk adjusts a supplied posture score only when a qualified path exists. The bounded penalty considers path length, confidence, and contextual severity rather than simply adding event severity values. Privileged-user and threat-intelligence factors are ignored unless the caller supplies evidence references.

## Storage and workflows

Graph entities, relationships, events, and integrity-hashed graph payloads are stored in SQLite. The existing evidence-graph dashboard displays enriched node/edge data, path count, score transition, and qualification. HTML and JSON reports include qualified paths and limitations.

Incident integration is decision support only. A high-confidence high/critical path may be eligible for an authorization-required evidence-preservation workflow; MSAA does not create an incident or perform containment automatically.

The graph covers only events and entities supplied by configured MSAA collectors. It cannot establish relationships to other systems without evidence for those systems.
