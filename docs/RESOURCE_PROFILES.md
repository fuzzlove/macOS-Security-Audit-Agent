# MSAA Resource Profiles

MSAA uses the `low_resource` profile by default for broadly deployed macOS workstations. Navigation pages are constructed only when first opened and then retained, so moving between sections preserves state without repeatedly rebuilding the interface.

## Low resource (general workstation)

- One concurrent scheduled task and one subprocess.
- Heavy status collection is deferred until the relevant section is opened.
- Hidden panel refresh timers stop.
- Completed scheduler history is bounded.
- Appropriate for general government users who primarily need workstation review and hardening.

## Balanced

- Two concurrent scheduled tasks and subprocesses.
- More frequent background refreshes.
- Appropriate for analyst workstations with additional memory and sustained monitoring needs.

## Thorough (contractor/forensics)

- Three concurrent scheduled tasks and subprocesses.
- Longer scan and export budgets and more frequent refresh eligibility.
- Appropriate for explicitly provisioned contractor, laboratory, or incident-response systems.

Profiles change resource ceilings and refresh behavior; they do not remove stored scan state or weaken authorization requirements. Expensive actions remain user initiated where practical.
