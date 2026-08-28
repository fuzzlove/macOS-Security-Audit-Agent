# Active Containment Contributor Handoff

Contributors provide identifiers, controlled signing access, signed artifacts, public verification evidence, or disposable-host execution—not private keys or passwords. Start with `python3.14 scripts/active_containment_contribution_preflight.py --config <non-secret.toml> --json`.

Project owner: provide the 10-character Team ID, approve final identifiers, signing policy and disposable-host use. Release signer: install identities in a controlled Keychain, set only identity/profile names in environment variables, run build/sign/verify/notarize scripts, and return signed artifacts plus public evidence. XPC/Endpoint Security engineers may contribute reviewed source and signed sensor evidence. A host operator creates a local authorization file and returns redacted evidence reports. A second-team contributor signs only the inert fixture and never transfers a key.

Never commit or paste p12/p8 files, passwords, private keys, Keychain exports, administrator passwords, or notarization secrets.
