# Acknowledgements

TCP/UDP scan functionality can optionally use Nmap as an external scanning engine. Nmap is a separate open-source project maintained by the Nmap Project. MSAA invokes Nmap locally as a wrapper when available.

https://nmap.org/

MSAA's optional Default Credential Scanner downloads the separately licensed
NNdefaccts fingerprint dataset through the Default HTTP Login Hunter project
and invokes Nmap's `http-default-accounts` NSE script. NNdefaccts and Default
HTTP Login Hunter identify their redistributed work as GNU GPL v3 or later.
The downloaded fingerprint file remains separately attributed and is stored in
private application data; it is not relicensed as MSAA code.

https://github.com/InfosecMatter/default-http-login-hunter

https://github.com/nnposter/nndefaccts

MSAA Persistence Intelligence incorporates concepts and, where compatible, implementation ideas from macOS Persistence Radar, an open-source macOS persistence visibility and audit project.

https://github.com/fuzzlove/macOS-Persistence-Radar

## Author / Developer

Liquidsky Network Security

MSAA is developed and maintained independently.

## License transition notice

Previously distributed MSAA copies licensed under MIT retain those grants.
Future proprietary licensing is under legal review. Separately licensed
dependencies, tools, downloaded intelligence, rules, and data are not
relicensed merely because MSAA adds product activation. See
`PROPRIETARY_LICENSE_TRANSITION_DRAFT.md` and `PRODUCT_LICENSING.md`.

## Community Acknowledgements

Thank you to the NSA for helping the cybersecurity community through public cybersecurity guidance, research, and open-source contributions.

This acknowledgement does not imply endorsement, affiliation, certification, or approval.

## Standards Attribution Disclaimer

MSAA is an independent project by Liquidsky Network Security. References to NIST, CISA, DoD, NSA, PCI SSC, MITRE, or other standards bodies are for standards mapping, source attribution, and public guidance alignment only. They do not imply endorsement, sponsorship, certification, or approval.
