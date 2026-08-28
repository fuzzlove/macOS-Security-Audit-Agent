# Anti-Ransomware License Review

MSAA declares the MIT license. RansomWhere is GPL-3.0. Direct incorporation would impose GPL obligations that have not been deliberately adopted for this repository. Therefore the implementation uses a clean-room behavioral boundary: public behavior and independently specified statistical thresholds are documented, while Objective-C source, comments, names, UI assets, and tests are not copied.

Attribution: Objective-See RansomWhere, Patrick Wardle/Objective-See contributors, official repository commit `4bed6e9bd8b0de5a6a9db3596053dba795c81b99`, reviewed 2026-07-10. Any future direct reuse requires an explicit project-wide licensing decision, provenance record, copyright preservation, and distribution review.

The upstream review was refreshed on 2026-08-26 at commit
`516918e334d1b84b9f7ddf604f91ae330e2eb444`. Changing language, framework,
names, or appearance would not remove GPL obligations from a derivative work.
MSAA therefore keeps the checkout in an ignored research cache and implements
only independently specified, generally applicable defensive behavior in its
own models and tests.
