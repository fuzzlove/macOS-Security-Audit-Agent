# Notarization

Create an approved `notarytool` keychain profile outside the repository, sign the app, archive it, then run:

```bash
export MSAA_NOTARYTOOL_PROFILE=MSAA-NOTARY
scripts/notarize-app.sh MSAA-arm64.zip
scripts/staple-app.sh 'Mac Audit Agent.app'
spctl --assess --type execute --verbose=4 'Mac Audit Agent.app'
```

Notarization cannot be claimed until submission succeeds and the ticket validates. Local integrity signatures do not substitute for Apple notarization.
