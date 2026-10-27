# SCA test fixtures

| File | Origin | Used for |
|---|---|---|
| `upstream-pip.json` | **Real Trivy output**: copy of `integration/testdata/pip.json.golden` from <https://github.com/aquasecurity/trivy> (commit `4e948808830af7bc0f02c9f8107ab0e9d2d4efce`, Apache-2.0 licence). It is a golden file of the Trivy project's own integration tests, not a scan made by this project. Its `Trivy.Version` is `dev`. | Proves the converter reads the real report shape, including `Packages[].Locations` line numbers. |
| `synthetic-demo-app.json` | **Synthetic**, hand-written in the same schema to mimic a scan of `demo-app/vulnerable`. It says nothing about what a real vulnerability database returns. It also contains a duplicate entry, a GHSA-only entry, an unknown severity label and an `UNKNOWN` severity. | Mapping, de-duplication, fallback line lookup, ordering. |
| `clean.json` | Synthetic: one manifest, no vulnerabilities. | Zero-finding scan. |
| `no-manifests.json` | Synthetic: no `Results` key (what Trivy emits for a tree without supported manifests). | "No manifests" is a valid empty scan, not a failure. |
