# OCSF schema provenance

`detection_finding-1.8.0.schema.json` is the official JSON Schema for the OCSF
**Detection Finding** class (`class_uid 2004`, category Findings), pinned to OCSF
schema version **1.8.0** (released 2026-03-18).

## Source

Downloaded from the official OCSF schema server:

```
https://schema.ocsf.io/schema/1.8.0/classes/detection_finding
```

It is a Draft-07 JSON Schema, fully self-contained (all `$ref`s are internal
`#/$defs/...`, no network resolution required) and uses `additionalProperties: false`,
so it rejects any field name that is not part of the official schema. This is what
guarantees this project never invents OCSF field names.

## The one modification we make

The export endpoint bundles **all** OCSF profiles. Two of them inject extra
top-level `required` entries that are not required by the base Detection Finding
class:

- `cloud`  — required only under the **Cloud** profile
- `osint`  — required only under the **OSINT** profile

We removed `cloud` and `osint` from the top-level `required` array so the vendored
schema reflects the base class (the profiles' *properties* are retained, so those
fields remain valid if a future mapping populates them). The resulting required set
matches the documented base class exactly:

```
activity_id, category_uid, class_uid, finding_info, metadata, severity_id, time, type_uid
```

No other changes were made.
