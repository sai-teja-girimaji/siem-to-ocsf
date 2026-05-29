# Field & severity mapping

This document records exactly how each vendor's native alert maps onto the OCSF
**Detection Finding** class (`class_uid 2004`, category Findings), pinned to OCSF
**1.8.0**. All OCSF field names and enum values are taken from the official schema
(see [`src/siem_to_ocsf/schema/PROVENANCE.md`](src/siem_to_ocsf/schema/PROVENANCE.md));
none are invented.

## OCSF classification (constant for every record)

| OCSF field      | Value                          | Notes |
|-----------------|--------------------------------|-------|
| `class_uid`     | `2004`                         | Detection Finding |
| `class_name`    | `Detection Finding`            | |
| `category_uid`  | `2`                            | Findings |
| `category_name` | `Findings`                     | |
| `activity_id`   | `1` (Create)                   | These are newly ingested alerts |
| `type_uid`      | `200401`                       | `class_uid * 100 + activity_id` |
| `metadata.version` | `1.8.0`                     | Pinned OCSF version |

`time` is normalised to **epoch milliseconds** (the OCSF time base) regardless of the
source's native representation (epoch seconds, epoch ms, or ISO-8601).

## Severity normalisation

OCSF `severity_id`: `0` Unknown · `1` Informational · `2` Low · `3` Medium · `4` High ·
`5` Critical · `6` Fatal · `99` Other.

| Vendor | Native scale | Mapping to OCSF `severity_id` |
|--------|--------------|-------------------------------|
| **Cortex XDR** | `informational`/`low`/`medium`/`high`/`critical` | informational→1, low→2, medium→3, high→4, critical→5 |
| **FortiSIEM** | numeric `incidentSeverity` 0–10 (LOW/MED/HIGH buckets) | 0–4→2 (Low), 5–8→3 (Medium), 9–10→4 (High) |
| **Microsoft Sentinel** | `Informational`/`Low`/`Medium`/`High` | Informational→1, Low→2, Medium→3, High→4 |
| **CrowdStrike LogScale** | numeric `severity` 0–100 (Falcon bands) | 0–19→1, 20–39→2, 40–59→3, 60–79→4, 80–100→5 |
| **Zscaler ZIA** | numeric `riskscore` 0–100 (no native sev. column) | 0→1, 1–39→2, 40–69→3, 70–89→4, 90–100→5 |
| **Check Point** | `Informational`/`Low`/`Medium`/`High`/`Critical` | Informational→1, Low→2, Medium→3, High→4, Critical→5 |

The original vendor severity is preserved in the intermediate model's
`native_severity` for traceability. Any unrecognised value maps to `0` (Unknown).

## Where source/destination endpoints go

OCSF Detection Finding has **no** top-level `src_endpoint`/`dst_endpoint`. Endpoints are
carried in the `evidences[]` array (each entry can hold `src_endpoint`/`dst_endpoint` as
`network_endpoint` objects) and are **also** surfaced as `observables[]` (IP Address
`type_id 2`, Hostname `type_id 1`) so they are immediately pivotable for correlation.
User and device names are surfaced as observables too (User Name `type_id 4`).

---

## Per-vendor field maps

Common targets used below: `finding_info.{uid,title,desc,attacks}`,
`metadata.product.{vendor_name,name}`, `message`, `status_id`, `evidences[]`,
`observables[]`, `enrichments[]`, `raw_data`.

### Palo Alto Cortex XDR (`cortex_xdr`)

| Native field | OCSF target |
|---|---|
| `alert_id` | `finding_info.uid` |
| `name` | `finding_info.title`, `message` (fallback) |
| `description` | `finding_info.desc` |
| `category` | `finding_info.types[]` |
| `severity` | `severity_id` (see table) |
| `detection_timestamp` | `time`, `time_dt`, `finding_info.created_time` |
| `action_pretty` | `message` |
| `host_name` | observable Hostname; device |
| `user_name` | observable User Name |
| `action_local_ip` / `action_local_port` | `evidences[].src_endpoint`; observable IP |
| `action_remote_ip` / `action_remote_port` | `evidences[].dst_endpoint`; observable IP |
| `action_file_sha256` | observable Hash (`type_id 8`) |
| `action_file_name` | observable File Name (`type_id 7`) |
| `mitre_tactic_id_and_name` | `finding_info.attacks[].tactic.{uid,name}` |
| `mitre_technique_id_and_name` | `finding_info.attacks[].technique.{uid,name}` |

### Fortinet FortiSIEM (`fortisiem`)

| Native field | OCSF target |
|---|---|
| `incidentId` | `finding_info.uid` |
| `incidentTitle` / `ruleName` | `finding_info.title` |
| `ruleDescription` | `finding_info.desc`, `message` |
| `ruleId` | `finding_info.uid` (preferred over `incidentId` when present) |
| `ruleName` | `finding_info.types[]` |
| `incidentSeverity` | `severity_id` (numeric buckets) |
| `incidentFirstSeen` | `time` |
| `incidentStatus` | `status_id` (Active→New, In Progress→In Progress, Cleared→Resolved) |
| `srcIpAddr` / `srcIpPort` / `srcName` | `evidences[].src_endpoint`; observable IP/Hostname |
| `destIpAddr` / `destIpPort` / `destName` | `evidences[].dst_endpoint`; observable IP/Hostname |
| `user` | observable User Name |
| `hostName` | observable Hostname; device |
| `attackTactic` / `attackTechnique` | `finding_info.attacks[]` |

### Microsoft Sentinel (`sentinel`)

| Native field | OCSF target |
|---|---|
| `SystemAlertId` | `finding_info.uid` |
| `AlertName` | `finding_info.title` |
| `Description` | `finding_info.desc`, `message` |
| `AlertSeverity` | `severity_id` |
| `TimeGenerated` (ISO-8601) | `time`, `time_dt` |
| `ProductName` | `metadata.product.name` |
| `Status` | `status_id` (New/InProgress/Resolved/Dismissed) |
| `AlertType` / `ProviderName` | `finding_info.types[]` |
| `Tactics[]` | `finding_info.attacks[].tactic.name` |
| `Techniques[]` | `finding_info.attacks[].technique.uid` |
| `Entities[]` (host/account/ip) | device hostname / observable User Name / `src_endpoint` + observable IP |
| `CompromisedEntity` | observable User Name (fallback) |

### CrowdStrike LogScale (`logscale`)

| Native field | OCSF target |
|---|---|
| `alert.id` / `@id` | `finding_info.uid` |
| `alert.name` | `finding_info.title` |
| `alert.description` | `finding_info.desc`, `message` |
| `severity` (0–100) | `severity_id` (Falcon bands) |
| `@timestamp` | `time`, `time_dt` |
| `host.name` | observable Hostname; device |
| `user.name` | observable User Name |
| `source.ip` | `evidences[].src_endpoint`; observable IP |
| `destination.ip` / `destination.port` | `evidences[].dst_endpoint`; observable IP |
| `file.hash.sha256` | observable Hash |
| `file.name` | observable File Name |
| `threat.tactic.{id,name}` / `threat.technique.{id,name}` | `finding_info.attacks[]` |

### Zscaler Internet Access (`zscaler_zia`)

| Native field | OCSF target |
|---|---|
| `recordid` / `transactionid` | `finding_info.uid` |
| `threatname` / `reason` | `finding_info.title` |
| `reason` / `threatcategory` | `finding_info.desc`, `message` |
| `riskscore` (0–100) | `severity_id` |
| `epochtime` (epoch s) | `time`, `time_dt` |
| `url` | observable URL String (`type_id 6`) |
| `host` | observable Hostname; device |
| `clientip` / `cip` | `evidences[].src_endpoint`; observable IP |
| `serverip` / `sip` | `evidences[].dst_endpoint`; observable IP |
| `user` | observable User Name |
| `ruletype` / `urlcategory` | `finding_info.types[]` |

### Check Point (`checkpoint`)

| Native field | OCSF target |
|---|---|
| `uuid` / `id` | `finding_info.uid` |
| `protection_name` / `attack_info` | `finding_info.title` |
| `attack_info` | `finding_info.desc`, `message` |
| `product` (blade) | `metadata.product.name` |
| `severity` | `severity_id` |
| `confidence_level` (1–3) | `confidence_id` (1 Low, 2 Medium, 3 High) |
| `time` (epoch s) | `time`, `time_dt` |
| `src` | `evidences[].src_endpoint`; observable IP |
| `dst` / `service` | `evidences[].dst_endpoint` (ip/port); observable IP |
| `src_user_name` / `user` | observable User Name |
| `origin` (gateway) | device hostname |
| `malware_family` / `protection_name` | observable (Other `type_id 99`) |
| `rule_name` | `finding_info.types[]` |
| `rule_uid` | `finding_info.uid` (preferred when present) |

## Enrichment output

The enrichment hook adds OCSF `enrichments[]` entries (`name`/`value`/`data`):

| `name` | `value` | `data` |
|--------|---------|--------|
| `ip_scope` | `internal` / `external` | `{ip, role, scope[, geo]}` — `geo` is a synthetic country/region/ASN stub for external IPs |

"Internal" is defined as RFC1918 / loopback / link-local / unique-local; everything else
is "external". See [`enrichment.py`](src/siem_to_ocsf/enrichment.py).
