// Verifies the JS demo port (docs/ocsf-core.js) produces output identical to the
// Python golden files. Run: node scripts/verify-web-demo.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { parse, toOcsfDict } from "../docs/ocsf-core.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const j = (p) => JSON.parse(readFileSync(join(ROOT, p), "utf8"));

const CASES = {
  cortex_xdr: "samples/cortex_xdr/alert_powershell_download.json",
  fortisiem: "samples/fortisiem/incident_ssh_bruteforce.json",
  sentinel: "samples/sentinel/alert_impossible_travel.json",
  logscale: "samples/logscale/detection_c2_beacon.json",
  zscaler_zia: "samples/zscaler_zia/web_malware_download.json",
  checkpoint: "samples/checkpoint/threat_emulation_malicious_doc.json",
};

// Deep, order-independent equality. raw_data is compared as parsed JSON so that any
// stringify nuance does not produce a false mismatch.
function normalize(obj, key) {
  if (key === "raw_data" && typeof obj === "string") return JSON.parse(obj);
  if (Array.isArray(obj)) return obj.map((v) => normalize(v));
  if (obj && typeof obj === "object") {
    const out = {};
    for (const k of Object.keys(obj).sort()) out[k] = normalize(obj[k], k);
    return out;
  }
  return obj;
}

let failures = 0;
for (const [src, sample] of Object.entries(CASES)) {
  const got = toOcsfDict(parse(j(sample), src));
  const want = j(`tests/golden/${src}.ocsf.json`);
  const a = JSON.stringify(normalize(got));
  const b = JSON.stringify(normalize(want));
  if (a === b) {
    console.log(`OK   ${src}`);
  } else {
    failures++;
    console.log(`FAIL ${src}`);
    // Show the first differing top-level key to aid debugging.
    const ng = normalize(got), nw = normalize(want);
    for (const k of new Set([...Object.keys(ng), ...Object.keys(nw)])) {
      if (JSON.stringify(ng[k]) !== JSON.stringify(nw[k])) {
        console.log(`   field '${k}':\n     got : ${JSON.stringify(ng[k])}\n     want: ${JSON.stringify(nw[k])}`);
      }
    }
  }
}

console.log(`\n${Object.keys(CASES).length - failures}/${Object.keys(CASES).length} match`);
process.exit(failures ? 1 : 0);
