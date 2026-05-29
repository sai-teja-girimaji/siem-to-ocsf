// Demo UI wiring: parse a raw alert -> map to OCSF -> validate against the vendored
// OCSF 1.8.0 schema -> render. All client-side.
import {
  OCSF_VERSION,
  SEVERITY_CAPTION,
  availableSources,
  detectSource,
  enrich,
  parse,
  toOcsfDict,
} from "./ocsf-core.js";
import { SAMPLES } from "./samples.js";

const SAMPLE_BY_ID = Object.fromEntries(SAMPLES.map((s) => [s.id, s]));
// Tracks the exact text of the last sample we injected, so we can tell an
// unmodified preset apart from a custom alert the user pasted in.
let loadedSampleText = null;

const $ = (id) => document.getElementById(id);
const els = {
  presets: $("presets"),
  source: $("source"),
  enrich: $("enrich"),
  run: $("run"),
  input: $("input"),
  output: $("output"),
  badges: $("badges"),
  copy: $("copy"),
  rawCount: $("raw-fieldcount"),
  ocsfCount: $("ocsf-fieldcount"),
};

// --- JSON Schema validator (Ajv from CDN; degrade gracefully if absent) -----
let validateFn = null;
let schemaLoadError = null;

async function initValidator() {
  try {
    const res = await fetch("./detection_finding-1.8.0.schema.json");
    const schema = await res.json();
    if (typeof window.Ajv !== "function") throw new Error("Ajv unavailable");
    const ajv = new window.Ajv({ allErrors: true, schemaId: "auto" });
    validateFn = ajv.compile(schema);
  } catch (err) {
    schemaLoadError = err.message || String(err);
  }
}

// --- rendering helpers ------------------------------------------------------

function highlightJson(obj) {
  const json = JSON.stringify(obj, null, 2);
  return json.replace(/("(\\.|[^"\\])*"(\s*:)?)|\b(true|false)\b|\bnull\b|(-?\d+(\.\d+)?([eE][+-]?\d+)?)/g, (m) => {
    if (/^"/.test(m)) return /:$/.test(m.trim()) ? `<span class="tok-key">${esc(m)}</span>` : `<span class="tok-str">${esc(m)}</span>`;
    if (/true|false/.test(m)) return `<span class="tok-bool">${m}</span>`;
    if (/null/.test(m)) return `<span class="tok-null">${m}</span>`;
    return `<span class="tok-num">${m}</span>`;
  });
}

function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function chip(text, kind) {
  const el = document.createElement("span");
  el.className = `chip ${kind || "info"}`;
  el.textContent = text;
  return el;
}

function setBadges(children) {
  els.badges.replaceChildren(...children);
}

function showError(title, detail) {
  setBadges([chip(title, "bad")]);
  els.output.innerHTML = `<span class="muted">${esc(detail || "")}</span>`;
  els.copy.hidden = true;
  els.ocsfCount.textContent = "";
}

// --- main action ------------------------------------------------------------

function normalise() {
  const text = els.input.value.trim();
  if (!text) { showError("no input", "Paste a raw alert or load a sample."); return; }

  let raw;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    showError("invalid JSON", e.message);
    return;
  }

  els.rawCount.textContent = (raw && typeof raw === "object" && !Array.isArray(raw))
    ? `${Object.keys(raw).length} fields` : "";

  // Resolve source.
  const chosen = els.source.value;
  let src = chosen;
  if (chosen === "auto") {
    src = detectSource(raw);
    if (!src) {
      // Dead-letter path — mirrors the Python pipeline's behaviour.
      setBadges([chip("dead-lettered", "warn"), chip("reason: unable to auto-detect source", "warn")]);
      els.output.innerHTML = `<span class="muted">No registered parser recognised this record.\nIn the full pipeline this is routed to the dead-letter output with a reason, and the run continues.</span>`;
      els.copy.hidden = true;
      els.ocsfCount.textContent = "";
      return;
    }
  }

  // Parse + map + (optionally) enrich.
  let event;
  try {
    let alert = parse(raw, src);
    if (els.enrich.checked) alert = enrich(alert);
    event = toOcsfDict(alert);
  } catch (e) {
    setBadges([chip("dead-lettered", "warn"), chip(`source: ${src}`, "info"), chip(`reason: ${e.message}`, "warn")]);
    els.output.innerHTML = `<span class="muted">Parsing failed; this record would be dead-lettered with the reason above. The run never crashes.</span>`;
    els.copy.hidden = true;
    els.ocsfCount.textContent = "";
    return;
  }

  // Validate against the pinned OCSF schema.
  const badges = [
    chip(`source: ${src}`, "info"),
    chip(`severity: ${event.severity_id} (${SEVERITY_CAPTION[event.severity_id]})`, "info"),
    chip(`type_uid: ${event.type_uid}`, "info"),
  ];
  if (validateFn) {
    const ok = validateFn(event);
    badges.unshift(ok
      ? chip(`✓ valid · OCSF ${OCSF_VERSION}`, "ok")
      : chip(`✗ schema invalid (${validateFn.errors.length})`, "bad"));
    if (!ok) {
      console.warn("OCSF validation errors:", validateFn.errors);
      badges.push(chip(validateFn.errors[0].dataPath + " " + validateFn.errors[0].message, "bad"));
    }
  } else {
    badges.unshift(chip(`schema check skipped${schemaLoadError ? " (" + schemaLoadError + ")" : ""}`, "warn"));
  }
  setBadges(badges);

  els.ocsfCount.textContent = `${Object.keys(event).length} fields`;
  els.output.innerHTML = highlightJson(event);
  els.copy.hidden = false;
  els.copy.dataset.json = JSON.stringify(event, null, 2);
}

// --- init -------------------------------------------------------------------

// Inject a sample into the input box and normalise it. `sourceValue` controls
// what the Source dropdown shows ("auto" for presets to demo auto-detection;
// the sample's own id when the dropdown drove the load).
function loadSample(sample, sourceValue) {
  const text = JSON.stringify(sample.raw, null, 2);
  els.input.value = text;
  loadedSampleText = text;
  els.source.value = sourceValue;
  els.rawCount.textContent = `${Object.keys(sample.raw).length} fields`;
  normalise();
}

// Is the box still showing an unmodified sample (or empty)? If so it's safe to
// swap in a different sample; if the user typed their own alert we leave it be.
function inputIsUnmodifiedSample() {
  const v = els.input.value.trim();
  return v === "" || els.input.value === loadedSampleText;
}

function buildPresets() {
  for (const s of SAMPLES) {
    const b = document.createElement("button");
    b.textContent = s.label;
    b.addEventListener("click", () => loadSample(s, "auto"));
    els.presets.appendChild(b);
  }
}

// Changing the vendor should "just work": if the box holds an unmodified
// sample, load the picked vendor's matching sample so it normalises cleanly
// instead of force-parsing leftover data from another vendor. If the user
// pasted custom data, respect it and just re-parse with the chosen parser.
els.source.addEventListener("change", () => {
  const picked = els.source.value;
  const sample = SAMPLE_BY_ID[picked];
  if (sample && inputIsUnmodifiedSample()) {
    loadSample(sample, picked);
  } else {
    normalise();
  }
});

els.run.addEventListener("click", normalise);
els.input.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") normalise();
});
els.copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(els.copy.dataset.json || "");
    els.copy.textContent = "Copied ✓";
    setTimeout(() => (els.copy.textContent = "Copy JSON"), 1500);
  } catch { /* clipboard may be blocked; ignore */ }
});

// Sanity: ensure the six sources are registered (defensive, dev aid).
console.log("siem-to-ocsf demo · sources:", availableSources().join(", "));

await initValidator();
buildPresets();
// Load the first sample so the page is never empty.
els.presets.firstChild?.click();
