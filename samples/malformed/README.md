# Malformed samples (intentional)

These records are deliberately broken to demonstrate the pipeline's data-quality
handling. When you run the CLI with `--source auto` over `samples/`, they are routed
to the dead-letter output instead of crashing the run:

- `cortex_missing_alert_id.json` — detected as Cortex XDR but fails to parse
  (no `alert_id`), so it is dead-lettered with a parse-error reason.
- `unknown_vendor.json` — matches no registered parser, so auto-detection fails and
  it is dead-lettered with an "unable to auto-detect source" reason.

All data here is synthetic.
