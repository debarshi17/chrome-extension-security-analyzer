# Detection Library

The analyzer uses a **standard detection library** under `data/` for known-malicious campaigns and artefacts. Campaigns are those identified as malicious in open web search by researchers.

## Layout

| File | Purpose |
|------|--------|
| **`data/known_malicious_extensions.json`** | Extension IDs and campaign metadata (name, description, impact, TTPs, sources). Matches here yield CONFIRMED attribution and a critical risk floor. |
| **`data/detection_artefacts.json`** | Per-campaign artefacts for matching: extension IDs, domains/URLs, cookie names, patterns. Used for pattern and domain checks. |

## known_malicious_extensions.json

- **metadata**: version, description, last_updated, sources (e.g. `"Public threat research"`).
- **campaigns**: keyed by campaign id (e.g. `vk_styles_2026`). Each campaign has:
  - `campaign_name`, `threat_actor`, `description`, `targets`, `data_exfiltrated`, `c2_infrastructure`, `ttps`, `impact`
  - `sources`: array of `{ "title", "url", "source": "Security research" }`
  - `extensions`: array of `{ "id", "status", "severity", "install_count" }`

Adding a new campaign: add an entry under `campaigns` with the same structure; source labels stay generic (e.g. "Security research").

## detection_artefacts.json

- **metadata**: version, description, last_updated.
- **campaigns**: keyed by campaign id. Each entry can have:
  - `extension_ids`: list of extension IDs
  - `domains_and_urls`: list of domains or URL fragments to match
  - `cookie_names`: list of cookie names (e.g. CSRF tokens)
  - `patterns`: key-value patterns (e.g. literal strings, computed patterns)
  - `notes`: short optional note

Use this file to add new campaigns or artefacts without creating separate docs or vendor-specific files.

## References

Attribution and report text refer to extensions as **found to be malicious in open web search by researchers** (or similar). Source labels in the library use generic terms such as "Security research" or "Public threat research."
