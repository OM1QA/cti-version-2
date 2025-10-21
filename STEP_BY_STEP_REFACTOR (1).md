# STEP-BY-STEP: Modularize your Threat Intel app (no programming required)

This guide gives you tiny, safe steps. After each step, you can run the app to confirm nothing broke.

## What I already generated for you

- `smetip/` — a new Python package with these modules already filled in:
  - `smetip/constants.py` — your `SOURCE_CONFIDENCE` dict.
  - `smetip/scoring/confidence.py` — `calculate_confidence_score()`.
  - `smetip/utils/dedupe.py` — `deduplicate_vulnerabilities()` + `deduplicate_indicators()`.
  - `smetip/ingesters/base.py` — `BaseIngester`.
  - `smetip/ingesters/cisa_kev.py` — `CISAKEVIngester`.
  - `smetip/ingesters/otx.py` — `OTXIngester`.
  - `smetip/ingesters/abuse_ch.py` — `AbuseCHIngester`.
  - `smetip/ingesters/nvd.py` — `NVDIngester` (optional for later).
  - `smetip/ingesters/cisa_advisories.py` — `CISAAdvisoriesIngester` (with a small bug fix so `published` is always safe).
  - `smetip/ransomware/store.py` — moved from `ransomware_store.py`.

- `streamlit_app_STEP1.py` — a **copy** of your big file that already imports the new modules and removes the duplicated code. Your original file is untouched.

## Step 0 — Make a quick backup (1 minute)

Just keep your original file as-is. You now also have a ready-to-run copy: `streamlit_app_STEP1.py`.

## Step 1 — Test the copy

From your project folder (same place as your original app):  
**Windows (PowerShell or CMD):**
```
streamlit run "streamlit_app_STEP1.py"
```
**macOS/Linux:**
```
streamlit run streamlit_app_STEP1.py
```

If it opens and looks the same, you’re good.

## Step 2 — Adopt the new modules (optional but recommended)

If you like the new structure, you can start using it going forward:
- Keep working with `streamlit_app_STEP1.py` **or** rename it to replace your original file.

## What changed (in plain English)

- We moved self-contained pieces into small files so they’re easier to read and change later:
  - **Ransomware DB helpers** now live in `smetip/ransomware/store.py`. Your app imports them from there.
  - **Confidence score** moved to `smetip/scoring/confidence.py` so anything can reuse it.
  - **Deduping helpers** moved to `smetip/utils/dedupe.py` and are reused by loaders.
  - **Data ingesters** (CISA KEV, OTX, Abuse.ch, plus NVD & CISA Advisories) each live in `smetip/ingesters/*.py`.

We did **not** change your UI, charts, or logic inside the functions. This is only a re‑organization.

## Next easy wins (when you’re ready)

1) **Wire NVD + CISA Advisories** into your loader (currently your quick loader uses CISA KEV, OTX, Abuse.ch).
   - In `load_threat_data()`, create `nvd = NVDIngester()` and `cisa_adv = CISAAdvisoriesIngester()` and add their DataFrames to your combined list **before** dedupe + scoring.

2) **Centralize constants** (add more items to `smetip/constants.py`) and import them where needed.

3) **Later** we can split the Streamlit UI into tabs under `smetip/ui/`, but there’s no rush.

## Rollback plan

If anything feels off, just run your original `"streamlit_app (1).py"` — it’s untouched.
