# Baymax — AI-Powered GRC Gap Analysis

<img width="1200" height="637" alt="image" src="https://github.com/user-attachments/assets/6fc21f51-f329-4527-8d1e-ea774d666d5a" />


> *Policy health check for GRC professionals.* Upload a security policy, pick a framework (NIST CSF 2.0, ISO/IEC 27001:2022, or SOC 2), and get a gap analysis with cited evidence, a compliance score, and prioritized remediation recommendations — all exportable to a polished executive PDF report.

<!-- ╔══════════════════════════════════════════════════════════╗
     ║  SCREENSHOT — Hero / landing screen                      ║
     ╚══════════════════════════════════════════════════════════╝ -->
<img width="824" height="776" alt="image" src="https://github.com/user-attachments/assets/cfb763ee-08c5-4b90-b330-c302b6578b2f" />


---

## Table of contents

- [What problem does it solve?](#what-problem-does-it-solve)
- [Features](#features)
- [Supported frameworks](#supported-frameworks)
- [Architecture](#architecture)
- [How the analysis works](#how-the-analysis-works)
- [Tech stack](#tech-stack)
- [Usage](#usage)
- [Project structure](#project-structure)


---

## What problem does it solve?

A manual gap analysis against a framework like NIST CSF 2.0 (106 subcategories), ISO 27001:2022 (93 controls), or SOC 2 can take **days of GRC analyst time** per document: read the policy, map every paragraph to the relevant controls, cite the evidence, assign a status (met / partial / missing), and write up actionable recommendations.

**Baymax automates the first pass** of that work:

- Takes the policy as input (PDF or TXT).
- Validates that the document is actually security / compliance related (pre-filter).
- Maps the content against the selected framework using an LLM (Gemini 2.5 Flash).
- For every control returns: status, compliance level (%), **verbatim evidence quote**, actionable recommendation, confidence score, and priority.
- Generates an executive-ready PDF report for auditors or steering committees.

> The goal is not to replace the analyst, but to **shrink the time between "I have the policy" and "I have a defensible starting point"** from days to minutes.

---

## Features

- **Multi-framework**: NIST CSF 2.0, ISO/IEC 27001:2022 Annex A, SOC 2 Trust Services Criteria.
- **Pre-validation of the document** — rejects non-security documents before spending tokens on the analysis.
- **Verbatim evidence quotes** from the document (≤150 chars per control), **verified against the source text** — any quote the model cannot back up is flagged `UNVERIFIED` in the UI and the PDF instead of being presented as fact.
- **Weighted compliance score over the whole framework**: `(met + 0.5·partial) / framework_controls · 100`, plus a separate **coverage** metric (how many controls the document addresses at all).
- **Prioritized remediations** (high / medium / low) sorted by urgency in the report.
- **In-memory caching** (SHA-256 of doc + framework key) — re-analyzing the same document is instant.
- **Executive PDF export** with summary, per-control detail table, and a prioritized recommendations block.
- **Output reconciliation**: control IDs the model invents or duplicates are dropped, and every framework control the model did not report is listed as *not addressed* — so the report always accounts for the full framework.
- **Single-page UI** with smooth transitions (anime.js), dark theme, and Space Grotesk typography.

---

## Supported frameworks

| Framework | Version | Controls / Items | Source |
|---|---|---|---|
| **NIST Cybersecurity Framework** | CSF 2.0 (Feb 2024) | 6 functions · 22 categories · 106 subcategories | NIST CSWP 29 |
| **ISO/IEC 27001** | 2022 (Annex A) | 93 controls | ISO/IEC 27001:2022 + 27002:2022 |
| **SOC 2** | TSC 2017 (rev. 2022) | Common Criteria + additional categories | AICPA |

Frameworks live as declarative JSON files in `frameworks/` — adding a new one is a matter of writing the file and registering its key in `FRAMEWORK_FILES`.

<!-- ╔══════════════════════════════════════════════════════════╗
     ║  SCREENSHOT — Framework selector                         ║
     ╚══════════════════════════════════════════════════════════╝ -->

<img width="636" height="641" alt="image" src="https://github.com/user-attachments/assets/2cda8c45-47dd-4447-9324-92e07be06ab4" />


---

## Architecture

```
┌─────────────────┐    POST /analyze    ┌──────────────────────┐
│   Browser       │  ─────────────────▶ │   Flask (app.py)     │
│   (index.html)  │  multipart upload   │                      │
└────────┬────────┘                     └─────────┬────────────┘
         │                                        │
         │  JSON result                           │ 1. extract_text (pypdf)
         │ ◀───────────────────────────────────── │ 2. SHA-256 hash → cache lookup
         │                                        │ 3. is_compliance_document?
         │                                        │ 4. build_prompt(controls)
         │  POST /export-pdf                      │ 5. Gemini 2.5 Flash
         │ ─────────────────────────────────────▶ │ 6. parse + reconcile
         │  application/pdf                       │ 7. verify quotes, score
         │ ◀───────────────────────────────────── │ 8. cache + return
         │   (reportlab)                          │
                                                  ▼
                                        ┌──────────────────────┐
                                        │   Google Gemini API  │
                                        │  (gemini-2.5-flash)  │
                                        └──────────────────────┘
```

**Two endpoints, no database.** State lives in memory (`_validation_cache` and `_analysis_cache`); uploads are temporary and deleted after the analysis completes.

---
<img width="242" height="386" alt="image" src="https://github.com/user-attachments/assets/c25c7563-38b1-4a51-bc3e-50470396b0f8" />

## How the analysis works

1. **Extraction** (`pdf_to_markdown`): the PDF is converted to lightweight Markdown — ALL-CAPS lines are promoted to `##`, Title Case to `###`, and bullets are normalized. This gives the LLM a hierarchical structure that's easier to map than flat text.
2. **Hash + cache**: SHA-256 of the extracted text. If this document has already been analyzed against this framework, the cached result is returned immediately.
3. **Relevance pre-filter**: before the expensive analysis, Gemini is asked with `max_tokens=5` whether the document deals with infosec / compliance / privacy / governance. If the answer doesn't start with "YES", the request aborts with a clear error. This avoids spending 32K tokens analyzing a restaurant menu.
4. **Analysis prompt** (`build_prompt`): the model receives a role ("senior GRC analyst"), a 12K-character excerpt of the document (longer documents are flagged as truncated in the results), the slimmed `{id, name}` list of controls, and a strict JSON contract for the output.
5. **Defensive parsing** (`parse`): code fences are stripped, the first `[` and last `]` are located, and `json.loads` runs on that slice. Resilient to the "thinking" preambles Gemini 2.5 sometimes emits.
6. **Reconciliation** (`reconcile_results`): control IDs are normalized (e.g. `A.5.15` → `5.15`, `GV.OC-1` → `GV.OC-01`), unknown or duplicated IDs are dropped, and the control name is taken from the framework file rather than from the model.
7. **Evidence verification** (`verify_evidence`): each quote is normalized (case, whitespace, smart quotes, Markdown markers) and matched against the full document text. Quotes shortened with `...` must match fragment by fragment. Quotes that don't match are flagged `UNVERIFIED` — a basic guard against hallucinated citations.
8. **Scoring**: `(met + 0.5 × partial) / framework_controls × 100`. Controls the document doesn't address count as gaps. Scoring only the controls the model returned would inflate the result: a policy covering 10 of 93 ISO controls could score above 90%. Coverage (`addressed / framework_controls`) is reported separately.
9. **PDF (`/export-pdf`)**: ReportLab renders the meta header, executive summary (with scoring caveats), color-coded per-control detail table, the list of controls not addressed, and a recommendations block sorted by priority.

<!-- ╔══════════════════════════════════════════════════════════╗
     ║  SCREENSHOT — Results view with score                    ║
     ╚══════════════════════════════════════════════════════════╝ -->

<img width="901" height="446" alt="image" src="https://github.com/user-attachments/assets/1d74db16-958b-4c6c-acf3-309216a3aa40" />


---

## Tech stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11+, Flask 3 |
| **LLM** | Google Gemini 2.5 Flash (`google-genai` SDK) |
| **PDF in** | pypdf 4 |
| **PDF out** | ReportLab 4 (Platypus) |
| **Frontend** | Vanilla HTML/CSS/JS + anime.js for transitions |
| **Typography** | Space Grotesk + Space Mono (Google Fonts) |
| **Config** | python-dotenv (`.env`) |

No database, no frontend framework, no container — a single `python app.py` boots the whole thing.

---


## Usage

1. **Upload** a security policy (PDF or TXT, up to 16 MB).
2. **Select** one of the three available frameworks.
3. **Wait** ~10–30 seconds — the analysis runs in a single LLM call.
4. **Review** the results: overall score, met/partial/missing distribution, per-control evidence, and recommendations.
5. **Export** to an executive PDF to share with stakeholders.

<!-- ╔══════════════════════════════════════════════════════════╗
     ║  SCREENSHOT — Generated PDF report (pages 1-2)           ║
     ╚══════════════════════════════════════════════════════════╝ -->

<img width="1196" height="140" alt="image" src="https://github.com/user-attachments/assets/049cb829-2569-4567-ba4f-244154a1cc0c" />
/
<img width="776" height="308" alt="image" src="https://github.com/user-attachments/assets/5ab22f4c-30ff-41b8-b12a-dd1d9c090194" />
/
<img width="654" height="192" alt="image" src="https://github.com/user-attachments/assets/41621cea-9ec3-474a-bc95-5ade9e4ef6ac" />

/
<img width="660" height="236" alt="image" src="https://github.com/user-attachments/assets/2ec1fb96-37cb-4470-bab2-b74f981cbe1d" />



---

## Project structure

```
Baymax/
├── app.py                    # Flask app + analysis and PDF logic
├── requirements.txt
├── frameworks/
│   ├── nist_csf.json         # NIST CSF 2.0 — 106 subcategories
│   ├── iso_27001.json        # ISO/IEC 27001:2022 — 93 controls
│   └── soc2.json             # SOC 2 TSC
├── templates/
│   └── index.html            # SPA — every screen lives in one HTML file
├── static/
│   └── style.css
└── uploads/                  # Temporary — files are deleted after analysis
```

---

Roadmap ideas:

- [ ] Multi-framework crosswalk (one control mapped against all three at once).
- [ ] Per-organization history + diff between revisions of the same policy.
- [ ] Integration with evidence repositories (Drive / SharePoint).
- [ ] HIPAA, PCI DSS, CIS Controls support.
- [ ] "Assistant" mode: chat about the findings, not just a static report.

---


---

## Credits

- **Héctor Silva** ([@Hector2304](https://github.com/Hector2304)) — LLM integration (model selection, Gemini API), framework ingestion and normalization, backend, scoring and evidence verification.
- **E. Aldir Alcalá** ([@21Aldir](https://github.com/21Aldir) · [LinkedIn](https://www.linkedin.com/in/aldiralcala/)) — GRC domain expertise: framework selection, versions, and assessment methodology.

> Most of the early commits appear under Aldir's account because the initial development was done on his machine.

<sub>2026</sub>
