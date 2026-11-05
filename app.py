import os
import json
import uuid
import re
import hashlib
import difflib
import html
from datetime import datetime
from pathlib import Path
import io
import logging

from flask import Flask, request, jsonify, render_template, send_file
from dotenv import load_dotenv
import anthropic
from pypdf import PdfReader
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, KeepTogether,
)
from reportlab.lib.enums import TA_CENTER

load_dotenv()

app = Flask(__name__)
app.logger.setLevel(logging.INFO)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

ANTHROPIC_API_KEY    = os.getenv('ANTHROPIC_API_KEY')
ANTHROPIC_MODEL      = os.getenv('ANTHROPIC_MODEL', 'claude-haiku-5-5')
ANTHROPIC_MAX_TOKENS = int(os.getenv('ANTHROPIC_MAX_TOKENS', '16000'))
# 'disabled' (default) or 'adaptive'. Thinking tokens count toward max_tokens,
# so with adaptive thinking raise ANTHROPIC_MAX_TOKENS accordingly.
ANTHROPIC_THINKING   = os.getenv('ANTHROPIC_THINKING', 'disabled').strip().lower()
FRAMEWORKS_DIR = Path(__file__).parent / 'frameworks'

# Characters of the document sent to the model (~4 chars per token, so ~50K
# tokens). Keeps the full prompt under 100K input tokens, where Haiku pricing
# jumps. Longer documents are truncated and flagged with `document_truncated`.
EXCERPT_CHARS = 200_000

FRAMEWORK_FILES = {
    'nist_csf':  'nist_csf.json',
    'iso_27001': 'iso_27001.json',
    'soc2':      'soc2.json',
    'nist_ir':   'nist_ir_profile.json',
}

# {doc_hash: True/False}  — resultado de validación
_validation_cache: dict[str, bool] = {}
# {doc_hash + framework_key: full analysis dict}  — resultado de análisis
_analysis_cache:   dict[str, dict] = {}


# ─── Document extraction ──────────────────────────────────────────────────────

def pdf_to_markdown(filepath: str) -> str:
    reader = PdfReader(filepath)
    pages_md = []
    for page in reader.pages:
        raw = page.extract_text() or ''
        lines = raw.split('\n')
        md = []
        for line in lines:
            s = line.strip()
            if not s:
                md.append('')
                continue
            if len(s) < 80 and s.isupper() and len(s) > 3:
                md.append(f'## {s}')
            elif len(s) < 60 and not s.endswith('.') and s.istitle():
                md.append(f'### {s}')
            elif re.match(r'^[•·\-\*]\s', s):
                md.append(f'- {s[2:]}')
            elif re.match(r'^\d+[\.\)]\s', s):
                md.append(s)
            else:
                md.append(s)
        pages_md.append('\n'.join(md))
    return '\n\n---\n\n'.join(pages_md)


def extract_text(filepath: str, ext: str) -> str:
    if ext == '.pdf':
        return pdf_to_markdown(filepath)
    with open(filepath, encoding='utf-8', errors='ignore') as f:
        return f.read()


# ─── Framework helpers ────────────────────────────────────────────────────────

def load_framework(key: str) -> dict:
    with open(FRAMEWORKS_DIR / FRAMEWORK_FILES[key]) as f:
        return json.load(f)


def normalize_controls(key: str, data: dict) -> list:
    out = []
    if key == 'nist_csf':
        for func in data.get('functions', []):
            fn = func.get('name', '')
            for cat in func.get('categories', []):
                label = f"{fn} › {cat.get('name', '')}"
                for sub in cat.get('subcategories', []):
                    out.append({
                        'id':       sub['id'],
                        'name':     sub.get('statement', sub.get('name', '')),
                        'category': label,
                    })
    elif key == 'iso_27001':
        for c in data.get('controls', []):
            out.append({
                'id':          c['id'],
                'name':        c.get('control_name', ''),
                'description': c.get('description', ''),
                'category':    c.get('category', ''),
            })
    elif key == 'nist_ir':
        # Profile over CSF 2.0: statements come from the base framework,
        # the profile only selects subcategories and tags their IR phase.
        csf = {c['id']: c for c in normalize_controls('nist_csf', load_framework('nist_csf'))}
        for sub in data.get('subcategories', []):
            base = csf.get(sub['id'])
            if not base:
                continue
            out.append({
                'id':          sub['id'],
                'name':        base['name'],
                'description': f"CSF category: {base['category']}. IR life-cycle phase: {sub.get('phase', '')}.",
                'category':    sub.get('phase', ''),
            })
    elif key == 'soc2':
        for c in data.get('criteria', []):
            out.append({
                'id':          c['id'],
                'name':        c.get('criteria_name', ''),
                'description': c.get('description', ''),
                'category':    c.get('category', ''),
            })
    return out


# ─── LLM (Claude API) ─────────────────────────────────────────────────────────

# Strict output contract: the API guarantees the response matches this schema,
# so there is no free-text JSON to clean up. Enums are compared
# case-insensitively downstream, as the docs recommend.
ANALYSIS_SCHEMA = {
    'type': 'object',
    'properties': {
        'controls': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'control_id':       {'type': 'string'},
                    'status':           {'type': 'string', 'enum': ['met', 'partial', 'missing']},
                    'compliance_level': {'type': 'integer', 'description': '0-100'},
                    'evidence_found':   {'type': 'string'},
                    'recommendation':   {'type': 'string'},
                    'confidence_score': {'type': 'number', 'description': '0.0-1.0'},
                    'priority':         {'type': 'string', 'enum': ['high', 'medium', 'low']},
                },
                'required': ['control_id', 'status', 'compliance_level', 'evidence_found',
                             'recommendation', 'confidence_score', 'priority'],
                'additionalProperties': False,
            },
        },
    },
    'required': ['controls'],
    'additionalProperties': False,
}

RELEVANCE_SCHEMA = {
    'type': 'object',
    'properties': {'is_security_document': {'type': 'boolean'}},
    'required': ['is_security_document'],
    'additionalProperties': False,
}


class ModelOutputError(Exception):
    """The model response could not be used (refusal, truncation, bad JSON)."""


def _json_from_response(resp) -> dict:
    if resp.stop_reason == 'max_tokens':
        tail = next((b.text for b in resp.content if b.type == 'text'), '')[-400:]
        app.logger.warning('Output truncated at max_tokens. Block types: %s. Last 400 chars: %r',
                           [b.type for b in resp.content], tail)
        raise ModelOutputError(
            'The model ran out of output tokens. Raise ANTHROPIC_MAX_TOKENS or use a shorter document.')
    if resp.stop_reason == 'refusal':
        raise ModelOutputError('The model declined to analyze this document.')
    text = next((b.text for b in resp.content if b.type == 'text'), '')
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        app.logger.error('Unparseable model output: %s', text[:500])
        raise ModelOutputError('The model returned unparseable output. Please try again.') from e


def is_compliance_document(doc_text: str, client) -> bool:
    resp = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=256,
        thinking={'type': 'disabled'},   # a yes/no classification needs no reasoning
        messages=[{'role': 'user', 'content': (
            "Does the following document relate to any of these topics: "
            "information security, cybersecurity, IT governance, risk management, "
            "compliance, data protection, access control, audit, privacy, or "
            "organizational security controls?\n\n"
            f"<document>\n{doc_text[:1500]}\n</document>"
        )}],
        output_config={'format': {'type': 'json_schema', 'schema': RELEVANCE_SCHEMA}},
    )
    return bool(_json_from_response(resp).get('is_security_document'))


def build_system_prompt(fw_name: str, controls: list, focus: str = '') -> str:
    """
    Static per framework: role, rules and the full control catalog.
    Sent as a cached system block, so repeated analyses against the same
    framework only pay full price for the document itself.
    """
    catalog = [
        {k: v for k, v in {'id': c['id'], 'name': c['name'],
                           'description': c.get('description', '')}.items() if v}
        for c in controls
    ]
    return (
        "You are a senior GRC analyst specializing in cybersecurity compliance. "
        f"You assess security policy documents against the {fw_name} framework.\n"
        f"{focus}\n\n"
        f"<controls total=\"{len(controls)}\">\n{json.dumps(catalog, ensure_ascii=False)}\n</controls>\n\n"
        "Assessment rules:\n"
        "- Only report controls for which the document contains relevant content. "
        "Skip controls with zero evidence; they are handled separately as 'not addressed'.\n"
        "- control_id: copy the id exactly as it appears in <controls>.\n"
        "- status: met (fully addressed), partial (addressed with gaps), missing "
        "(the document touches the topic but the control requirement is clearly absent).\n"
        "- compliance_level: integer 0-100.\n"
        "- evidence_found: an exact, verbatim quote copied from the document (max 150 characters). "
        "Do not paraphrase; quotes are automatically checked against the source text. "
        "Use \"none\" only if there is no quotable text.\n"
        "- recommendation: one specific, actionable remediation step, or \"none\" if met.\n"
        "- confidence_score: 0.0-1.0, your certainty in the assessment.\n"
        "- priority: high, medium or low, based on risk if the gap is not remediated."
    )


def analyze_with_claude(client, doc_text: str, fw_name: str, controls: list, focus: str = '') -> list:
    # Streaming is required by the SDK for requests that could run >10 min
    # (large max_tokens). We still wait for the complete message before parsing.
    with client.messages.stream(
        model=ANTHROPIC_MODEL,
        max_tokens=ANTHROPIC_MAX_TOKENS,
        thinking={'type': 'adaptive' if ANTHROPIC_THINKING == 'adaptive' else 'disabled'},
        system=[{
            'type': 'text',
            'text': build_system_prompt(fw_name, controls, focus),
            'cache_control': {'type': 'ephemeral'},
        }],
        messages=[{'role': 'user', 'content': (
            "Assess this policy document (converted to Markdown):\n\n"
            f"<document>\n{doc_text[:EXCERPT_CHARS]}\n</document>"
        )}],
        output_config={'format': {'type': 'json_schema', 'schema': ANALYSIS_SCHEMA}},
    ) as stream:
        resp = stream.get_final_message()
    u = resp.usage
    app.logger.info('Claude usage: input=%s cache_read=%s cache_write=%s output=%s',
                    u.input_tokens, getattr(u, 'cache_read_input_tokens', 0),
                    getattr(u, 'cache_creation_input_tokens', 0), u.output_tokens)
    return _json_from_response(resp).get('controls', [])


VALID_STATUSES = {'met', 'partial', 'missing'}

# Min length of a quote fragment to count as a meaningful match
_MIN_FRAGMENT = 12


def _normalize(text: str) -> str:
    """Lowercase, unify quotes/dashes, drop markdown markers, collapse whitespace."""
    text = text.lower()
    text = text.translate(str.maketrans({
        '‘': "'", '’': "'", '“': '"', '”': '"',
        '–': '-', '—': '-', ' ': ' ',
    }))
    text = re.sub(r'^\s*(#{1,6}|[-*•·])\s+', ' ', text, flags=re.MULTILINE)
    # Quote marks are dropped entirely: policies often write definitions as
    # '"Incident" means ...' and the model tends to quote them without the marks.
    text = re.sub(r'["\'`]', '', text)
    # Re-join words hyphenated across PDF line breaks ('secu-\nrity').
    text = re.sub(r'(\w)-\s+(\w)', r'\1\2', text)
    return re.sub(r'\s+', ' ', text).strip()


# A quote is 'approximate' when at least this share of its words appear, in
# order, within a window of the document not much longer than the quote itself.
_APPROX_MIN_WORDS = 0.85
_APPROX_MAX_SPAN = 1.6


class DocIndex:
    """Normalized document text plus a word-trigram index for fuzzy lookups."""
    def __init__(self, doc_text: str):
        self.norm   = _normalize(doc_text)
        self.tokens = re.findall(r'\w+', self.norm)
        self.trigrams: dict[tuple, list[int]] = {}
        for i in range(len(self.tokens) - 2):
            self.trigrams.setdefault(tuple(self.tokens[i:i + 3]), []).append(i)


def _fragment_match(fragment: str, doc: 'DocIndex') -> str:
    if fragment in doc.norm:
        return 'exact'
    q = re.findall(r'\w+', fragment)
    if not q:
        return 'not_found'
    if len(q) < 4:
        # Short fragment (e.g. the part before '...'): its words must appear in
        # order within a small window.
        limit = len(q) * 3
        for start, tok in enumerate(doc.tokens):
            if tok != q[0]:
                continue
            j, k = 1, start + 1
            while j < len(q) and k < start + limit:
                if doc.tokens[k] == q[j]:
                    j += 1
                k += 1
            if j == len(q):
                return 'approximate'
        return 'not_found'
    # Candidate windows: wherever any 3-word sequence of the quote appears.
    starts = set()
    for i in range(len(q) - 2):
        for pos in doc.trigrams.get(tuple(q[i:i + 3]), [])[:50]:
            starts.add(max(0, pos - i))
    for st in sorted(starts)[:300]:
        window = doc.tokens[max(0, st - 3): st + int(len(q) * _APPROX_MAX_SPAN) + 3]
        blocks = [b for b in difflib.SequenceMatcher(None, q, window, autojunk=False)
                  .get_matching_blocks() if b.size]
        if not blocks:
            continue
        matched = sum(b.size for b in blocks)
        span    = (blocks[-1].b + blocks[-1].size) - blocks[0].b
        if matched / len(q) >= _APPROX_MIN_WORDS and span <= len(q) * _APPROX_MAX_SPAN:
            return 'approximate'
    return 'not_found'


def match_evidence(quote, doc: 'DocIndex'):
    """
    Check the quote the model cited against the document.
      'exact'       – appears verbatim (after normalization)
      'approximate' – same words in the same order with small omissions or
                      additions (e.g. '"X," in this policy, means' quoted as 'X means')
      'not_found'   – could not be located; possibly fabricated
      None          – no quote given
    Quotes shortened with '...' are split; every fragment must match.
    """
    if not quote or str(quote).strip().lower() == 'none':
        return None
    q = _normalize(str(quote)).strip(' "\'')
    fragments = [f.strip(' "\'') for f in re.split(r'\.\.\.|\u2026', q)]
    fragments = [f for f in fragments if len(f) >= _MIN_FRAGMENT]
    if not fragments:
        return 'not_found'
    results = [_fragment_match(f, doc) for f in fragments]
    if 'not_found' in results:
        return 'not_found'
    return 'approximate' if 'approximate' in results else 'exact'


def verify_evidence(quote, doc_norm: str):
    """Backwards-compatible exact check: True / False / None."""
    if not quote or str(quote).strip().lower() == 'none':
        return None
    q = _normalize(str(quote)).strip(' "\'')
    fragments = [f.strip(' "\'') for f in re.split(r'\.\.\.|\u2026', q)]
    fragments = [f for f in fragments if len(f) >= _MIN_FRAGMENT]
    return bool(fragments) and all(f in doc_norm for f in fragments)


def _id_key(control_id) -> str:
    """
    Canonical form of a control ID so cosmetic variations from the model still
    match the framework: 'A.5.15' / '5.15', 'GV.OC-1' / 'GV.OC-01', ' cc6 ' / 'CC6'.
    """
    k = str(control_id).strip().upper()
    k = re.sub(r'^(ANNEX\s*)?A[\.\s]+(?=\d)', '', k)   # ISO 'A.5.15' -> '5.15'
    k = re.sub(r'(?<!\d)0+(?=\d)', '', k)              # drop leading zeros per segment
    return re.sub(r'\s+', '', k)


def reconcile_results(results: list, controls: list, doc_text: str) -> tuple:
    """
    Make the model output safe to score:
      - drop control IDs that don't exist in the framework (hallucinated IDs)
      - drop duplicates and invalid statuses
      - verify every evidence quote against the full document
      - list every framework control the model did not report as 'not addressed'
    """
    by_key   = {_id_key(c['id']): c for c in controls}
    doc_idx  = DocIndex(doc_text)
    clean, seen, dropped = [], set(), 0

    for r in results:
        ctrl = by_key.get(_id_key(r.get('control_id', '')))
        status = str(r.get('status', '')).strip().lower()
        if ctrl is None or ctrl['id'] in seen or status not in VALID_STATUSES:
            dropped += 1
            continue
        cid = ctrl['id']
        seen.add(cid)
        r['status']            = status
        r['priority']          = str(r.get('priority', 'medium')).strip().lower()
        r['control_id']        = cid
        r['control_name']      = ctrl['name']   # trust the framework, not the model
        r['category']          = ctrl.get('category', '')
        r['evidence_match']    = match_evidence(r.get('evidence_found'), doc_idx)
        # False only when the quote could not be located at all
        r['evidence_verified'] = None if r['evidence_match'] is None else r['evidence_match'] != 'not_found'
        clean.append(r)

    not_addressed = [
        {'control_id': c['id'], 'control_name': c['name'], 'category': c.get('category', '')}
        for c in controls if c['id'] not in seen
    ]
    return clean, not_addressed, dropped


def compute_score(results: list, framework_total: int) -> dict:
    """
    Score over the WHOLE framework: controls the policy doesn't address count
    as gaps. Scoring only the controls the model returned inflates the result
    (a policy covering 10 of 93 controls could otherwise score 90%+).
    """
    met     = sum(1 for c in results if c.get('status') == 'met')
    partial = sum(1 for c in results if c.get('status') == 'partial')
    missing = sum(1 for c in results if c.get('status') == 'missing')
    # 'Addressed' = the document has related text for the control. A 'missing'
    # finding with no quote is a gap the model inferred, not coverage.
    addressed = sum(1 for c in results
                    if str(c.get('evidence_found', '')).strip().lower() not in ('', 'none'))
    total   = framework_total or 1
    return {
        'score':          round((met + partial * 0.5) / total * 100, 1),
        'met':            met,
        'partial':        partial,
        'missing':        missing,
        'not_addressed':  framework_total - len(results),
        'total':          framework_total,
        'addressed':      addressed,
        'coverage':       round(addressed / total * 100, 1),
        'unverified':     sum(1 for c in results if c.get('evidence_match') == 'not_found'),
        'approximate':    sum(1 for c in results if c.get('evidence_match') == 'approximate'),
    }


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'document' not in request.files:
        return jsonify({'error': 'No document provided'}), 400

    file = request.files['document']
    key  = request.form.get('framework', '').strip()

    if not file or not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    if key not in FRAMEWORK_FILES:
        return jsonify({'error': 'Invalid framework selection'}), 400

    ext = Path(file.filename).suffix.lower()
    if ext not in ('.pdf', '.txt'):
        return jsonify({'error': 'Only PDF and TXT files are supported'}), 400

    if not ANTHROPIC_API_KEY:
        return jsonify({'error': 'ANTHROPIC_API_KEY is not configured in .env'}), 500

    tmp = Path(app.config['UPLOAD_FOLDER']) / f"{uuid.uuid4()}{ext}"
    try:
        file.save(str(tmp))

        doc_text = extract_text(str(tmp), ext)
        if not doc_text.strip():
            return jsonify({
                'error': 'Could not extract text. Is the PDF scanned / image-based?'
            }), 400

        doc_hash     = hashlib.sha256(doc_text.encode()).hexdigest()
        analysis_key = f"{doc_hash}:{key}"

        # ── Cache hit: análisis completo ya existe ────────────────────────────
        if analysis_key in _analysis_cache:
            app.logger.info('Cache hit: %s', analysis_key[:16])
            cached = _analysis_cache[analysis_key]
            return jsonify({**cached, 'document_name': file.filename, 'cached': True})

        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

        # ── Cache hit: ya sabemos que NO es compliance ────────────────────────
        if doc_hash in _validation_cache and not _validation_cache[doc_hash]:
            return jsonify({
                'error': 'The document does not appear to be a security policy or compliance document.'
            }), 400

        # ── Validación (solo si no está en cache) ─────────────────────────────
        if doc_hash not in _validation_cache:
            _validation_cache[doc_hash] = is_compliance_document(doc_text, client)

        if not _validation_cache[doc_hash]:
            return jsonify({
                'error': 'The document does not appear to be a security policy or compliance document.'
            }), 400

        fw_data  = load_framework(key)
        fw_name  = fw_data.get('framework', {}).get('name', key)
        controls = normalize_controls(key, fw_data)

        focus       = fw_data.get('framework', {}).get('assessment_focus', '')
        raw_results = analyze_with_claude(client, doc_text, fw_name, controls, focus)
        results, not_addressed, dropped = reconcile_results(raw_results, controls, doc_text)
        if dropped:
            app.logger.warning('Dropped %d invalid/duplicate control entries from model output', dropped)

        analysis_result = {
            'success':           True,
            'framework_name':    fw_name,
            'framework_key':     key,
            'analysis_date':     datetime.now().strftime('%B %d, %Y at %H:%M'),
            'model':             ANTHROPIC_MODEL,
            **compute_score(results, len(controls)),
            'controls':          results,
            'not_addressed_controls': not_addressed,
            'document_truncated': len(doc_text) > EXCERPT_CHARS,
        }
        _analysis_cache[analysis_key] = analysis_result

        return jsonify({**analysis_result, 'document_name': file.filename, 'cached': False})

    except ModelOutputError as e:
        return jsonify({'error': str(e)}), 502
    except anthropic.AuthenticationError:
        return jsonify({'error': 'Invalid ANTHROPIC_API_KEY.'}), 500
    except anthropic.RateLimitError:
        return jsonify({'error': 'Claude API rate limit reached. Wait a moment and try again.'}), 429
    except anthropic.APIError as e:
        app.logger.error('Claude API error: %s', e)
        return jsonify({'error': f'Claude API error: {getattr(e, "message", str(e))}'}), 502
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
    finally:
        if tmp.exists():
            tmp.unlink()


@app.route('/export-pdf', methods=['POST'])
def export_pdf():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=0.7*inch, rightMargin=0.7*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch,
    )

    base = getSampleStyleSheet()
    DARK = colors.HexColor('#0d1b2a')
    BLUE = colors.HexColor('#003580')
    GREY = colors.HexColor('#555555')

    _ps_cache = {}
    def ps(name, **kw):
        key = name + str(kw)
        if key not in _ps_cache:
            _ps_cache[key] = ParagraphStyle(name, parent=base['Normal'], **kw)
        return _ps_cache[key]

    def safe_str(v):
        return html.escape(str(v)) if v is not None else ''

    story = []



    # Meta table
    def mcell(txt, bold=False, col=None):
        kw = {'fontSize': 9}
        if bold: kw['fontName'] = 'Helvetica-Bold'
        if col:  kw['textColor'] = col
        return Paragraph(txt, ps('Meta_' + txt[:8].replace(' ', '_'), **kw))

    meta_rows = [
        [mcell('Framework', bold=True), mcell(safe_str(data.get('framework_name', ''))),
         mcell('Date',  bold=True),     mcell(safe_str(data.get('analysis_date', '')))],
        [mcell('Document', bold=True),  mcell(safe_str(data.get('document_name', ''))),
         mcell('Score', bold=True, col=BLUE),
         mcell(f"{data.get('score', 0)}%", bold=True, col=BLUE)],
    ]
    mt = Table(meta_rows, colWidths=[1.0*inch, 2.9*inch, 0.85*inch, 1.85*inch])
    mt.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,-1), colors.HexColor('#f8f9fa')),
        ('BOX',           (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('INNERGRID',     (0,0), (-1,-1), 0.3, colors.HexColor('#eeeeee')),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
    ]))
    story += [mt, Spacer(1, 14)]

    # Summary
    story.append(Paragraph("Executive Summary",
        ps('H1', fontSize=13, fontName='Helvetica-Bold',
           textColor=DARK, spaceAfter=8)))

    total = data.get('total', 1) or 1
    met   = data.get('met',     0)
    part  = data.get('partial', 0)
    miss  = data.get('missing', 0)
    nadd  = data.get('not_addressed', 0)
    score = data.get('score',   0)
    pct   = lambda n: f"{round(n / total * 100, 1)}%"

    sum_rows = [
        ['Status',                      'Controls',  'Percentage'],
        ['Met (Compliant)',              str(met),    pct(met)],
        ['Partial (Needs Work)',         str(part),   pct(part)],
        ['Missing (Gap)',                str(miss),   pct(miss)],
        ['Not Addressed in Document',    str(nadd),   pct(nadd)],
        ['Total Framework Controls',     str(total),  '100%'],
        ['Overall Compliance Score',     '',          f'{score}%'],
    ]
    st = Table(sum_rows, colWidths=[2.6*inch, 1.1*inch, 1.5*inch])
    st.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  DARK),
        ('TEXTCOLOR',     (0,0), (-1,0),  colors.white),
        ('FONTNAME',      (0,0), (-1,0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0,0), (-1,-1), 9),
        ('ALIGN',         (1,0), (-1,-1), 'CENTER'),
        ('GRID',          (0,0), (-1,-1), 0.4, colors.HexColor('#cccccc')),
        ('BACKGROUND',    (0,1), (-1,1),  colors.HexColor('#e8f5e9')),
        ('BACKGROUND',    (0,2), (-1,2),  colors.HexColor('#fffde7')),
        ('BACKGROUND',    (0,3), (-1,3),  colors.HexColor('#ffebee')),
        ('BACKGROUND',    (0,4), (-1,4),  colors.HexColor('#eeeeee')),
        ('BACKGROUND',    (0,5), (-1,5),  colors.HexColor('#f5f5f5')),
        ('BACKGROUND',    (0,6), (-1,6),  colors.HexColor('#e3f2fd')),
        ('FONTNAME',      (0,6), (-1,6),  'Helvetica-Bold'),
        ('TOPPADDING',    (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('LEFTPADDING',   (0,0), (-1,-1), 8),
    ]))
    story += [st, Spacer(1, 6)]

    caveats = [
        f"Score is calculated over all {total} framework controls; controls the "
        f"document does not address count as gaps. Coverage (controls with related "
        f"text in the document): {data.get('coverage', 0)}%."
    ]
    if data.get('unverified'):
        caveats.append(
            f"{data['unverified']} evidence quote(s) could not be matched to the source "
            f"document and are marked [UNVERIFIED]; review them manually.")
    if data.get('approximate'):
        caveats.append(
            f"{data['approximate']} quote(s) are marked [APPROX.]: the wording matches the "
            f"document with minor omissions or additions, not verbatim.")
    if data.get('document_truncated'):
        caveats.append(
            "The document exceeded the analysis limit and was truncated; "
            "later sections were not assessed.")
    for txt in caveats:
        story.append(Paragraph(f"• {safe_str(txt)}",
            ps('Cav' + txt[:6], fontSize=7.5, textColor=GREY, leading=10)))
    story.append(Spacer(1, 14))

    # Controls detail
    story.append(Paragraph("Controls Assessment Detail",
        ps('H2', fontSize=13, fontName='Helvetica-Bold',
           textColor=DARK, spaceAfter=8)))

    hdr_s = ps('Hdr', fontSize=8, fontName='Helvetica-Bold',
               textColor=colors.white, leading=10)
    cel_s = ps('Cel', fontSize=7.5, leading=10)
    ev_s  = ps('Ev',  fontSize=7, leading=9.5,
               textColor=colors.HexColor('#444444'))

    STATUS_BG = {
        'met':     colors.HexColor('#e8f5e9'),
        'partial': colors.HexColor('#fffde7'),
        'missing': colors.HexColor('#ffebee'),
    }
    STATUS_FG = {
        'met':     colors.HexColor('#1b5e20'),
        'partial': colors.HexColor('#795548'),
        'missing': colors.HexColor('#b71c1c'),
    }
    PRIO_FG = {
        'high':   colors.HexColor('#b71c1c'),
        'medium': colors.HexColor('#e65100'),
        'low':    colors.HexColor('#2e7d32'),
    }

    rows = [[
        Paragraph('ID',       hdr_s),
        Paragraph('Control',  hdr_s),
        Paragraph('Status',   hdr_s),
        Paragraph('Priority', hdr_s),
        Paragraph('Evidence / Recommendation', hdr_s),
    ]]
    row_styles = []

    for i, c in enumerate(data.get('controls', []), 1):
        st_v = c.get('status',         'missing')
        pr_v = c.get('priority',       'low')
        ev   = c.get('evidence_found',  'none') or 'none'
        rec  = c.get('recommendation', 'none') or 'none'

        note = ev if ev != 'none' else ''
        if note and st_v == 'missing':
            # For gaps the quote is context, not proof of compliance
            note = 'Related text: ' + note
        if note and c.get('evidence_match') == 'not_found':
            note = '[UNVERIFIED] ' + note
        elif note and c.get('evidence_match') == 'approximate':
            note = '[APPROX.] ' + note
        if rec != 'none':
            note += (' | ' if note else '') + f'→ {rec}'
        if len(note) > 120:
            note = note[:120] + '…'

        rows.append([
            Paragraph(safe_str(c.get('control_id', '')),
                ps(f'ID{i}', fontSize=7.5, fontName='Courier')),
            Paragraph(safe_str(c.get('control_name', '')[:70]), cel_s),
            Paragraph(safe_str(st_v).upper(),
                ps(f'ST{i}', fontSize=7.5, fontName='Helvetica-Bold',
                   textColor=STATUS_FG.get(st_v, colors.black))),
            Paragraph(safe_str(pr_v).upper(),
                ps(f'PR{i}', fontSize=7.5,
                   textColor=PRIO_FG.get(pr_v, colors.black))),
            Paragraph(safe_str(note) or '—', ev_s),
        ])
        row_styles.append(
            ('BACKGROUND', (0, i), (-1, i), STATUS_BG.get(st_v, colors.white))
        )

    cw = [0.85*inch, 1.75*inch, 0.72*inch, 0.72*inch, 2.6*inch]
    ct = Table(rows, colWidths=cw, repeatRows=1)
    ct.setStyle(TableStyle([
        ('BACKGROUND',    (0,0), (-1,0),  DARK),
        ('FONTSIZE',      (0,0), (-1,-1), 7.5),
        ('GRID',          (0,0), (-1,-1), 0.3, colors.HexColor('#cccccc')),
        ('TOPPADDING',    (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING',   (0,0), (-1,-1), 5),
        ('VALIGN',        (0,0), (-1,-1), 'TOP'),
    ] + row_styles))
    story.append(ct)

    # Controls not addressed by the document (compact list)
    nadd_list = data.get('not_addressed_controls', [])
    if nadd_list:
        story += [
            Spacer(1, 14),
            Paragraph(f"Controls Not Addressed in the Document ({len(nadd_list)})",
                ps('H2b', fontSize=13, fontName='Helvetica-Bold',
                   textColor=DARK, spaceAfter=4)),
            Paragraph("No relevant content was found for these controls. Each one "
                      "is a coverage gap to evaluate with the policy owner.",
                ps('H2bs', fontSize=8, textColor=GREY, spaceAfter=6)),
            Paragraph(", ".join(
                f"<font name='Courier'>{safe_str(n.get('control_id', ''))}</font>"
                for n in nadd_list),
                ps('NA', fontSize=7.5, leading=11)),
        ]

    # Recommendations
    action = [
        c for c in data.get('controls', [])
        if c.get('status') in ('partial', 'missing')
        and c.get('recommendation', 'none') not in ('none', '', None)
    ]
    if action:
        action.sort(
            key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(
                x.get('priority', 'low'), 2)
        )
        story += [
            Spacer(1, 14),
            Paragraph("Remediation Recommendations",
                ps('H3', fontSize=13, fontName='Helvetica-Bold',
                   textColor=DARK, spaceAfter=8)),
        ]
        PRIO_HEX = {'high': 'b71c1c', 'medium': 'e65100', 'low': '2e7d32'}
        for idx, c in enumerate(action):
            pr   = c.get('priority', 'low')
            stat = c.get('status',   'missing')
            hex_ = PRIO_HEX.get(pr, '333333')
            cid  = c.get('control_id', '')
            hdr  = Paragraph(
                f"<b>[{safe_str(cid)}]</b> {safe_str(c.get('control_name','')[:80])} "
                f"— <font color='#{hex_}'>{safe_str(pr).upper()}</font> ({safe_str(stat)})",
                ps(f'RH{idx}', fontSize=8.5, fontName='Helvetica-Bold', spaceAfter=2))
            body = Paragraph(
                f"→ {safe_str(c.get('recommendation', ''))}",
                ps(f'RB{idx}', fontSize=8, leftIndent=12, spaceAfter=7,
                   textColor=colors.HexColor('#333333')))
            story.append(KeepTogether([hdr, body]))

    # Footer
    story += [
        Spacer(1, 20),
        HRFlowable(width='100%', thickness=0.5,
                    color=colors.HexColor('#aaaaaa'), spaceAfter=5),
        Paragraph(
            safe_str(data.get('analysis_date', '')),
            ps('Ft', fontSize=10, textColor=GREY, alignment=TA_CENTER)),
    ]

    doc.build(story)
    buf.seek(0)
    fname = f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return send_file(buf, mimetype='application/pdf',
                     as_attachment=True, download_name=fname)


if __name__ == '__main__':
    Path('uploads').mkdir(exist_ok=True)
    app.run(debug=False, port=5000)
