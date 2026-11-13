"""Local, deterministic content checks; no network calls or model reviewers.

Recognisers are conservative holds, not proof of identity or anonymisation.
They deliberately include public-looking contact details: public mode cannot
establish whose contact details they are or permission to process them.
"""
from __future__ import annotations

import html
import json
import math
import re
import unicodedata
from urllib.parse import unquote


def strict_json(value):
    """Reject ambiguous objects and non-JSON numeric constants at boundaries."""
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("Duplicate JSON keys are not supported.")
            result[key] = item
        return result

    def invalid(_):
        raise ValueError("Non-finite JSON numbers are not supported.")
    def finite(value):
        result = float(value)
        if not math.isfinite(result):
            return invalid(value)
        return result
    return json.loads(value, object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite)


def normalise(value):
    return ''.join(c for c in unicodedata.normalize('NFKC', value) if unicodedata.category(c) != 'Cf')


def field_name(value):
    return ''.join(c for c in normalise(value).casefold() if c.isalnum())


PERSONAL_FIELDS = {
    'fullname', 'firstname', 'lastname', 'surname', 'dateofbirth', 'dob',
    'email', 'emailaddress', 'phone', 'phonenumber', 'mobile', 'mobilenumber',
    'homeaddress', 'postaladdress', 'postcode', 'donorrecord', 'beneficiaryrecord',
    'passportnumber', 'nhsnumber', 'nationalinsurancenumber',
}

# All repetitions are bounded. Inputs are also byte/depth limited by the caller.
PATTERNS = [
    ('email', re.compile(r'(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,5}(?![\w.-])', re.I)),
    ('phone', re.compile(r'(?<!\w)(?:\+44[ .()-]{0,3}(?:\(0\)[ .-]{0,2})?|0044[ .()-]{0,3}|0)[1-9](?:[ .()-]{0,3}[0-9]){9}(?![0-9])')),
    ('postcode', re.compile(r'(?<!\w)(?:GIR\s{0,2}0AA|[A-Z]{1,2}[0-9][A-Z0-9]?\s{0,2}[0-9][A-Z]{2})(?!\w)', re.I)),
    ('name', re.compile(r'\b(?:Mrs|Mr|Ms|Miss|Dr|Sir|Dame)\.?[ \t]{1,3}[A-Z][a-zA-Z\u00c0-\u024f\u2019\x27-]{1,39}(?:[ \t]{1,3}[A-Z][a-zA-Z\u00c0-\u024f\u2019\x27-]{1,39}){0,3}\b')),
    ('named_person', re.compile(r'\b(?:full[ _]name|first[ _]name|last[ _]name|surname|donor[ _]name|beneficiary[ _]name)[ \t]{0,2}[:=][ \t]{0,3}[A-Z][\w\u2019\x27-]{1,39}(?:[ \t]{1,3}[A-Z][\w\u2019\x27-]{1,39}){0,3}', re.I)),
    ('address', re.compile(r'\b[0-9]{1,5}[A-Za-z]?[ \t]{1,3}(?:[A-Za-z\u2019\x27-]{1,40}[ \t]{1,3}){1,5}(?:Street|Road|Lane|Avenue|Close|Drive|Way|Crescent|Terrace|Gardens|Place|Square|Court)\b', re.I)),
    ('date_of_birth', re.compile(r'\b(?:DOB|date of birth|born on)[ :\t]{1,5}[0-9]{1,4}[-/.][0-9]{1,2}[-/.][0-9]{1,4}\b', re.I)),
    ('national_insurance', re.compile(r'(?<!\w)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z][ -]?[0-9]{2}[ -]?[0-9]{2}[ -]?[0-9]{2}[ -]?[A-D](?!\w)', re.I)),
]

# Unknown secrets still need protection even when not present in local .env.
SECRET = re.compile(r'(?<![\w-])(?:AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,255}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,255})(?![\w-])')
# Enumerate boundaries within a bounded numeric run. A greedy whole-run match
# can swallow the month after a PAN and discard a valid card on Luhn failure.
NUMBER_START = re.compile(r'(?<!\w)(?=[0-9])')
PAYMENT_NUMBER = re.compile(r'[0-9](?:[\s-]{0,3}[0-9]){12,18}')
CARD_LABEL = re.compile(r'\b(?:(?:(?:credit|debit|payment)[ _-]{1,3})?card[ _-]{1,3}(?:details|number|no\.?|pan)|(?:credit|debit|payment)[ _-]{1,3}card|pan)[\s:=#-]{0,8}$', re.I)
DETAIL_GAP = r'[\s,;|:]{0,8}'
EXPIRY_LABEL = r'(?:(?:card[ _-]{1,3})?(?:exp(?:iry|iration)?(?:[ _-]{1,3}date)?|expires?))'
CODE_LABEL = r'(?:cvv2?|cvc2?|cid|(?:card[ _-]{1,3})?security[ _-]{1,3}code)'
EXPIRY_VALUE = r'(?:0[1-9]|1[0-2])[ \t]{0,2}[/\-][ \t]{0,2}(?:[0-9]{4}|[0-9]{2})(?!\w)'
EXPIRY_NEXT = re.compile(DETAIL_GAP + r'(?:' + EXPIRY_LABEL + r'[\s:=]{0,5})?' + EXPIRY_VALUE, re.I)
CODE_NEXT = re.compile(DETAIL_GAP + r'(?:' + CODE_LABEL + r'[\s:=]{0,5})?[0-9]{3,4}(?!\w)', re.I)
CODE_LABEL_NEXT = re.compile(DETAIL_GAP + CODE_LABEL + r'[\s:=]{0,5}[0-9]{3,4}(?!\w)', re.I)
LABELLED_CODE = re.compile(r'\b' + CODE_LABEL + r'[\s:=]{0,5}[0-9]{3,4}(?!\w)', re.I)
LABELLED_CARD_EXPIRY = re.compile(r'\bcard[ _-]{1,3}(?:exp(?:iry|iration)?(?:[ _-]{1,3}date)?|expires?)[\s:=]{0,5}' + EXPIRY_VALUE, re.I)
PAYMENT_FIELDS = {
    'cardnumber', 'cardno', 'creditcardnumber', 'debitcardnumber', 'paymentcardnumber',
    'ccnumber', 'pan', 'primaryaccountnumber', 'carddetails', 'creditcard', 'debitcard',
    'cvv', 'cvv2', 'cvc', 'cvc2', 'cid', 'cardsecuritycode', 'securitycode',
    'cardexpiry', 'cardexpirydate', 'cardexpiration', 'cardexpirationdate',
}
PAYMENT_COMPANION_FIELDS = {'expiry', 'expirydate', 'expirationdate', 'expiration', 'expmonth', 'expyear', 'expirationmonth', 'expirationyear', 'cardholder', 'cardholdername'}


def _number_candidates(text):
    for start in NUMBER_START.finditer(text):
        match = PAYMENT_NUMBER.match(text, start.start())
        if match is None:
            continue
        digits = []
        for offset, char in enumerate(match[0]):
            if char not in '0123456789':
                continue
            digits.append(int(char))
            end = match.start() + offset + 1
            if len(digits) >= 13 and (end == len(text) or not (text[end].isalnum() or text[end] == '_')):
                yield match.start(), end, digits.copy()


def _luhn(digits):
    return len(set(digits)) > 1 and sum((d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 else d for i, d in enumerate(reversed(digits))) % 10 == 0


def card_spans(text):
    """Plausible PANs, checked at each complete digit-group boundary."""
    return [(start, end, 'payment_card') for start, end, digits in _number_candidates(text) if digits[0] in range(2, 7) and _luhn(digits)]


def payment_spans(text):
    """Hold payment-shaped data even when its PAN fails Luhn; never verify it.

    Bare dates and three/four-digit numbers remain ordinary text. Card context,
    an adjacent expiry or an explicit security-code label supplies the evidence.
    All scans are bounded, including the number of digits and detail fields.
    """
    spans = [(m.start(), m.end(), 'payment_details') for pattern in (LABELLED_CODE, LABELLED_CARD_EXPIRY) for m in pattern.finditer(text)]
    for start, end, digits in _number_candidates(text):
        prefix_start = max(0, start - 80)
        label = CARD_LABEL.search(text[prefix_start:start])
        labelled = label is not None
        expiry = EXPIRY_NEXT.match(text, end)
        code = CODE_LABEL_NEXT.match(text, end)
        plausible = digits[0] in range(2, 7) and _luhn(digits)
        if not (labelled or expiry or code or plausible):
            continue
        # Consume both trailing fields so draft removal never leaves the CVV
        # or expiry behind. Labelled fields can appear in either order.
        cursor = end
        seen_expiry = seen_code = False
        for _ in range(2):
            match = None if seen_expiry else EXPIRY_NEXT.match(text, cursor)
            if match:
                seen_expiry = True
            else:
                match = None if seen_code else (CODE_NEXT if seen_expiry or labelled or plausible else CODE_LABEL_NEXT).match(text, cursor)
                if match:
                    seen_code = True
            if not match:
                break
            cursor = match.end()
        spans.append((prefix_start + label.start() if label else start, cursor, 'payment_details'))
    return spans


def contact_spans(text):
    return [(m.start(), m.end(), kind) for kind, pattern in PATTERNS for m in pattern.finditer(text)]


def inspection_text(text):
    # Also inspect the common textual encodings used in JSON, HTML and URLs.
    text = normalise(text)
    for _ in range(2):
        decoded = normalise(html.unescape(unquote(text)))
        if decoded == text:
            break
        text = decoded
    return text


def _redact_text(text):
    spans = sorted(contact_spans(text) + payment_spans(text))
    merged = []
    for start, end, _ in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        text = text[:start] + '[DETAIL REMOVED]' + text[end:]
    return text


def sanitise_draft(text):
    """Return an editable draft. This never grants permission or sends it."""
    text = inspection_text(text)
    if text.lstrip().startswith(('{', '[')):
        try:
            value = strict_json(text)
        except (ValueError, RecursionError):
            pass
        else:
            def strip_fields(item, depth=0):
                if depth > 64:
                    return '[DETAIL REMOVED]'
                if isinstance(item, dict):
                    # Drop the whole field and its payment companions; leaving
                    # just its name would correctly trigger the next check.
                    payment = any(field_name(k) in PAYMENT_FIELDS for k in item)
                    excluded = PERSONAL_FIELDS | PAYMENT_FIELDS | (PAYMENT_COMPANION_FIELDS if payment else set())
                    return {k:strip_fields(v, depth + 1) for k,v in item.items() if field_name(k) not in excluded}
                if isinstance(item, list):
                    return [strip_fields(v, depth + 1) for v in item]
                if isinstance(item, str):
                    return _redact_text(inspection_text(item))
                if type(item) is int and payment_spans(str(item)):
                    return '[DETAIL REMOVED]'
                return item
            # Redact values before serialisation, so removing a numeric PAN
            # cannot turn valid JSON into an unquoted placeholder.
            return json.dumps(strip_fields(value), ensure_ascii=False)
    return _redact_text(text)
