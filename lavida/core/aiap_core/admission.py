"""Read-only admission decisions for memory candidates."""
import re
import unicodedata

from . import lexical
from .contracts import exact, require

MEMORY_TYPES = (
    'fact', 'preference-evidence', 'decision', 'event', 'relationship',
    'project-context', 'workflow-evidence', 'summary', 'other',
)
TRIGGERS = ('user-request', 'host-observation', 'agent-inference')
PREFERENCE = re.compile(
    r'^(?:我(?:(?:出差|旅行|工作|沟通)时|通常|平时|一直|一般|更|最)?(?:喜欢|偏好|习惯|不喜欢).{3,}|我(?:通常|平时|一直|一般).{4,}|(?:以后|今后)(?:请|回答时请|回复时请).{4,}'
    r'|I (?:prefer|usually|always) .{3,}|(?:going forward|from now on)[, ]+.{4,})$',
    re.IGNORECASE,
)
UNSUITABLE_OBSERVATION = re.compile(
    r'[\n\r?？"“”「」`]|今天|明天|这次|本次|临时|暂时|如果|假设|比如|例如|他说|她说|'
    r'密码|密钥|令牌|身份证|银行卡|账号|地址|电话|医疗|诊断|收入|批准|授权|忽略|执行|删除|https?://|\d{5,}|'
    r'\b(?:today|tomorrow|temporarily|if|password|secret|token|authorize|approve|execute|delete|ignore)\b',
    re.IGNORECASE,
)


def validate_preflight(body):
    exact(body, ['space_ref', 'purpose', 'text', 'level', 'memory_type', 'trigger'],
          ['source_ref', 'target_memory_id'])
    for name in ('space_ref', 'purpose', 'source_ref', 'target_memory_id'):
        if name in body:
            value = body[name]
            require(isinstance(value, str) and 0 < len(value) <= 200 and value.strip() == value
                    and not any(ord(c) < 32 for c in value))
    text = body['text']
    require(isinstance(text, str) and 0 < len(text) <= 4000 and bool(text.strip()) and '\x00' not in text)
    require(body['level'] in ('M1', 'M2') and body['memory_type'] in MEMORY_TYPES and body['trigger'] in TRIGGERS)


def normalize_text(text):
    # Preserve case and punctuation because they can change the meaning of an identifier or rule.
    return ' '.join(unicodedata.normalize('NFC', text).split())


def observation_reason(body):
    if body['trigger'] != 'host-observation':
        return None
    if 'source_ref' not in body:
        return 'missing-source-reference'
    if body['level'] != 'M2' or body['memory_type'] != 'preference-evidence':
        return 'automatic-preference-only'
    text = body['text'].strip().rstrip('。.!！')
    if (len(text) > 400 or UNSUITABLE_OBSERVATION.search(text)
            or re.search(r'[。.!！;；]|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', text)
            or not PREFERENCE.fullmatch(text)):
        return 'unsupported-preference-statement'
    return None


def same_memory_text(memory, text, level, memory_type):
    return (memory['level'] == level and memory['type'] == memory_type
            and normalize_text(memory['content']) == text)


def comparison_score(query_terms, text):
    record_terms = set(lexical.terms(text))
    overlap = len(query_terms & record_terms)
    if overlap < 2:
        return 0
    return overlap / len(query_terms | record_terms)
