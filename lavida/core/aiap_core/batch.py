"""Bounded, independently committed memory proposal batches."""
from uuid import NAMESPACE_URL, uuid5

from .admission import normalize_text, validate_preflight
from .client import proposal
from .contracts import Fault, digest, exact, require


def memory_batch(service, token, body):
    exact(body, ['space_ref', 'purpose', 'batch_id', 'items', 'submit'])
    space, purpose, batch = body['space_ref'], body['purpose'], body['batch_id']
    items, submit = body['items'], body['submit']
    require(isinstance(batch, str) and 0 < len(batch) <= 100 and type(submit) is bool)
    require(isinstance(items, list) and 1 <= len(items) <= 20)
    session = service.session(token)
    require(space in session['space_refs'] and purpose == session['purpose']
            and all(a in session['actions'] for a in ('read', 'write')), 'E_DENIED', 403)
    results = []
    previewed = {}
    for index, item in enumerate(items):
        try:
            result = _one(service, token, session, space, batch, item, submit)
            if not submit and result['status'] in ('ready-to-propose', 'review-revision'):
                key = (item.get('memory_id'), item.get('base_revision'), item.get('level', 'M2'),
                       item.get('memory_type', 'fact'), normalize_text(item['text']))
                if key in previewed:
                    result = {'status': 'duplicate', 'reason': 'same-batch-row',
                              'first_index': previewed[key], 'submitted': False}
                else:
                    previewed[key] = index
        except Fault as exc:
            if exc.status in (401, 403) or exc.status >= 500:
                raise
            result = {'status': 'error', 'code': exc.code}
        results.append({'index': index, **result})
    return {'space_ref': space, 'results': results}


def _one(service, token, session, space, batch, item, submit):
    exact(item, ['text'], ['level', 'memory_type', 'memory_id', 'base_revision'])
    editing = 'memory_id' in item or 'base_revision' in item
    if editing:
        exact(item, ['text', 'memory_id', 'base_revision'])
        require(isinstance(item['memory_id'], str) and type(item['base_revision']) is int and item['base_revision'] > 0)
    request = {'space_ref': space, 'purpose': session['purpose'], 'level': item.get('level', 'M2'),
               'memory_type': item.get('memory_type', 'fact'), 'text': item['text'], 'trigger': 'user-request'}
    validate_preflight(request)
    namespace = uuid5(NAMESPACE_URL, digest(['aiap-batch-v1', session['auth_evidence_ref'], space, batch, item]))
    ident = 'aiap:state-delta:' + str(uuid5(namespace, 'delta'))
    prior = service.proposal_status(token, {'delta_id': ident, 'purpose': session['purpose'], 'space_ref': space})
    if prior['status'] != 'not-found':
        return {**prior, 'idempotent': True}
    previous = None
    if editing:
        previous = service.memory_for_update(token, space, item['memory_id'], item['base_revision'])
        request.update(target_memory_id=item['memory_id'], level=previous['level'], memory_type=previous['type'])
    if not submit:
        return {**service.preflight_candidate(token, request), 'submitted': False}
    envelope = proposal(session, space, item['text'], old=previous, level=request['level'],
                        source_type='inferred', id_namespace=namespace)
    envelope['delta']['changes'][0]['candidate']['type'] = request['memory_type']
    return service.propose_checked(token, {'envelope': envelope, 'trigger': 'user-request'})
