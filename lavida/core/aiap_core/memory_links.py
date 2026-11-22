"""Read-only pair review and one-hop relationships within a single grant scope."""
import json
from heapq import nsmallest

from . import lexical
from .admission import comparison_score, normalize_text
from .contracts import exact, require
from .service import VALIDITY_EXTENSION


def _ref(record):
    return {'memory_id': record['memory_id'], 'revision': record['revision']}


def _review_item(record):
    return {**_ref(record), 'content': record['content'], 'source_ref': record['source']['source_ref'],
            'level': record['level'], 'memory_type': record['type']}


def related_memories(service, token, body, *, similar):
    exact(body, ['space_ref', 'purpose', 'memory_id'], ['limit'])
    ident, space, purpose = body['memory_id'], body['space_ref'], body['purpose']
    limit = body.get('limit', 5)
    require(isinstance(ident, str) and 0 < len(ident) <= 200 and isinstance(purpose, str) and purpose)
    require(type(limit) is int and 1 <= limit <= 10)
    with service.tx(read_only=True) as c:
        grant = service._grant(c, token)
        service._allow(grant, [space], 'read', purpose)
        scope = service._scope(c, grant, space)
        params = (grant['avatar'], space, ident)
        row = c.execute('SELECT body FROM memories WHERE avatar=? AND space=? AND id=?', params).fetchone()
        require(row is not None, 'E_NOT_FOUND', 404)
        anchor = json.loads(row['body'])
        require(anchor['scope'] == scope, 'E_NOT_FOUND', 404)
        rows = c.execute('SELECT body FROM memories WHERE avatar=? AND space=? AND id<>? ORDER BY id', params)
        others = (json.loads(r['body']) for r in rows)
        others = (r for r in others if r['scope'] == scope)
        if similar:
            require(service.current_memory(anchor) and anchor['level'] != 'M3', 'E_NOT_FOUND', 404)
            words = set(lexical.terms(anchor['content']))
            text = normalize_text(anchor['content'])
            def pairs():
                for other in others:
                    if (not service.current_memory(other) or other['level'] != anchor['level']
                            or other['type'] != anchor['type']):
                        continue
                    same = text == normalize_text(other['content'])
                    score = 1.0 if same else comparison_score(words, other['content'])
                    if score >= 0.5:
                        yield (-score, other['memory_id'], other, same)
            best = nsmallest(limit + 1, pairs(), key=lambda p: p[:2])
            return {'space_ref': space, 'anchor': _review_item(anchor), 'possibly_more': len(best) > limit,
                    'suggestions': [{'candidate': _review_item(o), 'basis': 'same-text' if same else 'term-overlap'}
                                    for _, _, o, same in best[:limit]]}
        edges = []
        successor = anchor.get('extensions', {}).get(VALIDITY_EXTENSION, {}).get('superseded_by')
        source = anchor['source'].get('source_ref')
        for other in others:
            other_successor = other.get('extensions', {}).get(VALIDITY_EXTENSION, {}).get('superseded_by')
            relations = []
            if successor and successor['id'] == other['memory_id']:
                relations.append(('superseded-by', successor['revision']))
            if other_successor and other_successor['id'] == ident:
                relations.append(('supersedes', other_successor['revision']))
            if source and source == other['source'].get('source_ref'):
                relations.append(('shared-evidence-reference', None))
            for kind, at_revision in relations:
                edge = {'kind': kind, 'other': _ref(other)}
                if at_revision is not None:
                    edge['replacement_revision'] = at_revision
                edges.append(edge)
            if len(edges) > limit:
                break
        return {'space_ref': space, 'anchor': _ref(anchor), 'edges': edges[:limit], 'possibly_more': len(edges) > limit}
