"""Owner-managed, local procedural descriptors bound to a Core space."""
from bisect import insort
import os
from pathlib import Path
from dataclasses import dataclass
from graphlib import CycleError, TopologicalSorter
from heapq import nsmallest
import re
import stat
from tempfile import TemporaryDirectory

from .contracts import Fault, canonical, digest, exact, require, validate_schema_uri
from .recovery_checkpoint import strict_json
from .service import save_private, stamp


_INPUT_LIMIT = 64 * 1024
_RECORD_LIMIT = 128 * 1024
_BINDING_PREVIEW_LIMIT = 20
_BINDING_STATUSES = ('candidate', 'confirmation-required', 'ineligible')
_MAPPING_ORDER = ('exact', 'compatible', 'partial', 'composite', 'unresolved')
_IMPLEMENTATION_TYPES = ('skill', 'tool', 'agent', 'api', 'workflow', 'composite')


@dataclass(frozen=True)
class _DescriptorKind:
    schema: str
    id_field: str
    directory: str
    list_field: str


@dataclass(frozen=True)
class _AgentInventory:
    agent_id: str
    sha256: str
    implementations: frozenset[tuple[str, str]]

    def summary(self):
        return {'agent_id': self.agent_id, 'sha256': self.sha256, 'source': 'owner-supplied'}


_KINDS = {
    'capability': _DescriptorKind('capability', 'capability_id', 'local-capabilities', 'capabilities'),
    'workflow': _DescriptorKind('workflow-descriptor', 'workflow_id', 'local-workflows', 'workflows'),
    'runtime-binding': _DescriptorKind('runtime-binding', 'binding_id', 'local-runtime-bindings', 'bindings'),
}


def _read_document(path, limit, *, private=False):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'E_PROCEDURAL_FILE')
            if private:
                require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'E_PROCEDURAL_FILE')
            raw = stream.read(limit + 1)
        require(len(raw) <= limit, 'E_PROCEDURAL_FILE')
        return strict_json(raw)
    except FileNotFoundError:
        raise
    except (OSError, ValueError, RecursionError):
        raise Fault('E_PROCEDURAL_FILE') from None


def _validate_descriptor(kind, document):
    spec = _KINDS[kind]
    try:
        validate_schema_uri(f'https://aiap.dev/schema/v0.1/{spec.schema}.schema.json', document)
        require(_valid_id(kind, document[spec.id_field]) and len(canonical(document)) <= _INPUT_LIMIT,
                'E_PROCEDURAL_FILE')
    except (ValueError, RecursionError):
        raise Fault('E_PROCEDURAL_FILE') from None


def _private_directory(directory, create):
    try:
        if create:
            directory.mkdir(mode=0o700, exist_ok=True)
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                'E_PROCEDURAL_FILE')
    except FileNotFoundError:
        if not create:
            return False
        raise Fault('E_PROCEDURAL_FILE') from None
    except OSError:
        raise Fault('E_PROCEDURAL_FILE') from None
    return True


def _space_directory(service, kind, avatar, space, *, create=False):
    root = service.directory / _KINDS[kind].directory
    directory = root / digest([avatar, space])
    if _private_directory(root, create) and _private_directory(directory, create):
        return directory
    return None


def _valid_id(kind, value):
    prefix = _KINDS[kind].id_field.removesuffix('_id')
    return isinstance(value, str) and len(value) <= 200 and re.fullmatch(rf'aiap:{prefix}:[A-Za-z0-9._:-]+', value)


def _read_record(kind, path, avatar, scope, object_id=None):
    if path is None:
        return None
    try:
        record = _read_document(path, _RECORD_LIMIT, private=True)
    except FileNotFoundError:
        return None
    fields = ['avatar_id', 'scope', 'revision', 'previous_revision', 'updated_at', 'descriptor']
    if kind != 'capability':
        fields.append('capability_refs')
    exact(record, fields)
    require(record['avatar_id'] == avatar and record['scope'] == scope, 'E_SCOPE', 409)
    revision = record['revision']
    require(type(revision) is int and revision > 0 and (record['previous_revision'] is None if revision == 1
            else type(record['previous_revision']) is int and record['previous_revision'] == revision - 1),
            'E_PROCEDURAL_FILE')
    document = record['descriptor']
    _validate_descriptor(kind, document)
    stored_id = document[_KINDS[kind].id_field]
    require(path.name == digest(stored_id) + '.json' and (object_id is None or stored_id == object_id),
            'E_PROCEDURAL_FILE')
    if kind == 'workflow':
        require(document['owner_avatar_id'] == avatar, 'E_SCOPE', 409)
    if kind != 'capability':
        refs = record['capability_refs']
        require(isinstance(refs, dict) and set(refs) == _capability_ids(kind, document), 'E_PROCEDURAL_FILE')
    return record


def _space_records(kind, directory, avatar, scope):
    if directory is None:
        return
    try:
        for path in directory.iterdir():
            if re.fullmatch(r'[0-9a-f]{64}\.json', path.name):
                record = _read_record(kind, path, avatar, scope)
                if record is not None:
                    yield record
    except OSError:
        raise Fault('E_PROCEDURAL_FILE') from None


def _workflow_order(document):
    steps = document['steps']
    graph = {step['step_id']: step.get('depends_on', []) for step in steps}
    require(len(graph) == len(steps) and all(set(dependencies) <= graph.keys() for dependencies in graph.values()),
            'E_WORKFLOW_GRAPH')
    try:
        return list(TopologicalSorter(graph).static_order())
    except CycleError:
        raise Fault('E_WORKFLOW_GRAPH') from None


def _capability_ids(kind, document):
    if kind == 'workflow':
        return {step['capability_id'] for step in document['steps']}
    return {document['capability_id']}


def _capability_records(service, avatar, scope, capability_ids):
    records = {}
    directory = _space_directory(service, 'capability', avatar, scope['space_ref'])
    for capability_id in sorted(capability_ids):
        require(_valid_id('capability', capability_id), 'E_WORKFLOW_CAPABILITY')
        path = directory / (digest(capability_id) + '.json') if directory is not None else None
        capability = _read_record('capability', path, avatar, scope, capability_id)
        if capability is not None:
            records[capability_id] = capability
    return records


def _record_ref(record):
    return {'revision': record['revision'], 'sha256': digest(record)}


def _capability_refs(service, avatar, scope, capability_ids):
    return {capability_id: _record_ref(record) for capability_id, record
            in _capability_records(service, avatar, scope, capability_ids).items()
            if record['descriptor']['status'] == 'active'}


def save_descriptor(service, kind, token, space, source, base_revision):
    require(type(base_revision) is int and base_revision >= 0)
    with service.tx() as connection:
        owner = service._grant(connection, token)
        service._allow(owner, [space], 'write', owner=True)
        scope = service._scope(connection, owner, space)
        try:
            document = _read_document(Path(source), _INPUT_LIMIT)
        except FileNotFoundError:
            raise Fault('E_PROCEDURAL_FILE') from None
        _validate_descriptor(kind, document)
        id_field = _KINDS[kind].id_field
        object_id = document[id_field]
        avatar = owner['avatar']
        directory = _space_directory(service, kind, avatar, space)
        path = directory / (digest(object_id) + '.json') if directory is not None else None
        existing = _read_record(kind, path, avatar, scope, object_id)
        current_revision = existing['revision'] if existing is not None else 0
        require(base_revision == current_revision, 'E_VERSION_CONFLICT', 409)
        record = {'avatar_id': avatar, 'scope': scope, 'revision': current_revision + 1,
                  'previous_revision': current_revision or None, 'updated_at': stamp(service.now()),
                  'descriptor': document}
        if kind == 'workflow':
            require(document['owner_avatar_id'] == avatar, 'E_SCOPE', 409)
            _workflow_order(document)
        if kind != 'capability':
            ids = _capability_ids(kind, document)
            refs = _capability_refs(service, avatar, scope, ids)
            error = 'E_WORKFLOW_CAPABILITY' if kind == 'workflow' else 'E_BINDING_CAPABILITY'
            require(set(refs) == ids, error, 409)
            record['capability_refs'] = refs
        raw = canonical(record)
        require(len(raw) <= _RECORD_LIMIT, 'E_PROCEDURAL_FILE')
        if path is None:
            directory = _space_directory(service, kind, avatar, space, create=True)
            path = directory / (digest(object_id) + '.json')
        try:
            with TemporaryDirectory(prefix='.aiap-descriptor-', dir=path.parent) as staging:
                temporary = Path(staging) / path.name
                save_private(temporary, raw)
                with temporary.open('rb') as written:
                    os.fsync(written.fileno())
                temporary.replace(path)
        except OSError:
            raise Fault('E_PROCEDURAL_FILE') from None
        return {id_field: object_id, 'space_ref': space, 'revision': record['revision'],
                'sha256': digest(record)}


def read_descriptor(service, kind, token, space, object_id):
    require(_valid_id(kind, object_id))
    with service.tx(read_only=True) as connection:
        owner = service._grant(connection, token)
        service._allow(owner, [space], 'read', owner=True)
        scope = service._scope(connection, owner, space)
        avatar = owner['avatar']
        directory = _space_directory(service, kind, avatar, space)
        path = directory / (digest(object_id) + '.json') if directory is not None else None
        record = _read_record(kind, path, avatar, scope, object_id)
        require(record is not None, 'E_NOT_FOUND', 404)
        result = {'record': record, 'sha256': digest(record)}
        if kind != 'capability':
            current = _capability_refs(service, avatar, scope, record['capability_refs'])
            result['stale_capability_ids'] = sorted(capability_id for capability_id, ref in record['capability_refs'].items()
                                                    if current.get(capability_id) != ref)
        return result


def list_descriptors(service, kind, token, space, *, after=None, limit=20):
    require(after is None or _valid_id(kind, after))
    require(type(limit) is int and 1 <= limit <= 100)
    spec = _KINDS[kind]
    with service.tx(read_only=True) as connection:
        owner = service._grant(connection, token)
        service._allow(owner, [space], 'read', owner=True)
        scope = service._scope(connection, owner, space)
        avatar = owner['avatar']
        directory = _space_directory(service, kind, avatar, space)

        def entries():
            for record in _space_records(kind, directory, avatar, scope):
                descriptor = record['descriptor']
                if after is None or descriptor[spec.id_field] > after:
                    fields = (spec.id_field, 'capability_id', 'mapping_class', 'status') if kind == 'runtime-binding' else (
                        spec.id_field, 'name', 'version', 'status',
                    )
                    yield {**{key: descriptor[key] for key in fields},
                           'revision': record['revision']}

        rows = nsmallest(limit + 1, entries(), key=lambda row: row[spec.id_field])
        return {'space_ref': space, spec.list_field: rows[:limit],
                'next_after': rows[limit - 1][spec.id_field] if len(rows) > limit else None}


def _check_runtime(runtime_id, runtime_version):
    require(isinstance(runtime_id, str) and runtime_id)
    require(runtime_version is None or isinstance(runtime_version, str))


def _read_agent_inventory(source, avatar, space, runtime_id, runtime_version):
    if source is None:
        return None
    try:
        document = _read_document(Path(source), _INPUT_LIMIT)
        exact(document, ['agent_id', 'avatar_id', 'space_ref', 'runtime_id', 'runtime_version', 'implementations'])
        require(isinstance(document['agent_id'], str) and document['agent_id'].strip())
        require(isinstance(document['implementations'], list))
        available = set()
        for implementation in document['implementations']:
            exact(implementation, ['type', 'ref'])
            require(implementation['type'] in _IMPLEMENTATION_TYPES
                    and isinstance(implementation['ref'], str) and implementation['ref'].strip())
            key = (implementation['type'], implementation['ref'])
            require(key not in available)
            available.add(key)
    except (FileNotFoundError, Fault):
        raise Fault('E_AGENT_INVENTORY') from None
    require((document['avatar_id'], document['space_ref'], document['runtime_id'], document['runtime_version'])
            == (avatar, space, runtime_id, runtime_version), 'E_AGENT_INVENTORY_SCOPE', 409)
    return _AgentInventory(document['agent_id'], digest(document), frozenset(available))


def _binding_summary(record, ref, policy, runtime_version, inventory):
    binding = record['descriptor']
    mapping = binding['mapping_class']
    declared_version = binding['runtime'].get('runtime_version')
    reasons = []
    if binding['status'] != 'active':
        reasons.append('inactive-binding')
    if declared_version is not None and declared_version != runtime_version:
        reasons.append('runtime-version-mismatch')
    if record['capability_refs'][binding['capability_id']] != ref:
        reasons.append('stale-capability')
    if mapping == 'unresolved' or mapping not in policy.get('accepted_mapping_classes', ['exact', 'compatible']):
        reasons.append('mapping-class-not-accepted')
    if binding['confidence'] < policy.get('minimum_confidence', 0):
        reasons.append('confidence-below-policy')
    implementation = binding['implementation']
    if inventory is not None and (implementation['type'], implementation['ref']) not in inventory.implementations:
        reasons.append('implementation-unavailable-for-agent')
    if reasons:
        status = 'ineligible'
    elif binding.get('requires_user_confirmation', False) or mapping in ('partial', 'composite'):
        status = 'confirmation-required'
    else:
        status = 'candidate'
    return {'binding_id': binding['binding_id'], 'revision': record['revision'], 'mapping_class': mapping,
            'confidence': binding['confidence'], 'status': status, 'reasons': reasons}


def _rank_binding(row):
    return (_BINDING_STATUSES.index(row['status']), _MAPPING_ORDER.index(row['mapping_class']),
            -row['confidence'], row['binding_id'])


def _resolve_bindings(service, avatar, scope, capabilities, runtime_id, runtime_version, inventory):
    refs = {capability_id: _record_ref(record) for capability_id, record in capabilities.items()}
    counts = {capability_id: dict.fromkeys(_BINDING_STATUSES, 0) for capability_id in capabilities}
    rows = {capability_id: [] for capability_id in capabilities}
    if not capabilities:
        return {}
    directory = _space_directory(service, 'runtime-binding', avatar, scope['space_ref'])
    for record in _space_records('runtime-binding', directory, avatar, scope):
        binding = record['descriptor']
        capability_id = binding['capability_id']
        if capability_id not in capabilities or binding['runtime']['runtime_id'] != runtime_id:
            continue
        policy = capabilities[capability_id]['descriptor'].get('equivalence_policy', {})
        row = _binding_summary(record, refs[capability_id], policy, runtime_version, inventory)
        counts[capability_id][row['status']] += 1
        best = rows[capability_id]
        insort(best, row, key=_rank_binding)
        if len(best) > _BINDING_PREVIEW_LIMIT:
            best.pop()
    return {capability_id: {
        'capability_revision': ref['revision'],
        'status': next((status for status in _BINDING_STATUSES[:2] if counts[capability_id][status]), 'unresolved'),
        'binding_counts': counts[capability_id],
        'bindings': rows[capability_id],
        'possibly_more': sum(counts[capability_id].values()) > len(rows[capability_id]),
    } for capability_id, ref in refs.items()}


def resolve_capability(service, token, space, capability_id, runtime_id, *, runtime_version=None, agent_inventory=None):
    require(_valid_id('capability', capability_id))
    _check_runtime(runtime_id, runtime_version)
    # Hold the same reservation as descriptor writers while sampling related files.
    with service.tx() as connection:
        owner = service._grant(connection, token)
        service._allow(owner, [space], 'read', owner=True)
        scope = service._scope(connection, owner, space)
        avatar = owner['avatar']
        capabilities = _capability_records(service, avatar, scope, [capability_id])
        capability = capabilities.get(capability_id)
        require(capability is not None, 'E_NOT_FOUND', 404)
        require(capability['descriptor']['status'] == 'active', 'E_CAPABILITY_INACTIVE', 409)
        inventory = _read_agent_inventory(agent_inventory, avatar, space, runtime_id, runtime_version)
        result = _resolve_bindings(service, avatar, scope, capabilities, runtime_id, runtime_version, inventory)
        return {'space_ref': space, 'capability_id': capability_id, 'runtime_id': runtime_id,
                'runtime_version': runtime_version, **result[capability_id],
                **({'agent_inventory': inventory.summary()} if inventory is not None else {})}


def _workflow_capabilities(service, avatar, scope, refs, runtime_id, runtime_version, inventory):
    records = _capability_records(service, avatar, scope, refs)
    available, results = {}, {}
    for capability_id, ref in refs.items():
        record = records.get(capability_id)
        if record is None:
            reason = 'missing-capability'
        elif record['descriptor']['status'] != 'active':
            reason = 'inactive-capability'
        elif _record_ref(record) != ref:
            reason = 'stale-capability'
        else:
            available[capability_id] = record
            continue
        current_revision = record['revision'] if record is not None else None
        results[capability_id] = {'status': 'blocked', 'reason': reason,
                                  'current_revision': current_revision, 'expected': ref}
    results.update(_resolve_bindings(service, avatar, scope, available, runtime_id, runtime_version, inventory))
    return results


def _workflow_steps(document, order, capabilities):
    definitions = {step['step_id']: step for step in document['steps']}
    required = {step_id for step_id in order if definitions[step_id].get('required', True)}
    for step_id in reversed(order):
        if step_id in required:
            required.update(definitions[step_id].get('depends_on', []))
    result = []
    for step_id in order:
        step = definitions[step_id]
        capability_id = step['capability_id']
        result.append({'step_id': step_id, 'capability_id': capability_id,
                       'depends_on': step.get('depends_on', []), 'required': step.get('required', True),
                       'required_for_workflow': step_id in required, 'conditional': step.get('condition') is not None,
                       'status': capabilities[capability_id]['status']})
    return result


def resolve_workflow(service, token, space, workflow_id, runtime_id, *, runtime_version=None, agent_inventory=None):
    require(_valid_id('workflow', workflow_id))
    _check_runtime(runtime_id, runtime_version)
    with service.tx() as connection:
        owner = service._grant(connection, token)
        service._allow(owner, [space], 'read', owner=True)
        scope = service._scope(connection, owner, space)
        avatar = owner['avatar']
        directory = _space_directory(service, 'workflow', avatar, space)
        path = directory / (digest(workflow_id) + '.json') if directory is not None else None
        record = _read_record('workflow', path, avatar, scope, workflow_id)
        require(record is not None, 'E_NOT_FOUND', 404)
        document = record['descriptor']
        order = _workflow_order(document)
        inventory = _read_agent_inventory(agent_inventory, avatar, space, runtime_id, runtime_version)
        capabilities = _workflow_capabilities(service, avatar, scope, record['capability_refs'],
                                               runtime_id, runtime_version, inventory)
        steps = _workflow_steps(document, order, capabilities)
        required_statuses = {step['status'] for step in steps if step['required_for_workflow']}
        reasons = []
        if document['status'] in ('deprecated', 'dormant', 'archived'):
            reasons.append('inactive-workflow')
            required_statuses.add('blocked')
        if document.get('runtime_constraints') or document.get('portability') == 'runtime_specific':
            reasons.append('runtime-constraints-require-review')
            required_statuses.add('confirmation-required')
        status = next((value for value in ('blocked', 'unresolved', 'confirmation-required')
                       if value in required_statuses), 'candidate')
        return {'workflow_id': workflow_id, 'workflow_revision': record['revision'], 'workflow_sha256': digest(record),
                'workflow_status': document['status'], 'space_ref': space, 'runtime_id': runtime_id,
                'runtime_version': runtime_version, 'status': status, 'reasons': reasons,
                'steps': steps, 'capabilities': capabilities,
                **({'agent_inventory': inventory.summary()} if inventory is not None else {})}
