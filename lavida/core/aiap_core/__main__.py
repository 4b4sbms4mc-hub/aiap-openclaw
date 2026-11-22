import argparse,json,os,re,stat,sys,uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from .service import DECISION_REASONS, Service, save_private
from .server import serve
from .client import Client,proposal
from .admission import TRIGGERS
from .contracts import canonical,Fault,require

_LIFECYCLE_COMMANDS = {
    'propose-promotion': ('promote', 'Propose promoting one local M1 memory to M2 as Owner.'),
    'propose-reactivation': ('reactivate', 'Propose reactivating one local M3 memory as M1.'),
    'propose-archive': ('archive', 'Propose archiving one local M1 or M2 memory as M3.'),
}

_SESSION_EXCERPT_LIMIT = 16000

def _read_grant_token(path):
    limit = 64 * 1024
    try:
        if os.name == 'nt':
            from aiap._windows_files import read_private
            data = read_private(Path(path), limit)
        else:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                metadata = os.fstat(fd)
                require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= limit, 'E_CREDENTIAL_FILE')
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    data = stream.read(limit + 1)
            finally:
                os.close(fd)
        require(len(data) <= limit, 'E_CREDENTIAL_FILE')
        credential = json.loads(data.decode('utf-8'))
        require(isinstance(credential, dict), 'E_CREDENTIAL_FILE')
        token = credential.get('token')
        require(isinstance(token, str) and 20 <= len(token) <= 200, 'E_CREDENTIAL_FILE')
        return token
    except (OSError, ValueError, RecursionError, ImportError):
        raise Fault('E_CREDENTIAL_FILE') from None


def _add_recall_options(parser):
    parser.add_argument('--query', default='')
    parser.add_argument('--include-archived', action='store_true')
    parser.add_argument('--level', choices=('M1', 'M2', 'M3'),
                        help='Recall a single level. M3 also requires --include-archived.')


def _search_request(args, session):
    request = {'space_refs': [args.space], 'purpose': session['purpose'], 'query': args.query,
               'include_archived': args.include_archived}
    if args.level is not None:
        request['level'] = args.level
    return request


def _read_session_excerpt():
    max_bytes = _SESSION_EXCERPT_LIMIT * 4
    raw = sys.stdin.buffer.read(max_bytes + 1)
    require(len(raw) <= max_bytes, 'E_SESSION_EXCERPT')
    try:
        excerpt = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise Fault('E_SESSION_EXCERPT') from None
    require(bool(excerpt.strip()) and len(excerpt) <= _SESSION_EXCERPT_LIMIT and '\x00' not in excerpt,
            'E_SESSION_EXCERPT')
    return excerpt


def main():
    ap=argparse.ArgumentParser(description='AIAP Core Service 0.2.3 — Wang Lu');ap.add_argument('--data-dir',default=os.environ.get('AIAP_DATA_DIR','./data'));sp=ap.add_subparsers(dest='command',required=True)
    sp.add_parser('init',help='Initialize once without overwriting an existing identity.')
    sv=sp.add_parser('serve');sv.add_argument('--host',default='127.0.0.1');sv.add_argument('--port',type=int,default=8042);sv.add_argument('--archive-interval',type=int,default=3600)
    g=sp.add_parser('grant');g.add_argument('--spaces',nargs='+',required=True);g.add_argument('--purpose',required=True);g.add_argument('--runtime',required=True);g.add_argument('--role',choices=['adapter','owner'],default='adapter');g.add_argument('--days',type=int,default=7);g.add_argument('--output',required=True)
    project = sp.add_parser('project-space', help='Create an isolated local project space, without granting access.')
    project.add_argument('slug', help='Up to 63 lowercase letters, digits or hyphens, starting with a letter or digit.')
    reissue = sp.add_parser('grant-reissue', help='Issue a fresh local credential with the same permissions.')
    reissue.add_argument('--grant-id', required=True)
    reissue.add_argument('--days', type=int, default=7)
    reissue.add_argument('--output', required=True, help='New credential path.')
    grant_status = sp.add_parser('grant-status', help='Inspect a local credential without changing its grant.')
    grant_status.add_argument('--credential-file', required=True)
    grants = sp.add_parser('grants', help='List grant metadata as the local Core operator.')
    grants.add_argument('--role', choices=('owner', 'adapter'))
    grants.add_argument('--after', help='Continue from the previous page’s next_after value.')
    grants.add_argument('--limit', type=int, default=20)
    preflight = sp.add_parser('preflight-candidate', help='Check a JSON memory candidate from stdin without submitting it.')
    preflight.add_argument('--credential-file', required=True)
    browse = sp.add_parser('list-memories', help='Browse one space by memory ID.')
    browse.add_argument('--credential-file', required=True)
    browse.add_argument('--validity', choices=('current', 'expired', 'superseded'), help='Owner review of expired or superseded records.')
    browse.add_argument('--space', required=True)
    browse.add_argument('--purpose', required=True)
    for option in ('level', 'memory-type', 'updated-from', 'updated-before', 'after'):
        browse.add_argument('--' + option)
    browse.add_argument('--limit', type=int, default=20)
    pending = sp.add_parser('pending', help='List local proposals awaiting an Owner decision.')
    pending.add_argument('--credential-file', required=True)
    pending.add_argument('--space', help='Show proposals that include this space.')
    pending.add_argument('--trigger', choices=(*TRIGGERS, 'legacy'), help='Filter by the reported proposal trigger.')
    pending.add_argument('--after', help='Continue from the previous page’s next_after value.')
    pending.add_argument('--limit', type=int, default=20)
    procedural_commands = {'capability': '--capability-id', 'workflow': '--workflow-id', 'runtime-binding': '--binding-id'}
    for kind, id_option in procedural_commands.items():
        descriptor = sp.add_parser(kind, help=f'Manage local {kind} descriptors as Owner.')
        descriptor_commands = descriptor.add_subparsers(dest='descriptor_command', required=True)
        put_descriptor = descriptor_commands.add_parser('put', help=f'Save a local {kind} descriptor.')
        put_descriptor.add_argument('--file', required=True)
        put_descriptor.add_argument('--base-revision', type=int, required=True, help='Use zero for a new descriptor.')
        get_descriptor = descriptor_commands.add_parser('get', help=f'Read an authorized {kind} descriptor.')
        get_descriptor.add_argument(id_option, dest='descriptor_id', required=True)
        list_descriptor = descriptor_commands.add_parser('list', help=f'List {kind} metadata in one Owner space.')
        list_descriptor.add_argument('--after', help='Continue from the previous page’s next_after value.')
        list_descriptor.add_argument('--limit', type=int, default=20)
        operations = [put_descriptor, get_descriptor, list_descriptor]
        if kind in ('capability', 'workflow'):
            resolve = descriptor_commands.add_parser('resolve', help=f'Evaluate local Runtime bindings for a {kind}.')
            resolve.add_argument(id_option, dest='descriptor_id', required=True)
            resolve.add_argument('--runtime-id', required=True)
            resolve.add_argument('--runtime-version')
            resolve.add_argument('--agent-inventory', help='JSON file listing the target Agent’s available implementations.')
            operations.append(resolve)
        for operation in operations:
            operation.add_argument('--credential-file', required=True)
            operation.add_argument('--space', required=True)
    observation = sp.add_parser('capture-owner-observation', help='Check and queue one host-reported Owner preference from stdin.')
    observation.add_argument('--credential-file', required=True)
    observation.add_argument('--space', choices=('space:general',), required=True)
    capture = sp.add_parser('capture-session', help='Propose one selected UTF-8 session excerpt from stdin as M1.')
    capture.add_argument('--credential-file', required=True)
    capture.add_argument('--space', required=True)
    capture.add_argument('--preview', action='store_true', help='Validate input and show its scope without submitting it.')
    capture.add_argument('--capture-id', help='Reuse a caller-chosen ID to retry the same capture.')
    context = sp.add_parser('context', help='Compile a short-lived authorized view from local memories.')
    context.add_argument('--credential-file', required=True)
    context.add_argument('--space', required=True)
    context.add_argument('--preference-condition')
    context.add_argument('--skip-preferences', action='store_true')
    _add_recall_options(context)
    context.add_argument('--limit', type=int, default=20)
    acknowledge = sp.add_parser('context-ack', help='Record use of a local authorized view.')
    acknowledge.add_argument('--credential-file', required=True)
    acknowledge.add_argument('--view-id', required=True)
    confirm_use = sp.add_parser('confirm-use', help='Record Owner-confirmed usefulness for one local memory.')
    confirm_use.add_argument('--credential-file', required=True)
    confirm_use.add_argument('--space', required=True)
    confirm_use.add_argument('--memory-id', required=True)
    confirm_use.add_argument('--base-revision', type=int, required=True)
    for command, (_, help_text) in _LIFECYCLE_COMMANDS.items():
        transition = sp.add_parser(command, help=help_text)
        transition.add_argument('--credential-file', required=True)
        transition.add_argument('--space', required=True)
        transition.add_argument('--memory-id', required=True)
        transition.add_argument('--base-revision', type=int, required=True)
        transition.add_argument('--reason', required=True)
    summary = sp.add_parser('summary', help='Count local memories and pending proposals by Owner space.')
    summary.add_argument('--credential-file', required=True)
    summary.add_argument('--space', help='Limit counts to one authorized space.')
    compact = sp.add_parser('compact-core', help='Show the local compact Core projection as Owner.')
    compact.add_argument('--credential-file', required=True)
    compact.add_argument('--summary-memory', action='append', default=[], metavar='MEMORY_ID',
                         help='Include an approved pinned M2 memory as a summary reference. Repeat for distinct spaces.')
    profile_summary = sp.add_parser('profile-summary', help='Read a selected local summary source as Owner.')
    profile_summary.add_argument('--credential-file', required=True)
    profile_summary.add_argument('--space', required=True)
    profile_summary.add_argument('--memory-id', help='Read this source instead of the saved one, with --revision.')
    profile_summary.add_argument('--revision', type=int, help='Current source revision, with --memory-id.')
    select_summary = sp.add_parser('profile-summary-select', help='Save a local summary source for one Owner space.')
    select_summary.add_argument('--memory-id', required=True)
    select_summary.add_argument('--revision', type=int, required=True)
    clear_summary = sp.add_parser('profile-summary-clear', help='Clear the saved local summary source for one Owner space.')
    for selector in (select_summary, clear_summary):
        selector.add_argument('--credential-file', required=True)
        selector.add_argument('--space', required=True)
    manifest = sp.add_parser('compact-manifest', help='Read one space manifest from the current compact Core revision.')
    manifest.add_argument('--credential-file', required=True)
    manifest.add_argument('--space', required=True)
    manifest.add_argument('--core-revision', type=int, required=True)
    validity = sp.add_parser('set-validity', help='Set an absolute expiry or record a replacement as local Owner.')
    validity.add_argument('--credential-file', required=True)
    validity.add_argument('--space', required=True)
    validity.add_argument('--memory-id', required=True)
    validity.add_argument('--base-revision', type=int, required=True)
    mode = validity.add_mutually_exclusive_group(required=True)
    mode.add_argument('--expires-at', help='ISO timestamp with timezone offset.')
    mode.add_argument('--clear-expiry', action='store_true', help='Remove the deadline at the specified current revision.')
    mode.add_argument('--successor-id', help='Approved replacement in the same space.')
    validity.add_argument('--successor-revision', type=int)
    find_evidence = sp.add_parser('find-preference-evidence', help='Find potentially related M1 observations as Owner.')
    find_evidence.add_argument('--credential-file', required=True)
    find_evidence.add_argument('--space', required=True)
    find_evidence.add_argument('--query', required=True)
    find_evidence.add_argument('--limit', type=int, default=20)
    candidates = sp.add_parser('preference-candidates', help='Browse repeated M1 preference evidence as Owner.')
    candidates.add_argument('--credential-file', required=True)
    candidates.add_argument('--space', required=True)
    candidates.add_argument('--after', default='')
    candidates.add_argument('--limit', type=int, default=20)
    evidence = sp.add_parser('review-preference-evidence', help='Review approved M1 observations grouped by source as local Owner.')
    evidence.add_argument('--credential-file', required=True)
    evidence.add_argument('--space', required=True)
    evidence.add_argument('--memory-ids', nargs='+', required=True)
    for command in ('preview-preference', 'confirm-preference'):
        preview = sp.add_parser(command)
        for option in ('credential-file', 'space', 'statement', 'condition'):
            preview.add_argument('--' + option, required=True)
        preview.add_argument('--runtime', action='append', required=True)
        preview.add_argument('--replaces')
        preview.add_argument('--exception')
        preview.add_argument('--project-rule')
        preview.add_argument('--same-event', nargs='+', action='append', metavar='SOURCE_REF',
                             help='Group two or more selected sources describing one event; repeat for other events.')
        preview.add_argument('--evidence-revision', nargs=2, action='append', metavar=('ID', 'REVISION'),
                             help='Require the selected evidence to match the revision you reviewed; repeat per ID.')
        preview.add_argument('--supporting', nargs='+')
        preview.add_argument('--counterexamples', nargs='+')
        if command == 'confirm-preference':
            preview.add_argument('--preview-sha256', required=True)
    recall = sp.add_parser('recall-preferences', help='Read confirmed defaults for an exact condition and credential runtime.')
    for option in ('credential-file', 'space', 'condition'):
        recall.add_argument('--' + option, required=True)
    baseline = sp.add_parser('preview-preference-baseline', help='Review the unsigned registry across every space as Owner.')
    baseline.add_argument('--credential-file', required=True)
    pref_manifest = sp.add_parser('preference-manifest', help='Read a preference digest and its local Core signature status as Owner.')
    pref_manifest.add_argument('--credential-file', required=True)
    pref_manifest.add_argument('--space', required=True)
    pref_list = sp.add_parser('list-preferences', help='Browse current and historical preferences as Owner.')
    pref_list.add_argument('--credential-file', required=True)
    pref_list.add_argument('--space', required=True)
    pref_list.add_argument('--after', default='')
    pref_list.add_argument('--limit', type=int, default=20)
    withdraw = sp.add_parser('withdraw-preference')
    for option in ('credential-file', 'space', 'preference-id'):
        withdraw.add_argument('--' + option, required=True)
    history = sp.add_parser('history', help='List local memory revisions or read one revision as Owner.')
    history.add_argument('--credential-file', required=True)
    history.add_argument('--space', required=True)
    history.add_argument('--memory-id', required=True)
    history_mode = history.add_mutually_exclusive_group()
    history_mode.add_argument('--revision', type=int, help='Read one revision instead of listing revisions.')
    history_mode.add_argument('--before', type=int, help='Continue from the previous page’s next_before value.')
    history.add_argument('--limit', type=int, default=20, help='Maximum revisions per page.')
    audit = sp.add_parser('audit', help='List local audit events visible to an Owner.')
    audit.add_argument('--credential-file', required=True)
    audit.add_argument('--space', help='Filter to events recorded for this space.')
    audit.add_argument('--event', help='Filter by exact event name.')
    audit.add_argument('--object-id', help='Filter by exact proposal, memory or grant ID.')
    audit.add_argument('--before', help='Continue from the previous page’s next_before value.')
    audit.add_argument('--limit', type=int, default=20)
    sync = sp.add_parser('sync', help='Prepare signed memory snapshots for another Core.')
    sync_commands = sync.add_subparsers(dest='sync_command', required=True)
    identity = sync_commands.add_parser('identity', help='Show the local enrollment fingerprint.')
    export = sync_commands.add_parser('export', help='Export one space to a private signed file.')
    preview = sync_commands.add_parser('preview', help='Verify a signed bundle against the receiving Core.')
    for command_parser in (identity, export, preview):
        command_parser.add_argument('--credential-file', required=True)
    for command_parser in (export, preview):
        command_parser.add_argument('--space', required=True, help='Source Core space.')
        command_parser.add_argument('--target-space', required=True)
    export.add_argument('--target-enrollment-sha256', required=True)
    export.add_argument('--output', required=True)
    preview.add_argument('--bundle', required=True)
    preview.add_argument('--source-enrollment-sha256', required=True)
    rev=sp.add_parser('revoke');rev.add_argument('--grant-id',required=True)
    archive = sp.add_parser('archive', help='Run or preview automatic local archive rules.')
    archive.add_argument('--dry-run', action='store_true', help='Count and preview eligible records without changing them.')
    compare = sp.add_parser('compare-local-checkpoint', help='Compare local governance and indexed preferences against a pinned checkpoint.')
    compare.add_argument('--credential-file', required=True)
    compare.add_argument('--checkpoint', required=True)
    compare.add_argument('--checkpoint-sha256', required=True)
    inspect_index = sp.add_parser('inspect-checkpoint-index', help='Inspect a pinned checkpoint index without a registry.')
    inspect_index.add_argument('--checkpoint', required=True)
    inspect_index.add_argument('--checkpoint-sha256', required=True)
    recovery=sp.add_parser('recovery',help='Manage checkpoints and create isolated recovery copies.')
    recovery.add_argument('--registry-dir',required=True,help='Private registry directory outside Core data and backups.')
    rc=recovery.add_subparsers(dest='recovery_command',required=True)
    rc.add_parser('init',help='Initialize a registry with an independently verified enrollment digest.').add_argument('--enrollment-sha256',required=True)
    register=rc.add_parser('register',help='Record an independently pinned signed checkpoint.')
    register.add_argument('--checkpoint',required=True)
    register.add_argument('--checkpoint-sha256',required=True)
    rc.add_parser('status',help='Show local registration metadata without authorizing recovery.')
    rc.add_parser('review',help='Check that a checkpoint file exactly matches the registry.').add_argument('--checkpoint',required=True)
    live=rc.add_parser('review-live',help='Verify a fresh Avatar v2 source observation.')
    isolated=rc.add_parser('restore-isolated',help='Create a private recovery copy using fresh source proofs.')
    for command_parser in (live,isolated):
        command_parser.add_argument('--checkpoint',required=True)
        command_parser.add_argument('--observer-executable',required=True,
                                    help='Absolute path to the separately trusted Avatar v2 stdio launcher.')
    isolated.add_argument('--snapshot',required=True)
    isolated.add_argument('--snapshot-sha256',required=True,help='Independently recorded SQLite backup SHA-256.')
    isolated.add_argument('--target',required=True,help='New private directory outside source, backup and registry.')
    delete_preview = sp.add_parser('delete-preview', help='Preview the impact of deleting one memory.')
    preview_transport = delete_preview.add_mutually_exclusive_group()
    preview_transport.add_argument('--base-url', default='http://127.0.0.1:8042')
    preview_transport.add_argument('--local', action='store_true', help='Use the Core data directory directly.')
    delete = sp.add_parser('delete', help='Delete one memory from the local Core.')
    delete.add_argument('--local', action='store_true', required=True, help='Use the Core data directory directly.')
    delete.add_argument('--confirm', action='store_true', required=True, help='Confirm deletion at the specified revision.')
    for command_parser in (delete_preview, delete):
        command_parser.add_argument('--credential-file', required=True)
        command_parser.add_argument('--memory-id', required=True)
        command_parser.add_argument('--space', required=True)
        command_parser.add_argument('--base-revision', type=int, required=True)
    for command in ['session','core','search','propose','review','decide','demo']:
        x=sp.add_parser(command);x.add_argument('--credential-file',required=True)
        local_supported = command in ('search', 'propose', 'review', 'decide')
        transport=x.add_mutually_exclusive_group() if local_supported else x
        transport.add_argument('--base-url',default='http://127.0.0.1:8042')
        if local_supported:transport.add_argument('--local',action='store_true',help='Use the Core data directory directly without starting an HTTP service.')
        if command in ['search','propose']:x.add_argument('--space',required=True)
        if command == 'search':
            _add_recall_options(x)
        if command == 'propose':
            proposal_content = x.add_mutually_exclusive_group(required=True)
            proposal_content.add_argument('--text')
            proposal_content.add_argument('--from-revision', type=int, help='Use the text of an earlier local revision as Owner.')
            x.add_argument('--pinned', action='store_true')
            x.add_argument('--level', choices=('M1', 'M2'), help='Set an initial level for a new local memory.')
            x.add_argument('--memory-id', help='Existing memory to update locally.')
            x.add_argument('--base-revision', type=int, help='Expected current revision of the memory.')
        if command in ['review','decide']:x.add_argument('--delta-id',required=True)
        if command == 'review':
            x.add_argument('--changes', action='store_true', help='Preview proposed text and revisions in local mode.')
        if command=='decide':x.add_argument('--reason', choices=DECISION_REASONS, help='Record an optional Owner decision reason.')
        if command=='decide':x.add_argument('--approve',action='store_true',help='Explicitly approve the reviewed candidate; otherwise reject.')
    args=ap.parse_args()
    if args.command in ('search', 'context') and args.level == 'M3' and not args.include_archived:
        ap.error('--level M3 requires --include-archived')
    if args.command == 'profile-summary' and (args.memory_id is None) != (args.revision is None):
        ap.error('--memory-id and --revision must be supplied together')
    if args.command == 'review' and args.changes and not args.local:
        ap.error('--changes requires --local')
    if args.command == 'propose' and args.level is not None and (not args.local or args.memory_id is not None):
        ap.error('--level is only available for a new local memory')
    if args.command == 'propose' and any(value is not None for value in
                                         (args.memory_id, args.base_revision, args.from_revision)):
        if not args.local or not args.memory_id or args.base_revision is None or args.base_revision < 1:
            ap.error('updating a memory requires --local, --memory-id and a positive --base-revision')
        if args.pinned:
            ap.error('updates preserve the existing pin setting')
        if args.from_revision is not None and not 1 <= args.from_revision < args.base_revision:
            ap.error('--from-revision must be positive and earlier than --base-revision')
    if args.command == 'sync':
        from .contracts import digest
        from .memory_sync import export_memory, preview_memory
        service = Service(args.data_dir, enable_semantic=False)
        token = _read_grant_token(args.credential_file)
        if args.sync_command == 'identity':
            with service.tx(read_only=True) as connection:
                grant = service._grant(connection, token)
                require(grant['role'] == 'owner', 'E_DENIED', 403)
                result = {'enrollment_sha256': digest(service.meta(connection, 'enrollment'))}
        elif args.sync_command == 'export':
            result = export_memory(service, token, args.space, args.target_space,
                                   args.target_enrollment_sha256, args.output)
        else:
            result = preview_memory(service, token, args.bundle, args.source_enrollment_sha256,
                                    args.space, args.target_space)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if args.command == 'inspect-checkpoint-index':
        from datetime import datetime, timezone
        from .recovery_checkpoint import inspect_checkpoint_index
        result = inspect_checkpoint_index(args.checkpoint, args.checkpoint_sha256, datetime.now(timezone.utc))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    if args.command=='recovery':
        from .recovery_registry import CheckpointRegistry
        registry=CheckpointRegistry(args.registry_dir,args.data_dir)
        if args.recovery_command=='init':result=registry.initialize(args.enrollment_sha256)
        elif args.recovery_command=='register':result=registry.register(args.checkpoint,args.checkpoint_sha256)
        elif args.recovery_command=='review':result=registry.review(args.checkpoint)
        elif args.recovery_command in ('review-live','restore-isolated'):
            from .recovery_transport import trusted_stdio_observer
            outside=[args.data_dir,args.registry_dir]
            if args.recovery_command=='restore-isolated':outside.extend((args.snapshot,args.target))
            observe=trusted_stdio_observer(args.observer_executable,outside=outside)
            if args.recovery_command=='review-live':
                result=registry.review_live(args.checkpoint,observe)
            else:
                from .recovery_isolated import restore_isolated
                result=restore_isolated(registry,args.checkpoint,args.snapshot,args.snapshot_sha256,args.target,observe)
        else:result=registry.status()
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return
    local=getattr(args,'local',False)
    local_commands = ('list-memories', 'preflight-candidate', 'pending', *procedural_commands, 'capture-session', 'capture-owner-observation', 'context', 'context-ack', 'confirm-use',
                      'summary', 'project-space', 'set-validity', 'compare-local-checkpoint', 'preference-candidates', 'review-preference-evidence', 'preview-preference', 'confirm-preference', 'withdraw-preference', 'recall-preferences', 'list-preferences', 'preference-manifest', 'preview-preference-baseline', 'history', 'grants', 'grant-reissue', 'audit',
                      'compact-core', 'compact-manifest', 'profile-summary',
                      'profile-summary-select', 'profile-summary-clear', *_LIFECYCLE_COMMANDS)
    s=Service(args.data_dir,enable_semantic=not local and args.command not in local_commands)
    if args.command=='init':result=s.initialize()
    elif args.command=='serve':return serve(s,args.host,args.port,args.archive_interval)
    elif args.command=='archive':result=s.archive_cycle(dry_run=args.dry_run)
    elif args.command == 'compare-local-checkpoint':
        from .recovery_checkpoint import compare_local_checkpoint
        result = compare_local_checkpoint(s, _read_grant_token(args.credential_file), args.checkpoint, args.checkpoint_sha256)
    elif args.command == 'project-space':result=s.create_project_space(args.slug)
    elif args.command=='grant':
        if Path(args.output).exists():raise Fault('E_OUTPUT_EXISTS',409)
        r=s.issue_grant(args.spaces,args.purpose,args.runtime,args.role,args.days)
        try:save_private(Path(args.output),canonical(r))
        except Exception:s.revoke_grant(r['grant_id']);raise
        result={'grant_id':r['grant_id'],'credential_file':args.output,'expires_at':r['expires_at']}
    elif args.command == 'grant-reissue':
        output = Path(args.output)
        require(not os.path.lexists(output), 'E_OUTPUT_EXISTS', 409)
        try:
            with TemporaryDirectory(prefix='.aiap-grant-', dir=output.parent) as staging:
                credential = s.reissue_grant(args.grant_id, days=args.days)
                temp = Path(staging) / 'credential.json'
                try:
                    save_private(temp, canonical(credential))
                    os.link(temp, output)
                except Exception:
                    s.revoke_grant(credential['grant_id'])
                    raise
        except FileExistsError:
            raise Fault('E_OUTPUT_EXISTS', 409) from None
        except OSError:
            raise Fault('E_CREDENTIAL_OUTPUT') from None
        result = {'grant_id': credential['grant_id'], 'previous_grant_id': args.grant_id,
                  'credential_file': args.output, 'expires_at': credential['expires_at']}
    elif args.command=='revoke':s.revoke_grant(args.grant_id);result={'revoked':True}
    elif args.command=='grant-status':result=s.grant_status(_read_grant_token(args.credential_file))
    elif args.command == 'grants':
        result = s.list_grants(role=args.role, after=args.after, limit=args.limit)
    elif args.command == 'list-memories':
        body = {'space_ref': args.space, 'purpose': args.purpose, 'limit': args.limit}
        for key in ('level', 'memory_type', 'updated_from', 'updated_before', 'after', 'validity'):
            if getattr(args, key) is not None:
                body[key] = getattr(args, key)
        result = s.list_memories(_read_grant_token(args.credential_file), body)
    elif args.command == 'preflight-candidate':
        from .server import reject_duplicates
        try:
            body = json.loads(_read_session_excerpt(), object_pairs_hook=reject_duplicates)
        except (ValueError, RecursionError):
            raise Fault('E_SCHEMA') from None
        result = s.preflight_candidate(_read_grant_token(args.credential_file), body)
    elif args.command == 'pending':
        result = s.pending_proposals(_read_grant_token(args.credential_file), space=args.space,
                                     after=args.after, limit=args.limit, trigger=args.trigger)
    elif args.command in procedural_commands:
        from .procedural import list_descriptors, read_descriptor, resolve_capability, resolve_workflow, save_descriptor
        token = _read_grant_token(args.credential_file)
        if args.descriptor_command == 'put':
            result = save_descriptor(s, args.command, token, args.space, args.file, args.base_revision)
        elif args.descriptor_command == 'get':
            result = read_descriptor(s, args.command, token, args.space, args.descriptor_id)
        elif args.descriptor_command == 'resolve':
            resolve = resolve_capability if args.command == 'capability' else resolve_workflow
            result = resolve(s, token, args.space, args.descriptor_id, args.runtime_id,
                             runtime_version=args.runtime_version, agent_inventory=args.agent_inventory)
        else:
            result = list_descriptors(s, args.command, token, args.space, after=args.after, limit=args.limit)
    elif args.command == 'capture-owner-observation':
        from .server import reject_duplicates
        from .contracts import exact

        try:
            body = json.loads(_read_session_excerpt(), object_pairs_hook=reject_duplicates)
        except (ValueError, RecursionError):
            raise Fault('E_SCHEMA') from None
        exact(body, ['session_id', 'message_id', 'text'])
        for key in ('session_id', 'message_id'):
            require(isinstance(body[key], str) and re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', body[key]))
        require(isinstance(body['text'], str) and 0 < len(body['text']) <= 400 and body['text'].strip())
        token = _read_grant_token(args.credential_file)
        session = s.session(token)
        require(session['role'] == 'adapter' and session['space_refs'] == [args.space]
                and 'write' in session['actions'], 'E_DENIED', 403)
        observation_key = ['aiap-local-dsh-observation-v1', session['avatar_id'], session['auth_evidence_ref'],
                           args.space, body['session_id'], body['message_id']]
        namespace = uuid.uuid5(uuid.NAMESPACE_URL, canonical(observation_key).decode('utf-8'))
        envelope = proposal(session, args.space, body['text'], source_type='observed', id_namespace=namespace)
        source = 'evidence:dsh-host:' + str(namespace)
        change = envelope['delta']['changes'][0]
        change['candidate']['type'] = 'preference-evidence'
        change['candidate']['source']['source_ref'] = source
        change['evidence'] = [{'source_ref': source}]
        envelope['bindings'][0]['source_refs'] = [source]
        result = s.propose_checked(token, {'envelope': envelope, 'trigger': 'host-observation'})
    elif args.command == 'capture-session':
        token = _read_grant_token(args.credential_file)
        session = s.session(token)
        require(args.space in session['space_refs'] and 'write' in session['actions'], 'E_DENIED', 403)
        namespace = None
        if args.capture_id is not None:
            require(re.fullmatch(r'[A-Za-z0-9._:-]{1,128}', args.capture_id), 'E_CAPTURE_ID')
            capture_key = ['aiap-local-session-capture-v1', session['avatar_id'], session['auth_evidence_ref'],
                           args.space, args.capture_id]
            namespace = uuid.uuid5(uuid.NAMESPACE_URL, canonical(capture_key).decode('utf-8'))
        excerpt = _read_session_excerpt()
        if args.preview:
            result = {'status': 'preview', 'space_ref': args.space, 'level': 'M1',
                      'source_type': 'observed', 'characters': len(excerpt)}
        else:
            draft = proposal(session, args.space, excerpt, level='M1', source_type='observed', id_namespace=namespace)
            result = s.propose(token, draft)
    elif args.command == 'context':
        token = _read_grant_token(args.credential_file)
        request = _search_request(args, s.session(token))
        if args.preference_condition is not None:
            request['preference_condition'] = args.preference_condition
        request['skip_preferences'] = args.skip_preferences
        result = s.search(token, {**request, 'limit': args.limit}, context=True)
    elif args.command == 'context-ack':
        result = s.acknowledge(_read_grant_token(args.credential_file), {'view_id': args.view_id})
    elif args.command == 'confirm-use':
        result = s.confirm_memory_use(_read_grant_token(args.credential_file), args.space, args.memory_id,
                                      args.base_revision)
    elif args.command in _LIFECYCLE_COMMANDS:
        kind, _ = _LIFECYCLE_COMMANDS[args.command]
        result = s.propose_lifecycle(_read_grant_token(args.credential_file), args.space, args.memory_id,
                                     args.base_revision, kind=kind, reason=args.reason)
    elif args.command == 'summary':
        result = s.local_summary(_read_grant_token(args.credential_file), space=args.space)
    elif args.command == 'compact-core':
        result = s.compact_core(_read_grant_token(args.credential_file), summary_ids=args.summary_memory)
    elif args.command == 'compact-manifest':
        result = s.compact_core(_read_grant_token(args.credential_file), space=args.space, revision=args.core_revision)
    elif args.command == 'profile-summary':
        result = s.read_profile_summary(_read_grant_token(args.credential_file), args.space, args.memory_id, args.revision)
    elif args.command in ('profile-summary-select', 'profile-summary-clear'):
        result = s.set_summary_selection(_read_grant_token(args.credential_file), args.space,
                                         memory_id=getattr(args, 'memory_id', None),
                                         revision=getattr(args, 'revision', None))
    elif args.command == 'set-validity':
        result = s.set_memory_validity(_read_grant_token(args.credential_file), args.space, args.memory_id,
                                       args.base_revision, expires_at=args.expires_at, successor_id=args.successor_id,
                                       successor_revision=args.successor_revision, clear_expiry=args.clear_expiry)
    elif args.command == 'find-preference-evidence':
        result = s.find_preference_evidence(_read_grant_token(args.credential_file), args.space, args.query, args.limit)
    elif args.command == 'preference-candidates':
        result = s.preference_candidates(_read_grant_token(args.credential_file), args.space,
                                        after=args.after, limit=args.limit)
    elif args.command == 'review-preference-evidence':
        result = s.review_preference_evidence(_read_grant_token(args.credential_file), args.space, args.memory_ids)
    elif args.command in ('preview-preference', 'confirm-preference'):
        revisions = {}
        for ident, raw in args.evidence_revision or ():
            require(re.fullmatch(r'[1-9][0-9]{0,18}', raw) and ident not in revisions)
            revisions[ident] = int(raw)
        fields = dict(statement=args.statement, condition=args.condition, runtimes=args.runtime,
                      exception=args.exception, project_rule=args.project_rule,
                      supporting=args.supporting, counterexamples=args.counterexamples, replaces=args.replaces, same_event=args.same_event,
                      evidence_revisions=revisions)
        token = _read_grant_token(args.credential_file)
        if args.command == 'confirm-preference':
            result = s.confirm_preference(token, args.space, args.preview_sha256, **fields)
        else:
            result = s.preview_preference(token, args.space, **fields)
    elif args.command == 'preview-preference-baseline':
        result = s.preview_preference_baseline(_read_grant_token(args.credential_file))
    elif args.command == 'preference-manifest':
        result = s.preference_manifest(_read_grant_token(args.credential_file), args.space)
    elif args.command == 'list-preferences':
        result = s.list_preferences(_read_grant_token(args.credential_file), args.space, after=args.after, limit=args.limit)
    elif args.command == 'recall-preferences':
        result = s.recall_preferences(_read_grant_token(args.credential_file), args.space, args.condition)
    elif args.command == 'withdraw-preference':
        result = s.withdraw_preference(_read_grant_token(args.credential_file), args.space, args.preference_id)
    elif args.command == 'history':
        result = s.memory_history(_read_grant_token(args.credential_file), args.space, args.memory_id,
                                  revision=args.revision, before=args.before, limit=args.limit)
    elif args.command == 'audit':
        result = s.list_audit(_read_grant_token(args.credential_file), space=args.space,
                              event=args.event, object_id=args.object_id, before=args.before, limit=args.limit)
    elif args.command in ('delete-preview', 'delete'):
        target = {'memory_id': args.memory_id, 'space_ref': args.space, 'base_revision': args.base_revision}
        if args.command == 'delete':
            result = s.delete(_read_grant_token(args.credential_file), target)
        elif local:
            result = s.preview_delete(_read_grant_token(args.credential_file), target)
        else:
            credential = json.loads(Path(args.credential_file).read_text(encoding='utf-8'))
            result = Client(args.base_url, credential['token']).call('/v1/memories/delete/preview', target)
    elif local:
        token=_read_grant_token(args.credential_file)
        session = s.session(token)
        if args.command == 'search':
            result = s.search(token, _search_request(args, session))
        elif args.command == 'propose':
            require(args.space in session['space_refs'], 'E_DENIED', 403)
            text = args.text
            if args.from_revision is not None:
                history = s.memory_history(token, args.space, args.memory_id, revision=args.from_revision)
                require(history['current_revision'] == args.base_revision, 'E_VERSION_CONFLICT', 409)
                text = history['record']['content']
            old = None
            if args.memory_id is not None:
                old = s.memory_for_update(token, args.space, args.memory_id, args.base_revision)
            draft = proposal(session, args.space, text, old=old,
                             pinned=True if args.pinned else None, level=args.level)
            result = s.propose(token, draft)
        else:
            require(session['role']=='owner','E_DENIED',403)
            if args.command=='review':result=s.review(token,args.delta_id,changes=args.changes)
            else:result=s.decide(token,args.delta_id,args.approve,allow_lifecycle=True,reason=args.reason)
    else:
        credential=json.loads(Path(args.credential_file).read_text(encoding='utf-8'));client=Client(args.base_url,credential['token']);session=client.call('/v1/session')
        if args.command=='session':result=session
        elif args.command=='core':result=client.call('/v1/core')
        elif args.command=='search':result=client.call('/v1/search',_search_request(args,session))
        elif args.command=='propose':result=client.call('/v1/deltas/propose',proposal(session,args.space,args.text,pinned=args.pinned))
        elif args.command=='review':result=client.call('/v1/deltas/review',{'delta_id':args.delta_id})
        elif args.command=='decide':result=client.call('/v1/deltas/decide',{'delta_id':args.delta_id,'approve':args.approve,**({'reason':args.reason} if args.reason else {})})
        else:
            if session['role']!='owner':raise Fault('E_DENIED',403)
            for space,text in [('space:work','DEMO：配置服务器时每次只给一步。'),('space:life','DEMO：周六参加陶艺活动。')]:
                p=proposal(session,space,text,pinned=(space=='space:work'));r=client.call('/v1/deltas/propose',p);client.call('/v1/deltas/decide',{'delta_id':r['delta_id'],'approve':True})
            result={'synthetic_demo_created':True,'note':'Verify isolation using separate scoped credentials.'}
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':
    try:main()
    except (Fault,RuntimeError) as e:print(str(e));raise SystemExit(1)
