"""Deterministic review of a deliberately narrow MCP configuration format."""
import hashlib
import json
import posixpath
import re

RULES = {
    'server_added': True, 'scope_expanded': True, 'scope_changed': True,
    'package_unpinned': True, 'configuration_changed': True,
    'server_removed': False, 'scope_narrowed': False,
}
DEFAULT_POLICY = {'rules': RULES, 'scanner_fail_on': 'high'}
SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
PACKAGE = '@modelcontextprotocol/server-filesystem'
PIN = re.compile(r'^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$')


class ReviewError(ValueError):
    pass


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReviewError('Duplicate JSON keys are not supported.')
        result[key] = value
    return result


def load_json(path):
    try:
        with open(path, encoding='utf-8') as stream:
            return json.load(stream, object_pairs_hook=no_duplicates,
                             parse_constant=lambda _: (_ for _ in ()).throw(ReviewError('Invalid JSON constant.')))
    except (OSError, json.JSONDecodeError, UnicodeError) as exc:
        raise ReviewError('Cannot read valid UTF-8 JSON input.') from exc


def validate_config(data):
    if not isinstance(data, dict) or set(data) - {'mcpServers', '$schema'} or not isinstance(data.get('mcpServers'), dict):
        raise ReviewError('Expected a JSON object with mcpServers; other client formats are unsupported.')
    for name, server in data['mcpServers'].items():
        if not name or not isinstance(server, dict):
            raise ReviewError('Each server must have a nonempty name and an object configuration.')
        if ('command' in server) == ('url' in server):
            raise ReviewError('Each server must specify exactly one command or URL.')
        for field in ['command', 'url']:
            if field in server and (not isinstance(server[field], str) or not server[field].strip()):
                raise ReviewError('Server command and URL must be nonempty strings.')
        if 'args' in server and (not isinstance(server['args'], list) or not all(isinstance(x, str) for x in server['args'])):
            raise ReviewError('Server args must be a string array.')
        for field in ['env', 'headers']:
            if field in server and (not isinstance(server[field], dict) or not all(isinstance(v, str) for v in server[field].values())):
                raise ReviewError('Server env and headers must be string maps.')
    return data


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) - {'rules', 'scanner_fail_on'}:
        raise ReviewError('Unknown policy fields.')
    rules = policy.get('rules', {})
    if not isinstance(rules, dict) or set(rules) - set(RULES) or any(type(v) is not bool for v in rules.values()):
        raise ReviewError('Policy rules must use supported names and boolean values.')
    severity = policy.get('scanner_fail_on', 'high')
    if severity not in SEVERITIES:
        raise ReviewError('Invalid scanner severity threshold.')
    return {'rules': {**RULES, **rules}, 'scanner_fail_on': severity}


def fingerprint(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def npx_package(server):
    if server.get('command') != 'npx':
        return None
    args = list(server.get('args', []))
    if args and args[0] in ('-y', '--yes'):
        args.pop(0)
    if not args or args[0].startswith('-'):
        return None
    spec = args.pop(0)
    # Only registry package syntax, never URLs, file paths, or arbitrary commands.
    match = re.fullmatch(r'(@[\w.-]+/[\w.-]+|[\w.-]+)(?:@([^\s/]+))?', spec)
    return (match[1], match[2], args) if match else None


def filesystem_paths(server):
    package = npx_package(server)
    if not package or package[0] != PACKAGE or not package[2]:
        return None
    paths = package[2]
    if any(not p.startswith('/') or p.startswith('//') or '$' in p or '\\' in p or any(ord(c) < 32 for c in p) for p in paths):
        return None
    return sorted(set(posixpath.normpath(p) for p in paths))


def covered(path, roots):
    return any(path == root or path.startswith(root.rstrip('/') + '/') for root in roots)


def compare(before, after, policy=None):
    validate_config(before)
    validate_config(after)
    policy = validate_policy(policy or {})
    changes = []
    def add(rule, name, explanation, **evidence):
        changes.append(dict(rule=rule, server=name, explanation=explanation,
                            review_required=policy['rules'][rule], evidence=evidence))
    old, new = before['mcpServers'], after['mcpServers']
    for name in sorted(set(old) | set(new)):
        if name not in old:
            add('server_added', name, 'A new server is configured. Its actual permissions cannot be established from this file alone.')
            continue
        if name not in new:
            add('server_removed', name, 'This server was removed from the configuration. This does not stop an already running server.')
            continue
        a, b = old[name], new[name]
        if a == b:
            continue
        pa, pb = filesystem_paths(a), filesystem_paths(b)
        args_explained = False
        if pa is not None and pb is not None:
            if pa != pb:
                new_inside_old = all(covered(p, pa) for p in pb)
                old_inside_new = all(covered(p, pb) for p in pa)
                if new_inside_old and not old_inside_new:
                    kind = 'scope_narrowed'
                elif old_inside_new and not new_inside_old:
                    kind = 'scope_expanded'
                else:
                    kind = 'scope_changed'
                add(kind, name, 'Configured filesystem roots changed. Comparison is lexical; symlinks, runtime roots and operating-system permissions are not inspected.', before=pa, after=pb)
            na, nb = npx_package(a), npx_package(b)
            args_explained = na[:2] == nb[:2]
        na, nb = npx_package(a), npx_package(b)
        if na and nb and na[0] == nb[0] and PIN.fullmatch(na[1] or '') and not PIN.fullmatch(nb[1] or ''):
            add('package_unpinned', name, 'An exact package version was replaced by a floating or unspecified version.')
        changed = sorted(k for k in set(a) | set(b) if k not in a or k not in b or a[k] != b[k])
        if args_explained:
            changed = [k for k in changed if k != 'args']
        if changed:
            # Do not publish arbitrary command, URL, environment or argument values.
            add('configuration_changed', name, 'Other configuration fields changed; their access implications require review.', fields=changed)
    return {'schema_version': 1, 'configuration_fingerprint': fingerprint(after),
            'status': 'review_required' if any(c['review_required'] for c in changes) else 'no_review_required',
            'changes': changes, 'scanner': {'status': 'not_run'},
            'limitations': 'Configuration review only. No servers are started, no runtime access is enforced, and no human approval is verified.'}
