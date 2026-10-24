import argparse
import html
import json
from pathlib import Path
import re
import sys
from .core import ReviewError, compare, load_json, validate_config, validate_policy
from .scanner import scan


def redact(report, configs):
    values = set()
    for config in configs:
        for server in config['mcpServers'].values():
            for field in ('env', 'headers'):
                values.update(v for v in server.get(field, {}).values() if v)
            if server.get('url'):
                values.add(server['url'])
    def clean(value):
        if isinstance(value, str):
            for secret in sorted(values, key=len, reverse=True):
                value = value.replace(secret, '[REDACTED]')
            return value
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, dict):
            return {clean(k): clean(v) for k, v in value.items()}
        return value
    # Redact display fields only: secret values must never alter status/rule identifiers.
    for change in report['changes']:
        change['server'] = clean(change['server'])
        change['explanation'] = clean(change['explanation'])
        change['evidence'] = {key: clean(value) for key, value in change['evidence'].items()}
    return report


def safe(value):
    value = ''.join(c if ord(c) >= 32 else ' ' for c in str(value))
    return re.sub(r'([\\`*_{}\[\]()#+.!|>~-])', r'\\\1', html.escape(value))


def markdown(report):
    status = 'Review required' if report['status'] == 'review_required' else 'No review required by the configured rules'
    out = ['# Agent Access Review', '', '**' + status + '**', '',
           'Configuration fingerprint: `' + report['configuration_fingerprint'] + '`', '']
    if not report['changes']:
        out.append('No server configuration changes detected.')
    for c in report['changes']:
        out += ['### ' + safe(c['rule'].replace('_', ' ').capitalize()) + ': ' + safe(c['server']), '',
                safe(c['explanation']), '', '**Team rule:** ' + ('Review required.' if c['review_required'] else 'Informational.'), '']
        for key, value in c['evidence'].items():
            out.append('- **' + safe(key.capitalize()) + ':** ' + safe(', '.join(value)))
        out.append('')
    out += ['## Scanner', '']
    scanner = report['scanner']
    if scanner['status'] == 'not_run':
        out.append('Not run. This report only compares configurations and applies team rules.')
    else:
        out.append('Completed with @cruxet/mcp-audit 0.2.0. These are findings in the proposed configuration, including pre-existing findings.')
        for f in scanner['findings']:
            out.append(f"- {f['rule']}: {f['severity']} ({f['count']})")
        if not scanner['findings']:
            out.append('No findings reported by this scanner; this is not a safety certification.')
    out += ['', '## Limits', '', report['limitations'], '',
            'Command values, URLs, environment values, header values and raw scanner evidence are omitted. '
            'Server names and recognized filesystem roots are included; review them before public sharing.', '']
    return '\n'.join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(description='Explain MCP access changes. Never starts configured MCP servers.')
    parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path)
    parser.add_argument('--policy', type=Path)
    parser.add_argument('--scanner', type=Path, help='Explicit path to installed mcp-audit 0.2.0; optional, never downloaded automatically.')
    parser.add_argument('--format', choices=['markdown', 'json'], default='markdown')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        inputs = [args.before, args.after] + ([args.policy] if args.policy else [])
        if args.output and args.output.resolve() in {p.resolve() for p in inputs}:
            raise ReviewError('Output must not overwrite an input file.')
        before, after = [validate_config(load_json(p)) for p in (args.before, args.after)]
        policy = validate_policy(load_json(args.policy) if args.policy else {})
        report = compare(before, after, policy)
        if args.scanner:
            report['scanner'] = scan(args.after, args.scanner.resolve(), policy['scanner_fail_on'])
            if report['scanner']['review_required']:
                report['status'] = 'review_required'
        report = redact(report, [before, after])
        output = json.dumps(report, indent=2) + '\n' if args.format == 'json' else markdown(report)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output, encoding='utf-8')
        else:
            print(output, end='')
        return 2 if report['status'] == 'review_required' else 0
    except ReviewError as exc:
        print('Review error: ' + str(exc), file=sys.stderr)
        return 1
    except OSError:
        print('Review error: Could not write the report.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
