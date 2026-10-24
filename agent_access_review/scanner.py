"""Adapter for the separately installed, pinned @cruxet/mcp-audit 0.2.0."""
import json
import re
import subprocess
from collections import Counter
from .core import ReviewError, SEVERITIES


def scan(config_path, executable, threshold):
    try:
        process = subprocess.run([str(executable), 'scan', '--config', str(config_path.resolve()),
                                  '--format', 'json', '--no-color'],
                                 capture_output=True, text=True, timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReviewError('Scanner could not complete. No clean result can be claimed.') from exc
    if process.returncode not in range(5):
        raise ReviewError('Scanner failed. Raw output is withheld because it may contain secrets.')
    try:
        data = json.loads(process.stdout)
        if data['tool'] != 'mcp-audit' or data['version'] != '0.2.0':
            raise ValueError('Unsupported scanner version')
        if not isinstance(data['findings'], list) or len(data['configs']) != 1:
            raise ValueError('Incomplete scan')
        if data['summary']['parseErrors'] or any(c.get('parseError') for c in data['configs']):
            raise ValueError('Parse failure')
        if process.stderr.strip():
            raise ValueError('Scanner emitted diagnostics')
        counts = Counter()
        for finding in data['findings']:
            rule, severity = finding['ruleId'], finding['severity']
            if not isinstance(rule, str) or not re.fullmatch(r'MCP-AUDIT-\d{3}', rule) or severity not in SEVERITIES:
                raise ValueError('Unknown finding schema')
            counts[(rule, severity)] += 1
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ReviewError('Scanner result is incomplete or unsupported. No clean result can be claimed.') from exc
    findings = [dict(rule=rule, severity=sev, count=count) for (rule, sev), count in sorted(counts.items())]
    return {'status': 'completed', 'tool': '@cruxet/mcp-audit', 'version': '0.2.0',
            'findings': findings, 'review_required': any(SEVERITIES.index(f['severity']) >= SEVERITIES.index(threshold) for f in findings)}
