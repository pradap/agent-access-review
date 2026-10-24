import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from agent_access_review.core import compare, ReviewError, validate_policy, validate_config, fingerprint, load_json
from agent_access_review.cli import main, redact, markdown
from agent_access_review.scanner import scan


def config(paths=None, version='1.2.3'):
    return {'mcpServers': {'files': {'command': 'npx', 'args': ['-y', '@modelcontextprotocol/server-filesystem@' + version] + (paths or ['/project/docs'])}}}


class ReviewTests(unittest.TestCase):
    def test_expansion(self):
        r = compare(config(), config(['/project']))
        self.assertEqual(r['status'], 'review_required')
        self.assertEqual([c['rule'] for c in r['changes']], ['scope_expanded'])

    def test_narrowing(self):
        self.assertEqual(compare(config(['/project']), config())['status'], 'no_review_required')

    def test_prefix_is_not_parent(self):
        self.assertEqual(compare(config(['/project']), config(['/project-other']))['changes'][0]['rule'], 'scope_changed')

    def test_added_root(self):
        self.assertEqual(compare(config(), config(['/project/docs', '/photos']))['changes'][0]['rule'], 'scope_expanded')

    def test_unknown_relative_paths_require_review(self):
        for path in ['../private', '$HOME/private', 'C:\\Users\\alex']:
            r = compare(config(), config([path]))
            self.assertEqual(r['changes'][0]['rule'], 'configuration_changed')

    def test_custom_command_not_treated_as_filesystem(self):
        after = config(['/'])
        after['mcpServers']['files']['command'] = 'my-npx'
        self.assertEqual([c['rule'] for c in compare(config(), after)['changes']], ['configuration_changed'])

    def test_version_and_environment_changes_not_hidden_by_narrowing(self):
        after = config(['/project/docs'], 'latest')
        after['mcpServers']['files']['env'] = {'TOKEN': 'secret'}
        r = compare(config(['/project']), after)
        self.assertEqual(r['status'], 'review_required')
        self.assertIn('package_unpinned', [c['rule'] for c in r['changes']])
        self.assertIn('configuration_changed', [c['rule'] for c in r['changes']])

    def test_unknown_field_change_requires_review(self):
        a = config(); b = copy.deepcopy(a)
        b['mcpServers']['files']['disabled'] = None
        self.assertEqual(compare(a, b)['status'], 'review_required')

    def test_added_and_removed_servers(self):
        empty = {'mcpServers': {}}
        self.assertEqual(compare(empty, config())['changes'][0]['rule'], 'server_added')
        self.assertEqual(compare(config(), empty)['changes'][0]['rule'], 'server_removed')

    def test_invalid_configs_rejected(self):
        for data in [{}, {'servers': {}}, {'mcpServers': []}, {'mcpServers': {'x': {'command': 'npx', 'url': 'http://example.com'}}}, {'mcpServers': {'x': {'command': 'npx', 'args': 'not-array'}}}]:
            with self.assertRaises(ReviewError):
                validate_config(data)

    def test_unknown_policy_is_error(self):
        for p in [{'rules': {'typo': True}}, {'rules': {'server_added': 'false'}}, {'scanner_fail_on': 'none'}, {'approval': True}]:
            with self.assertRaises(ReviewError):
                validate_policy(p)

    def test_team_policy_can_require_narrowing_review(self):
        self.assertEqual(compare(config(['/project']), config(), {'rules': {'scope_narrowed': True}})['status'], 'review_required')

    def test_redaction_cannot_change_decision(self):
        a = config(); b = config(['/project'])
        b['mcpServers']['files']['env'] = {'TOKEN': 'review_required'}
        r = redact(compare(a, b), [a, b])
        self.assertEqual(r['status'], 'review_required')

    def test_secrets_not_emitted_and_html_escaped(self):
        a = {'mcpServers': {}}
        b = {'mcpServers': {'<img src=x>': {'url': 'https://user:password@example.com', 'headers': {'Authorization': 'Bearer hidden-secret'}}}}
        out = markdown(redact(compare(a, b), [a, b]))
        self.assertNotIn('password', out)
        self.assertNotIn('hidden-secret', out)
        self.assertNotIn('<img', out)

    def test_noop_and_stable_fingerprint(self):
        self.assertEqual(compare(config(), config())['changes'], [])
        self.assertEqual(fingerprint(config()), fingerprint(copy.deepcopy(config())))

    def test_cli_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as d:
            a, b, out = [Path(d) / s for s in ('before.json', 'after.json', 'out.md')]
            a.write_text(json.dumps(config())); b.write_text(json.dumps(config(['/project'])))
            self.assertEqual(main([str(a), str(b), '--output', str(out)]), 2)
            self.assertIn('Scope expanded', out.read_text())
            with patch('sys.stderr'):
                self.assertEqual(main([str(a), str(b), '--output', str(a)]), 1)
            b.write_text('{"mcpServers": {}, "mcpServers": {}}')
            with self.assertRaises(ReviewError):
                load_json(b)


class ScannerTests(unittest.TestCase):
    def response(self):
        return {'tool': 'mcp-audit', 'version': '0.2.0', 'configs': [{}], 'summary': {'parseErrors': []},
                'findings': [{'ruleId': 'MCP-AUDIT-003', 'severity': 'critical', 'evidence': 'hidden-secret'}]}

    def run_scan(self, data, code=4, stderr=''):
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], code, json.dumps(data), stderr)):
            return scan(Path('sample.json'), Path('/scanner'), 'high')

    def test_scanner_findings_redacted_and_gated(self):
        result = self.run_scan(self.response())
        self.assertTrue(result['review_required'])
        self.assertNotIn('hidden-secret', json.dumps(result))

    def test_scanner_errors_are_not_clean(self):
        for code in [10, 127, -1]:
            with self.assertRaises(ReviewError):
                self.run_scan(self.response(), code=code)
        data = self.response(); data['summary']['parseErrors'] = [{'message': 'secret'}]
        with self.assertRaises(ReviewError):
            self.run_scan(data)
        with self.assertRaises(ReviewError):
            self.run_scan(self.response(), stderr='Rule failed')

    def test_unknown_scanner_version_rejected(self):
        data = self.response(); data['version'] = '9.0.0'
        with self.assertRaises(ReviewError):
            self.run_scan(data)

    def test_no_configs_rejected(self):
        data = self.response(); data['configs'] = []
        with self.assertRaises(ReviewError):
            self.run_scan(data)


if __name__ == '__main__':
    unittest.main()
