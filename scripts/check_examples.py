"""Live scanner smoke test; does not start the servers in the fixture files."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
for name, expected in [('expanded', 2), ('fixed', 0)]:
    result = subprocess.run([sys.executable, '-m', 'agent_access_review', 'examples/before.json',
                             f'examples/{name}.json', '--policy', '.agent-review/policy.json',
                             '--scanner', 'node_modules/.bin/mcp-audit', '--output', f'output/{name}.md'], cwd=root)
    if result.returncode != expected:
        raise SystemExit(f'{name}: expected exit {expected}, got {result.returncode}')
    print(f'{name}: expected result verified (exit {expected})')
