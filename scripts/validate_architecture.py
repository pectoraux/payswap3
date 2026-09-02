#!/usr/bin/env python3
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
ARCH = ROOT / 'spec' / 'architecture' / 'v0.1'
MANIFEST = ARCH / 'frozen-artifacts-manifest.json'

def main():
    try:
        manifest=json.loads(MANIFEST.read_text())
        if manifest['status']!='frozen' or manifest['architectureVersion']!='v0.1':
            raise RuntimeError('invalid frozen architecture manifest')
        import hashlib
        for name in manifest['requiredArtifacts']:
            p=ARCH/name
            if not p.exists():
                raise RuntimeError(f'missing frozen architecture artifact: {name}')
            expected=manifest.get('sha256',{}).get(name)
            if expected and hashlib.sha256(p.read_bytes()).hexdigest()!=expected:
                raise RuntimeError(f'frozen artifact hash mismatch: {name}')
        lock=(ARCH/'architecture-lock.md').read_text()
        for phrase in ['FROZEN','Architecture Change Request','PaySwap protocol state machine','Simulation']:
            if phrase not in lock:
                raise RuntimeError(f'architecture lock missing required rule: {phrase}')
        trace=json.loads((ROOT/'spec/requirements-to-work-orders.json').read_text())
        if trace.get('architectureVersion') != 'v0.1' or not trace.get('mapping'):
            raise RuntimeError('requirements-to-work-orders traceability is missing or invalid')
        registry=json.loads((ROOT/'spec/registry/protocol-registry.json').read_text())
        if registry['status']!='frozen':
            raise RuntimeError('protocol registry is not frozen')
        print('PAYSWAP ARCHITECTURE: PASS')
        print(f"version: {manifest['architectureVersion']}")
        print(f"frozen artifacts: {len(manifest['requiredArtifacts'])}")
        print('protocol registry: frozen')
        return 0
    except Exception as e:
        print(f'PAYSWAP ARCHITECTURE: FAIL — {e}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
