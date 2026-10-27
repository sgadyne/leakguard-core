"""Verify frozen historical holdout evidence; do not rerun or tune the corpus."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--prior-root', required=True, type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    root = args.source.resolve()
    index_path = root / 'tools/recognizer_eval/HOLDOUT_ARTIFACTS.json'
    index = json.loads(index_path.read_text())
    manifest = index['corpus']
    assert manifest['holdout_counts'] == {'jwe': 400, 'jws': 200, 'clean_negative': 2000, 'total': 2600}
    assert sha(root / manifest['manifest_path']) == manifest['manifest_sha256']
    for name, item in index['freeze']['files'].items():
        assert sha(root / name) == item['sha256']
    target = args.output_dir.absolute()
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    rows = []
    for item in index['native_outputs']:
        assert item['split_cases'] == 2600
        assert sha(root / item['profile_file']) == item['profile_sha256']
        path = args.prior_root / item['path']
        assert sha(path) == item['sha256']
        dest = target / path.name
        shutil.copyfile(path, dest)
        if item['profile'] != 'baseline-presidio-default-entities':
            union, jwe, jws = (item['counts'][key] for key in ('jose_union', 'jwe_vs_clean', 'jws_target'))
            assert (union['tp'], union['fp'], union['tn'], union['fn']) == (600, 0, 2000, 0)
            assert (jwe['tp'], jwe['fn']) == (400, 0)
            assert (jws['tp'], jws['fn']) == (200, 0)
        rows.append({'profile': item['profile'], 'sha256': item['sha256'], 'file': dest.name})
    receipt = {'status': 'passed', 'historical_not_rerun': True, 'holdout_counts': manifest['holdout_counts'],
               'manifest_sha256': manifest['manifest_sha256'], 'frozen_sources': index['freeze']['files'],
               'outputs': rows, 'limitations': 'Synthetic evaluation; broad PII false alerts and finite-sample limits remain; see recognizer-evaluation.md.'}
    (target / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status':'passed','receipt':str(target / 'receipt.json')}))


if __name__ == '__main__':
    main()
