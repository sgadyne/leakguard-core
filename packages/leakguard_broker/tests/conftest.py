from __future__ import annotations

from pathlib import Path

import pytest

from .tls_fixtures import SyntheticHttpsWitness, SyntheticPKI


@pytest.fixture(scope="session")
def synthetic_pki(tmp_path_factory: pytest.TempPathFactory) -> SyntheticPKI:
    return SyntheticPKI(Path(tmp_path_factory.mktemp("broker-pki")))


@pytest.fixture
def upstream_witness(synthetic_pki: SyntheticPKI):
    with SyntheticHttpsWitness(synthetic_pki.upstream_server) as witness:
        yield witness
