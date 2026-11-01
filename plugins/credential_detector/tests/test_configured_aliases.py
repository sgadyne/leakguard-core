import pytest

from credential_detector.plugin import create_plugin
from leakguard_core.plugins import DetectionContext


def test_configured_alias_extends_defaults_and_preserves_boundaries():
    detector = create_plugin({'aliases':['corpPassword:password','corpSession:access-token']})
    context = DetectionContext('/synthetic/config.env', 'text', 'text')
    rows = list(detector.detect('corpPassword="synthetic-value"\npassword="builtin-value"\ncorpSession="session-value"', context))
    assert [x.rule for x in rows] == ['credential-password','credential-password','credential-access-token']
    assert list(detector.detect('myCorpPasswordSuffix="synthetic-value"\ncorpPassword=$ENV_REFERENCE', context)) == []
    assert list(create_plugin({}).detect('corpPassword="synthetic-value"', context)) == []


@pytest.mark.parametrize('aliases', [['password:password'], ['corpPassword:password','corp-password:password'],
    ['corp:unknown-role'], ['not valid:password'], ['missing-role'], [True], 'not-a-list'])
def test_invalid_or_colliding_aliases_rejected(aliases):
    with pytest.raises(ValueError): create_plugin({'aliases': aliases})
