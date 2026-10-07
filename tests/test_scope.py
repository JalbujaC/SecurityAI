import pytest

from scope.schemas import ScopeConfig
from scope.validator import ScopeValidator

@pytest.fixture
def validator():
    config = ScopeConfig(allowed_domains=["example.com"], excluded_domains=["internal.example.com"])

    return ScopeValidator(config)

def test_exact_domain_is_allowed(validator):
    assert validator.is_allowed("example.com")


def test_subdomain_is_allowed(validator):
    assert validator.is_allowed("api.example.com")


def test_url_is_normalized(validator):
    assert validator.is_allowed(
        "https://api.example.com/users/123"
    )


def test_unrelated_domain_is_rejected(validator):
    assert not validator.is_allowed("evil.com")


def test_excluded_domain_is_rejected(validator):
    assert not validator.is_allowed(
        "internal.example.com"
    )


def test_excluded_subdomain_is_rejected(validator):
    assert not validator.is_allowed(
        "dev.internal.example.com"
    )


def test_validate_raises_on_out_of_scope_target(validator):
    with pytest.raises(PermissionError):
        validator.validate("evil.com")


def test_validate_allows_valid_target(validator):
    validator.validate("api.example.com")