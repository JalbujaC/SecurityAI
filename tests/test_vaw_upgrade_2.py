from types import SimpleNamespace
from scope.resource_policy import classify_resource, tool_target_allowed
from agent.failure_policy import FailureCircuitBreaker
from analysis.observations import normalize_url, observation_fingerprint, summarize_result
from analysis.js_hints import extract_endpoint_hints
from scope.targets import TargetAsset
from scope.tool_targets import ToolTargetPolicy

def test_static_asset_is_not_scanned():
    assert classify_resource('https://example.com/assets/app.js?v=1') == 'javascript_asset'
    assert classify_resource('https://example.com/assets/app.css') == 'static_asset'
    for tool in ('katana', 'nuclei', 'ffuf', 'nuclei_dast', 'dalfox'):
        assert not tool_target_allowed(tool, 'https://example.com/assets/app.js')
    assert tool_target_allowed('nuclei', 'https://example.com/api/users')


def test_circuit_breaker_suspends_repeated_failure_and_resets_success():
    policy = FailureCircuitBreaker(threshold=2)
    bad = SimpleNamespace(success=False)
    good = SimpleNamespace(success=True)
    policy.observe('nuclei', bad)
    assert policy.allowed('nuclei')
    policy.observe('nuclei', good)
    policy.observe('nuclei', bad)
    assert policy.allowed('nuclei')
    policy.observe('nuclei', bad)
    assert not policy.allowed('nuclei')
    assert policy.allowed('httpx')


def test_observation_fingerprint_and_negative_evidence():
    a = observation_fingerprint('httpx', 'https://EXAMPLE.com/a/?b=2&a=1', {'code':200})
    b = observation_fingerprint('httpx', 'https://example.com/a?a=1&b=2', {'code':200})
    assert a == b
    assert summarize_result(SimpleNamespace(success=True, output={'findings': [], 'count': 0}))['classification'] == 'negative_observation'
    assert summarize_result(SimpleNamespace(success=False, output=None))['classification'] == 'tool_failure'


def test_js_hints_are_offline():
    hints = extract_endpoint_hints("const a='/api/accounts/42';", 'https://example.com/assets/app.js')
    assert hints == ['https://example.com/api/accounts/42']





def test_compatible_root_target_returns_true():
    asset = TargetAsset(
        value="example.com",
        kind="root_domain",
        source="scope",
    )

    assert ToolTargetPolicy.is_compatible(
        "subfinder",
        asset,
    ) is True


def test_static_asset_is_filtered_but_web_endpoint_is_allowed():
    javascript = TargetAsset(
        value="https://example.com/app.js",
        kind="url",
        source="katana",
    )

    endpoint = TargetAsset(
        value="https://example.com/api/users",
        kind="url",
        source="katana",
    )

    assert ToolTargetPolicy.is_compatible(
        "nuclei",
        javascript,
    ) is False

    assert ToolTargetPolicy.is_compatible(
        "nuclei",
        endpoint,
    ) is True