from analysis.redirect_noise import redirect_groups


def test_ffuf_login_redirects_are_grouped_not_claimed():
    findings = [
        {'url': f'https://example.com/{name}', 'status': 302,
         'redirect_location': '/sign_in?next=' + name}
        for name in ('admin', 'api', 'uploads', 'dashboard')
    ]
    groups = redirect_groups(findings)
    assert len(groups) == 1
    assert groups[0]['count'] == 4
    assert groups[0]['redirect_path'] == '/sign_in'
    assert groups[0]['classification'] == 'redirect_observation_not_vulnerability'
