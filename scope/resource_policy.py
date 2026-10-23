"""Deterministic routing for passive security reconnaissance targets."""
from pathlib import PurePosixPath
from urllib.parse import urlsplit

STATIC_EXTENSIONS = frozenset({
    '.css', '.js', '.mjs', '.map', '.png', '.jpg', '.jpeg', '.gif',
    '.webp', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot',
    '.otf', '.mp3', '.mp4', '.webm', '.pdf', '.zip', '.gz', '.br',
})
# Do not execute scanners against discovered static files. Passive inspection
# of JavaScript text is a separate offline workflow.
SCANNER_TOOLS = frozenset({'katana', 'nuclei', 'ffuf', 'dalfox', 'nuclei_dast'})


def classify_resource(value: str) -> str:
    url = urlsplit(value)
    if url.scheme not in ('http', 'https'):
        return 'host'
    suffix = PurePosixPath(url.path.lower()).suffix
    if suffix in STATIC_EXTENSIONS:
        return 'javascript_asset' if suffix in {'.js', '.mjs'} else 'static_asset'
    return 'web_endpoint'


def tool_target_allowed(tool: str, value: str) -> bool:
    if tool in SCANNER_TOOLS and classify_resource(value) in {'static_asset', 'javascript_asset'}:
        return False
    return True
