"""Tech stack fingerprinting via whatweb."""

from __future__ import annotations

import json

from argus_lite.core.tool_runner import BaseToolRunner, ToolOutput
from argus_lite.models.analysis import Technology

# Skip these whatweb plugins (not useful as "technologies")
_SKIP_PLUGINS = {"Title", "HTTPServer", "IP", "Country", "UncommonHeaders"}


def parse_whatweb_output(raw: str) -> list[Technology]:
    """Parse whatweb JSON output into Technology list."""
    if not raw.strip():
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, list) or not data:
        return []

    techs: list[Technology] = []
    entry = data[0]
    plugins = entry.get("plugins", {})

    for plugin_name, plugin_data in plugins.items():
        if plugin_name in _SKIP_PLUGINS:
            continue

        version = ""
        if isinstance(plugin_data, dict):
            version = plugin_data.get("version", [""])[0] if "version" in plugin_data else ""

        techs.append(
            Technology(
                name=plugin_name,
                version=version,
                category=_guess_category(plugin_name),
            )
        )

    return techs


def _guess_category(name: str) -> str:
    """Guess technology category from plugin name."""
    categories = {
        "WordPress": "cms",
        "Drupal": "cms",
        "Joomla": "cms",
        "jQuery": "js-library",
        "Bootstrap": "css-framework",
        "React": "js-framework",
        "Angular": "js-framework",
        "Vue": "js-framework",
        "PHP": "language",
        "Python": "language",
        "Ruby": "language",
        "Apache": "server",
        "Nginx": "server",
        "OpenSSL": "library",
    }
    return categories.get(name, "")


async def tech_scan(
    target: str,
    runner: BaseToolRunner | None = None,
) -> list[Technology]:
    """Run whatweb and parse tech stack."""
    if runner is None:
        runner = BaseToolRunner(name="whatweb", path="/usr/bin/whatweb")

    result: ToolOutput = await runner.run([
        "-q", "--log-json=-", target,
    ])
    return parse_whatweb_output(result.stdout)
