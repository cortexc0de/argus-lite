"""Tests for the plugin system (plugin interface and loader)."""

from __future__ import annotations

import textwrap

import pytest

from argus_lite.core.plugin import ArgusPlugin
from argus_lite.core.plugin_loader import PluginLoader


# ---------------------------------------------------------------------------
# test_plugin_interface_enforced
# ---------------------------------------------------------------------------

def test_plugin_interface_enforced():
    """Subclass without abstract methods raises TypeError on instantiation."""
    class IncompletePlugin(ArgusPlugin):
        pass

    with pytest.raises(TypeError):
        IncompletePlugin()


# ---------------------------------------------------------------------------
# test_discover_from_directory
# ---------------------------------------------------------------------------

def test_discover_from_directory(tmp_path):
    """Loader discovers ArgusPlugin subclasses from .py files in a directory."""
    plugin_file = tmp_path / "my_plugin.py"
    plugin_file.write_text(textwrap.dedent("""\
        from argus_lite.core.plugin import ArgusPlugin

        class MyPlugin(ArgusPlugin):
            @property
            def name(self) -> str:
                return "my_plugin"

            @property
            def stage(self) -> str:
                return "recon"

            def check_available(self) -> bool:
                return True

            async def run(self, context, config):
                pass
    """))

    loader = PluginLoader(plugin_dirs=[tmp_path])
    discovered = loader.discover()

    assert len(discovered) == 1
    assert discovered[0].__name__ == "MyPlugin"


# ---------------------------------------------------------------------------
# test_load_all_returns_instances
# ---------------------------------------------------------------------------

def test_load_all_returns_instances(tmp_path):
    """load_all returns dict mapping plugin name -> instance."""
    plugin_file = tmp_path / "good_plugin.py"
    plugin_file.write_text(textwrap.dedent("""\
        from argus_lite.core.plugin import ArgusPlugin

        class GoodPlugin(ArgusPlugin):
            @property
            def name(self) -> str:
                return "good_scanner"

            @property
            def stage(self) -> str:
                return "analysis"

            def check_available(self) -> bool:
                return True

            async def run(self, context, config):
                pass
    """))

    loader = PluginLoader(plugin_dirs=[tmp_path])
    instances = loader.load_all()

    assert "good_scanner" in instances
    assert instances["good_scanner"].name == "good_scanner"
    assert instances["good_scanner"].stage == "analysis"
    assert instances["good_scanner"].version == "0.1.0"


# ---------------------------------------------------------------------------
# test_empty_dir_returns_empty
# ---------------------------------------------------------------------------

def test_empty_dir_returns_empty(tmp_path):
    """Empty directory yields no plugins."""
    loader = PluginLoader(plugin_dirs=[tmp_path])
    assert loader.discover() == []
    assert loader.load_all() == {}


# ---------------------------------------------------------------------------
# test_invalid_plugin_skipped
# ---------------------------------------------------------------------------

def test_invalid_plugin_skipped(tmp_path):
    """A broken .py file does not crash the loader."""
    bad_file = tmp_path / "broken.py"
    bad_file.write_text("raise RuntimeError('boom')")

    # Also place a valid plugin alongside the broken one
    good_file = tmp_path / "valid.py"
    good_file.write_text(textwrap.dedent("""\
        from argus_lite.core.plugin import ArgusPlugin

        class ValidPlugin(ArgusPlugin):
            @property
            def name(self) -> str:
                return "valid"

            @property
            def stage(self) -> str:
                return "recon"

            def check_available(self) -> bool:
                return True

            async def run(self, context, config):
                pass
    """))

    loader = PluginLoader(plugin_dirs=[tmp_path])
    instances = loader.load_all()

    # Broken plugin is skipped; valid one still loaded
    assert "valid" in instances
