import importlib.util
import logging
from pathlib import Path

from argus_lite.core.plugin import ArgusPlugin

logger = logging.getLogger(__name__)


class PluginLoader:
    def __init__(self, plugin_dirs: list[Path] | None = None):
        self._dirs = plugin_dirs or []

    def discover(self) -> list[type[ArgusPlugin]]:
        """Find all ArgusPlugin subclasses in plugin directories."""
        plugins = []
        for d in self._dirs:
            d = Path(d).expanduser()
            if not d.is_dir():
                continue
            for py_file in d.glob("*.py"):
                try:
                    spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if isinstance(attr, type) and issubclass(attr, ArgusPlugin) and attr is not ArgusPlugin:
                            plugins.append(attr)
                except Exception as e:
                    logger.warning("Failed to load plugin %s: %s", py_file, e)
        return plugins

    def load_all(self) -> dict[str, ArgusPlugin]:
        """Discover, instantiate all plugins. Returns name -> instance."""
        result = {}
        for cls in self.discover():
            try:
                instance = cls()
                result[instance.name] = instance
            except Exception as e:
                logger.warning("Failed to instantiate plugin %s: %s", cls, e)
        return result
