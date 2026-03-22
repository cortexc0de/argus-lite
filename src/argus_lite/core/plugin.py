from abc import ABC, abstractmethod
from typing import Any


class ArgusPlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def stage(self) -> str: ...

    @property
    def version(self) -> str:
        return "0.1.0"

    @abstractmethod
    def check_available(self) -> bool: ...

    @abstractmethod
    async def run(self, context: dict, config: Any) -> None: ...
