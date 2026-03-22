from argus_lite.core.plugin import ArgusPlugin


class SamplePlugin(ArgusPlugin):
    @property
    def name(self) -> str:
        return "sample_scanner"

    @property
    def stage(self) -> str:
        return "recon"

    def check_available(self) -> bool:
        return True

    async def run(self, context: dict, config) -> None:
        context["sample_scanner"] = {"found": ["test.example.com"]}
