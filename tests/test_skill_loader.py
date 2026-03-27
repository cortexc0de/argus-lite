"""TDD: Tests for Markdown Skill Loader — .md files as custom agent skills."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from argus_lite.core.config import AppConfig


class TestParseMarkdownSkill:
    """Parse a single .md file into a SkillDefinition."""

    def test_parse_valid_skill(self, tmp_path):
        from argus_lite.core.skill_loader import parse_skill_markdown

        md = tmp_path / "check_wp.md"
        md.write_text("""\
---
name: check_wordpress
description: WordPress-specific security checks
tools: [nuclei, httpx]
---

## Steps

1. Probe /wp-admin and /wp-login.php for accessibility
2. Run nuclei with wordpress tags
3. Check xmlrpc.php exposure
""")
        skill_def = parse_skill_markdown(md)
        assert skill_def.name == "check_wordpress"
        assert skill_def.description == "WordPress-specific security checks"
        assert skill_def.tools == ["nuclei", "httpx"]
        assert len(skill_def.steps) == 3
        assert "wp-admin" in skill_def.steps[0]

    def test_parse_minimal_skill(self, tmp_path):
        from argus_lite.core.skill_loader import parse_skill_markdown

        md = tmp_path / "minimal.md"
        md.write_text("""\
---
name: quick_check
description: A quick check
---

1. Do something
""")
        skill_def = parse_skill_markdown(md)
        assert skill_def.name == "quick_check"
        assert skill_def.tools == []
        assert len(skill_def.steps) == 1

    def test_parse_missing_name_raises(self, tmp_path):
        from argus_lite.core.skill_loader import SkillParseError, parse_skill_markdown

        md = tmp_path / "bad.md"
        md.write_text("""\
---
description: No name field
---

1. Step
""")
        with pytest.raises(SkillParseError):
            parse_skill_markdown(md)

    def test_parse_no_frontmatter_raises(self, tmp_path):
        from argus_lite.core.skill_loader import SkillParseError, parse_skill_markdown

        md = tmp_path / "plain.md"
        md.write_text("# Just a heading\n\nNo frontmatter here.\n")
        with pytest.raises(SkillParseError):
            parse_skill_markdown(md)

    def test_parse_empty_file_raises(self, tmp_path):
        from argus_lite.core.skill_loader import SkillParseError, parse_skill_markdown

        md = tmp_path / "empty.md"
        md.write_text("")
        with pytest.raises(SkillParseError):
            parse_skill_markdown(md)


class TestLoadSkillDirectory:
    """Load all .md skills from a directory."""

    def test_load_multiple_skills(self, tmp_path):
        from argus_lite.core.skill_loader import load_skill_directory

        for i in range(3):
            (tmp_path / f"skill_{i}.md").write_text(f"""\
---
name: skill_{i}
description: Test skill {i}
---

1. Step for skill {i}
""")

        skills = load_skill_directory(tmp_path)
        assert len(skills) == 3
        names = {s.name for s in skills}
        assert names == {"skill_0", "skill_1", "skill_2"}

    def test_load_empty_directory(self, tmp_path):
        from argus_lite.core.skill_loader import load_skill_directory

        skills = load_skill_directory(tmp_path)
        assert skills == []

    def test_load_nonexistent_directory(self):
        from argus_lite.core.skill_loader import load_skill_directory

        skills = load_skill_directory(Path("/nonexistent/path"))
        assert skills == []

    def test_load_skips_invalid_files(self, tmp_path):
        from argus_lite.core.skill_loader import load_skill_directory

        # Valid skill
        (tmp_path / "good.md").write_text("""\
---
name: good_skill
description: Works fine
---

1. Do thing
""")
        # Invalid skill (no name)
        (tmp_path / "bad.md").write_text("no frontmatter")
        # Non-md file (should be ignored)
        (tmp_path / "notes.txt").write_text("not a skill")

        skills = load_skill_directory(tmp_path)
        assert len(skills) == 1
        assert skills[0].name == "good_skill"


class TestMarkdownSkillExecution:
    """MarkdownSkill wraps a SkillDefinition and can execute."""

    def test_markdown_skill_has_name_and_description(self, tmp_path):
        from argus_lite.core.skill_loader import MarkdownSkill, parse_skill_markdown

        md = tmp_path / "test.md"
        md.write_text("""\
---
name: test_skill
description: A test skill
---

1. Check headers
""")
        defn = parse_skill_markdown(md)
        skill = MarkdownSkill(defn)
        assert skill.name == "test_skill"
        assert skill.description == "A test skill"
        assert skill.is_available()

    def test_markdown_skill_execute_returns_result(self, tmp_path):
        from argus_lite.core.agent_context import AgentContext
        from argus_lite.core.skill_loader import MarkdownSkill, parse_skill_markdown

        md = tmp_path / "test.md"
        md.write_text("""\
---
name: test_skill
description: A test skill
---

1. Check target accessibility
2. Verify headers
""")
        defn = parse_skill_markdown(md)
        skill = MarkdownSkill(defn)
        ctx = AgentContext(target="example.com")

        result = asyncio.get_event_loop().run_until_complete(
            skill.execute({}, ctx)
        )
        assert result.success
        assert "2 steps" in result.summary
        assert result.data["steps"] == defn.steps


class TestSkillRegistration:
    """Markdown skills integrate into SkillRegistry."""

    def test_register_markdown_skills(self, tmp_path):
        from argus_lite.core.skill_loader import register_markdown_skills
        from argus_lite.core.skills import SkillRegistry

        (tmp_path / "custom.md").write_text("""\
---
name: custom_scan
description: My custom scan
---

1. Do custom thing
""")
        registry = SkillRegistry()
        count = register_markdown_skills(registry, [tmp_path])
        assert count == 1
        assert registry.get("custom_scan") is not None

    def test_build_skill_registry_with_custom_skills(self, tmp_path):
        from argus_lite.core.skills import build_skill_registry

        (tmp_path / "extra.md").write_text("""\
---
name: extra_check
description: Extra security check
---

1. Run extra check
""")
        registry = build_skill_registry(AppConfig(), skill_dirs=[tmp_path])
        assert registry.get("extra_check") is not None
        # All 11 built-in skills still present
        assert len(registry._skills) == 15  # 14 built-in + 1 custom

    def test_build_skill_registry_without_custom_skills(self):
        from argus_lite.core.skills import build_skill_registry

        registry = build_skill_registry(AppConfig())
        assert len(registry._skills) == 14  # unchanged

    def test_duplicate_name_skipped(self, tmp_path):
        from argus_lite.core.skill_loader import register_markdown_skills
        from argus_lite.core.skills import SkillRegistry

        # Try to register a skill with same name as built-in
        (tmp_path / "headers.md").write_text("""\
---
name: check_headers
description: Override attempt
---

1. This should not override
""")
        registry = SkillRegistry()
        # Pre-register a built-in
        from argus_lite.core.skills import CheckHeadersSkill
        registry.register(CheckHeadersSkill())
        count = register_markdown_skills(registry, [tmp_path])
        assert count == 0  # skipped because name exists


class TestSkillDefinitionModel:
    """SkillDefinition Pydantic model validation."""

    def test_valid_definition(self):
        from argus_lite.models.skill import SkillDefinition

        sd = SkillDefinition(
            name="test", description="A test",
            tools=["nuclei"], steps=["Step 1"],
        )
        assert sd.name == "test"

    def test_name_required(self):
        from pydantic import ValidationError

        from argus_lite.models.skill import SkillDefinition

        with pytest.raises(ValidationError):
            SkillDefinition(description="no name")

    def test_description_required(self):
        from pydantic import ValidationError

        from argus_lite.models.skill import SkillDefinition

        with pytest.raises(ValidationError):
            SkillDefinition(name="no_desc")
