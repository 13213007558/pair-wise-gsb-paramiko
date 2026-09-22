# This file is part of Paramiko and subject to the license in /LICENSE in this
# repository

"""
Tests for ``Include`` directive support in `SSHConfig`.

All configs live in pytest ``tmp_path`` directories so the real
``~/.ssh`` and ``/etc/ssh`` are never touched.
"""

import os
from io import StringIO

import pytest
from pytest import raises

from paramiko import SSHConfig, ConfigParseError


def _write(root, relpath, text):
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class TestInclude:
    def test_basic_include_from_path(self, tmp_path):
        main = _write(tmp_path, "config", "Include extra.conf\n")
        _write(tmp_path, "extra.conf", "User included\n")
        config = SSHConfig.from_path(str(main))
        assert config.lookup("anything")["user"] == "included"

    def test_include_inside_host_block_hit_and_miss(self, tmp_path):
        main = _write(
            tmp_path,
            "config",
            "Host web\n    Include web.conf\n\nHost *\n    Port 22\n",
        )
        _write(tmp_path, "web.conf", "User webadmin\n")
        config = SSHConfig.from_path(str(main))
        hit = config.lookup("web")
        assert hit["user"] == "webadmin"
        assert hit["port"] == "22"
        miss = config.lookup("db")
        assert "user" not in miss
        assert miss["port"] == "22"

    def test_include_inside_match_block_hit_and_miss(self, tmp_path):
        main = _write(
            tmp_path,
            "config",
            "Match host web*\n    Include webonly.conf\n",
        )
        _write(tmp_path, "webonly.conf", "User webuser\n")
        config = SSHConfig.from_path(str(main))
        assert config.lookup("web1")["user"] == "webuser"
        assert "user" not in config.lookup("db1")

    def test_glob_expands_in_lexicographic_order(self, tmp_path):
        # Written in reverse order so creation order cannot leak through.
        _write(tmp_path, "conf.d/10-second.conf", "User second\n")
        _write(tmp_path, "conf.d/00-first.conf", "User first\n")
        main = _write(tmp_path, "config", "Include conf.d/*.conf\n")
        config = SSHConfig.from_path(str(main))
        # First-value-wins proves 00-first.conf was parsed first.
        assert config.lookup("x")["user"] == "first"

    def test_repeatable_keys_accumulate_in_include_order(self, tmp_path):
        _write(tmp_path, "conf.d/10-b.conf", "IdentityFile id_b\n")
        _write(tmp_path, "conf.d/00-a.conf", "IdentityFile id_a\n")
        main = _write(tmp_path, "config", "Include conf.d/*.conf\n")
        config = SSHConfig.from_path(str(main))
        assert config.lookup("x")["identityfile"] == ["id_a", "id_b"]

    def test_same_file_included_twice_in_different_blocks(self, tmp_path):
        main = _write(
            tmp_path,
            "config",
            "Host alpha\n    Include common.conf\n"
            "Host beta\n    Include common.conf\n",
        )
        _write(tmp_path, "common.conf", "User common\nIdentityFile id_c\n")
        config = SSHConfig.from_path(str(main))
        for host in ("alpha", "beta"):
            result = config.lookup(host)
            assert result["user"] == "common"
            assert result["identityfile"] == ["id_c"]

    def test_nested_include_then_parent_continues_in_order(self, tmp_path):
        main = _write(
            tmp_path,
            "config",
            "Host one\n    Include sub.conf\n    Compression no\n",
        )
        _write(tmp_path, "sub.conf", "User subuser\nCompression yes\n")
        config = SSHConfig.from_path(str(main))
        result = config.lookup("one")
        assert result["user"] == "subuser"
        # Parent lines after the Include are parsed after the included
        # content, so the included (first) value still wins.
        assert result["compression"] == "yes"

    def test_included_file_may_open_new_blocks(self, tmp_path):
        # Textual inclusion, as in OpenSSH: a Host opened by an included
        # file remains the active block when the parent file resumes.
        main = _write(
            tmp_path,
            "config",
            "Host one\n    Include sub.conf\n    Port 1111\n",
        )
        _write(tmp_path, "sub.conf", "User subuser\nHost two\n    User two\n")
        config = SSHConfig.from_path(str(main))
        assert config.lookup("one")["user"] == "subuser"
        two = config.lookup("two")
        assert two["user"] == "two"
        assert two["port"] == "1111"

    def test_multiple_patterns_on_one_line(self, tmp_path):
        _write(tmp_path, "a.conf", "User from_a\n")
        _write(tmp_path, "b.conf", "Port 2222\n")
        main = _write(tmp_path, "config", "Include a.conf b.conf\n")
        config = SSHConfig.from_path(str(main))
        result = config.lookup("x")
        assert result["user"] == "from_a"
        assert result["port"] == "2222"

    def test_lookups_do_not_pollute_each_other(self, tmp_path):
        main = _write(
            tmp_path,
            "config",
            "Host specific\n    Include specific.conf\n"
            "Host *\n    Include fallback.conf\n",
        )
        _write(
            tmp_path,
            "specific.conf",
            "User spec\nIdentityFile id_specific\n",
        )
        _write(tmp_path, "fallback.conf", "IdentityFile id_fallback\n")
        config = SSHConfig.from_path(str(main))
        first = config.lookup("specific")
        assert first["identityfile"] == ["id_specific", "id_fallback"]
        other = config.lookup("other")
        assert other["identityfile"] == ["id_fallback"]
        assert "user" not in other
        # Repeating the lookups yields identical, unpolluted results.
        again = config.lookup("specific")
        assert again["identityfile"] == ["id_specific", "id_fallback"]
        assert config.lookup("other")["identityfile"] == ["id_fallback"]

    def test_from_file_with_explicit_source_dir(self, tmp_path, monkeypatch):
        root = tmp_path / "sshroot"
        _write(root, "config", "Include conf.d/*.conf\n")
        _write(root, "conf.d/00-a.conf", "User from_subdir\n")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        with open(root / "config") as flo:
            config = SSHConfig.from_file(flo, source_dir=str(root))
        assert config.lookup("x")["user"] == "from_subdir"

    def test_from_path_defaults_to_config_file_dir(
        self, tmp_path, monkeypatch
    ):
        root = tmp_path / "sshroot"
        main = _write(root, "config", "Include extra.conf\n")
        _write(root, "extra.conf", "User neighbor\n")
        monkeypatch.chdir(tmp_path)
        config = SSHConfig.from_path(str(main))
        assert config.lookup("x")["user"] == "neighbor"

    def test_user_config_root_used_for_anonymous_streams(
        self, tmp_path, monkeypatch
    ):
        dotssh = tmp_path / ".ssh"
        _write(dotssh, "conf.d/00-a.conf", "User homedir\n")
        monkeypatch.setenv("HOME", str(tmp_path))
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        config = SSHConfig.from_file(StringIO("Include conf.d/*.conf\n"))
        assert config.lookup("x")["user"] == "homedir"

    def test_system_config_uses_system_root_not_cwd(
        self, tmp_path, monkeypatch
    ):
        # A relative Include in a system config must resolve under
        # /etc/ssh, never the current working directory.
        _write(tmp_path, "sneaky.conf", "User cwd\n")
        monkeypatch.chdir(tmp_path)
        with raises(ConfigParseError) as err:
            SSHConfig.from_file(
                StringIO("Include sneaky.conf\n"), config_type="system"
            )
        assert os.path.join(os.sep, "etc", "ssh", "sneaky.conf") in str(
            err.value
        )

    def test_invalid_config_type_rejected(self):
        with raises(ValueError):
            SSHConfig.from_file(StringIO(""), config_type="bogus")

    def test_missing_literal_include_errors(self, tmp_path):
        main = _write(tmp_path, "config", "Include nope.conf\n")
        with raises(ConfigParseError) as err:
            SSHConfig.from_path(str(main))
        message = str(err.value)
        assert "not found" in message
        assert "nope.conf" in message
        assert str(main) in message

    def test_unmatched_glob_is_ignored(self, tmp_path):
        main = _write(
            tmp_path,
            "config",
            "Include missing.d/*.conf\nHost *\n    User ok\n",
        )
        config = SSHConfig.from_path(str(main))
        assert config.lookup("x")["user"] == "ok"

    def test_include_cycle_reports_chain(self, tmp_path):
        main = _write(tmp_path, "a.conf", "Include b.conf\n")
        _write(tmp_path, "b.conf", "Include a.conf\n")
        with raises(ConfigParseError) as err:
            SSHConfig.from_path(str(main))
        message = str(err.value)
        assert "cycle" in message.lower()
        assert "a.conf" in message
        assert "b.conf" in message
        assert "include chain" in message

    def test_symlink_cycle_detected(self, tmp_path):
        main = _write(tmp_path, "main.conf", "Include link.conf\n")
        os.symlink(main, tmp_path / "link.conf")
        with raises(ConfigParseError) as err:
            SSHConfig.from_path(str(main))
        assert "cycle" in str(err.value).lower()

    @pytest.mark.skipif(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        reason="root can read anything",
    )
    def test_unreadable_file_reports_location_and_chain(self, tmp_path):
        main = _write(tmp_path, "config", "Include sub/child.conf\n")
        _write(tmp_path, "sub/child.conf", "Include sub/secret.conf\n")
        secret = _write(tmp_path, "sub/secret.conf", "User nope\n")
        os.chmod(secret, 0)
        try:
            with raises(ConfigParseError) as err:
                SSHConfig.from_path(str(main))
        finally:
            os.chmod(secret, 0o644)
        message = str(err.value)
        assert "Unable to read" in message
        assert "secret.conf" in message
        assert "child.conf" in message
        assert "include chain" in message

    def test_syntax_error_reports_file_line_and_chain(self, tmp_path):
        main = _write(
            tmp_path,
            "config",
            "User top\n\nInclude sub/bad.conf\n",
        )
        _write(tmp_path, "sub/bad.conf", "User ok\n!!!bogus!!!\n")
        with raises(ConfigParseError) as err:
            SSHConfig.from_path(str(main))
        message = str(err.value)
        assert "bad.conf:2" in message
        assert "config:3" in message
        assert "include chain" in message

    def test_max_include_depth_is_configurable(self, tmp_path):
        _write(tmp_path, "d2.conf", "User deep\n")
        _write(tmp_path, "d1.conf", "Include d2.conf\n")
        main = _write(tmp_path, "d0.conf", "Include d1.conf\n")
        # Default limits allow this shallow chain.
        config = SSHConfig.from_path(str(main))
        assert config.lookup("x")["user"] == "deep"
        with raises(ConfigParseError) as err:
            SSHConfig.from_path(str(main), max_include_depth=1)
        assert "depth" in str(err.value).lower()

    def test_max_include_files_is_configurable(self, tmp_path):
        for name in ("00-a", "01-b", "02-c"):
            _write(tmp_path, "conf.d/{}.conf".format(name), "User x\n")
        main = _write(tmp_path, "config", "Include conf.d/*.conf\n")
        config = SSHConfig.from_path(str(main))
        assert config.lookup("x")["user"] == "x"
        with raises(ConfigParseError) as err:
            SSHConfig.from_path(str(main), max_include_files=2)
        assert "count" in str(err.value).lower()

    def test_parse_does_not_execute_match_exec(self, tmp_path):
        sentinel = tmp_path / "executed"
        main = _write(tmp_path, "config", "Include matched.conf\n")
        _write(
            tmp_path,
            "matched.conf",
            'Match exec "touch {}"\n    User pwned\n'.format(sentinel),
        )
        SSHConfig.from_path(str(main))
        assert not sentinel.exists()

    def test_parse_from_read_only_directory(self, tmp_path):
        main = _write(tmp_path, "config", "Include conf.d/*.conf\n")
        _write(tmp_path, "conf.d/00-a.conf", "User readonly\n")
        os.chmod(tmp_path / "conf.d", 0o555)
        os.chmod(tmp_path, 0o555)
        try:
            config = SSHConfig.from_path(str(main))
        finally:
            os.chmod(tmp_path, 0o755)
            os.chmod(tmp_path / "conf.d", 0o755)
        assert config.lookup("anything")["user"] == "readonly"
