import os
from pathlib import Path

import pytest

from rofi_passage import store
from rofi_passage.errors import RofiPassageError


def touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")


def test_list_entries_follows_the_contract(tmp_path: Path) -> None:
    touch(tmp_path / "web/example.com.age")
    touch(tmp_path / "web/example.com/work.age")
    touch(tmp_path / "bank/b.fr.age")
    touch(tmp_path / ".git/objects/x.age")
    touch(tmp_path / ".extensions/ext.age")
    touch(tmp_path / ".age-recipients")
    touch(tmp_path / ".gitattributes")
    touch(tmp_path / "web/notes.txt")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    touch(outside / "secret.age")
    os.symlink(outside / "secret.age", tmp_path / "web/link.age")
    os.symlink(outside, tmp_path / "linked-dir")
    touch(tmp_path / "web/bad\nname.age")

    assert store.list_entries(tmp_path) == ["bank/b.fr", "web/example.com", "web/example.com/work"]


def test_symlinked_store_root_is_followed(tmp_path: Path) -> None:
    # Only links inside the store are skipped; the root itself may be a link.
    touch(tmp_path / "real/web/example.com.age")
    os.symlink(tmp_path / "real", tmp_path / "store")
    assert store.list_entries(tmp_path / "store") == ["web/example.com"]
    store.check_writable(tmp_path / "store", "web/new.org")


def test_display_name_strips_controls() -> None:
    assert store.display_name("a\x1b[31mb\nc\u2028d\x00") == "a[31mbcd"
    assert store.display_name("<b>markup</b>") == "<b>markup</b>"  # shown as text, not stripped


def test_categories(tmp_path: Path) -> None:
    touch(tmp_path / "web/example.com/work.age")
    touch(tmp_path / "web/shop/x.org.age")
    touch(tmp_path / "bank/b.fr.age")
    touch(tmp_path / ".git/x")
    assert store.categories(tmp_path) == ["bank", "web", "web/shop"]


@pytest.mark.parametrize(
    ("name", "site"),
    [
        ("web/example.com", "example.com"),
        ("web/example.com/work", "example.com"),
        ("web/a.com/sub.b.org/1", "sub.b.org"),
        ("notes/wifi", None),
    ],
)
def test_site_of(name: str, site: str | None) -> None:
    assert store.site_of(name) == site


@pytest.mark.parametrize("name", ["../x", "a/../b", "/abs", "a//b", "", "a/", "-rf", "a\nb"])
def test_check_name_refuses(name: str) -> None:
    with pytest.raises(RofiPassageError):
        store.check_name(name)


def test_check_writable_refuses_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "store"
    root.mkdir()
    os.symlink(outside, root / "web")
    with pytest.raises(RofiPassageError, match="symlink"):
        store.check_writable(root, "web/example.com")
    touch(outside / "target.age")
    os.symlink(outside / "target.age", root / "x.age")
    with pytest.raises(RofiPassageError, match="symlink"):
        store.check_writable(root, "x")
    assert store.check_writable(root, "new/example.com") == root / "new/example.com.age"


@pytest.mark.parametrize(
    ("args", "name"),
    [
        (("web", "Example.com", ""), "web/example.com"),
        (("web", "example.com", "work"), "web/example.com/work"),
        (("", "example.com", "1"), "example.com/1"),
        (("web/shop/", "x.org", ""), "web/shop/x.org"),
    ],
)
def test_new_entry_name(args: tuple[str, str, str], name: str) -> None:
    assert store.new_entry_name(*args) == name


@pytest.mark.parametrize(
    ("args", "reason"),
    [
        (("web", "www.example.com", ""), "www"),
        (("web", "example.com", "a.b"), "Label"),
        (("web", "localhost", ""), "example.com"),
        (("web", "https://example.com", ""), "URL"),
        (("we.b", "example.com", ""), "Category"),
        (("..", "example.com", ""), "Category|'..'"),
        (("web", "", ""), "empty"),
    ],
)
def test_new_entry_name_refuses(args: tuple[str, str, str], reason: str) -> None:
    with pytest.raises(RofiPassageError, match=reason):
        store.new_entry_name(*args)
