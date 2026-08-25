from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import subprocess
import tempfile

from .config import Config
from .models import ScanResult
from .reporters import ledger_payload
from .scanner import MARKDOWN_SUFFIXES, MAX_HASH_BYTES, scan_paths


MAX_REF_LENGTH = 512
MAX_TREE_LIST_BYTES = 64 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 60


@dataclass(frozen=True, slots=True)
class GitRefScan:
    result: ScanResult
    ledger: dict[str, object]
    commit: str


@dataclass(frozen=True, slots=True)
class _TreeEntry:
    mode: str
    object_id: str
    size: int | None
    path: str


def scan_git_ref(
    root: Path,
    requested_paths: list[Path],
    config: Config,
    ref: str,
) -> GitRefScan:
    """Scan repository Markdown as stored in an existing local Git commit.

    The current configuration is deliberately applied to both revisions. Git objects are
    read without checking out the ref, running hooks, invoking filters, or changing HEAD.
    """

    repository_root = root.resolve()
    _require_repository_root(repository_root)
    commit = _resolve_commit(repository_root, ref)
    tree = _read_tree(repository_root, commit)
    scopes = _requested_scopes(repository_root, requested_paths)

    with tempfile.TemporaryDirectory(prefix="claimfence-git-ref-") as directory:
        snapshot_root = Path(directory).resolve()
        snapshot_paths: list[Path] = []

        for relative, is_directory in scopes:
            destination = snapshot_root / relative
            if is_directory:
                destination.mkdir(parents=True, exist_ok=True)
                snapshot_paths.append(destination)
            elif relative in tree:
                _materialize(repository_root, tree[relative], destination, full_content=True)
                snapshot_paths.append(destination)

        for entry in tree.values():
            if Path(entry.path).suffix.lower() not in MARKDOWN_SUFFIXES:
                continue
            if not _within_scopes(entry.path, scopes):
                continue
            _materialize(
                repository_root,
                entry,
                snapshot_root / PurePosixPath(entry.path),
                full_content=True,
            )

        initial = scan_paths(snapshot_paths, config, snapshot_root, contain_to_root=True)
        _materialize_evidence(repository_root, tree, snapshot_root, initial)
        result = scan_paths(snapshot_paths, config, snapshot_root, contain_to_root=True)
        ledger = ledger_payload(result, snapshot_root)

    return GitRefScan(result=result, ledger=ledger, commit=commit)


def _require_repository_root(root: Path) -> None:
    discovered = _git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    if Path(discovered).resolve() != root:
        raise ValueError("--compare-ref requires --root to be the Git worktree root")


def _resolve_commit(root: Path, ref: str) -> str:
    if (
        not ref
        or len(ref) > MAX_REF_LENGTH
        or any(character in ref for character in "\0\r\n")
    ):
        raise ValueError("--compare-ref must be a non-empty local Git revision")
    commit = _git(
        root,
        "rev-parse",
        "--verify",
        "--end-of-options",
        f"{ref}^{{commit}}",
    ).decode("ascii").strip()
    if len(commit) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise ValueError("Git returned an invalid resolved commit identifier")
    return commit


def _read_tree(root: Path, commit: str) -> dict[str, _TreeEntry]:
    raw = _git(root, "ls-tree", "-r", "-z", "--long", commit, "--")
    if len(raw) > MAX_TREE_LIST_BYTES:
        raise ValueError("Git tree listing exceeds ClaimFence's 64 MiB comparison limit")
    entries: dict[str, _TreeEntry] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id, raw_size = header.split()
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("Git tree contains an unsupported path or entry") from exc
        if object_type != b"blob":
            continue
        _validate_tree_path(path)
        size = None if raw_size == b"-" else int(raw_size)
        entries[path] = _TreeEntry(
            mode.decode("ascii"),
            object_id.decode("ascii"),
            size,
            path,
        )
    return entries


def _requested_scopes(root: Path, paths: list[Path]) -> list[tuple[str, bool]]:
    scopes: list[tuple[str, bool]] = []
    for path in paths:
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError(f"scan path escapes the repository root: {path}") from exc
        scopes.append(("" if relative == "." else relative, resolved.is_dir()))
    return scopes


def _within_scopes(path: str, scopes: list[tuple[str, bool]]) -> bool:
    for relative, is_directory in scopes:
        if is_directory and (not relative or path.startswith(f"{relative}/")):
            return True
        if not is_directory and path == relative:
            return True
    return False


def _materialize_evidence(
    root: Path,
    tree: dict[str, _TreeEntry],
    snapshot_root: Path,
    result: ScanResult,
) -> None:
    paths = {
        anchor.repository_path
        for claim in result.claims
        for anchor in claim.evidence
        if anchor.repository_path is not None
    }
    for repository_path in sorted(paths):
        entry = tree.get(repository_path)
        destination = snapshot_root / PurePosixPath(repository_path)
        if entry is not None:
            _materialize(
                root,
                entry,
                destination,
                full_content=(entry.size or 0) <= MAX_HASH_BYTES,
            )
            continue
        prefix = f"{repository_path.rstrip('/')}/"
        if any(path.startswith(prefix) for path in tree):
            destination.mkdir(parents=True, exist_ok=True)


def _materialize(
    root: Path,
    entry: _TreeEntry,
    destination: Path,
    *,
    full_content: bool,
) -> None:
    if entry.mode == "120000":
        raise ValueError(
            f"Git comparison does not follow symbolic-link input: {entry.path}"
        )
    if entry.mode not in {"100644", "100755"}:
        raise ValueError(f"Git comparison cannot materialize mode {entry.mode}: {entry.path}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not full_content and entry.size is not None:
        with destination.open("wb") as stream:
            stream.truncate(entry.size)
        return
    content = _git(root, "cat-file", "blob", entry.object_id)
    if entry.size is not None and len(content) != entry.size:
        raise ValueError(f"Git blob size changed while reading {entry.path}")
    destination.write_bytes(content)


def _validate_tree_path(path: str) -> None:
    pure = PurePosixPath(path)
    if not path or pure.is_absolute() or ".." in pure.parts or "\0" in path:
        raise ValueError("Git tree contains an unsafe path")


def _git(root: Path, *arguments: str) -> bytes:
    # Caller-controlled Git environment variables can redirect object reads away from
    # ``root``. Keep ordinary process settings such as PATH, but establish repository
    # selection from the explicit -C argument and Git's own discovery only.
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LC_ALL": "C",
        }
    )
    try:
        process = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("could not read the local Git comparison revision") from exc
    if process.returncode:
        detail = process.stderr.decode("utf-8", errors="replace").splitlines()
        suffix = f": {detail[0]}" if detail else ""
        raise ValueError(f"Git comparison command failed{suffix}")
    return process.stdout
