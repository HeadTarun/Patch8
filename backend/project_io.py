"""Shared upload validation; never trust paths or ZIP directory metadata."""
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import uuid
import zipfile

SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
PROJECT_EXTENSIONS = SOURCE_EXTENSIONS | {".cmake", ".txt", ".md", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".mk", ".xml", ".sh", ".properties", ".gradle", ".bazel", ".bzl", ".make", ".conf"}
PROJECT_FILENAMES = {"makefile", "cmakelists.txt", "dockerfile", "meson.build", "meson.options", "configure", "configure.ac", "readme", ".gitignore", ".editorconfig"}
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", "venv", ".venv", "__pycache__", "target", ".idea", ".vscode"}


class ProjectInputError(ValueError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def safe_path(name: str) -> PurePosixPath:
    name = name.replace("\\", "/")
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or not path.parts or
        any(part in {".", ".."} for part in name.rstrip("/").split("/")) or
        any(":" in part or "\x00" in part or part.endswith((".", " ")) or
            re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)
            for part in path.parts)):
        raise ProjectInputError("Project contains an unsafe path.")
    return path


def supported(path: PurePosixPath) -> bool:
    return (not any(part.casefold() in SKIP_DIRS for part in path.parts)
            and (path.suffix.lower() in PROJECT_EXTENSIONS or path.name.casefold() in PROJECT_FILENAMES))


def validate_text(data: bytes, source: bool) -> None:
    if source and not data:
        raise ProjectInputError("Source files must not be empty.")
    if b"\x00" in data:
        raise ProjectInputError("Project source and configuration must be text files, not binary data.")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProjectInputError("Source and configuration files must use UTF-8 encoding.") from exc


def inspect_archive(archive_path: Path, *, target: Path | None = None,
                    max_files: int = 5000, max_bytes: int = 100_000_000,
                    max_source: int = 200_000) -> int:
    total = 0
    source_count = 0
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(archive_path) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > max_files:
                raise ProjectInputError("ZIP is empty or exceeds the file limit.")
            if sum(entry.file_size for entry in entries) > max_bytes:
                raise ProjectInputError("Expanded project exceeds the size limit.", 413)
            for entry in entries:
                path = safe_path(entry.filename)
                key = str(path).casefold()
                if key in seen:
                    raise ProjectInputError("Archive contains duplicate file paths.")
                seen.add(key)
                mode = stat.S_IFMT(entry.external_attr >> 16)
                if mode not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise ProjectInputError("Archive contains a symbolic link or special file.")
                if entry.flag_bits & 1:
                    raise ProjectInputError("Encrypted ZIP archives are not supported.")
                if entry.is_dir():
                    continue
                keep = supported(path)
                source = path.suffix.lower() in SOURCE_EXTENSIONS
                limit = max_source if source else max_source * 10
                data = bytearray()
                with archive.open(entry) as stream:
                    while chunk := stream.read(65536):
                        total += len(chunk)
                        if total > max_bytes:
                            raise ProjectInputError("Expanded project exceeds the size limit.", 413)
                        if keep:
                            data.extend(chunk)
                            if len(data) > limit:
                                raise ProjectInputError("Project file exceeds the configured size limit.", 413)
                if not keep:
                    continue
                validate_text(data, source)
                source_count += int(source)
                if target is not None:
                    destination = (target / Path(*path.parts)).resolve()
                    if not destination.is_relative_to(target.resolve()):
                        raise ProjectInputError("Archive contains an unsafe path.")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError) as exc:
        raise ProjectInputError("Could not read this ZIP archive. Use an unencrypted, valid ZIP.") from exc
    if not source_count:
        raise ProjectInputError("The ZIP archive must contain C/C++ source or header files.")
    return source_count


def normalize_project_root(target: Path) -> None:
    """Remove one archive wrapper, but keep a real project's src/include directories."""
    children = list(target.iterdir())
    if len(children) != 1 or not children[0].is_dir():
        return
    wrapper = children[0]
    if wrapper.name.casefold() in {"src", "source", "include", "lib", "tests"}:
        return
    # Rename the wrapper first so a nested directory with the same name cannot
    # collide with its parent during normalization.
    staging = target.parent / (target.name + "-wrapper-" + uuid.uuid4().hex)
    wrapper.rename(staging)
    try:
        for child in staging.iterdir():
            shutil.move(str(child), target / child.name)
    finally:
        shutil.rmtree(staging)
