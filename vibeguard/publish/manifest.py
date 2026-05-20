"""Publish manifest model — describes the file set a publish would produce."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Ecosystem = Literal["npm", "python-sdist", "python-wheel"]


class PublishedFile(BaseModel):
    """One file that would be included in the published artifact."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="Path relative to the package root")
    size_bytes: int = Field(ge=0)
    included_by: str = Field(
        description=(
            "Why this file is included: 'files-allowlist', 'always-included', "
            "'package-discovery', 'manifest-in', 'default-walk'."
        )
    )


class PublishManifest(BaseModel):
    """Result of a single simulated publish."""

    model_config = ConfigDict(extra="forbid")

    ecosystem: Ecosystem
    package_root: str
    package_name: str | None = None
    package_version: str | None = None
    files: list[PublishedFile] = Field(default_factory=list)
    excluded: list[str] = Field(
        default_factory=list,
        description="Files present on disk but excluded from the publish (relative paths).",
    )
    total_bytes: int = 0
    warnings: list[str] = Field(default_factory=list)

    def to_json(self, *, indent: int | None = 2) -> str:
        """Return a deterministic JSON serialization (files sorted by path)."""
        data = self.model_dump(mode="json")
        data["files"] = sorted(data["files"], key=lambda f: f["path"])
        data["excluded"] = sorted(data["excluded"])
        return json.dumps(data, indent=indent, sort_keys=True)

    def included_paths(self) -> list[str]:
        return sorted(f.path for f in self.files)
