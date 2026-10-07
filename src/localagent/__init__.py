"""Public package metadata for :mod:`localagent`."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("localagent")
except PackageNotFoundError:
    # Source checkouts are importable through pytest's ``pythonpath`` setting
    # before an editable install. The packaged distribution remains the source
    # of truth for released version metadata.
    __version__ = "0.0.0+source"

__all__ = ["__version__"]
