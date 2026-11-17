"""OnnDemand host CLI. Installed versions are derived from release tags."""
try:
    from ._version import __version__
except ImportError:
    __version__ = '0.0.0.dev0'
