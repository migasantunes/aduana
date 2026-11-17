"""aduana: a security gateway for the Model Context Protocol."""

__version__ = "0.0.1"

#: Protocol revisions the gateway speaks to downstream clients.
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("2026-07-28",)

#: Reverse-DNS prefix for aduana's own ``_meta`` keys.
META_PREFIX = "io.github.migasantunes.aduana/"
