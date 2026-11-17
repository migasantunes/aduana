"""aduana as an MCP client: the upstream HTTP client and the aggregated tool catalog."""

from aduana.upstream.catalog import Catalog, CatalogEntry, CatalogListing, split_exposed_name
from aduana.upstream.client import (
    SseEvent,
    SseParser,
    UpstreamClient,
    UpstreamError,
    UpstreamHttpError,
    UpstreamProtocolError,
    UpstreamRpcError,
    UpstreamUnavailable,
    parse_sse,
)

__all__ = [
    "Catalog",
    "CatalogEntry",
    "CatalogListing",
    "SseEvent",
    "SseParser",
    "UpstreamClient",
    "UpstreamError",
    "UpstreamHttpError",
    "UpstreamProtocolError",
    "UpstreamRpcError",
    "UpstreamUnavailable",
    "parse_sse",
    "split_exposed_name",
]
