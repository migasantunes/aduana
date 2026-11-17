"""Command line: ``aduana serve`` and ``aduana pin``.

This is the only module that knows about every package: it turns a config file
into a pipeline, an audit sink and the gateway app.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import httpx
import typer
import uvicorn

from aduana.audit import build_audit_sink
from aduana.config import Config, load_config
from aduana.gateway import AllowAllPipeline, NullAuditSink, create_app
from aduana.pinning import PinStore
from aduana.pipeline.engine import build_pipeline
from aduana.upstream import Catalog, UpstreamClient, UpstreamError

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__)

ConfigOption = Annotated[
    Path, typer.Option("--config", "-c", exists=True, dir_okay=False, help="YAML config file.")
]


@app.command()
def serve(
    config: ConfigOption,
    host: Annotated[str | None, typer.Option(help="Override gateway.host.")] = None,
    port: Annotated[int | None, typer.Option(help="Override gateway.port.")] = None,
) -> None:
    """Run the gateway."""
    cfg = load_config(config)
    asgi = create_app(cfg, pipeline=build_pipeline(cfg), audit=build_audit_sink(cfg))
    uvicorn.run(
        asgi,
        host=host or cfg.gateway.host,
        port=port or cfg.gateway.port,
        log_level="info",
    )


@app.command()
def pin(config: ConfigOption) -> None:
    """Record the upstreams' current tool definitions in the lockfile.

    Run this after reviewing what the upstreams expose. From then on a changed
    definition is drift: reported in ``warn`` mode, hidden in ``enforce`` mode.
    An upstream that cannot be reached keeps its existing pins.
    """
    cfg = load_config(config)
    pinned, failed = asyncio.run(_pin(cfg))
    for name, count in pinned.items():
        typer.echo(f"pinned {count} tool(s) from {name}")
    for name in failed:
        typer.echo(f"could not reach {name}; its pins were left unchanged", err=True)
    typer.echo(f"wrote {cfg.pinning.lockfile}")
    if failed:
        raise typer.Exit(code=1)


async def _pin(
    cfg: Config, http_client: httpx.AsyncClient | None = None
) -> tuple[dict[str, int], list[str]]:
    store = PinStore.load(cfg.pinning.lockfile)
    pinned: dict[str, int] = {}
    failed: list[str] = []
    http = http_client or httpx.AsyncClient()
    try:
        clients = [
            UpstreamClient(u, http, timeout_s=cfg.gateway.upstream_timeout_s) for u in cfg.upstreams
        ]
        # The catalog is used only for its paginated fetch; nothing is vetted here,
        # because pinning records what the operator has just reviewed.
        catalog = Catalog(
            clients, AllowAllPipeline(), NullAuditSink(), max_ttl_ms=cfg.gateway.max_list_ttl_ms
        )
        for client in clients:
            try:
                tools, _ttl = await catalog.fetch_all(client)
            except UpstreamError:
                failed.append(client.name)
                continue
            valid = [t for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)]
            store.pin(client.name, valid)
            pinned[client.name] = len(valid)
    finally:
        if http_client is None:
            await http.aclose()
    store.save()
    return pinned, failed


if __name__ == "__main__":
    app()
