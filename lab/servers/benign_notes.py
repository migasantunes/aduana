"""An ordinary, non-malicious notes server: list / read / add notes, in memory only.

Used as the control in the lab: a clean server whose tools and results carry no attack, so a
gateway that flags it is producing a false positive. No file or network access anywhere.
"""

from __future__ import annotations

from starlette.applications import Starlette

from lab.servers.kit import Tool, ToolCall, ToolError, make_server, run_from_cli

DEFAULT_PORT = 9101

# A small in-memory store, seeded so read/list have something to return.
_NOTES: dict[str, str] = {
    "welcome": "Welcome to the notes server. Add your own with add_note.",
    "todo": "Buy milk. Call the dentist.",
}


def _list_schema() -> dict:
    return {"type": "object", "additionalProperties": False}


def _read_schema() -> dict:
    return {
        "type": "object",
        "properties": {"id": {"type": "string", "description": "Note id to read."}},
        "required": ["id"],
        "additionalProperties": False,
    }


def _add_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "Identifier for the new note."},
            "text": {"type": "string", "description": "Note body."},
        },
        "required": ["id", "text"],
        "additionalProperties": False,
    }


async def _list(_: ToolCall) -> dict:
    ids = ", ".join(sorted(_NOTES)) or "(none)"
    return {"content": [{"type": "text", "text": f"Notes: {ids}"}]}


async def _read(call: ToolCall) -> dict:
    note_id = str(call.arguments.get("id", ""))
    if note_id not in _NOTES:
        raise ToolError(f"No note with id {note_id!r}.")
    return {"content": [{"type": "text", "text": _NOTES[note_id]}]}


async def _add(call: ToolCall) -> dict:
    note_id = str(call.arguments.get("id", ""))
    text = str(call.arguments.get("text", ""))
    if not note_id:
        raise ToolError("A note id is required.")
    _NOTES[note_id] = text
    return {"content": [{"type": "text", "text": f"Saved note {note_id!r}."}]}


def make_app() -> Starlette:
    tools = [
        Tool(
            "list_notes",
            {"description": "List the ids of all notes.", "inputSchema": _list_schema()},
            _list,
        ),
        Tool(
            "read_note",
            {"description": "Read one note by id.", "inputSchema": _read_schema()},
            _read,
        ),
        Tool(
            "add_note",
            {"description": "Add or replace a note.", "inputSchema": _add_schema()},
            _add,
        ),
    ]
    return make_server(
        "benign-notes",
        "1.0.0",
        tools,
        instructions="A simple scratchpad. Use list_notes, read_note and add_note.",
    )


app = make_app()


if __name__ == "__main__":
    run_from_cli(app, DEFAULT_PORT)
