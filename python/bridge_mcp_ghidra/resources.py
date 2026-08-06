"""Ghidra functions exposed as MCP resources.

Why resources and not just tools: a client caches a `resources/read` by URI and drops
that cache entry when the server sends `notifications/resources/updated` for it. So a
re-read after a write costs nothing until the server says the content moved — which is
what removes the write→re-read churn. Reads also arrive through the client's own built-in
read-only resource tool, so one permission grant covers reading every function instead of
a rule per Ghidra tool.

Shape, and why it is not symmetrical:

* ``resources/list`` carries exactly one entry, ``ghidra://programs``. It is the discovery
  root: it names every open program and spells out how to build the other URIs.
* everything else is a **template**. Templates never appear in ``resources/list`` (the SDK
  lists them only under ``resources/templates/list``) and ``list_resources`` has no cursor,
  so enumerating one resource per function is not merely impractical at 25k+ functions,
  it is unreachable. Per-function labels therefore live in the ``functions`` index rows and
  in the bundle body — a ``resources/read`` result carries only uri/mimeType/text, with no
  name field to put them in.

URI keys are **addresses, never names**. Renaming is the most common write, and a
name-keyed URI would die exactly when its content changes: the client's cached body would
be stranded at the old name with no notification able to reach it, since
``resources/list_changed`` evicts only listings and MCP has no rename notification.
"""

import json
from urllib.parse import quote, unquote

from . import dispatch
from . import state
from .config import logger
from .server import mcp

# Caps chosen so a single read stays a reasonable size for a model to consume.
_MAX_INDEX_FUNCTIONS = 2000
_MAX_SEARCH_HITS = 200

_JSON = "application/json"


def canonical_function_uri(program: str, address: str) -> str:
    """The one place a function's resource URI is constructed.

    Every producer — the index rows, the bundle body's own ``canonical_uri``, search
    results and the invalidation emitter — goes through this, so the client's cache key
    and the key we later invalidate are the same string by construction.

    The address is used exactly as Ghidra emits it (lowercase hex, no ``0x``, optionally
    ``space:hex``), matching ``ServiceUtils.addressToJson`` so the URI and the payload can
    never disagree.
    """
    return f"ghidra://function/{quote(program, safe='')}/{quote(address, safe=':')}"


def _read(endpoint: str, **params) -> str:
    """One upstream GET, off the event loop, with failures surfaced as errors."""
    query = {k: str(v) for k, v in params.items() if v is not None and v != ""}
    text = dispatch.dispatch_get(endpoint, params=query or None)
    return dispatch.raise_on_failure(text)


async def _read_async(endpoint: str, **params) -> str:
    return await state.run_blocking_ghidra_call(_read, endpoint, **params)


def _json(payload) -> str:
    return json.dumps(payload, indent=2)


def parse_function_hit(item) -> tuple[str | None, str | None]:
    """Normalise a listing/search row into ``(name, address)``.

    ``/list_functions`` and ``/list_functions_enhanced`` return dicts;
    ``/search_functions`` returns legacy ``"name @ address"`` strings. One parser
    keeps every resource that builds a ``uri`` field from producing a different
    address spelling than ``canonical_function_uri``.
    """
    if isinstance(item, dict):
        address = item.get("address")
        name = item.get("name")
        if address:
            return (str(name) if name is not None else None, str(address))
        return None, None
    if isinstance(item, str) and " @ " in item:
        name, address = item.rsplit(" @ ", 1)
        name, address = name.strip(), address.strip()
        if name and address:
            return name, address
    return None, None


# ---------------------------------------------------------------------------
# The discovery root — the only entry in resources/list
# ---------------------------------------------------------------------------
@mcp.resource(
    "ghidra://programs",
    name="Ghidra programs",
    title="Open Ghidra programs and how to address them",
    description="Every program open in the connected Ghidra, plus the URI contract for "
                "reading a function bundle. Start here.",
    mime_type=_JSON,
)
async def programs_resource() -> str:
    """List open programs and document how to build the other URIs."""
    try:
        raw = await _read_async("/list_open_programs")
        programs = json.loads(raw)
    except Exception as e:
        return _json({"connected": False, "error": str(e)})

    entries = programs if isinstance(programs, list) else programs.get("programs", programs)
    listed = []
    if isinstance(entries, list):
        for item in entries:
            name = item.get("name") if isinstance(item, dict) else str(item)
            if not name:
                continue
            encoded = quote(name, safe="")
            listed.append({
                "program": name,
                "index": f"ghidra://program/{encoded}/index",
                "functions": f"ghidra://program/{encoded}/functions",
                "search": f"ghidra://search/{encoded}/functions/{{pattern}}",
            })

    return _json({
        "connected": True,
        "programs": listed,
        "uri_contract": {
            "function_by_address": "ghidra://function/{program}/{address}",
            "function_by_name": "ghidra://function/{program}/by-name/{name}",
            "search": "ghidra://search/{program}/functions/{pattern}",
            "notes": [
                "Addresses are lowercase hex without 0x, exactly as Ghidra reports them "
                "(use space:hex on programs with several address spaces).",
                "The address form is canonical and stable across renames; the by-name form "
                "is a redirect that returns the canonical URI.",
                "Percent-encode a program name that contains / or spaces.",
            ],
        },
    })


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
@mcp.resource(
    "ghidra://program/{program}/index",
    name="Ghidra program summary",
    description="Metadata for one program: language, image base, function count.",
    mime_type=_JSON,
)
async def program_index_resource(program: str) -> str:
    return await _read_async("/get_current_program_info", program=unquote(program))


@mcp.resource(
    "ghidra://program/{program}/functions",
    name="Ghidra function index",
    description="Every function as {name, address, uri}. This is where a function's "
                "current descriptive name is visible — a resource read result has no name "
                "field of its own.",
    mime_type=_JSON,
)
async def function_index_resource(program: str) -> str:
    name = unquote(program)
    # /list_functions has no limit and materialises every function; enhanced is paginated.
    raw = await _read_async(
        "/list_functions_enhanced",
        program=name,
        offset=0,
        limit=_MAX_INDEX_FUNCTIONS,
    )
    payload = json.loads(raw)
    items = payload.get("functions", payload) if isinstance(payload, dict) else payload
    rows = []
    if isinstance(items, list):
        for item in items:
            fname, address = parse_function_hit(item)
            if not address:
                continue
            rows.append({
                "name": fname,
                "address": address,
                "uri": canonical_function_uri(name, address),
            })
    truncated = len(rows) >= _MAX_INDEX_FUNCTIONS
    total = len(rows)
    if truncated:
        try:
            info = json.loads(await _read_async("/get_current_program_info", program=name))
            if isinstance(info, dict) and info.get("function_count") is not None:
                total = int(info["function_count"])
        except Exception:
            total = len(rows)
    return _json({
        "program": name,
        "functions": rows,
        "count": len(rows),
        "total": total,
        "truncated": truncated,
    })


@mcp.resource(
    "ghidra://function/{program}/{address}",
    name="Ghidra function bundle",
    title="Decompilation, documentation, callers and call-site context for one function",
    description="Everything about one function from a single decompilation: decompiled C, "
                "signature, plate and inline comments, parameters, locals, labels, callers "
                "with their actual call-site source lines, callees and xrefs. Replaces the "
                "decompile_function + get_function_variables + get_function_callers + "
                "get_comment + get_function_xrefs sequence.",
    mime_type=_JSON,
)
async def function_bundle_resource(program: str, address: str) -> str:
    program_name, addr = unquote(program), unquote(address)
    raw = await _read_async("/get_function_bundle", name=addr, program=program_name)
    payload = json.loads(raw)
    if isinstance(payload, dict):
        # Stamp the cache key onto the body so a client that only kept the text
        # still knows which URI to re-read after resources/updated.
        payload.setdefault("canonical_uri", canonical_function_uri(program_name, addr))
        return _json(payload)
    return raw


@mcp.resource(
    "ghidra://function/{program}/by-name/{name}",
    name="Ghidra function by name",
    description="Resolve a function name to its canonical address URI. Deliberately tiny: "
                "names change, so the address URI is what should be cached and read.",
    mime_type=_JSON,
)
async def function_by_name_resource(program: str, name: str) -> str:
    program_name, function_name = unquote(program), unquote(name)
    # /get_function_by_address's sole locator param is `address`, but
    # ServiceUtils.resolveFunction accepts a function name there too.
    raw = await _read_async(
        "/get_function_by_address", address=function_name, program=program_name
    )
    payload = json.loads(raw)
    address = payload.get("address") if isinstance(payload, dict) else None
    if not address:
        return _json({"name": function_name, "resolved": False, "detail": payload})
    return _json({
        "name": payload.get("name", function_name),
        "address": address,
        "resolved": True,
        "canonical_uri": canonical_function_uri(program_name, address),
    })


@mcp.resource(
    "ghidra://search/{program}/functions/{pattern}",
    name="Ghidra function search",
    description="Functions whose name matches a pattern, as {name, address, uri}. A "
                "filtered result set has no stable identity, so this is not cached against "
                "per-function invalidation — re-read it when the program changes.",
    mime_type=_JSON,
)
async def function_search_resource(program: str, pattern: str) -> str:
    program_name, needle = unquote(program), unquote(pattern)
    raw = await _read_async(
        "/search_functions", name_pattern=needle, program=program_name, limit=_MAX_SEARCH_HITS
    )
    payload = json.loads(raw)
    items = payload.get("functions", payload) if isinstance(payload, dict) else payload
    hits = []
    if isinstance(items, list):
        for item in items:
            fname, address = parse_function_hit(item)
            if not address:
                continue
            hits.append({
                "name": fname,
                "address": address,
                "uri": canonical_function_uri(program_name, address),
            })
    total = payload.get("total", len(hits)) if isinstance(payload, dict) else len(hits)
    return _json({
        "program": program_name,
        "pattern": needle,
        "matches": hits,
        "count": len(hits),
        "total": total,
        "truncated": bool(total and total > len(hits)),
    })


# ---------------------------------------------------------------------------
# Argument completion
# ---------------------------------------------------------------------------
# Templates are invisible in resources/list, so without completion an agent has to guess
# a URI. This is the main mitigation for resources being less discoverable than tools.
_COMPLETION_LIMIT = 40


@mcp.completion()
async def complete_resource_argument(ref, argument, context):
    """Offer candidate values for {program}, {name} and {pattern}."""
    from mcp.types import Completion, ResourceTemplateReference

    if not isinstance(ref, ResourceTemplateReference):
        return None
    try:
        if argument.name == "program":
            raw = await _read_async("/list_open_programs")
            payload = json.loads(raw)
            entries = payload if isinstance(payload, list) else payload.get("programs", [])
            names = [e.get("name") for e in entries if isinstance(e, dict) and e.get("name")]
            return Completion(values=_prefixed(names, argument.value))

        if argument.name in ("name", "pattern"):
            program = (context.arguments or {}).get("program") if context else None
            partial = argument.value or ""
            if not partial:
                return Completion(values=[])
            raw = await _read_async(
                "/search_functions",
                name_pattern=partial,
                program=unquote(program) if program else None,
                limit=_COMPLETION_LIMIT,
            )
            payload = json.loads(raw)
            items = payload.get("functions", payload) if isinstance(payload, dict) else payload
            names = []
            if isinstance(items, list):
                for item in items:
                    fname, _address = parse_function_hit(item)
                    if fname:
                        names.append(fname)
            return Completion(values=names[:_COMPLETION_LIMIT])
    except Exception as e:
        # Completion is a convenience; a failure here must never break the session.
        logger.debug("Resource completion for %r failed: %s", argument.name, e)
    return None


def _prefixed(values, partial):
    partial = (partial or "").lower()
    matches = [v for v in values if not partial or v.lower().startswith(partial)]
    return matches[:_COMPLETION_LIMIT]
