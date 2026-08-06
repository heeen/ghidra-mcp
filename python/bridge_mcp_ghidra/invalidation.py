"""Write-triggered MCP resource invalidation.

After a mutating tool succeeds, figure out which resource URIs may have changed
and emit ``resources/updated`` (and ``resources/list_changed`` when a listing
row's label moved). Read-only tools return immediately.

Tier resolution for LOCAL and CALLERS is done here with existing Ghidra
endpoints; TYPE waits on ``/find_type_users`` (commit 7) and currently degrades
to the program's known URIs. UNBOUNDED always does that plus list_changed.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any

from . import dispatch
from . import state
from . import subscriptions
from .config import logger
from .resources import canonical_function_uri

# Cap per-write fan-out. Beyond this, a single list_changed is cheaper than a
# storm of updated notifications the client will re-list for anyway.
_MAX_URI_FANOUT = 64


class InvalidationTier(str, Enum):
    LOCAL = "local"          # the write's own target function
    CALLERS = "callers"      # target + functions that call it
    TYPE = "type"            # DataTypeReferenceFinder (stub → known URIs for now)
    UNBOUNDED = "unbounded"  # create/destroy functions or rewrite the program


# Every non-read-only tool path must appear here. The coverage test fails CI
# when a new write endpoint is added without a tier, so silent non-invalidation
# cannot ship.
ENDPOINT_TIER: dict[str, InvalidationTier] = {
    # --- LOCAL: body/docs of one function, callers' decompilations untouched ---
    "/set_comment": InvalidationTier.LOCAL,
    "/batch_set_comments": InvalidationTier.LOCAL,
    "/clear_function_comments": InvalidationTier.LOCAL,
    "/set_variables": InvalidationTier.LOCAL,
    "/rename_variables": InvalidationTier.LOCAL,
    "/set_variable_type": InvalidationTier.LOCAL,
    "/set_variable_storage": InvalidationTier.LOCAL,
    "/add_function_tag": InvalidationTier.LOCAL,
    "/remove_function_tag": InvalidationTier.LOCAL,
    "/set_function_tag_comment": InvalidationTier.LOCAL,
    "/apply_function_documentation": InvalidationTier.LOCAL,
    "/archive_ingest_function": InvalidationTier.LOCAL,
    "/batch_rename_function_components": InvalidationTier.LOCAL,
    "/clear_instruction_flow_override": InvalidationTier.LOCAL,
    "/add_memory_reference": InvalidationTier.LOCAL,
    "/remove_reference": InvalidationTier.LOCAL,
    # --- CALLERS: signature/name visible at call sites ---
    "/rename_function": InvalidationTier.CALLERS,
    "/rename_symbol": InvalidationTier.CALLERS,
    "/create_label": InvalidationTier.CALLERS,
    "/delete_label": InvalidationTier.CALLERS,
    "/set_function_prototype": InvalidationTier.CALLERS,
    "/set_function_this_type": InvalidationTier.CALLERS,
    "/set_function_no_return": InvalidationTier.CALLERS,
    "/apply_data_type": InvalidationTier.CALLERS,
    "/create_function": InvalidationTier.CALLERS,
    "/delete_function": InvalidationTier.CALLERS,
    "/create_function_tag": InvalidationTier.CALLERS,
    "/delete_function_tag": InvalidationTier.CALLERS,
    # --- TYPE: struct/enum/typedef edits (precise fan-out in commit 7) ---
    "/add_struct_field": InvalidationTier.TYPE,
    "/remove_struct_field": InvalidationTier.TYPE,
    "/modify_struct_field": InvalidationTier.TYPE,
    "/modify_struct_field_type": InvalidationTier.TYPE,
    "/embed_struct_field": InvalidationTier.TYPE,
    "/create_struct": InvalidationTier.TYPE,
    "/recreate_struct": InvalidationTier.TYPE,
    "/resize_struct": InvalidationTier.TYPE,
    "/create_enum": InvalidationTier.TYPE,
    "/create_typedef": InvalidationTier.TYPE,
    "/create_union": InvalidationTier.TYPE,
    "/create_array_type": InvalidationTier.TYPE,
    "/create_pointer_type": InvalidationTier.TYPE,
    "/create_function_signature": InvalidationTier.TYPE,
    "/create_data_type_category": InvalidationTier.TYPE,
    "/clone_data_type": InvalidationTier.TYPE,
    "/delete_data_type": InvalidationTier.TYPE,
    "/rename_data_type": InvalidationTier.TYPE,
    "/move_data_type_to_category": InvalidationTier.TYPE,
    "/import_data_types": InvalidationTier.TYPE,
    "/resolve_duplicate_type": InvalidationTier.TYPE,
    "/apply_data_classification": InvalidationTier.TYPE,
    "/set_global": InvalidationTier.TYPE,
    # --- UNBOUNDED: analysis, scripts, program lifecycle, project ops ---
    "/reanalyze": InvalidationTier.UNBOUNDED,
    "/run_analysis": InvalidationTier.UNBOUNDED,
    "/analyze_data_region": InvalidationTier.UNBOUNDED,
    "/detect_array_bounds": InvalidationTier.UNBOUNDED,
    "/run_ghidra_script": InvalidationTier.UNBOUNDED,
    "/run_script_inline": InvalidationTier.UNBOUNDED,
    "/disassemble_bytes": InvalidationTier.UNBOUNDED,
    "/clear_flow_and_repair": InvalidationTier.UNBOUNDED,
    "/set_image_base": InvalidationTier.UNBOUNDED,
    "/create_memory_block": InvalidationTier.UNBOUNDED,
    "/open_program": InvalidationTier.UNBOUNDED,
    "/close_program": InvalidationTier.UNBOUNDED,
    "/switch_program": InvalidationTier.UNBOUNDED,
    "/import_file": InvalidationTier.UNBOUNDED,
    "/save_program": InvalidationTier.UNBOUNDED,
    "/save_all_programs": InvalidationTier.UNBOUNDED,
    "/set_bookmark": InvalidationTier.UNBOUNDED,
    "/delete_bookmark": InvalidationTier.UNBOUNDED,
    "/set_program_option": InvalidationTier.UNBOUNDED,
    "/remove_program_option": InvalidationTier.UNBOUNDED,
    "/set_property": InvalidationTier.UNBOUNDED,
    "/remove_property": InvalidationTier.UNBOUNDED,
    "/create_property_map": InvalidationTier.UNBOUNDED,
    "/delete_property_map": InvalidationTier.UNBOUNDED,
    "/create_folder": InvalidationTier.UNBOUNDED,
    "/move_folder": InvalidationTier.UNBOUNDED,
    "/move_file": InvalidationTier.UNBOUNDED,
    "/delete_file": InvalidationTier.UNBOUNDED,
    "/archive_ingest_program": InvalidationTier.UNBOUNDED,
    "/merge_program_documentation": InvalidationTier.UNBOUNDED,
    "/create_project": InvalidationTier.UNBOUNDED,
    "/close_project": InvalidationTier.UNBOUNDED,
    "/restore_project": InvalidationTier.UNBOUNDED,
    "/archive_project": InvalidationTier.UNBOUNDED,
    "/open_project": InvalidationTier.UNBOUNDED,
    "/checkin_program": InvalidationTier.UNBOUNDED,
    "/export_program": InvalidationTier.UNBOUNDED,
    "/import_program": InvalidationTier.UNBOUNDED,
    "/load_program": InvalidationTier.UNBOUNDED,
    "/load_program_from_project": InvalidationTier.UNBOUNDED,
    "/prompt_policy": InvalidationTier.UNBOUNDED,
    "/debugger/launch": InvalidationTier.UNBOUNDED,
    "/debugger/set_breakpoint": InvalidationTier.UNBOUNDED,
    "/debugger/remove_breakpoint": InvalidationTier.UNBOUNDED,
    "/debugger/resume": InvalidationTier.UNBOUNDED,
    "/debugger/interrupt": InvalidationTier.UNBOUNDED,
    "/debugger/step_into": InvalidationTier.UNBOUNDED,
    "/debugger/step_over": InvalidationTier.UNBOUNDED,
    "/debugger/step_out": InvalidationTier.UNBOUNDED,
}


def after_successful_write(tool_def: dict, kwargs: dict, ctx, result: str) -> None:
    """Sync entry point from the registry hook — schedules async emit if needed.

    Called only after ``raise_on_failure`` has accepted ``result``. Read-only
    tools are a no-op so the read path pays nothing.
    """
    if tool_def.get("read_only"):
        return
    endpoint = tool_def.get("endpoint") or ""
    tier = ENDPOINT_TIER.get(endpoint)
    if tier is None:
        logger.debug("No invalidation tier for %s; skipping", endpoint)
        return
    # Remember the session so later emits (and the change-token poller) have a
    # place to send to, even if this write's fan-out is empty.
    if ctx is not None and getattr(ctx, "_request_context", None) is not None:
        try:
            state.remember_resource_interest(ctx.request_context.session)
        except Exception:
            pass

    related_id = None
    if ctx is not None and getattr(ctx, "_request_context", None) is not None:
        try:
            related_id = ctx.request_context.request_id
        except Exception:
            related_id = None

    # Resolution may hit Ghidra (CALLERS); keep it off the event loop.
    import asyncio

    async def _run() -> None:
        try:
            await _invalidate(endpoint, tier, kwargs, related_id)
        except Exception as e:
            logger.debug("Resource invalidation after %s failed: %s", endpoint, e)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(_run())


async def _invalidate(
    endpoint: str,
    tier: InvalidationTier,
    kwargs: dict,
    related_request_id,
) -> None:
    program = _program_name(kwargs)
    uris: set[str] = set()
    list_changed = False

    if tier is InvalidationTier.LOCAL:
        uris |= await _local_uris(program, kwargs)
    elif tier is InvalidationTier.CALLERS:
        uris |= await _local_uris(program, kwargs)
        uris |= await _caller_uris(program, kwargs)
        # Renames change the index row label and any by-name URI the client held.
        if endpoint in ("/rename_function", "/rename_symbol"):
            list_changed = True
            uris |= _by_name_uris(program, kwargs)
    elif tier is InvalidationTier.TYPE:
        # Precise fan-out via /find_type_users (DataTypeReferenceFinder, off EDT).
        # On timeout/error, degrade to the program's known URIs.
        type_uris = await _type_user_uris(program, kwargs)
        if type_uris is None:
            uris |= _known_uris_for_program(program)
            list_changed = True
        else:
            uris |= type_uris
            list_changed = True  # index rows may mention the type name indirectly
    else:  # UNBOUNDED
        uris |= _known_uris_for_program(program)
        list_changed = True

    # Always refresh the discovery root when the program set may have moved.
    if endpoint in ("/open_program", "/close_program", "/switch_program", "/import_file"):
        uris.add("ghidra://programs")
        list_changed = True

    uris = _intersect_with_interest(uris)
    if len(uris) > _MAX_URI_FANOUT:
        logger.debug(
            "Invalidation fan-out for %s is %d (>%d); collapsing to list_changed",
            endpoint, len(uris), _MAX_URI_FANOUT,
        )
        list_changed = True
        uris = set()

    for uri in sorted(uris):
        await subscriptions.emit_resource_updated(
            uri, related_request_id=related_request_id
        )
    if list_changed:
        await subscriptions.emit_resource_list_changed(
            related_request_id=related_request_id
        )


def _program_name(kwargs: dict) -> str | None:
    value = kwargs.get("program")
    if value is None or value == "":
        return None
    return str(value)


def _intersect_with_interest(uris: set[str]) -> set[str]:
    known = state.known_resource_uris()
    if not known:
        return set()
    return uris & known


def _known_uris_for_program(program: str | None) -> set[str]:
    known = state.known_resource_uris()
    if not program:
        return set(known)
    # Match both raw and percent-encoded program segments.
    from urllib.parse import quote
    markers = (f"/{program}/", f"/{quote(program, safe='')}/")
    return {u for u in known if any(m in u for m in markers) or u == "ghidra://programs"}


async def _local_uris(program: str | None, kwargs: dict) -> set[str]:
    addr = await _resolve_target_address(program, kwargs)
    if not addr or not program:
        # Without a program name we cannot build a canonical URI; the change
        # token poller (commit 8) will catch these coarse.
        if addr and program is None:
            return set()
        return set()
    return {canonical_function_uri(program, addr)}


def _by_name_uris(program: str | None, kwargs: dict) -> set[str]:
    if not program:
        return set()
    from urllib.parse import quote
    out: set[str] = set()
    for key in ("old_name", "new_name", "name", "symbol_name"):
        value = kwargs.get(key)
        if value:
            out.add(
                f"ghidra://function/{quote(program, safe='')}/by-name/{quote(str(value), safe='')}"
            )
    return out


async def _caller_uris(program: str | None, kwargs: dict) -> set[str]:
    if not program:
        return set()
    name = _first(kwargs, "old_name", "name", "function", "function_name")
    address = _first(
        kwargs, "function_address", "address", "entry", "entry_point"
    )
    params: dict[str, Any] = {"program": program, "limit": _MAX_URI_FANOUT}
    if address:
        params["address"] = address
    elif name:
        params["name"] = name
    else:
        return set()
    try:
        raw = await state.run_blocking_ghidra_call(
            lambda: dispatch.raise_on_failure(
                dispatch.dispatch_get("/get_function_callers", params=params)
            )
        )
        payload = json.loads(raw)
    except Exception as e:
        logger.debug("get_function_callers for invalidation failed: %s", e)
        return set()
    callers = payload.get("callers", []) if isinstance(payload, dict) else []
    uris: set[str] = set()
    if isinstance(callers, list):
        for item in callers:
            if not isinstance(item, dict):
                continue
            caddr = item.get("address")
            if caddr:
                uris.add(canonical_function_uri(program, str(caddr)))
    return uris


async def _type_user_uris(program: str | None, kwargs: dict) -> set[str] | None:
    """Return precise URIs for a TYPE-tier write, or None to degrade.

    ``None`` means the finder timed out / errored / could not resolve the type
    name from the write kwargs — the caller should fall back to known URIs.
    An empty set means the finder ran and found no users (nothing to invalidate).
    """
    type_name = _first(
        kwargs,
        "type_name",
        "name",
        "struct_name",
        "data_type",
        "datatype",
        "enum_name",
        "old_name",
    )
    if not type_name or not program:
        return None
    field = _first(kwargs, "field", "field_name", "member", "member_name")
    params: dict[str, Any] = {
        "type_name": type_name,
        "program": program,
        "timeout_seconds": 10,
    }
    if field:
        params["field"] = field
    try:
        raw = await state.run_blocking_ghidra_call(
            lambda: dispatch.raise_on_failure(
                dispatch.dispatch_get("/find_type_users", params=params)
            )
        )
        payload = json.loads(raw)
    except Exception as e:
        logger.debug("find_type_users for invalidation failed: %s", e)
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("timed_out"):
        logger.debug("find_type_users timed out for %s; degrading", type_name)
        return None
    functions = payload.get("functions", [])
    uris: set[str] = set()
    if isinstance(functions, list):
        for item in functions:
            if not isinstance(item, dict) or not item.get("address"):
                continue
            uris.add(canonical_function_uri(program, str(item["address"])))
    return uris


async def _resolve_target_address(program: str | None, kwargs: dict) -> str | None:
    """Best-effort entry point for the function a write touched."""
    direct = _first(
        kwargs,
        "function_address",
        "address",
        "entry",
        "entry_point",
    )
    name = _first(
        kwargs,
        "old_name",
        "function",
        "function_name",
        "name",
    )
    locator = direct or name
    if not locator:
        return None
    # Already looks like an address and get_function_by_address accepts names
    # too, so one call covers both. Prefer the resolved entry point so a
    # mid-function comment address still maps to the function's canonical URI.
    params: dict[str, Any] = {"address": locator}
    if program:
        params["program"] = program
    try:
        raw = await state.run_blocking_ghidra_call(
            lambda: dispatch.raise_on_failure(
                dispatch.dispatch_get("/get_function_by_address", params=params)
            )
        )
        payload = json.loads(raw)
        if isinstance(payload, dict) and payload.get("address"):
            return str(payload["address"])
    except Exception as e:
        logger.debug("resolve target for invalidation failed: %s", e)
    return str(direct) if direct else None


def _first(kwargs: dict, *keys: str) -> str | None:
    for key in keys:
        value = kwargs.get(key)
        if value is not None and value != "":
            return str(value)
    return None
