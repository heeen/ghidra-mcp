"""Render a function bundle as Markdown instead of JSON-inside-JSON.

A ``resources/read`` result carries its body in a JSON *string*, so a JSON body
arrives at the model doubly escaped: every key quoted and re-quoted, every line
of decompiled C as a literal ``\\n``. Measured on one real bundle, all fields
present, counting the bytes as they reach the model:

    JSON, indent=2   18,233 chars   2,746 quote/backslash chars
    JSON, compact    15,026 chars   2,336
    Markdown         10,131 chars     336

56% of the payload for the same facts, and 8x fewer escapes, because the code
sits in a fence with one level of escaping rather than two.

The **tool** ``/get_function_bundle`` still answers JSON — that is the machine
contract, it is in ``/mcp/schema`` and ``tests/endpoints.json``, and anything
parsing it keeps working. This rendering is only for the resource read, whose
sole consumer is a model reading prose.
"""

from __future__ import annotations

_MAX_LOCALS = 80


def _fence(code: str, lang: str = "c") -> list[str]:
    return [f"```{lang}", code.rstrip(), "```"]


def _kv_line(bundle: dict) -> list[str]:
    out = [f"# {bundle.get('name', '?')}  `{bundle.get('address', '?')}`"]
    program = bundle.get("program")
    if program:
        out[0] += f"  ({program})"
    signature = bundle.get("signature")
    if signature:
        out.append(f"signature: `{signature}`")
    bits = []
    if bundle.get("classification"):
        bits.append(f"classification: {bundle['classification']}")
    revision = bundle.get("revision") or {}
    if revision.get("modification_number") is not None:
        bits.append(f"modification_number: {revision['modification_number']}")
    if bits:
        out.append(" · ".join(bits))
    # A wrong return type silently poisons every caller's reading of the code,
    # so the warning goes above the fold rather than into a field nobody reads.
    if bundle.get("return_type") and not bundle.get("return_type_resolved", True):
        out.append(f"> ⚠ return type `{bundle['return_type']}` is unresolved — "
                   "verify the return register at RET; do not trust a decompiler 'void'.")
    return out


def _variables(bundle: dict) -> list[str]:
    rows = list(bundle.get("parameters") or []) + list(bundle.get("locals") or [])
    if not rows:
        return []
    out = ["", f"## Parameters and locals ({len(rows)})"]
    for var in rows[:_MAX_LOCALS]:
        line = f"- `{var.get('name')}` : {var.get('type')}"
        if var.get("storage"):
            line += f" @ {var['storage']}"
        notes = []
        if var.get("is_phantom"):
            notes.append("phantom")
        if var.get("in_decompiled_code") is False:
            notes.append("not in decompiled code")
        if notes:
            line += f"  ({', '.join(notes)})"
        out.append(line)
    if len(rows) > _MAX_LOCALS:
        out.append(f"- … {len(rows) - _MAX_LOCALS} more")
    return out


def _call_context(bundle: dict) -> list[str]:
    sites = bundle.get("call_context") or []
    if not sites:
        return []
    out = ["", "## Call context — who calls this, and how"]
    for site in sites:
        head = f"- **{site.get('caller')}** `{site.get('caller_address')}`"
        if site.get("site_address"):
            head += f" · call site `{site['site_address']}`"
        out.append(head)
        text = site.get("text")
        if text:
            # The window is several physical lines and each one needs the list
            # indent, so this cannot go through _fence's single-string form.
            out.append("  ```c")
            out.extend("  " + line for line in text.splitlines())
            out.append("  ```")
    return out


def _named_addresses(title: str, rows, count=None) -> list[str]:
    rows = rows or []
    if not rows and count in (None, 0):
        return []
    heading = f"## {title}" + (f" ({count})" if count is not None else f" ({len(rows)})")
    out = ["", heading]
    out.extend(f"- {row.get('name')} `{row.get('address')}`" for row in rows)
    if count is not None and count > len(rows):
        out.append(f"- … {count - len(rows)} more")
    return out


def function_bundle_markdown(bundle: dict) -> str:
    """Render ``/get_function_bundle``'s JSON as Markdown."""
    out = _kv_line(bundle)

    code = bundle.get("decompiled_code")
    if code:
        out += ["", "## Decompiled"] + _fence(code)
    elif bundle.get("decompile_failed"):
        out += ["", "## Decompiled", "_Decompilation failed._"]
    if bundle.get("decompiled_code_note"):
        out.append(f"_{bundle['decompiled_code_note']}_")

    plate = bundle.get("plate_comment")
    if plate:
        out += ["", "## Plate comment", plate]
    for issue in bundle.get("plate_comment_issues") or []:
        out.append(f"- ⚠ {issue}")

    comments = [c for c in (bundle.get("comments") or []) if c.get("kind") != "plate"]
    if comments:
        out += ["", "## Inline comments"]
        for c in comments:
            offset = c.get("relative_offset")
            where = f"+{offset:#x}" if isinstance(offset, int) else c.get("address", "?")
            out.append(f"- `{where}` {c.get('kind')}: {c.get('text')}")

    out += _variables(bundle)

    labels = bundle.get("labels") or []
    if labels:
        out += ["", f"## Labels ({len(labels)})"]
        for label in labels:
            offset = label.get("relative_offset")
            where = f"+{offset:#x}" if isinstance(offset, int) else label.get("address", "?")
            out.append(f"- {label.get('name')} `{where}` ({label.get('source')})")

    out += _call_context(bundle)
    out += _named_addresses("Callers", bundle.get("callers"), bundle.get("caller_count"))
    out += _named_addresses("Callees", bundle.get("callees"), bundle.get("callee_count"))

    xrefs = bundle.get("xrefs") or []
    if xrefs:
        out += ["", f"## Xrefs ({len(xrefs)})"]
        for xref in xrefs:
            line = f"- `{xref.get('from')}` {xref.get('type')}"
            if xref.get("from_function"):
                line += f" in {xref['from_function']}"
            out.append(line)

    if bundle.get("disassembly"):
        out += ["", "## Disassembly"] + _fence(
            "\n".join(
                f"{i.get('address')}  {i.get('mnemonic', '')} {i.get('operands', '')}".rstrip()
                for i in bundle["disassembly"]
            ),
            "asm",
        )

    truncated = [k for k, v in (bundle.get("truncation") or {}).items() if v]
    if truncated:
        out += ["", f"_Truncated sections: {', '.join(sorted(truncated))}._"]

    # The URI is the cache key: a client that kept only this text still knows
    # what to re-read when resources/updated names it.
    if bundle.get("canonical_uri"):
        out += ["", f"_Resource: {bundle['canonical_uri']}_"]
    return "\n".join(out) + "\n"
