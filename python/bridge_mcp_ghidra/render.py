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

import re

_MAX_LOCALS = 80

# Ghidra's own naming, i.e. nobody has looked at this variable yet. The stack
# forms encode their own offset (local_f0 is Stack[-0xf0]), which is why an
# auto-named stack local adds nothing to what the declaration already said.
_AUTO_NAMED = re.compile(
    r"""^(
        local_[0-9a-fA-F]+          # local_f0
      | local_res[0-9a-fA-F]+       # positive-offset (caller frame) slot
      | [a-z]{0,3}Stack_[0-9a-fA-F]+  # auStack_110, uStack_120
      | [a-z]{1,4}Var\d+            # uVar1, pcVar5, puVar1
      | param_\d+                   # unnamed parameter
      | in_\w+                      # in_AL, in_FS_OFFSET (decompiler-invented)
      | extraout_\w+
      | unaff_\w+
    )$""",
    re.VERBOSE,
)


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


def _row(var: dict) -> str:
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
    return line


def _variables(bundle: dict) -> list[str]:
    """Parameters, and only the locals that say something the C does not.

    The decompiled code above already declares every local with its name and its
    type, so repeating all 48 of them is the single largest redundancy in a
    bundle. What the C text cannot carry is: which register a value lives in,
    the stack offset of a local that has been *renamed* away from Ghidra's
    offset-derived auto-name, and variables Ghidra knows about that the
    decompiler dropped. Those survive; the rest are counted, not listed.

    Parameters always survive — there are few of them and their storage is the
    calling convention, which is exactly what a wrong signature hides.
    """
    params = list(bundle.get("parameters") or [])
    locals_ = list(bundle.get("locals") or [])
    keep = [v for v in locals_ if _says_something(v)]
    omitted = len(locals_) - len(keep)
    rows = params + keep
    if not rows and not omitted:
        return []

    out = ["", "## Parameters and notable locals"]
    for var in rows[:_MAX_LOCALS]:
        out.append(_row(var))
    if len(rows) > _MAX_LOCALS:
        out.append(f"- … {len(rows) - _MAX_LOCALS} more")
    if omitted:
        out.append(f"- _{omitted} auto-named locals omitted — the declarations above "
                   "carry their names and types, and their stack offsets are in their names._")
    return out


def _says_something(var: dict) -> bool:
    """True when a local carries a fact the decompiled declarations do not.

    An auto-named local never does: the name IS the storage. ``local_f0`` is
    Stack[-0xf0]; ``in_AL``, ``extraout_EAX`` and ``unaff_EBX`` name their
    register; and ``uVar7``'s register is a register-allocation artifact nobody
    acts on. Rename it to ``bytesRead`` and the offset lives nowhere else — which
    is when the row starts earning its place.
    """
    if var.get("in_decompiled_code") is False:
        return True  # Ghidra knows it; the decompiler dropped it
    return not _AUTO_NAMED.match(var.get("name") or "")


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
