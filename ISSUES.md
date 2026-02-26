# GhidraMCP Issues

## 1. ~~`run_ghidra_script` does not support passing script arguments~~ **FIXED**

**Fix**: Added `args` parameter to `run_ghidra_script` endpoint and Python bridge.
Args are passed via `script.setScriptArgs()` before execution, so `getScriptArgs()`
returns them instead of falling through to `askString()`.

---

## 2. ~~`run_script` cannot find scripts by path~~ **FIXED**

**Fix**: `runGhidraScript()` now auto-copies scripts from arbitrary paths to
`~/ghidra_scripts/` before execution, so Ghidra's OSGi class loader can find the
source bundle. The copy is cleaned up after execution.

---

## 3. ~~`save_ghidra_script` and `run_ghidra_script` use different directories~~ **FIXED**

**Fix**: `save_ghidra_script` and `list_ghidra_scripts` now use `~/ghidra_scripts/`
(via `os.path.expanduser("~")`) instead of a CWD-relative `ghidra_scripts/` path.
All script tools now agree on `~/ghidra_scripts/` as the canonical directory.

---

## 4. ~~`list_scripts` returns invalid output (Pydantic validation error)~~ **FIXED**

**Fix**: Changed `list_scripts` to use `safe_get_json()` (returns `str`) instead of
`safe_get()` (returns `list`), matching the `-> str` return type annotation.

---

## 5. `run_ghidra_script` blocks on GUI-prompting scripts with no timeout recovery

**Status**: Partially mitigated.

**Mitigation**: Issue #1 fix (args support) prevents the most common trigger — scripts
calling `askString()` / `askFile()` because they didn't receive arguments. With args
properly passed via `setScriptArgs()`, these scripts no longer fall through to GUI prompts.

**Remaining risk**: Scripts that unconditionally call `askString()` (ignoring args) or
use other interactive Ghidra APIs will still block. A full fix would require either:
- Running scripts on a separate thread with a timeout + `monitor.cancel()`
- Overriding `GhidraScript`'s ask methods to throw instead of showing dialogs

**Workaround**: Always pass args to scripts that expect input. If a dialog appears,
dismiss it manually in the Ghidra GUI.

---

## 6. `run_script_inline` previously wrote corrupted scripts (FIXED)

**Problem**: `parseJsonParams()` did not unescape JSON string escapes (`\n`, `\"`, `\\`),
so inline script code was written with literal backslash-n instead of newlines. Every
inline script failed Java compilation.

**Fix**: Added `unescapeJsonString()` to properly convert JSON escape sequences. Also:
- Inline scripts now use `_mcp_inline_` prefix to avoid collisions with user scripts
- Scripts are written to `~/ghidra_scripts/` (not `/tmp/`) for OSGi compatibility
- Cleanup deletes both `.java` and `.class` files, with `deleteOnExit()` fallback

---

## 7. ~~`bulk_fuzzy_match` returns list instead of string (Pydantic validation error)~~ **FIXED**

**Fix**: Changed `safe_get()` to `safe_get_json()` in `bridge_mcp_ghidra.py`.

**Problem**: `bulk_fuzzy_match()` returns a Python `list` but the Pydantic output model
expects `str`. This causes a validation error:

```
1 validation error for bulk_fuzzy_matchOutput
result
  Input should be a valid string [type=string_type, input_value=['{"source_program": "fir...}]}'], input_type=list
```

**Reproduction**: Any call to `bulk_fuzzy_match()` with two open programs fails:
```python
bulk_fuzzy_match("firmware_reconstructed.bin", "dongle_working_256k.bin", filter="named", threshold=0.7)
```

**Likely fix**: Same pattern as issue #4 — the endpoint function returns a `list` but needs
to return `str` (JSON string). Use `safe_get_json()` instead of `safe_get()`, or
`json.dumps()` the result before returning.

---

## 8. ~~`find_similar_functions_fuzzy` same list-vs-string validation error~~ **FIXED**

**Fix**: Changed `safe_get()` to `safe_get_json()` in `bridge_mcp_ghidra.py`.

**Problem**: Identical to issue #7 — `find_similar_functions_fuzzy()` returns a `list`
but Pydantic expects `str`.

```
1 validation error for find_similar_functions_fuzzyOutput
result
  Input should be a valid string [type=string_type, input_value=['{"source": {"name": "ve...es": 0, "matches": []}'], input_type=list
```

**Likely fix**: Same as #7 — wrap result with `json.dumps()` or use `safe_get_json()`.

---

## 9. `run_script_inline` OSGi class loading fails for complex scripts

**Status**: Open / intermittent.

**Problem**: Inline scripts that reference service classes (e.g., `ProgramManager`,
`ProjectDataService`) sometimes fail with OSGi `ClassNotFoundException` even though
the same code works fine when saved as a named script via `save_ghidra_script` +
`run_ghidra_script`.

```
GhidraScriptLoadException: The class could not be found.
_mcp_inline_CrossMatchByBytes not found by 38876517 [5]
```

**Workaround**: Save complex scripts with `save_ghidra_script` and run them with
`run_ghidra_script` instead of using `run_script_inline`.

**Likely cause**: The `_mcp_inline_` prefix or the temporary compilation context may
interfere with OSGi bundle resolution for imported packages.

---

## 10. Multi-program tools fail with "Endpoint not found: //switch_program"

**Status**: Open.

**Problem**: `switch_program`, `open_program`, `list_open_programs`, and
`get_current_program_info` all fail with double-slash path errors:

```
{"error": "Endpoint not found: //switch_program"}
{"error": "Endpoint not found: //list_open_programs"}
{"error": "Endpoint not found: //open_program"}
{"error": "Endpoint not found: //get_current_program_info"}
```

**Root cause**: `DEFAULT_GHIDRA_SERVER` is `"http://127.0.0.1:8089/"` (trailing `/`).
These tool functions construct URLs with f-strings:

```python
url = f"{ghidra_server_url}/switch_program"  # → http://127.0.0.1:8089//switch_program
```

In `make_request()`, the UDS path extracts `endpoint = urlparse(url).path` which yields
`//switch_program`. The Java `EndpointRouter` registers `/switch_program` (single slash)
and doesn't match.

Most other tools use `safe_get()` / `safe_post()` which call `urljoin()` and avoid this,
but the multi-program tools at lines 5514, 5574, 5639 use raw f-strings.

**Fix**: Either:
- Remove trailing `/` from `DEFAULT_GHIDRA_SERVER` (line 27)
- Or use `urljoin()` / `safe_get()` in the multi-program tools
- Or strip leading double slashes in `make_request()` before passing to UDS

**Impact**: All multi-program workflows are broken when using UDS transport — cannot switch
between programs, cannot list open programs, cannot open programs from the project.

---

## 11. `save_program` fails with "Unable to lock due to active transaction"

**Status**: Open.

**Problem**: `save_program` returns `{"error": "Unable to lock due to active transaction"}`
when called after script execution or bulk operations that leave an auto-analysis transaction
open. The Ghidra program's domain object lock cannot be acquired while a transaction is active.

**Reproduction**: Run any script that modifies the program (e.g., `ImportSDKHeaders`,
`batch_create_labels`), then immediately call `save_program`.

**Workaround**: Let Ghidra auto-save on program close, or wait for auto-analysis to complete
before calling `save_program`.

**Likely fix**: The Java plugin's `save_program` endpoint should wait for active transactions
to complete (with a timeout) before attempting to save, or queue the save for after the
current transaction ends.
