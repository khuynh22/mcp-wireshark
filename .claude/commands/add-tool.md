Scaffold a new MCP tool for this project following all project conventions.

Ask the user for:
1. **Tool name** (snake_case, e.g. `filter_goose`)
2. **Description** — one sentence, what does this tool do for an AI assistant?
3. **Read or write** — does this tool only read state (file analysis, listing, version
   checks) or does it capture traffic / write files? This decides which module the tool
   lives in.
4. **Parameters** — name, type, required/optional, description for each
5. **tshark command** — what tshark arguments will this run? (e.g. `-r $file -q -z follow,tcp,ascii,$stream_id`)

Then generate all four required changes in one response.

If **read** → add to `src/mcp_wireshark/read_tools.py`.
If **write** → add to `src/mcp_wireshark/write_tools.py`.

## Step 1 — Tool schema

Append a `Tool(...)` entry to the `READ_TOOLS` or `WRITE_TOOLS` list. Always include
`ToolAnnotations(...)`:

For read tools:
```python
annotations=ToolAnnotations(title="Human title", readOnlyHint=True, openWorldHint=False),
```

For write tools:
```python
annotations=ToolAnnotations(
    title="Human title",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
),
```

Use `"type": "number"` for numeric params, `"type": "string"` for strings. Mark
required params in the `"required"` array.

## Step 2 — Handler function

Place inside the same module (`read_tools.py` or `write_tools.py`). Follow this
exact pattern:

```python
async def handle_TOOL_NAME(arguments: dict[str, Any]) -> list[TextContent]:
    """One-line description."""
    file_path = arguments["file_path"]
    # ... extract other params with .get() for optional ones

    try:
        validated_path = validate_file_path(file_path)
        if not validated_path.exists():
            return [TextContent(type="text", text=f"Error: File not found: {file_path}")]
        file_path = str(validated_path)

        # validate display_filter if present
        # if display_filter:
        #     display_filter = validate_display_filter(display_filter)

        args = ["-r", file_path, ...]  # build tshark args
        output = await run_tshark(args, timeout=60)

        if output.strip():
            return [TextContent(type="text", text=f"Result:\n\n{output}")]
        return [TextContent(type="text", text="No results found.")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error in TOOL_NAME: {e}")]
```

Rules:
- Never use `shell=True`
- Always call `validate_file_path()` for file paths
- Always call `validate_display_filter()` for filter strings
- Limit packet output to 5 items max when returning JSON; always include a total count
- Prefer tshark `-q -z` statistics over raw packet JSON when the goal is summarization

## Step 3 — Register the handler

Add to the `READ_HANDLERS` or `WRITE_HANDLERS` dict at the bottom of the module:

```python
"TOOL_NAME": handle_TOOL_NAME,
```

The router in `server.py` does not need to change — it dispatches via dict lookup.

## Step 4 — Tests (tests/test_server.py)

Add at minimum:
1. A test for missing/nonexistent file → expects "not found" or "error" in response text
2. A test for the happy path (mock `run_tshark` to return sample output)
3. If the tool accepts a display filter, add an injection-attempt test

Import handlers from the new module path:
```python
from mcp_wireshark.read_tools import handle_TOOL_NAME    # for read tools
from mcp_wireshark.write_tools import handle_TOOL_NAME   # for write tools
```

## Step 5 — Update mcp.json

Add an entry to the `"tools"` array. Read tools go in the read group (top), write
tools at the bottom:
```json
{
  "name": "TOOL_NAME",
  "category": "read",        // or "write"
  "readOnly": true,          // or false
  "description": "Same one-sentence description as the Tool schema"
}
```

## Step 6 — Update README.md

Add a row to the **Read tools** table or **Write tools** table accordingly:
```markdown
| `TOOL_NAME` | Description |
```

After generating all changes, remind the user to run `/validate` before committing.
