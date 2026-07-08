# parsec-impl Skill

A structured workflow for planning and implementing new features or large
changes in parsec. Gathers JIRA context, acceptance criteria, and external
references, then produces a comprehensive implementation plan aligned with
parsec conventions.

## Setup

This skill works with both **Cursor** and **Claude CLI (Claude Code)**.

### Cursor

The skill is automatically available to anyone cloning the repo — no extra
setup needed beyond MCP configuration.

**Invoke with**: `@parsec-impl` in chat.

### Claude CLI (Claude Code)

The skill is symlinked at `.claude/skills/parsec-impl` in the repo (pointing
to `.cursor/skills/parsec-impl`). If you clone the repo after this is merged,
it works out of the box — no extra setup needed.

**Invoke with**: `/parsec-impl` in an interactive session, or:

```bash
claude "/parsec-impl plan for KESSEL-123"
```

#### Manual setup (if the symlink is missing or you prefer a copy)

If you don't see `.claude/skills/parsec-impl` after cloning, or if skill
discovery isn't working, set it up manually:

```bash
# Option A: Create the symlink yourself (recommended — single source of truth)
mkdir -p .claude/skills
ln -s ../../.cursor/skills/parsec-impl .claude/skills/parsec-impl

# Option B: Copy the skill folder (works if symlinks cause issues on your OS)
mkdir -p .claude/skills
cp -r .cursor/skills/parsec-impl .claude/skills/parsec-impl
```

You can also reference the skill directly without `/parsec-impl` by pasting
the skill file path into your prompt:

```bash
claude "Read .cursor/skills/parsec-impl/SKILL.md and follow it for KESSEL-123"
```

---

## MCP Configuration

Both Cursor and Claude CLI need the Atlassian MCP for JIRA/Confluence access.

### Cursor

1. Open **Cursor Settings > MCP**
2. Add `Atlassian-MCP-Server` (e.g. `@anthropic/atlassian-mcp-server`)
3. Authenticate when prompted

### Claude CLI

Create or update `.mcp.json` in the repo root:

```json
{
  "mcpServers": {
    "atlassian": {
      "command": "npx",
      "args": ["-y", "@anthropic/atlassian-mcp-server"]
    }
  }
}
```

Or add to `~/.claude/settings.json` under `mcpServers` for all projects.

---

## Google Docs Access (Optional)

Three options, tried in order:

1. **GWS CLI/SDK** — Works in both Cursor and Claude CLI via shell:
   ```bash
   pip install gws-cli
   gws auth login
   ```

2. **Google Drive MCP** — Add via Cursor Settings > MCP, or in `.mcp.json`:
   ```json
   {
     "mcpServers": {
       "google-drive": {
         "command": "npx",
         "args": ["-y", "@anthropic/google-drive-mcp"]
       }
     }
   }
   ```

3. **Manual paste** — Always works as a fallback.

See [mcp-setup-guide.md](mcp-setup-guide.md) for detailed instructions.

---

## Compatibility Notes

| Feature | Cursor | Claude CLI |
|---------|--------|------------|
| Skill discovery | `.cursor/skills/` | `.claude/skills/` (symlinked) |
| Invocation | `@parsec-impl` | `/parsec-impl` |
| JIRA MCP config | Cursor Settings > MCP | `.mcp.json` or `~/.claude/settings.json` |
| `AskQuestion` (structured prompts) | Native | Falls back to conversational prompts |
| `SwitchMode` (Agent/Plan mode) | Native | Not applicable — proceeds without |
| GWS CLI for Google Docs | Shell tool | Shell tool |
| Plan file output | `docs/impl-plans/` | `docs/impl-plans/` |

The skill degrades gracefully — when Cursor-specific tools (`AskQuestion`,
`SwitchMode`) are unavailable, the agent uses conversational equivalents.

## Quick Reference

| Action | Cursor | Claude CLI |
|--------|--------|------------|
| Start a new plan | `@parsec-impl` or `@parsec-impl KESSEL-123` | `/parsec-impl` or `/parsec-impl KESSEL-123` |
| Iterate on plan | `@parsec-impl iterate` | `/parsec-impl iterate` |
| Update a section | `@parsec-impl update` | `/parsec-impl update` |
| Scrap and restart | `@parsec-impl scrap` | `/parsec-impl scrap` |
| Delete the plan | `@parsec-impl delete` | `/parsec-impl delete` |
| Execute the plan | `@parsec-impl execute` | `/parsec-impl execute` |
