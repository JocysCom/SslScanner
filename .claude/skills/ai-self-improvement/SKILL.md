---
name: ai-self-improvement
description: Update, create, improve, and synchronise this repository's AI agent instructions and related assets (including skills). Use when the user asks to create or edit a skill/SKILL.md, modify the agent's own instructions/processes, restructure instruction governance, migrate instruction content into skills, or run/adjust the sync pipeline that publishes `.ai/` sources into agent-specific folders. Load this skill before writing any SKILL.md, .instructions.md, or touching any skills/ folder (.ai/, .claude/, .roo/, .github/). It tells you the correct location (.ai/) and the sync step, so files end up in the right place.
---

# AI Self-Improvement (Instructions + Skills + Agents)

## Critical: `.ai/` is the Primary Source for ALL Agents

The `.ai/` folder is the **single source of truth** for all AI agent configurations in this repository. Agent definitions are stored in `agents.json` and the sync script propagates changes automatically.

### What gets synced

| Asset | Source | Scope | Description |
|-------|--------|-------|-------------|
| Instructions | `.ai/*instructions.md` | Project | Agent rules and guidelines |
| Skills | `.ai/skills/` | Project | Reusable skill definitions |
| Custom agents | `.ai/agents/` | Project | Agent prompt templates for this repository |
| Global agents | `.ai/.global/agents/` | User | Agent prompt templates for ALL repositories (synced with `-Global` flag) |

### Agent configuration (`agents.json`)

The file `agents.json` (next to this SKILL.md) defines each agent's sync targets:

| Agent | Instructions | Skills | Project Agents | Global Agents | Shared `.agents/` |
|-------|-------------|--------|----------------|---------------|-------------------|
| **Cline** | `.clinerules/` (multiple) | — | — | — | ❌ |
| **Roo Code** ⚠️ sunset 2026-05-15 | `.roo/rules/` (multiple) | `.roo/skills/` | `.roomodes` (JSON) | `{AppData}/.../custom_modes.yaml` (JSON) | ✅ skills (project + user) |
| **GitHub Copilot** | `.github/copilot-instructions.md` (single) | `.github/skills/` | `.github/agents/` | — | ✅ skills (project + user) |
| **OpenAI Codex** | `AGENTS.md` (single) | — | — | — | ✅ skills (project + user) |
| **Claude Code** | `.claude/` (multiple) | `.claude/skills/` | `.claude/commands/` | `~/.claude/commands/` | ❌ |
| **Kilo Code** | `.kilo/rules/` (multiple) | `.kilo/skills/` | `.kilo/agents/` | `~/.config/kilo/agent/` | ✅ skills (project + user) |
| **Gemini CLI** | `GEMINI.md` (single) | `.gemini/skills/` | `.gemini/agents/` | `~/.gemini/agents/` | ✅ skills (project + user) |

### Path arrays — primary + obsolete

`skills` and `globalSkills` in `agents.json` are **ordered arrays**:

- **Position 0** is the PRIMARY target. The sync script mirrors only there.
- **Positions 1+** are OBSOLETE alternatives the agent may still read. The script does not write to them, but it scans for them after each sync and reports any that still exist on disk so you can clean them up.

Multiple agents may declare the same primary path (e.g. Roo Code, Kilo Code, Codex, Copilot, and Gemini all share `.agents/skills`). The script deduplicates so each unique target is mirrored once.

**Migration is just rearranging the array.** When a vendor adopts the universal `.agents/` convention, prepend the new path:

```jsonc
// Before — Claude Code only reads its own folder
"skills": [".claude/skills"]

// After — Claude added .agents/skills support; promote to primary
"skills": [".agents/skills", ".claude/skills"]
```

The next sync will mirror to `.agents/skills` and report `.claude/skills` as obsolete (delete when ready).

### Universal `.agents/` folder

Several modern agents read skills from a shared `.agents/skills/` (project) and `~/.agents/skills/` (user) — Codex CLI, GitHub Copilot, Roo Code, Kilo Code, Gemini CLI, OpenCode, Antigravity. To opt an agent in, just put `.agents/skills` at position 0 of its `skills` array.

Cline and Claude Code do **not** currently support the `.agents/` convention — they keep using their own paths. Instructions are not synced into `.agents/` because the universal convention there is `AGENTS.md` (or `GEMINI.md`) at the repository root, already covered by the Codex/Gemini single-file targets. MCP servers are tracked per-agent in `agents.json` for reference only — MCP sync is not performed by this script.

**IMPORTANT:** When asked to modify skills, instructions, or custom agents, you MUST:

1. Locate the source file under `.ai/` (not the agent-specific output)
2. Make changes to the `.ai/` source
3. Run the sync script to propagate changes to all agents

### Custom agents format

Source files in `.ai/agents/` use YAML frontmatter + markdown body. The frontmatter captures metadata for all platforms, and the sync script transforms to each platform's native format:

- **GitHub Copilot** — synced directly to `.github/agents/` (native Copilot agent format)
- **Claude Code** — synced to `.claude/commands/` (Claude uses the full file as a slash command)
- **Roo Code** — transformed into `.roomodes` JSON (maps `name` → `name`, `description` → `roleDefinition`, body → `customInstructions`, `groups` → `groups`)

```yaml
---
name: Repository Analyze and Sync
description: Regenerate the architecture map and sync changes to all agents.
tools: ["search", "edit", "runCommands"]
groups: ["read", "edit", "command"]
---

Prompt instructions here...
```

| Field | Copilot | Claude | Roo Code |
|-------|---------|--------|----------|
| `name` | Agent display name | — | Mode display name |
| `description` | Agent description | — | `roleDefinition` |
| `tools` | Tool access list | — | — |
| `groups` | — | — | Permission groups (`read`, `edit`, `command`, `mcp`) |
| Body | Agent instructions | Slash command prompt | `customInstructions` |

## Path Mapping Reference

When you encounter a path in an agent-specific folder, map it to `.ai/`:

| Agent-Specific Path | Source Path (Edit Here) |
|---------------------|------------------------|
| `.roo/rules/*.md` | `.ai/*.instructions.md` |
| `.roo/skills/<name>/SKILL.md` | `.ai/skills/<name>/SKILL.md` |
| `.github/copilot-instructions.md` | `.ai/instructions.md` (generated) |
| `.github/agents/<name>.md` | `.ai/agents/<name>.md` |
| `AGENTS.md` | `.ai/instructions.md` (generated) |
| `.claude/*.instructions.md` | `.ai/*.instructions.md` |
| `.claude/skills/<name>/SKILL.md` | `.ai/skills/<name>/SKILL.md` |
| `.claude/commands/<name>.md` | `.ai/agents/<name>.md` |
| `.agents/skills/<name>/SKILL.md` | `.ai/skills/<name>/SKILL.md` |
| `~/.agents/skills/<name>/SKILL.md` | `.ai/.global/skills/<name>/SKILL.md` |
| `.kilo/rules/*.md` | `.ai/*.instructions.md` |
| `.kilo/skills/<name>/SKILL.md` | `.ai/skills/<name>/SKILL.md` |
| `.kilo/agents/<name>.md` | `.ai/agents/<name>.md` |
| `GEMINI.md` | `.ai/instructions.md` (generated, single-file like AGENTS.md) |
| `.gemini/skills/<name>/SKILL.md` | `.ai/skills/<name>/SKILL.md` |
| `.gemini/agents/<name>.md` | `.ai/agents/<name>.md` |

**Example:** If asked to update `.roo/skills/ai-self-improvement/SKILL.md`, you must edit `.ai/skills/ai-self-improvement/SKILL.md` instead.

## Editable files (sources of truth)

- `.ai/instructions.md` — the main system instructions file
- `.ai/*instructions.md` — additional instruction files (auto-included)
- `.ai/*instructions-detail.md` — detailed instruction files (read only when needed)
- `.ai/skills/<name>/SKILL.md` — skill definition files
- `.ai/agents/<name>.md` — project-level agent prompt templates
- `.ai/.global/agents/<name>.md` — global agent prompt templates (all repositories)

## Workflow

1. Treat `.ai/` as the **single source of truth** for agent instructions, skills, and custom agents.
2. When creating or migrating a skill, create/update it under `.ai/skills/`.
3. When creating a custom agent, create it under `.ai/agents/` using YAML frontmatter + markdown.
4. Make instruction changes in `.ai/instructions.md` and related `*.instructions.md` files.
5. Do **not** edit generated outputs directly (they are produced by the sync script):
   - `.roo/rules/`, `.roo/skills/`
   - `.github/copilot-instructions.md`, `.github/skills/`, `.github/agents/`
   - `AGENTS.md`, `GEMINI.md`
   - `.claude/*.instructions.md`, `.claude/skills/`, `.claude/commands/`
   - `.kilo/rules/`, `.kilo/skills/`, `.kilo/agents/`
   - `.gemini/skills/`, `.gemini/agents/`
   - `.agents/skills/`, `~/.agents/skills/` (universal convention)
6. **Test changes before syncing** — verify scripts execute correctly and changes work as expected.
7. After testing, run the sync script to apply to all agents.

## Testing Before Sync

Before running the sync script, always verify your changes work correctly:

- **For script changes**: Execute the modified script and verify output is correct
- **For instruction changes**: Review the markdown renders properly and instructions are clear
- **For skill changes**: Test any bundled tools or scripts included in the skill

## Activation process

After editing instruction files, skills, or custom agents, run from repository root. The script is cross-platform (Windows, macOS, Linux) and requires Python 3.8+.

```bash
# Project-level sync (default — safe)
python .ai/skills/ai-self-improvement/scripts/sync_agent_assets.py AUTO

# Include global agents (affects ALL repositories — use carefully)
python .ai/skills/ai-self-improvement/scripts/sync_agent_assets.py AUTO --global
```

On Windows, `python` may need to be `py` or `python3` depending on how Python is installed.

### Sync modes

| Mode | Description |
|------|-------------|
| `AUTO` | Update only agents detected in this repository (default) |
| `ALL` | Update all known agent outputs |
| Agent name | Update a specific agent (e.g. `"Claude Code"`, `roo-code`) |
| `--global` | Also sync `.ai/.global/agents/` to user-level paths (off by default) |
| `--cleanup-obsolete` | After sync, prompt to delete legacy folders flagged as obsolete in `agents.json` (positions 1+ of `skills`/`globalSkills` arrays). Safe — y/N confirmation required. |
| `--no-clear` | Do not clear the console on start; also skips the 4-second exit pause (signals scripted/piped use). |

When invoked without arguments, the menu offers: AUTO, AUTO + Global, Cleanup (option 3), then numbered entries for each agent. `ALL` / `ALL + Global` are still supported as CLI parameters but no longer in the menu — they were rarely used.

### Menu indicators

- **Bold green name** — agent is *detected* in this repository (its signature folder or instructions target exists on disk).
- **`[supported]` suffix** — agent is *fully `.agents/`-compatible*, meaning every one of its outputs lands under `.agents/` (or — for single-file outputs only — at the repository root). Such an agent needs **no agent-specific folder**. Currently only **OpenAI Codex** qualifies (`AGENTS.md` + `.agents/skills/`). The flag is computed from `agents.json`, so any other agent automatically lights up the moment its config is rewritten to drop agent-specific paths.

### Detection and stale-file behavior

- **Empty folders count as enabled.** AUTO detection treats an agent as enabled when its target folder exists at the repository root, even if it is empty. Wiping the contents of `.roo/rules/`, `.clinerules/`, or `.claude/` does not disable the agent — the next sync repopulates it. For single-file agents (Codex, Copilot), the file or its companion folder counts.
- **Stale instruction files are removed before copy.** Before copying instructions, the script deletes any `*instructions.md` files in the target folder that are not present in `.ai/`. Renaming or removing a source file removes the matching target file on the next sync, instead of leaving a stale copy behind.

## Single source of truth

**Never embed template content in instructions — reference template files instead.**

- "Template maintained in `pr/checklist.template.md`"
- Do not paste template content into instructions

## Bundled files

- Agent config: `.ai/skills/ai-self-improvement/agents.json`
- Sync script (Python, cross-platform): `.ai/skills/ai-self-improvement/scripts/sync_agent_assets.py`
