==== START OF INSTRUCTIONS FROM: coding-guidelines.instructions.md ====

# Instructions from: coding-guidelines.instructions.md

# Coding Guidelines

- If the qdrant-mcp-server is running, use it for all permanent memory operations (e.g. storing user information).
- After making changes, ALWAYS start a new server for testing.
- Kill all existing related servers from previous testing before starting a new server.
- Prefer the simplest viable solution; avoid over-engineering.
- Do not add broad try/catch or wrapper layers unless required by a failing test or explicit requirement; if you catch, rethrow to preserve the stack.
- Before writing new code, actively look for existing utilities or functions that can be reused instead of duplicated.
- New helper methods or classes must be justified with a clear, documented need for functionality that is unavailable elsewhere in the codebase.
- Always iterate on and reuse existing code instead of creating new implementations.
- Avoid adding layers of abstraction that do not deliver clear value.
- Do not drastically change established patterns before iterating on them.
- No duplication / SSOT: update or move existing code instead of adding parallel implementations. If you introduce a replacement, remove the old one **in the same change**.
- **Bidirectional simplification (two-way street)**: when refactoring two components that share a structural relationship (model ↔ schema, layout ↔ CSS, route ↔ controller, file ↔ folder, descriptor catalog ↔ generated form, data shape ↔ wire protocol, etc.), always consider adjusting **either** side to simplify the other — never treat one side as immutable. Full rule, layer enumeration, and the exception conditions live in the `solution-patterns` skill (§2 #2). Load that skill before any structural refactor.
- Write code that accounts for different environments (dev, test, and prod).
- Only modify what is explicitly requested or clearly necessary; do **not** create new files or modules unless explicitly requested.
- When fixing bugs, exhaust current implementations before introducing new patterns; if new methods are used, remove the old ones.
- Keep the codebase clean and organized.
- Avoid one-off scripts unless absolutely necessary.
- Use mocks only for tests, not for dev or prod.
- Never add stubbing or fake data in dev or prod environments.
- Never overwrite the .env file without explicit confirmation.
- Focus solely on areas relevant to the task; leave unrelated code untouched.
- Write thorough tests for all major functionality.
- Avoid major changes to the existing architecture unless explicitly instructed.
- Always consider the impact on other methods and areas of the code.
- Prefer to wrap long lines for better readability.
- Preserve existing formatting; limit formatting to lines you changed and match surrounding style. Also remove any unused imports/usings or dead code **introduced by your edits**.
- Stability primitives (repeatability > cleverness): when the repo provides an established way to perform an operation (repo-owned script, documented command snippet, standard PS1 under .ai/Scripts), treat it as the single source of truth. Use it verbatim instead of synthesizing “equivalent” commands. Only deviate when explicitly asked or when the primitive is proven broken in this environment (and then fix the primitive, not invent a parallel path).
- No code file that you **create or modify** may exceed **6000 tokens (~24 KB)** once your changes are applied.
  - If your changes alone would push the file past this limit, either trim the change or ask for explicit permission to refactor; do **not** alter unrelated code solely to meet the limit.
  - Existing oversized files are left untouched unless the user explicitly requests a refactor.

## Source Control Conventions

Naming conventions for issues, branches, and pull requests.

### Categories

| Category | Use for |
|----------|---------|
| `FEAT`   | New features |
| `FIX`    | Bug fixes |
| `TECH`   | Infrastructure, dependencies, refactoring |
| `DOCS`   | Documentation |

### Naming Patterns

| Item       | Pattern | Example |
|------------|---------|---------|
| **Issue**  | `{CATEGORY}: {Description}` | `FEAT: Download logs to CSV` |
| **Branch** | `{CATEGORY}-{issue#}-{lowercase-dashed-name}` | `FEAT-21-download-logs-to-csv` |
| **PR**     | `PR: #{issue#}: {CATEGORY}: {Description}` | `PR: #21: FEAT: Download logs to CSV` |

- Branch names: lowercase, words separated by dashes, non-ASCII replaced with a single dash, derived from issue title but may be shortened.
- PR body must reference the issue with `Closes #{issue#}`.
- Merge via PR only — no direct pushes to `main` or `master`.
- Feature branches are always created from `main` or `master`. Never merge one feature branch into another — only merge `main` if you need to catch up.
- Always create branches from latest origin/main or origin/main, never merge sub-branches, confirm before risky git ops.
- Do not add Co-Authored-By {AI model}/{AI company} lines to commits.
- Never close issues before a release is published with the fix.

Use the following guidelines:

1. Doc Comment Enhancement for IntelliSense

    - Replace or augment simple comments with relevant doc comment syntax that is supported by IntelliSense as needed.
    - Preserve the original intent and wording of existing comments wherever possible.

2. Code Layout for Clarity

    - Place the most important or user-editable sections at the top if logically appropriate.
    - Insert headings or separators within the code to clearly delineate where customizations or key logic sections can be adjusted.

3. No Extraneous Code Comments

    - Do not include "one-off" or user-directed commentary in the code.
    - Confine all clarifications or additional suggestions to explanations outside of the code snippet.
	- Comments must describe the current state of the code, not its history. No changelog-style comments ("changed from", "previously", "added/removed/fixed", dates, ticket refs).

4. Avoid Outdated or Deprecated Methods

    - Refrain from introducing or relying on obsolete or deprecated methods and libraries.
    - If the current code relies on potentially deprecated approaches, ask for clarification or provide viable, modern alternatives that align with best practices.

5. Testing and Validation

    - Suggest running unit tests or simulations on the modified segments to confirm that the changes fix the issue without impacting overall functionality.
    - Ensure that any proposed improvements, including doc comment upgrades, integrate seamlessly with the existing codebase.
    - After all code modifications, navigate to the affected project directory and build C# then Angular to confirm the application compiles without errors:
		cd {PROJECT} && dotnet build {PROJECT}.csproj
		cd {PROJECT}/ClientApp && ng build
    - Run relevant unit tests if code changes affect core logic.
    - If the developer certificate is not trusted, then execute: dotnet dev-certs https --trust
    - To launch project use: dotnet watch run --project {PROJECT}/{PROJECT}.csproj --launch-profile "{PROJECT} (NG Build)"

6. Rationale and Explanation

    - For every change (including comment conversions), provide a concise explanation detailing how the modification resolves the identified issue while preserving the original design and context.
    - Clearly highlight only the modifications made, ensuring that no previously validated progress is altered.
    - NOTE: Summarize reasoning for the user, but do NOT expose full chain-of-thought. Keep internal deliberations internal; surface only the concise rationale needed to justify each change.

7. Contextual Analysis

    - Use all available context—such as code history, inline documentation, style guidelines—to understand the intended functionality.
    - When inspecting an existing file for understanding, prefer reading the whole file in a
      single `read_file` call when it comfortably fits in context; switch to targeted slices
      only when the file is too large, the tool truncates it, or a specific anchor line is
      already known.
    - If the role or intent behind a code segment is ambiguous, ask for clarification rather than making assumptions.

8. Targeted, Incremental Changes

    - Identify and isolate only the problematic code segments (including places where IntelliSense doc comments can replace simple comments).
    - Provide minimal code snippets that address the issue without rewriting larger sections.
    - For each suggested code change, explicitly indicate the exact location in the code (e.g., by specifying the function name, class name, line number, or section heading) where the modification should be implemented.

9. Preservation of Context

    - Maintain all developer comments, annotations, and workarounds exactly as they appear, transforming them to doc comment format only when it improves IntelliSense support.
    - Do not modify or remove any non-code context unless explicitly instructed.
    - Avoid introducing new, irrelevant comments in the code.

10. Launching {PROJECT} Correctly:
    - Navigate to the {PROJECT} project folder.
    - Run the following command to launch the project with live reload and proper debugging configuration:
      dotnet watch run --launch-profile "{PROJECT} (NG Build)" --project {PROJECT}/{PROJECT}.csproj
    - This command will start the {PROJECT} project on the designated debugging session URL.
    - Ensure that any previous {PROJECT} instances are terminated before running this command.

==== END OF INSTRUCTIONS FROM: coding-guidelines.instructions.md ====

==== START OF INSTRUCTIONS FROM: coding.instructions.md ====

# Instructions from: coding.instructions.md

## Role

Your role is to analyze and improve code by making only localized, targeted changes. You must preserve all validated code, comments, and documented workarounds exactly as they appear. Your suggestions should strictly address only the specific issues identified—such as upgrading simple comments to doc comments for IntelliSense—without altering any surrounding context. Additionally, ensure that no obsolete or deprecated methods are introduced during the improvement process, and do not add extraneous comments that do not directly contribute to the code’s logic. Furthermore, ensure code snippets are clearly structured for readability, placing important or user-editable sections at the top when logical, and using clear separators or headings to highlight customization points.
Wherever beneficial, convert simple comments into recognized documentation comment syntax (e.g., JSDoc for JavaScript, XML comments for C#, JavaDoc for Java) that can be parsed by code intelligence tools like IntelliSense.
Maintain the original meaning of these comments, but structure them in a way that provides maximum benefit for automated tools and refactoring methods.
Apply chain-of-thought reasoning to identify code segments best served by doc comments, analyze the existing context of each comment, and then make precise, incremental modifications that enhance IntelliSense compatibility while preserving existing functionality.

## Output

Wrap any and all code—including regular code snippets, inline code segments, outputs, pseudocode, or any text that represents code—in Markdown code blocks with a language identifier (e.g., ```typescript, ```powershell).

==== END OF INSTRUCTIONS FROM: coding.instructions.md ====

==== START OF INSTRUCTIONS FROM: layout-guidelines.instructions.md ====

# Instructions from: layout-guidelines.instructions.md

# Layout Guidelines

> For the general bidirectional-simplification principle (markup ↔ CSS is one of several structural pairs it covers — alongside file ↔ folder, route ↔ controller, model ↔ schema), see the `solution-patterns` skill (§2 #2). The rules below are the markup ↔ CSS-specific tactics.

Use intrinsic, fluid, constraint-based layout design.

Prefer layouts that adapt naturally to available space, content, scaling, localization, and platform behavior.

Avoid fixed dimensions, absolute positioning, and pixel-perfect assumptions unless they are clearly necessary.

Use the platform or framework’s best layout primitives instead of manually positioning UI elements.

Prefer:
- natural sizing
- relative sizing
- minimum and maximum constraints
- wrapping and reflow
- shared spacing and sizing tokens
- adaptive layout features

Layouts must remain usable when windows, containers, text, scaling, DPI, or content change.

Use fixed values only for true constants, such as borders, icons, minimum hit targets, or platform-required measurements.

When choosing between a rigid layout and a flexible layout, choose the flexible layout unless there is a strong reason not to.

## Information density in tabular lists

Pack narrow columns on the left so a reader's eye can follow each row without crossing wide empty gutters. Wide free-text columns (descriptions, comments, multi-line notes) belong **at the right**, where they absorb the slack of the surrounding viewport. Narrow columns interleaved with a wide one in the middle of a row break visual continuity.

A reasonable default order:

1. Identifier (key or short code).
2. Inline state controls (toggles, badges).
3. Row action icons (edit, delete) at single-icon width.
4. Narrow data columns (codes, counts, statuses, dates).
5. One greedy / trailing column for the longest content, or an empty filler cell when nothing fits the role.

Never place a free-text column in the middle of a row.

## Simplicity is the goal — fix at the source

Every visual problem has a root cause. Find it before adding anything.

1. **Search for the rule that caused the visible defect** before writing CSS to mask it. A `width: 100%` somewhere upstream is fixed by deleting that rule, not by adding `width: auto !important` downstream. A `margin-bottom` on `[type=submit]` from the framework is fixed by overriding the same selector with the same specificity, not by wrapping the button in `<div style="margin-bottom: -10px">`.
2. **Reuse before invent.** If a list, panel, button, header, or row pattern already exists, every new instance uses the same class names — no `chat-session-list`, `link-picker-list`, `nav-item`, `help-doc-list` parallel implementations of the same concept. They share `.list-item`, `.surface`, `.panel-head`, `.icon-btn`, `.pill-toggle` primitives.
3. **Remove before add.** Refactoring CSS means *fewer* rules, not more. If a new component requires a new class, first ask whether the existing primitives + a small markup change cover it. They almost always do.
4. **Refactor BOTH layout and CSS together.** When a page demands a new visual, treat that as evidence the page is wrong, not the system. Adapt the page to the canonical pattern; reserve new CSS only for genuinely novel mechanics that no existing page would also benefit from.
5. **Match Pico's selector specificity** when overriding framework rules. A plain `button { ... }` rule (specificity 0,0,1) loses to Pico's `[type=submit] { ... }` (0,1,0). Override with the same selectors so the cascade naturally wins on file order.
6. **Auto-size before forcing a size.** A button with content + padding + border auto-sizes correctly in most cases. `width`, `height`, `min-height`, `min-width` are reserved for cases where content cannot drive the size (icon-only buttons that must be square, fixed-grid layouts).
7. **Drop framework anti-patterns at the source.** Pico's `[role=group]` triggers a connected-input-group visual (full-width children, cut adjoining corners). On any UI that wants individually rounded buttons, omit `role="group"` from the markup; an `aria-label` on the wrapper provides the screen-reader grouping without the visual cost.

==== END OF INSTRUCTIONS FROM: layout-guidelines.instructions.md ====

==== START OF INSTRUCTIONS FROM: secrets.instructions.md ====

# Instructions from: secrets.instructions.md

# Secret Handling Rules

## Never Read `.env` Files

Do NOT read, open, cat, or display `.env`, `.env.local`, `.env.keys`, or any dotenv file.
These files may contain plaintext secrets. Use `envManage.py` for all management operations.

## Never Execute Commands to Retrieve or Inspect Secret Values

Do NOT run terminal commands to read, print, or inspect secret values — not even masked ones.
This includes commands like `$env:OPENAI_API_KEY`, `echo $env:VAR`, `[Environment]::GetEnvironmentVariable(...)`, or any expression that would output a secret value into the terminal or a file.

## How Scripts and Code Must Reference Secrets

After `python envManage.py load`, secrets live in User/Process scope (Windows).
When **writing scripts or code**, reference secrets via `$env:VAR_NAME` / `[System.Environment]::GetEnvironmentVariable('VAR_NAME')` (PowerShell) or `os.environ['VAR_NAME']` (Python) — these expressions belong in code that passes secrets to APIs or tools, not in commands the AI runs itself.

## Never Log or Write Secret Values

Never include secret values in: log files, scripts, configs, docs, or git commits.

## Checking Whether a Variable Is Set (in Scripts)

```powershell
# Correct — test presence only, never log or compare the value itself
if (-not [string]::IsNullOrEmpty($env:OPENAI_API_KEY)) { ... }
```

To report back to the user whether a variable is set, say: "`OPENAI_API_KEY` is set (length: N)" — obtain the length via `$env:OPENAI_API_KEY.Length`, do not print the value.

## Script Pattern for Masked Display

Scripts (not the AI) may display a masked value to confirm a secret was loaded correctly.
Use the last few characters only — never the full value:

- Long secrets (name contains `KEY`, `TOKEN`, `PASS`, `CODE`, or `SECRET`, and value length > 32): **last 4 chars**
- All others: **last 2 chars**
- Empty values: show nothing

```powershell
function Get-MaskedValue([string]$Name, [string]$Value) {
    if ([string]::IsNullOrEmpty($Value)) { return '' }
    $isLongSecret = ($Name -match '(KEY|TOKEN|PASS|CODE|SECRET)') -and ($Value.Length -gt 32)
    $tailLen = if ($isLongSecret) { 4 } else { 2 }
    if ($Value.Length -le $tailLen) { return '****' }
    return '****' + $Value.Substring($Value.Length - $tailLen)
}

# Used inside scripts (e.g. Import-EnvFileVariables), not run by the AI directly:
Write-Host "OPENAI_API_KEY=$(Get-MaskedValue 'OPENAI_API_KEY' $env:OPENAI_API_KEY)"
# Output: OPENAI_API_KEY=****a3f9
```

## File Reference

| File | Purpose | Commit? |
|------|---------|---------|
| `.env` | Encrypted secrets (dotenvx) | Yes (encrypted only) |
| `.env.example` | Template with empty values | Yes |
| `.env.keys` | Decryption private key | **Never** |

## Managing Secrets

```
python envManage.py install      # install dotenvx
python envManage.py encrypt      # encrypt before committing
python envManage.py decrypt      # decrypt for local editing
python envManage.py load         # load into User + Process scope (Windows)
python envManage.py unload       # remove from User + Process scope (Windows)
python envManage.py list         # list variable names grouped by section
python envManage.py set-key -Group OpenAI -Key OPENAI_API_KEY
                                 # prompts for value via masked terminal input
python envManage.py remove-key -Key OPENAI_API_KEY
```

`set-key` and `remove-key` automatically refresh `.env.example` via `dotenvx ext genexample`.

==== END OF INSTRUCTIONS FROM: secrets.instructions.md ====
