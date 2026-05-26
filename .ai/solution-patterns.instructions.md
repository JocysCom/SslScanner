# Solution Patterns — JocysCom/SslScanner

> Per-project declaration for the [`solution-patterns`](skills/solution-patterns/SKILL.md) skill. Overrides stack defaults when this repo's choices differ. Companion file: [`solution-patterns.csv`](solution-patterns.csv) (generated — never hand-edit).

## Detected stacks

| Stack | Evidence | Reason |
|---|---|---|
| `wpf` | `Tool/JocysCom.SslScanner.Tool.csproj` | `<UseWPF>true</UseWPF>` |
| `winforms` | `Tool/JocysCom.SslScanner.Tool.csproj` | `<UseWindowsForms>true</UseWindowsForms>` |

Single solution (`JocysCom.SslScanner.slnx`), single project (`Tool/JocysCom.SslScanner.Tool.csproj`), `WinExe` output targeting `net8.0-windows`. No test project exists.

## SSOT directions

No `sql-model`, `Code-First`, or `Database-First` correspondences apply — this project has no database, no migrations, no `.sqlproj`. All scan state is held in-memory and serialised to a single XML file beside the executable (`{exeName}.xml`) via `SettingsData<AppData>`. Persistence is therefore *generated from* the in-memory model; the model is canonical.

## Folder spine (this repo)

The folder hierarchy under `Tool/` is the single source of truth. Routes in this app are **menu-tab breadcrumbs**, not URLs — the equivalent of `ExpectedNavPath` for a `desktop-view` row in the CSV is a breadcrumb like `MainWindow > {TabHeader}`.

```
Tool/                                  Single .csproj root
├── App.xaml(.cs)                      Application bootstrap, DPI awareness
├── MainWindow.xaml(.cs)               Shell — TabControl with 4 tabs
├── Common/                            App-level domain code (no UI)
│   ├── AppData.cs                     Settings root
│   ├── DataItem.cs                    Per-row model
│   ├── DataItemType.cs                Tab enum
│   ├── Global.cs                      Static singleton accessor
│   ├── ScriptExecutor.cs              Per-row scan orchestrator (engine glue)
│   ├── Test_SSL_Support.cs            TLS probe (direct + STARTTLS)
│   └── ...
├── Controls/                          WPF UserControls bound to AppData
│   ├── AboutControl.xaml(.cs)         ← MainWindow > About
│   ├── DataListControl.xaml(.cs)      ← MainWindow > Certificates / Domains (reused, DataType property)
│   └── OptionsControl.xaml(.cs)       ← MainWindow > Options
├── Documents/                         Embedded resources (ChangeLog, License) + signing helper
├── JocysCom/                          Vendored JocysCom.ClassLibrary subset (treat as third-party source)
├── Properties/PublishProfiles/        win-x64 single-file publish profile
├── Resources/                         Embedded build artefacts + icon ResourceDictionary
└── ThirdParty/                        Vendored Whois.NET + IP range helpers (third-party source)
```

## Overrides

### `wpf`

- **`desktop_view_breadcrumb = MainWindow > {TabHeader}`** (single shell, four tabs)
  - **Why:** the app has one window. The "breadcrumb" is just `MainWindow > {TabHeader}` because the `TabControl` is the only navigation surface — there is no nested `TreeView`, ribbon, or pane hierarchy. Routes/REST endpoints do not apply.
  - **How to apply:** the four user-visible tabs are `Certificates`, `Domains`, `Options`, `About`. The first two both load `Controls/DataListControl` with a different `DataType` property (`Certificates` / `Domains`). Don't introduce a per-tab UserControl just to satisfy a 1:1 file-to-tab convention; that re-creates the duplication this design deliberately collapses.

- **`view_model_pattern = code-behind`** (no MVVM)
  - **Why:** The app is small. WPF code-behind binds straight to `Global.AppSettings.Certificates` / `Global.AppSettings.Domains`. There are no `*ViewModel.cs` files, no DI container, no `INotifyCommand`. Trying to introduce a "missing view-model" pattern would add ceremony without benefit at this scale.
  - **How to apply:** `*.xaml.cs` is the canonical companion for every `*.xaml`. There is no `ExpectedViewModelPath` to enforce.

- **`shared_lib_in_tree = Tool/JocysCom/`** (vendored JocysCom.ClassLibrary subset)
  - **Why:** the repo mirrors a curated subset of `JocysCom.ClassLibrary` source files via `Tool/JocysCom/MakeLinks_Ref.ps1` so the project can build standalone without a NuGet feed. These files are **not authored here** — they are a read-only mirror.
  - **How to apply:** never re-implement, refactor, or "clean up" anything under `Tool/JocysCom/`. Bug fixes and improvements belong upstream in `JocysCom.ClassLibrary` and propagate back via the link script. Treat the folder as third-party source for review purposes. The deviation report's `test-missing` rows for `Tool/JocysCom/Controls/*` are expected and should be ignored — those controls are tested in their owning library.

- **`third_party_source_in_tree = Tool/ThirdParty/`** (Whois.NET + IP range)
  - **Why:** `Tool/ThirdParty/WhoisClient.cs`, `WhoisResponse.cs`, and the `IPAddressRange` / `IPv4RangeOperator` / `IPv6RangeOperator` family are vendored third-party source from Whois.NET (and adjacent IP utilities).
  - **How to apply:** same rule as `Tool/JocysCom/` — do not modify, refactor, or substitute these with a `PackageReference`. If a fix is needed, propose it upstream first. Their `test-missing` deviation rows should be ignored.

### `winforms`

- **`winforms_role = interop-only`**
  - **Why:** `<UseWindowsForms>true</UseWindowsForms>` is set so the project can host WinForms-only primitives (e.g. dialogs, certain controls) inside the WPF shell. There are no `.Designer.cs` files or WinForms-first windows in the tree.
  - **How to apply:** do not introduce new `Form` classes. New UI belongs in WPF (`Controls/`).

## Test project absence

No `*.Tests.csproj` exists. The 20 `test-missing` rows in the deviation report are the natural consequence. The recommended path forward — when test coverage becomes desirable — is documented in `.ai/skills/qa-tester/SKILL.md` §5.2: add `Tool.Tests/` as a sibling project, mirror the folder structure under `Tool/`, and let the qa-tester `@under-test` headers link tests to their subjects. This is **not in scope** for the AI onboarding work item; record only.

## Generated artefacts

The following files in the working tree are generated, not hand-authored:

| Path | Generator | Trigger |
|---|---|---|
| `Tool/Resources/BuildDate.txt` | `Tool.csproj` PreBuild target (PowerShell) | Every build |
| `Tool/JocysCom/**` | `Tool/JocysCom/MakeLinks_Ref.ps1` | Manual, when refreshing the JocysCom.ClassLibrary mirror |
| `Tool/Resources/Icons/Icons_Default.xaml` | `Tool/Resources/Icons/Icons_Default.SVG_to_XAML.ps1` | Manual, when adding/updating SVG sources |
| `{exeName}.xml` (next to published .exe) | `SettingsData<AppData>.Save()` | First run / on close |
| `.github/copilot-instructions.md`, `.claude/skills/**`, `.agents/skills/**` | `.ai/skills/ai-self-improvement/scripts/sync_agent_assets.py` | Refresh from `.ai/` source of truth |

Hand-edits to any of these are flagged as `manual-edit-of-generated` and must be reverted (regenerate from the canonical source instead).

## Naming conventions in effect

- **Tab → UserControl:** the `Options` and `About` tabs each load a dedicated `*Control.xaml` named after the tab. The `Certificates` and `Domains` tabs share `DataListControl.xaml` with a `DataType` property switch — this is the only declared deviation from a 1:1 tab-to-control mapping, and it is intentional (see `desktop_view_breadcrumb` override).
- **`Common/`:** non-UI app-level code (settings, domain models, scan engine glue). New non-UI types go here unless they belong inside `JocysCom/` (shared-library mirror) or `ThirdParty/` (vendored).
- **`JocysCom/` vs `Common/`:** the `Tool/JocysCom/*` namespace prefix is reserved for the vendored library mirror. App-specific code uses the root `JocysCom.SslScanner.Tool` namespace and lives in `Common/`. Do not place app-specific code inside `JocysCom/` even if its sub-folder name (e.g. `Configuration/`, `Controls/`) seems to fit.
- **Companion rule:** every `*.xaml` has a sibling `*.xaml.cs` of the same base name in the same folder. No MVVM ViewModels (see `view_model_pattern = code-behind` override).

## Source Control Conventions

Inherited from `coding-guidelines.instructions.md` — `{CATEGORY}: {Description}` for issues; `{CATEGORY}-{issue#}-{lowercase-dashed-name}` for branches; `PR: #{issue#}: {CATEGORY}: {Description}` for PRs. Categories: `FEAT`, `FIX`, `TECH`, `DOCS`. Branches cut from `main` only.
