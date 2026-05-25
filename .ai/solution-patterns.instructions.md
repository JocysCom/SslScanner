---
applyTo: '**'
---

# Solution Patterns — declared for this repo

This file is the single declarative source for **Code ↔ UI ↔ Test** path conventions in the SslScanner repository. Stack defaults that ship with the `solution-patterns` skill apply unless an **Override** below says otherwise. The generated catalogue lives at [`solution-patterns.csv`](solution-patterns.csv); do **not** hand-edit the CSV — re-run `pattern_map.py` instead.

## Detected stacks

Auto-detected by [`scripts/detect_stack.py`](skills/solution-patterns/scripts/detect_stack.py):

- **wpf** — from `Tool/JocysCom.SslScanner.Tool.csproj` (`<UseWPF>true</UseWPF>`)
- **winforms** — from `Tool/JocysCom.SslScanner.Tool.csproj` (`<UseWindowsForms>true</UseWindowsForms>`)

The application is **primarily WPF**; WinForms is enabled only because the vendored `JocysCom.ClassLibrary.Controls.ControlsHelper.WPF.UseWindowsForms.cs` interop bridge needs it. Treat the `wpf` patterns from [`skills/solution-patterns/references/wpf-winui-patterns.md`](skills/solution-patterns/references/wpf-winui-patterns.md) as authoritative; the WinForms reference applies only if a true WinForms control is added (none exist today).

## SSOT directions

There are no name-mapping correspondences in this repo:

- **No SQL Data project** and no models generated from a schema — `sql-model` row direction is **not applicable**. The CSV's `ExpectedSqlTable` / `ActualSqlTable` columns are blank for every row in this repo.

## Code spine

```
JocysCom.SslScanner.slnx                  Solution (slnx format)
Tool/                                     Single application project (WinExe, net8.0-windows)
├── MainWindow.xaml + .xaml.cs            Top-level WPF window; tab host
├── App.xaml + .xaml.cs                   Application entry; sets DPI awareness
├── Common/                                Domain model + scan engine
├── Controls/                              WPF UserControls bound to MainWindow tabs
├── Resources/Icons/                       XAML icon resource dictionaries
├── Documents/                             Embedded assets (ChangeLog, License) + signing script
├── Resources/                             Build-time generated assets (BuildDate.txt)
├── JocysCom/                              Vendored JocysCom.ClassLibrary source (subset)
└── ThirdParty/                            Vendored Whois.NET + IP range helpers
```

There are **no `*.Tests` projects** in the solution; the CSV's `ExpectedTestPath` column reflects what the path-mirror rule *would* produce, and every row currently shows `test-missing`. See the Overrides section below for the policy.

## Overrides

### wpf — desktop view ↔ navigation breadcrumb

- **Pattern:** `Tool/Controls/{Name}Control.xaml` (and `.xaml.cs`) → `ExpectedNavPath = MainWindow > {Name}`. The reference's default rule (find the nearest `TabItem` / `MenuItem` whose content loads this control) is what `pattern_map.py` already encodes; nothing custom needed.
- **Why:** `MainWindow.xaml` has exactly four `TabItem`s, each hosting one user control by name. The breadcrumb is therefore always `MainWindow > {Tab header}`.
- **AutomationId convention:** `{ControlName}.{ElementName}` (e.g. `DataList.MainDataGrid`, `Options.WhoisValidFromTextBox`). The CSV's `Notes` column hints at the prefix per row.

### Vendored code (`Tool/JocysCom/` and `Tool/ThirdParty/`)

- **Override:** files under these two folders are **not subject** to this repo's structural conventions.
- **Why:** they are copied source from external libraries (`JocysCom.ClassLibrary` and `Whois.NET`). Renaming or relocating them would break diffability against the upstream source. They are listed in the CSV because the scanner is path-based and cannot distinguish vendored from owned code without a hint, but any `nav-mismatch` / `off-convention` rows under those paths should be treated as **accepted** and not acted upon.
- **How to apply:** if the deviation report flags a vendored row, leave it alone. Bug-fix or feature work that touches `Tool/JocysCom/*` or `Tool/ThirdParty/*` should be considered for upstreaming to the source library rather than diverging locally.

### tests = <absent>

- **Override:** no test project exists. Every row in the CSV reports `test-missing`; this is **expected and accepted** for the repo's current state.
- **Why:** the tool is a small interactive utility; historical practice has been manual verification against live hosts. Adding an automated test project is a deliberate future investment, not a hidden gap to fix piecemeal.
- **How to apply:** do **not** create one-off `*Tests.cs` files alongside production code to "fix" individual `test-missing` rows. When tests are added, do it via a new MSTest project at `Tool.Tests/Tool.Tests.csproj` that mirrors the `Tool/` folder structure (per the path-mirror rule in [`qa-tester/SKILL.md`](skills/qa-tester/SKILL.md) §5.2). At that point, the `test-missing` rows will resolve naturally.

### nav = <single-window>

- **Override:** the application has no router, no nav tree configuration file, no URL space. There is exactly one window (`MainWindow.xaml`) hosting a four-tab `TabControl`. The "nav path" is purely the tab name.
- **Why:** it is a single-purpose desktop tool. There is no breadcrumb component, no sidebar, no AutomationPeer-backed accessibility tree beyond what WPF gives for free.
- **How to apply:** treat `ExpectedNavPath = MainWindow > {Tab}` as descriptive only — there is no nav source file to compare against, so `ActualNavPath` is blank for every row. `nav-mismatch` cannot be raised here; only `off-convention` (file placement) is actionable.

## Recommended future direction

- Add `Tool.Tests/Tool.Tests.csproj` (MSTest, sibling to `Tool/`) when test coverage becomes a real goal. The path-mirror rule will then start populating `ActualTestPath` and clearing `test-missing` rows organically.
- Continue resisting the introduction of a router / DI container / settings facade — the existing `Global.AppData` / `Global.AppSettings` pair is intentional and matches the single-window scope.
