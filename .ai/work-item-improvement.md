# Work-Item Improvement registry — SslScanner

<!-- Schema: v1. Next-Id: WI-11. Last full refresh: 2026-05-26. Last competitor-parity scan: never. -->

> Living document. Re-read on every Improvement work item. Status advances Open → Working → Done;
> rejections need a Falsifier; rejections older than 90 days re-enter triage automatically.
> Confidence can only rise when Evidence is added in the same edit.
> Open ideas untouched > 365 days move to Dormant; > 180 days have Confidence capped at 2.
> Ids (`WI-N`) are stable forever — never re-numbered. `Parent: WI-N` records lineage; `Kind:` is idea / improvement / fix.

## Scoring anchors (project-specific examples — update when better ones emerge)

- **Impact 5 example:** _(none yet — needs a shipped row whose user-visible impact was unmistakable)_.
- **Impact 1 example:** _(none yet)_.
- **Effort 1 example:** Fix `+OK`/`STLS` to `* OK`/`STARTTLS` in IMAP branch (WI-1) — ≤ 10 lines, single file.
- **Effort 5 example:** _(none yet)_.

## Done — most recent year only; older years in `work-item-improvement/archive-{YYYY}.md`

- [Done] Id: WI-9. Kind: idea. Tool - **STARTTLS protocol support (SMTP/POP3/IMAP):** Scan SSL on STARTTLS ports 25/110/143. Impact: 4. Confidence: 5. Effort: 3. Score: 6.67. Source: project. Refs: commit 5bf9b6a `-Fix: StarTLS Support.`. LastConsidered: 2026-05-26.
- [Done] Id: WI-10. Kind: improvement. Tool - **HTTPS response status column:** Show HTTP response status for port-443 entries during scan. Impact: 3. Confidence: 5. Effort: 2. Score: 7.5. Source: project. Refs: commit 63e9f91 `Add response status.`. LastConsidered: 2026-05-26.
- [Done] Id: WI-1. Kind: fix. Tool/Common/Test_SSL_Support - **IMAP STARTTLS protocol error:** IMAP branch (port 143) reuses POP3 wire format — checks `+OK` greeting and sends `STLS`, but RFC 3501/2595 require `* OK` greeting and `STARTTLS` (tagged). Every IMAP STARTTLS scan currently throws `InvalidOperationException`. Impact: 4. Confidence: 5. Effort: 1. Score: 20. Source: project. Refs: https://github.com/JocysCom/SslScanner/issues/8. LastConsidered: 2026-05-26. Evidence: Tool/Common/Test_SSL_Support.cs:277-290 confirms `+OK`/`STLS` in the `port == 143` branch.

## Working

_(none yet)_

## Open — sorted descending by Score (includes Verifying)

- [Open] Id: WI-2. Kind: improvement. Tool/Common/ScriptExecutor - **Populate DataItem.SAN from certificate extensions:** UI column `SAN` is bound in `DataListControl.xaml` and the property exists on `DataItem`, but `ScriptExecutor` never sets it — column always empty. Read `X509SubjectAlternativeNameExtension` (or parse `OID 2.5.29.17` from `cert.Extensions`) and join the DNS names. Impact: 3. Confidence: 5. Effort: 1. Score: 15. Source: project. Refs: —. LastConsidered: 2026-05-26. Evidence: Tool/Common/DataItem.cs:151 declares SAN; Tool/Controls/DataListControl.xaml:406 binds it; Tool/Common/ScriptExecutor.cs never writes to it.
- [Open] Id: WI-3. Kind: fix. Tool/Common/ScriptExecutor - **Honor ScriptExecutorParam.Cancel in scan loop:** `Cancel` boolean exists on `ScriptExecutorParam` but the `ProcessData` loop never reads it. Long scans cannot be aborted. Add an `if (param.Cancel) break;` at the top of the loop. Impact: 3. Confidence: 5. Effort: 1. Score: 15. Source: project. Refs: —. LastConsidered: 2026-05-26. Evidence: Tool/Common/ScriptExecutorParam.cs:8 declares Cancel; `grep "Cancel" Tool/Common/ScriptExecutor.cs` returns no matches.
- [Open] Id: WI-4. Kind: improvement. Tool/Common/ScriptExecutor - **Extend ResponseStatus capture to non-443 HTTPS ports:** `item.ResponseStatus` is set only when `item.Port == 443`. Servers on 8443/4443/etc. show blank status. Drop the port guard or replace it with a "HTTPS-capable port" check. Impact: 2. Confidence: 4. Effort: 1. Score: 8. Source: project. Refs: —. LastConsidered: 2026-05-26. Evidence: Tool/Common/ScriptExecutor.cs:136 `item.Port == 443`.
- [Open] Id: WI-5. Kind: improvement. Tool/ThirdParty/WhoisResponse - **Surface WHOIS OrganizationName in the UI:** `OrganizationName` is parsed from the WHOIS response (`WhoisResponse.cs:40,72,100`) but never displayed. Add a column / detail field bound to it. Impact: 2. Confidence: 4. Effort: 1. Score: 8. Source: project. Refs: —. LastConsidered: 2026-05-26. Evidence: Tool/ThirdParty/WhoisResponse.cs:40,72,100.
- [Open] Id: WI-6. Kind: idea. Tool/Controls - **Wire SslTestButton_Click and WebTestButton_Click handlers:** Both toolbar buttons exist in `DataListControl.xaml` but their `_Click` handlers in `DataListControl.xaml.cs:222-228` are empty. Decide intended behaviour (likely: run a single-item scan with the relevant test path) and implement. Impact: 3. Confidence: 4. Effort: 2. Score: 6. Source: project. Refs: —. LastConsidered: 2026-05-26. Evidence: Tool/Controls/DataListControl.xaml.cs:222-228.
- [Open] Id: WI-7. Kind: idea. Tool/Common/AppData + Tool/Controls/OptionsControl - **User-configurable expiry-warning thresholds:** 30/60/90-day thresholds are hardcoded in `DataListControl.xaml.cs:69-70`. Move to `AppData` and expose in `OptionsControl`. Impact: 3. Confidence: 3. Effort: 2. Score: 4.5. Source: project. Refs: —. LastConsidered: 2026-05-26. Evidence: Tool/Controls/DataListControl.xaml.cs:69-70.
- [Open] Id: WI-8. Kind: improvement. Tool/Common/Test_SSL_Support - **Replace static mutable Results/result with instance state:** `public static List<Result> Results` and the `result` field on `Test_SSL_Support` make concurrent / parallel scans unsafe. Refactor to instance state so the executor can fan out. Impact: 2. Confidence: 3. Effort: 3. Score: 2. Source: project. Refs: —. LastConsidered: 2026-05-26. Evidence: Tool/Common/Test_SSL_Support.cs:63.

## Rejected

_(none yet)_

## Retired — built then deliberately removed; do not re-propose without reading why

_(none yet)_

## Dormant — Open ideas untouched > 365 days; bump LastConsidered + add Evidence to reactivate

_(none yet)_
