# ReportMate fleet app (native macOS)

`ReportMate.app` is the SwiftUI counterpart of the ReportMate web dashboard
(`reportmate-app-web`). It talks to the same API the web app talks to and
renders the same pages: the dashboard, the device list, the events feed, the
per-device page with its ten tabs, the nine fleet reports, and the fleet
settings. It is a monitoring app for operators, not a control panel for the
per-device runner; the runner keeps collecting on its own schedule and the
app polls the API.

## Building and running

The app is the `ReportMateMac` product in `Package.swift`, built from
`Sources/ReportMateMac` on top of the `ReportMateKit` library (API client,
JSON model, per-module readers, report aggregations).

Build the app bundle into `.build/app/ReportMate.app`:

```bash
make app
```

Build and launch it:

```bash
make app-open
```

Sign it with the identity from `.env`:

```bash
scripts/build-app.sh --sign
```

A Command Line Tools install on a macOS beta can ship an SDK whose SwiftUI
macros plugin is missing. The build script then falls back to the previous
SDK automatically; to pick one by hand, export it before building:

```bash
export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.sdk
```

The Kit tests are Swift Testing suites in `Tests/ReportMateKitTests`. They
run with `swift test` wherever XCTest is available; on a Command Line Tools
only machine, point the compiler at the testing plugin:

```bash
swift test -Xswiftc -plugin-path -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing
```

## Connecting

Settings (⌘,) → Connection takes the API base URL and one of three
credentials:

| Method | Header | Notes |
|---|---|---|
| API key | `X-API-Key` | A per-client key minted from the API's admin key endpoints with the read scopes the app needs. |
| Passphrase | `X-Client-Passphrase` | The legacy shared client passphrase (full access). |
| Entra sign-in | `Authorization: Bearer` | A delegated token for the API app registration, minted from the signed-in user's `az login` session; nothing is stored on the Mac. |

Credentials are kept in the Keychain. The endpoint's own ingest key is not a
read credential and will be refused with 403.

## Navigation

The header mirrors the web app: **Dashboard | Devices | Events** and then the
reports as tabs (Installs, Applications, System, Management, Identity,
Hardware, Peripherals, Security, Network). A narrow window collapses the
reports into a Reports menu. ⌘1–⌘9 and ⌘0 jump between sections, ⌘K opens
device search, ⌘R refreshes, and the toolbar's platform toggle (Mac / Windows
/ All) applies everywhere the web platform filter does.

Device pages and drill-downs (per-application usage, usage coverage) push onto
the navigation stack; Back is ⌘[ or the toolbar arrow.

## Parity matrix

Every web page and the widgets, filters, drill-downs and exports on it, with
where the native counterpart lives.

| Web page | Native view | Status |
|---|---|---|
| `/dashboard` (fleet status donut, error and warning counters, new clients, recent events with type filter, platform distribution with drill-downs and filters, macOS and Windows version donuts with drill-down) | `Views/Dashboard/DashboardView.swift`, `RecentEventsWidget.swift` | Complete; polls every 30 s like the web page. Version donuts link to the System report's OS version filter. |
| `/devices` (search, Selections accordion, sortable table, status and inventory pills, `?status=` from the dashboard) | `Views/Devices/DevicesView.swift` | Complete. Adds a Registered column. |
| `/device/[serial]` header and tabs: Info, Installs, Applications, Hardware, Network, Security, Management (with logs), Identity, Peripherals, System, Events | `Views/Device/DeviceDetailView.swift`, `Views/Device/Tabs/*` | Complete for all tabs, including the management log viewer, the security certificate and CVE tables, launchd and scheduled task tables, and the identity session analytics. |
| `/events` (date range, kind chips with System and Info shown alone, search, infinite scroll, live refresh, expanded rows with run summary, details, raw payload copy and search) | `Views/Events/EventsView.swift`, `EventRows.swift` | Complete. |
| `/events/failures` (rejected check-ins by reason and row) | `IngestFailuresView` in `EventsView.swift` | Complete, as the second mode of the Events section. |
| `/installs` (config report, items-with-status tables, error and warning message widgets, repo, tool version and manifest widgets, status pills, status drill-down by device or by message, item report builder, CSV) | `Views/Reports/InstallsReportView.swift`, `InstallsReportModel.swift`, `InstallsReportWidgets.swift` | Complete. The item report keeps Munki rows as well as Cimian rows; the web route drops Munki rows. |
| `/applications` (chip cloud, Versions report with version distribution and Missing mode, Usage report with device-level widgets and per-version device table, in-report app filter, period selector, CSV) | `Views/Reports/ApplicationsReportView.swift`, `ApplicationsReportModel.swift`, `ApplicationsReportComponents.swift` | Complete. The chip cloud renders the first 2000 names; search narrows it. Copy Link is not ported: the app has no shareable URL. |
| `/applications/usage/[app]` (per-device usage, widgets, CSV) | `Views/Reports/ApplicationUsageDetailView.swift` | Complete. |
| `/applications/coverage` (usage telemetry collection health) | `Views/Reports/ApplicationCoverageView.swift` | Complete; reachable from the Usage report's Coverage button. |
| `/system` (OS version filter widget, uptime and pending update buckets, Windows edition, activation and license widgets) | `Views/Reports/SystemReportView.swift` | Complete. |
| `/management` (providers, enrollment status and type widgets, enrollment table) | `Views/Reports/ManagementReportView.swift` | Complete. |
| `/identity` (directory and authentication donuts with drill-downs, admin accounts, admins and utilization reports) | `Views/Reports/IdentityReportView.swift` | Complete. |
| `/hardware` (architecture, chip, processor, graphics, memory and storage widgets) | `Views/Reports/HardwareReportView.swift` | Complete. |
| `/peripherals` (kind and printer widgets) | `Views/Reports/PeripheralsReportView.swift` | Complete. |
| `/security` (eight status donuts, certificate search) | `Views/Reports/SecurityReportView.swift` | Complete. |
| `/network` (wireless state, networks, speed and signal widgets) | `Views/Reports/NetworkReportView.swift` | Complete. |
| `/settings` (General, Inventory Mapping, Security Rules, Kiosk Displays, Maintenance) and `/settings/onboarding` | `Views/Settings/SettingsView.swift`, `FleetSettingsView.swift` | Complete. Theme and text size live under Appearance. |
| `/live-installs` | — | Not ported: the page reads a Next.js route that no longer exists. |

Shared behaviour: every report has the platform toggle, the Selections
accordion (status, usage, catalog, fleet, area, location), search, widget-driven
filters, sortable columns and a CSV export through the save panel.

## Links

The app registers the `reportmate://` scheme. Links are the web app's routes
with the scheme swapped, so any web URL becomes an app link by replacing
`https://<host>` with `reportmate://`, and the app accepts a pasted web URL
as-is:

```
reportmate://dashboard
reportmate://devices?status=active&search=lab
reportmate://device/<serial>?tab=installs&filter=errors
reportmate://events?filter=errors
reportmate://events/failures
reportmate://installs?filter=warnings&view=messages
reportmate://applications?type=usage&apps=Blender,Zoom&period=30
reportmate://applications/usage/<app>?days=30
reportmate://applications/coverage
reportmate://system?osVersion=15.4
reportmate://settings
reportmate://this-mac
```

A bare `reportmate://` link does nothing on a machine without the app, so the
link to share is the web dashboard's handoff form:

```
https://<web host>/open/device/<serial>?filter=errors#installs
```

The `/open/...` route on the web app tries the app and, when nothing answers,
continues to the same page in the browser. No host is built into the app or
the web app: Settings → Connection takes the web dashboard URL, and **Copy
Link** in the toolbar (⌘⇧C) copies that handoff form, with the plain web link
and the raw `reportmate://` link as alternatives. Every page contributes its
filters, so a copied link reopens the exact view: the device tab and filter,
the report's selections, the events kinds and date-independent filters, the
system OS version, and the applications report type, apps, period and mode.

## This Mac

The device page can also show this Mac's own report without an API
connection. **This Mac** on the Devices page (and on the not-connected screen)
reads the runner cache at `/Library/Managed Reports/cache/<run>/event.json`,
takes the newest copy of each module across runs, gathers the run events, and
renders the same tabs. `ReportMateKit/Local/LocalReportStore.swift` does the
assembly; admin actions are hidden for the local report.

## Layout of the code

```
Sources/ReportMateKit/          shared library, no UI
├── API/ReportMateAPI.swift     every endpoint the app calls
├── Auth/                       Keychain store, Entra token source
├── Config/AppConfiguration     base URL and credential
├── JSON/JSONValue              the tree every reader walks
├── Models/                     devices, events, settings document
├── Events/                     bundling, inline details, last-run summary
└── Processing/                 per-module readers and report aggregations
Sources/ReportMateMac/          the SwiftUI app
├── AppState.swift              navigation, devices cache, platform filter
├── Navigation/                 sections, routes, top bar
└── Views/                      Dashboard, Devices, Events, Device tabs,
                                Reports, Settings, Shared components
```
