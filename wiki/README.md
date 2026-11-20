# ReportMate macOS client wiki

The macOS client collects device telemetry on managed Macs and sends it to the ReportMate API. It runs on a schedule as root, gathers each module's data with osquery and bash, and posts one JSON payload per run that the API stores by device and module.

## Read first

- [Project overview, build and install](../README.md)
- [Contributor instructions and source layout](../AGENTS.md)
- [Swift package and targets](../Package.swift)
- [Munki postflight integration](../docs/MUNKI_INTEGRATION.md)

## Architecture

The package builds one executable from [Package.swift](../Package.swift), `managedreportsrunner`, the app's only Mach-O. Its arguments pick the role in [AppEntry.swift](../Sources/App/AppEntry.swift): with none it opens the SwiftUI settings, run and log window in [Sources/App](../Sources/App); `--helper` serves the privileged XPC helper in [Sources/Helper](../Sources/Helper), which runs the collector and writes system preferences for the window and accepts connections only from its own signed executable; `--appusage` runs the watcher in [Sources/Watcher](../Sources/Watcher), which records application usage to a local SQLite database; anything else is the collection CLI in [ReportMateClient.swift](../Sources/ReportMateClient.swift).

[ConfigurationManager.swift](../Sources/Core/Configuration/ConfigurationManager.swift) resolves settings in rising precedence: embedded defaults, the user plist, `REPORTMATE_*` environment variables, `/Library/Preferences/com.github.reportmate.plist`, a configuration profile, then command-line overrides. The passphrase and API key come only from the system plist or a profile, never the environment.

[DataCollectionService.swift](../Sources/DataCollection/DataCollectionService.swift) runs one processor per module from [Sources/DataCollection/Modules](../Sources/DataCollection/Modules). Each processor extends the base in [ModuleProcessor.swift](../Sources/DataCollection/Modules/ModuleProcessor.swift) and tries osquery first, through [OSQueryService.swift](../Sources/DataCollection/OSQueryService.swift) and the bundled macadmins extension, then falls back to bash through [BashService.swift](../Sources/Core/Services/BashService.swift). The osquery statements live in [queries.json](../Sources/Resources/queries.json). Payload models are in [Sources/Models](../Sources/Models), and [APIClient.swift](../Sources/Core/Services/APIClient.swift) transmits the result.

The app carries LaunchDaemons that run different module sets hourly, every four hours and daily, plus the app usage watcher and the helper. They live in the bundle's `Contents/Library/LaunchDaemons`, and the package registers them with SMAppService. [build.sh](../build.sh) defines them and assembles the app bundle and installer package.

## Development and verification

Use the [contributor instructions](../AGENTS.md) and the current README for setup. New collection code uses Swift, osquery and bash only; do not add Python.

Build with `swift build` or `make build`, and run the tests with `swift test` or `make test`. Tests live in [Tests](../Tests), one target per library or executable. A local run of the collector needs root:

```bash
sudo .build/debug/managedreportsrunner --collect-only --run-module hardware
```

The [CI workflow](../.github/workflows/ci.yml) compiles the client with `build.sh`, compiles the app icon and runs `swift test` on pull requests that touch sources, tests, the package or the build script. The [release workflow](../.github/workflows/release.yml) builds an unsigned package on a version tag or manual run and publishes it as a GitHub release; signing and notarization happen downstream.

## Documentation ownership

Keep this wiki as the entry point and update the linked pages where the facts belong. Examples use fictional data. Deployment inventories, credentials, signing identities, MDM profiles for a specific fleet and organization-specific operations belong with their deployment owner.
