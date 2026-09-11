# ReportMate macOS Client

Native macOS endpoint agent for ReportMate. It collects device telemetry —
hardware, system, security, network, identity, applications, managed installs,
MDM state and peripherals — and POSTs it to the ReportMate API as a single JSON
payload.

Written in Swift (Swift tools 6.0, `.macOS(.v14)`) and built with Swift Package
Manager. Data comes from osquery and the macadmins osquery extension where a
table exists, and from `system_profiler`, `ioreg`, `dscl`, `profiles` and other
command-line tools where it does not, so a Mac without osquery still reports.

Full documentation lives in the
[wiki](https://github.com/reportmate/reportmate-client-mac/wiki).

## Install

Releases publish an **unsigned** `ReportMate-<version>.pkg`. Sign and notarize
it with your own Developer ID before deploying it to managed Macs; the release
notes on each release carry the exact `codesign` / `productsign` / `notarytool`
invocations.

Install it the usual way.

```bash
sudo installer -pkg ReportMate-<version>.pkg -target /
```

The postinstall installs osquery 5.21.0 from the upstream GitHub release if
`/usr/local/bin/osqueryi` is missing, installs and bootstraps the LaunchDaemons,
and adds the Munki postflight hook when `/usr/local/munki` exists. See
[Installation](https://github.com/reportmate/reportmate-client-mac/wiki/Installation).

## Configure

The preference domain is `com.github.reportmate`. Settings are merged from the
embedded defaults, then `~/Library/Managed Reports/reportmate.plist`, then
`/Library/Preferences/com.github.reportmate.plist`, then managed preferences
delivered by an MDM configuration profile, then `REPORTMATE_*` environment
variables, then command-line overrides — each source winning over the ones
before it.

At minimum the agent needs an API URL.

```bash
sudo defaults write /Library/Preferences/com.github.reportmate ApiUrl "https://reportmate.example.com"
```

A configuration profile in the same domain can set `ApiUrl`, `DeviceId`,
`Passphrase`, `ApiKey`, `CollectionInterval`, `LogLevel` and `EnabledModules`.
Every key, its default and its effect is listed in
[Configuration](https://github.com/reportmate/reportmate-client-mac/wiki/Configuration).

## Run

The CLI is flag-based; there are no subcommands. It must run as root — any other
uid exits immediately with `ERROR: You must run this as root!`. With no flags it
runs every module in `EnabledModules` and transmits.

```bash
sudo /usr/local/bin/managedreportsrunner --run-modules security,network -vv
```

| Flag | Effect |
|---|---|
| `-v`, `--verbose` | Raise verbosity; repeatable up to `-vvv` |
| `--force` | Accepted and echoed in the run header; no other effect in the collection path |
| `--collect-only` | Collect and cache, do not transmit |
| `--transmit-only` | Do not collect; re-send the newest cached payload |
| `--run-module <name>` | Run exactly one module |
| `--run-modules <a,b,c>` | Run a comma-separated list, in the order given |
| `--device-id <id>` | Override `DeviceId` |
| `--api-url <url>` | Override `ApiUrl` |
| `--storage-mode <mode>` | Override `StorageMode`: `quick`, `deep` or `auto` |
| `--test`, `--info`, `--build` | Stubs: each prints one line and exits without doing the work its name suggests |
| `--version`, `--help` | Build version; usage |

Modules: `hardware`, `system`, `network`, `security`, `applications`,
`management`, `inventory`, `identity`, `peripherals`, `installs`. `displays` and
`printers` are accepted as aliases of `peripherals`. Details of each are in
[Modules](https://github.com/reportmate/reportmate-client-mac/wiki/Modules), and
the full flag reference — including the verbosity table — is in
[Command Line Reference](https://github.com/reportmate/reportmate-client-mac/wiki/Command-Line-Reference).

## On disk

| Path | Contents |
|---|---|
| `/Applications/Utilities/Managed Reports Runner.app` | App bundle; `managedreportsrunner`, `ReportMateApp` and `ReportMateHelper` in `Contents/MacOS/` |
| `/usr/local/bin/managedreportsrunner` | Symlink to the bundle's CLI |
| `/usr/local/reportmate/managedreportsrunner` | Wrapper script that execs the bundle's CLI |
| `/usr/local/reportmate/reportmate-appusage` | Application usage watcher |
| `/usr/local/reportmate/macadmins_extension.ext` | Bundled macadmins osquery extension |
| `/Library/Preferences/com.github.reportmate.plist` | System preferences |
| `/Library/Managed Reports/logs/` | `reportmate.log`, rolled daily and kept 30 days, plus per-daemon launchd logs |
| `/Library/Managed Reports/cache/` | Timestamped per-run payload cache, newest 24 runs kept |
| `/Library/Managed Reports/appusage.sqlite` | Watcher database |

## Schedule

The installer bootstraps these LaunchDaemons.

| Label | When | Modules |
|---|---|---|
| `com.github.reportmate.hourly` | `StartInterval` 3600 | `security,network,management,hardware` with `--storage-mode quick` |
| `com.github.reportmate.fourhourly` | `StartInterval` 14400 | `applications,inventory,system,identity,peripherals` |
| `com.github.reportmate.daily` | 09:00, random sleep up to 59 minutes | `hardware` with `--storage-mode deep` |
| `com.github.reportmate.allmodules` | 04:00, random sleep up to 2 hours | All enabled modules |
| `com.github.reportmate.installs` | No schedule; kickstarted by the Munki postflight | `installs` with `--force` |
| `com.github.reportmate.appusage` | `RunAtLoad` + `KeepAlive` | The usage watcher, not a collection |

## Privacy permissions

ReportMate needs Full Disk Access, and TCC grants are not inherited by child
processes, so `managedreportsrunner`, `osqueryi` and the macadmins extension
each need their own. A PPPC template that grants `SystemPolicyAllFiles` and
`SystemPolicySysAdminFiles` to all three ships at
[`Sources/Resources/profiles/ReportMate-FullDiskAccess.mobileconfig`](Sources/Resources/profiles/ReportMate-FullDiskAccess.mobileconfig).

Before deploying it through your MDM, replace `PayloadOrganization`, the
top-level `PayloadIdentifier`, and the `TEAMID0000` placeholder in the code
requirements with your own Team ID; regenerate the payload UUIDs with `uuidgen`.

## Build from source

Requirements: macOS 14+, the Xcode command line tools, a Swift 6 toolchain, and
Homebrew `bash` — `build.sh` has a `#!/opt/homebrew/bin/bash` shebang and needs
bash 5.

Compile without packaging.

```bash
./build.sh --skip-pkg --skip-zip --skip-dmg
```

Build the pkg, ZIP and DMG for a given version.

```bash
./build.sh --version 2026.01.15.1200
```

Sign and notarize a distribution build; both read identities from a `.env` file
(see [`.env.example`](.env.example)).

```bash
./build.sh --clean --sign --notarize
```

`make build`, `make release`, `make package`, `make sign` and `make notarize`
wrap the same script; `make test` runs `swift test`. `build.sh --help` lists
every flag, and
[Building and Releasing](https://github.com/reportmate/reportmate-client-mac/wiki/Building-and-Releasing)
covers the pipeline in full.

CI compiles the release configuration on every push and pull request to `main`;
it does not run tests, package, or sign. Pushing a `v*` or `YYYY.MM.DD.HHMM` tag
builds the unsigned pkg and publishes it as a GitHub release with its SHA-256.

## License

MIT — see [LICENSE](LICENSE).
