# ReportMate Client Deployment Scripts

This directory contains scripts used for deploying the ReportMate client via [munkipkg](https://github.com/munki/munki-pkg).

## munkipkg Project Structure

The macintosh client follows munkipkg's project layout:

```
clients/macintosh/
├── build-info.json    # Package metadata (identifier, version, signing)
├── payload/           # Files to install (empty = scripts-only package)
├── scripts/           # Installation scripts
│   ├── postinstall    # Runs after installation
│   └── README.md      # This file
├── build/             # Generated .pkg files (gitignored)
├── .env               # Secrets from Key Vault (gitignored)
└── .env.example       # Template for .env file
```

## `postinstall`

This script runs after the package installation. It configures the client with the necessary settings stored in `/Library/Preferences/com.reportmate.client.plist`.

## Environment Variables & Secrets

munkipkg supports `.env` files for injecting secrets at build time using `${VAR}` syntax.

### Setup

```bash
# Copy template and fill in values from Azure Key Vault
cp .env.example .env
```

### Key Vault Secret Mappings

| Environment Variable | Key Vault Secret | Description |
|---------------------|------------------|-------------|
| `REPORTMATE_API_URL` | `reportmate-custom-domain-name` | API endpoint URL |
| `REPORTMATE_CLIENT_PASSPHRASE` | `reportmate-client-passphrase` | Client authentication key |

### Fetching Secrets from Key Vault

```bash
# List all secrets
az keyvault secret list --vault-name reportmate-kv --query "[].name" -o tsv

# Get a specific secret value
az keyvault secret show --vault-name reportmate-kv --name reportmate-custom-domain-name --query value -o tsv
```

## Building the Package

```bash
# Install munkipkg if needed
pip install munkipkg

# Navigate to the macintosh client directory
cd clients/macintosh

# Build the package (munkipkg will read .env and substitute variables)
munkipkg .
```

The built package will be in the `build/` directory.

## CI/CD Pipeline Integration

For Azure DevOps pipelines, use the `Replace Tokens` task to substitute placeholders with Key Vault secrets before building.

## Troubleshooting

The script logs to stdout/stderr, captured by the macOS Installer log:

```bash
log show --predicate 'process == "installer"' --last 1h
```
