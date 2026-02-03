# Deploy-NCSCBaselineToIntune.ps1

This script deploys NCSC Windows baseline security configurations to Microsoft Intune via the Microsoft Graph API.

## What It Does

The script imports security policy JSON files from your local configuration folder into Intune, supporting three policy types:

- **Settings Catalog** policies
- **Endpoint Security** policies
- **Device Configuration** profiles

## Prerequisites

### 1. PowerShell Modules

Install the Microsoft Graph SDK:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

### 2. Permissions

Your account or app registration needs these Graph permissions:

- `DeviceManagementConfiguration.ReadWrite.All`
- `DeviceManagementManagedDevices.ReadWrite.All`
- `DeviceManagementServiceConfig.ReadWrite.All`

### 3. Configuration Files

JSON policies should be located in `.\Microsoft\Windows\MDM\Configurations` (default path) with the following structure:

```
Configurations/
├── SettingsCatalog/
│   └── *.json
├── EndpointSecurity/
│   └── *.json
└── DeviceConfiguration/
    └── *.json
```

## How to Run

### Preview First (Recommended)

```powershell
.\Deploy-NCSCBaselineToIntune.ps1 -DryRun
```

This shows what would be created without making changes.

### Interactive Deployment

```powershell
.\Deploy-NCSCBaselineToIntune.ps1
```

You'll sign in via browser popup.

### With App Registration (Automation)

```powershell
$secret = ConvertTo-SecureString "your-secret" -AsPlainText -Force
.\Deploy-NCSCBaselineToIntune.ps1 -AuthMethod AppRegistration -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret $secret
```

### With Managed Identity (Azure Automation)

```powershell
.\Deploy-NCSCBaselineToIntune.ps1 -AuthMethod ManagedIdentity
```

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-ConfigurationPath` | Path to the JSON configuration files | `.\Microsoft\Windows\MDM\Configurations` |
| `-AuthMethod` | Authentication method: `Interactive`, `AppRegistration`, or `ManagedIdentity` | `Interactive` |
| `-TenantId` | Azure AD Tenant ID (required for AppRegistration) | - |
| `-ClientId` | Application (client) ID (required for AppRegistration) | - |
| `-ClientSecret` | Application client secret as SecureString (required for AppRegistration) | - |
| `-DryRun` | Preview what would be created without making changes | `$false` |
| `-Force` | Overwrite existing policies with the same name | `$false` |
| `-LogPath` | Path to the log file | `.\NCSCDeployment.log` |

## Workflow

1. Validates the configuration path exists
2. Discovers JSON policy files in `SettingsCatalog/`, `EndpointSecurity/`, and `DeviceConfiguration/` subfolders
3. Connects to Microsoft Graph
4. For each policy file:
   - Reads and parses the JSON
   - Checks if a policy with the same name exists
   - Creates the policy (or replaces it if `-Force` is specified)
5. Outputs a summary of successful/failed/skipped policies
6. Writes detailed logs to the log file

## Output

The script produces:

- Console output with color-coded status messages
- A log file (default: `.\NCSCDeployment.log`) with timestamps
- A deployment summary showing successful, failed, and skipped policy counts
