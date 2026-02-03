<#
.SYNOPSIS
    Deploys NCSC Windows baseline configurations to Microsoft Intune.

.DESCRIPTION
    This script imports NCSC Windows baseline configuration policies into Microsoft Intune
    using the Microsoft Graph API. It supports Settings Catalog policies, Endpoint Security
    policies, and Device Configuration profiles.

.PARAMETER ConfigurationPath
    Path to the NCSC configuration files. Defaults to .\Microsoft\Windows\MDM\Configurations

.PARAMETER AuthMethod
    Authentication method: Interactive, AppRegistration, or ManagedIdentity

.PARAMETER TenantId
    Azure AD Tenant ID. Required for AppRegistration auth method.

.PARAMETER ClientId
    Application (client) ID. Required for AppRegistration auth method.

.PARAMETER ClientSecret
    Application client secret as SecureString. Required for AppRegistration auth method.

.PARAMETER DryRun
    Preview what would be created without making changes.

.PARAMETER Force
    Overwrite existing policies with the same name.

.PARAMETER LogPath
    Path to the log file. Defaults to .\NCSCDeployment.log

.EXAMPLE
    .\Deploy-NCSCBaselineToIntune.ps1 -DryRun
    Preview deployment without making changes.

.EXAMPLE
    .\Deploy-NCSCBaselineToIntune.ps1
    Deploy using interactive authentication.

.EXAMPLE
    $secret = ConvertTo-SecureString "your-secret" -AsPlainText -Force
    .\Deploy-NCSCBaselineToIntune.ps1 -AuthMethod AppRegistration -TenantId "tenant-id" -ClientId "client-id" -ClientSecret $secret
    Deploy using app registration credentials.

.NOTES
    Requires Microsoft.Graph PowerShell SDK v2.
    Required Graph permissions:
    - DeviceManagementConfiguration.ReadWrite.All
    - DeviceManagementManagedDevices.ReadWrite.All
    - DeviceManagementServiceConfig.ReadWrite.All
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigurationPath = ".\Microsoft\Windows\MDM\Configurations",

    [Parameter()]
    [ValidateSet("Interactive", "AppRegistration", "ManagedIdentity")]
    [string]$AuthMethod = "Interactive",

    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$ClientId,

    [Parameter()]
    [SecureString]$ClientSecret,

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [string]$LogPath = ".\NCSCDeployment.log"
)

#Requires -Version 5.1

$ErrorActionPreference = "Stop"

# Deployment statistics
$script:Stats = @{
    Success = 0
    Failed  = 0
    Skipped = 0
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "Info"    { Write-Host $logMessage -ForegroundColor Cyan }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error"   { Write-Host $logMessage -ForegroundColor Red }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
    }

    Add-Content -Path $LogPath -Value $logMessage -ErrorAction SilentlyContinue
}

function Test-GraphModules {
    <#
    .SYNOPSIS
        Verifies Microsoft.Graph modules are installed.
    #>
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Beta.DeviceManagement"
    )

    $missing = @()
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missing += $module
        }
    }

    if ($missing.Count -gt 0) {
        Write-Log "Missing required modules: $($missing -join ', ')" -Level Error
        Write-Log "Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -Level Info
        return $false
    }

    return $true
}

function Connect-IntuneGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with the specified authentication method.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$AuthMethod,
        [string]$TenantId,
        [string]$ClientId,
        [SecureString]$ClientSecret
    )

    $scopes = @(
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "DeviceManagementServiceConfig.ReadWrite.All"
    )

    try {
        switch ($AuthMethod) {
            "Interactive" {
                Write-Log "Connecting to Microsoft Graph using interactive authentication..."
                Connect-MgGraph -Scopes $scopes -NoWelcome
            }
            "AppRegistration" {
                if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
                    throw "TenantId, ClientId, and ClientSecret are required for AppRegistration authentication."
                }
                Write-Log "Connecting to Microsoft Graph using app registration..."
                $credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome
            }
            "ManagedIdentity" {
                Write-Log "Connecting to Microsoft Graph using managed identity..."
                Connect-MgGraph -Identity -NoWelcome
            }
        }

        $context = Get-MgContext
        if ($context) {
            Write-Log "Connected to tenant: $($context.TenantId)" -Level Success
            return $true
        } else {
            throw "Failed to establish Graph connection."
        }
    }
    catch {
        Write-Log "Authentication failed: $_" -Level Error
        return $false
    }
}

function Read-PolicyJsonFile {
    <#
    .SYNOPSIS
        Reads a JSON policy file, handling UTF-16 LE encoding.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )

    try {
        # Read raw bytes to detect encoding
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)

        # Check for UTF-16 LE BOM (FF FE)
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
            $content = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
        }
        # Check for UTF-8 BOM (EF BB BF)
        elseif ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
            $content = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
        }
        else {
            # Assume UTF-8 without BOM
            $content = [System.Text.Encoding]::UTF8.GetString($bytes)
        }

        return $content | ConvertFrom-Json
    }
    catch {
        Write-Log "Failed to read file $FilePath : $_" -Level Error
        return $null
    }
}

function Get-PolicyType {
    <#
    .SYNOPSIS
        Determines the policy type from JSON content.
    #>
    param(
        [Parameter(Mandatory)]
        $PolicyJson
    )

    $odataType = $PolicyJson.'@odata.type'

    switch -Wildcard ($odataType) {
        "#microsoft.graph.deviceManagementConfigurationPolicy" { return "SettingsCatalog" }
        "#microsoft.graph.deviceManagementIntent" { return "EndpointSecurity" }
        "#microsoft.graph.windows10*" { return "DeviceConfiguration" }
        default {
            # Fallback: check for other indicators
            if ($PolicyJson.templateId -and $PolicyJson.displayName) {
                return "EndpointSecurity"
            }
            if ($PolicyJson.settings -and $PolicyJson.platforms) {
                return "SettingsCatalog"
            }
            return "Unknown"
        }
    }
}

function Remove-ReadOnlyProperties {
    <#
    .SYNOPSIS
        Removes read-only properties from policy JSON before POST.
    #>
    param(
        [Parameter(Mandatory)]
        $PolicyObject
    )

    $readOnlyProps = @(
        '@odata.context',
        '@odata.id',
        '@odata.editLink',
        'id',
        'createdDateTime',
        'lastModifiedDateTime',
        'createdDateTime@odata.type',
        'lastModifiedDateTime@odata.type',
        'version',
        'isAssigned',
        'isMigratingToConfigurationPolicy',
        'settingCount',
        'assignments@odata.context',
        'assignments@odata.associationLink',
        'assignments@odata.navigationLink',
        'settings@odata.context',
        'settings@odata.associationLink',
        'settings@odata.navigationLink',
        '#microsoft.graph.assign',
        '#microsoft.graph.assignedAccessMultiModeProfiles',
        '#microsoft.graph.windowsPrivacyAccessControls',
        '#microsoft.graph.getOmaSettingPlainTextValue'
    )

    # Convert to hashtable for easier manipulation
    $hash = @{}
    $PolicyObject.PSObject.Properties | ForEach-Object {
        # Skip explicit read-only props, @odata.type annotations, and #microsoft.graph actions
        if ($_.Name -notin $readOnlyProps -and
            $_.Name -notlike '*@odata.type' -and
            $_.Name -notlike '#microsoft.graph.*') {
            $hash[$_.Name] = $_.Value
        }
    }

    # Clean nested settings array
    if ($hash.settings) {
        $cleanSettings = @()
        foreach ($setting in $hash.settings) {
            $cleanSetting = @{}
            $setting.PSObject.Properties | ForEach-Object {
                if ($_.Name -notin $readOnlyProps) {
                    $cleanSetting[$_.Name] = $_.Value
                }
            }
            $cleanSettings += $cleanSetting
        }
        $hash.settings = $cleanSettings
    }

    # Remove assignments (we don't import assignments)
    $hash.Remove('assignments')

    return $hash
}

function Test-PolicyExists {
    <#
    .SYNOPSIS
        Checks if a policy with the given name already exists.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,
        [Parameter(Mandatory)]
        [string]$PolicyType
    )

    try {
        switch ($PolicyType) {
            "SettingsCatalog" {
                $filter = "name eq '$PolicyName'"
                $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=$filter"
                return $existing.value.Count -gt 0
            }
            "EndpointSecurity" {
                $filter = "displayName eq '$PolicyName'"
                $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/intents?`$filter=$filter"
                return $existing.value.Count -gt 0
            }
            "DeviceConfiguration" {
                $filter = "displayName eq '$PolicyName'"
                $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=$filter"
                return $existing.value.Count -gt 0
            }
        }
    }
    catch {
        Write-Log "Error checking for existing policy: $_" -Level Warning
        return $false
    }

    return $false
}

function Remove-ExistingPolicy {
    <#
    .SYNOPSIS
        Removes an existing policy by name.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$PolicyName,
        [Parameter(Mandatory)]
        [string]$PolicyType
    )

    try {
        switch ($PolicyType) {
            "SettingsCatalog" {
                $filter = "name eq '$PolicyName'"
                $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?`$filter=$filter"
                foreach ($policy in $existing.value) {
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($policy.id)"
                    Write-Log "Deleted existing Settings Catalog policy: $PolicyName"
                }
            }
            "EndpointSecurity" {
                $filter = "displayName eq '$PolicyName'"
                $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/intents?`$filter=$filter"
                foreach ($policy in $existing.value) {
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/intents/$($policy.id)"
                    Write-Log "Deleted existing Endpoint Security policy: $PolicyName"
                }
            }
            "DeviceConfiguration" {
                $filter = "displayName eq '$PolicyName'"
                $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=$filter"
                foreach ($policy in $existing.value) {
                    Invoke-MgGraphRequest -Method DELETE -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($policy.id)"
                    Write-Log "Deleted existing Device Configuration profile: $PolicyName"
                }
            }
        }
        return $true
    }
    catch {
        Write-Log "Failed to remove existing policy: $_" -Level Error
        return $false
    }
}

function Import-SettingsCatalogPolicy {
    <#
    .SYNOPSIS
        Imports a Settings Catalog policy to Intune.
    #>
    param(
        [Parameter(Mandatory)]
        $PolicyJson,
        [switch]$DryRun
    )

    $policyName = $PolicyJson.name

    if ($DryRun) {
        Write-Log "[DRY RUN] Would create Settings Catalog policy: $policyName" -Level Info
        return $true
    }

    try {
        $cleanPolicy = Remove-ReadOnlyProperties -PolicyObject $PolicyJson
        $body = $cleanPolicy | ConvertTo-Json -Depth 50 -Compress

        $result = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -Body $body -ContentType "application/json"

        Write-Log "Created Settings Catalog policy: $policyName (ID: $($result.id))" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to create Settings Catalog policy '$policyName': $_" -Level Error
        return $false
    }
}

function Import-EndpointSecurityPolicy {
    <#
    .SYNOPSIS
        Imports an Endpoint Security policy to Intune using template-based creation.
    #>
    param(
        [Parameter(Mandatory)]
        $PolicyJson,
        [switch]$DryRun
    )

    $policyName = $PolicyJson.displayName
    $templateId = $PolicyJson.templateId

    if (-not $templateId) {
        Write-Log "No templateId found for Endpoint Security policy: $policyName" -Level Error
        return $false
    }

    if ($DryRun) {
        Write-Log "[DRY RUN] Would create Endpoint Security policy: $policyName (Template: $templateId)" -Level Info
        return $true
    }

    try {
        # Prepare settings for createInstance
        $cleanSettings = @()
        foreach ($setting in $PolicyJson.settings) {
            $cleanSetting = @{
                '@odata.type' = $setting.'@odata.type'
                definitionId  = $setting.definitionId
            }

            # Add value based on setting type
            if ($null -ne $setting.value) {
                $cleanSetting.value = $setting.value
            }
            if ($null -ne $setting.valueJson) {
                $cleanSetting.valueJson = $setting.valueJson
            }

            $cleanSettings += $cleanSetting
        }

        $body = @{
            displayName   = $policyName
            description   = $PolicyJson.description
            settingsDelta = $cleanSettings
            roleScopeTagIds = @("0")
        } | ConvertTo-Json -Depth 50 -Compress

        $result = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateId/createInstance" -Body $body -ContentType "application/json"

        Write-Log "Created Endpoint Security policy: $policyName (ID: $($result.id))" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to create Endpoint Security policy '$policyName': $_" -Level Error
        return $false
    }
}

function Import-DeviceConfigurationProfile {
    <#
    .SYNOPSIS
        Imports a Device Configuration profile to Intune.
    #>
    param(
        [Parameter(Mandatory)]
        $PolicyJson,
        [switch]$DryRun
    )

    $policyName = $PolicyJson.displayName

    if ($DryRun) {
        Write-Log "[DRY RUN] Would create Device Configuration profile: $policyName" -Level Info
        return $true
    }

    try {
        $cleanPolicy = Remove-ReadOnlyProperties -PolicyObject $PolicyJson
        $body = $cleanPolicy | ConvertTo-Json -Depth 50 -Compress

        $result = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -Body $body -ContentType "application/json"

        Write-Log "Created Device Configuration profile: $policyName (ID: $($result.id))" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to create Device Configuration profile '$policyName': $_" -Level Error
        return $false
    }
}

function Get-PolicyFiles {
    <#
    .SYNOPSIS
        Discovers all policy JSON files to import.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$BasePath
    )

    $files = @()

    # Settings Catalog files
    $settingsCatalogPath = Join-Path $BasePath "SettingsCatalog"
    if (Test-Path $settingsCatalogPath) {
        $files += Get-ChildItem -Path $settingsCatalogPath -Filter "*.json" | ForEach-Object {
            [PSCustomObject]@{
                Path     = $_.FullName
                Name     = $_.BaseName
                Category = "SettingsCatalog"
            }
        }
    }

    # Endpoint Security files (excluding _Settings companion files)
    $endpointSecurityPath = Join-Path $BasePath "EndpointSecurity"
    if (Test-Path $endpointSecurityPath) {
        $files += Get-ChildItem -Path $endpointSecurityPath -Filter "*.json" |
            Where-Object { $_.Name -notlike "*_Settings.json" } |
            ForEach-Object {
                [PSCustomObject]@{
                    Path     = $_.FullName
                    Name     = $_.BaseName
                    Category = "EndpointSecurity"
                }
            }
    }

    # Device Configuration files
    $deviceConfigPath = Join-Path $BasePath "DeviceConfiguration"
    if (Test-Path $deviceConfigPath) {
        $files += Get-ChildItem -Path $deviceConfigPath -Filter "*.json" | ForEach-Object {
            [PSCustomObject]@{
                Path     = $_.FullName
                Name     = $_.BaseName
                Category = "DeviceConfiguration"
            }
        }
    }

    return $files
}

# Main execution
function Main {
    Write-Log "========================================" -Level Info
    Write-Log "NCSC Baseline Intune Deployment Script" -Level Info
    Write-Log "========================================" -Level Info

    if ($DryRun) {
        Write-Log "*** DRY RUN MODE - No changes will be made ***" -Level Warning
    }

    # Validate configuration path
    $ConfigurationPath = Resolve-Path $ConfigurationPath -ErrorAction SilentlyContinue
    if (-not $ConfigurationPath -or -not (Test-Path $ConfigurationPath)) {
        Write-Log "Configuration path not found: $ConfigurationPath" -Level Error
        return
    }
    Write-Log "Configuration path: $ConfigurationPath"

    # Check for required modules (skip in dry run to allow file discovery testing)
    if (-not $DryRun) {
        if (-not (Test-GraphModules)) {
            return
        }
    }

    # Discover policy files
    $policyFiles = Get-PolicyFiles -BasePath $ConfigurationPath
    if ($policyFiles.Count -eq 0) {
        Write-Log "No policy files found in $ConfigurationPath" -Level Error
        return
    }

    Write-Log "Discovered $($policyFiles.Count) policy files:" -Level Info
    $policyFiles | Group-Object Category | ForEach-Object {
        Write-Log "  $($_.Name): $($_.Count) files"
    }

    # Connect to Graph (skip in dry run if testing file parsing only)
    if (-not $DryRun) {
        if (-not (Connect-IntuneGraph -AuthMethod $AuthMethod -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret)) {
            return
        }
    }

    Write-Host ""
    Write-Log "Processing policy files..." -Level Info
    Write-Host ""

    # Process each policy file
    foreach ($file in $policyFiles) {
        Write-Log "Processing: $($file.Name) ($($file.Category))"

        # Read and parse JSON
        $policyJson = Read-PolicyJsonFile -FilePath $file.Path
        if (-not $policyJson) {
            $script:Stats.Failed++
            continue
        }

        # Determine policy type
        $policyType = Get-PolicyType -PolicyJson $policyJson

        # Get policy name
        $policyName = switch ($policyType) {
            "SettingsCatalog" { $policyJson.name }
            "EndpointSecurity" { $policyJson.displayName }
            "DeviceConfiguration" { $policyJson.displayName }
            default { $file.Name }
        }

        # Check for existing policy (skip in dry run)
        if (-not $DryRun) {
            $exists = Test-PolicyExists -PolicyName $policyName -PolicyType $policyType
            if ($exists) {
                if ($Force) {
                    Write-Log "Policy '$policyName' exists. Removing due to -Force flag..." -Level Warning
                    if (-not (Remove-ExistingPolicy -PolicyName $policyName -PolicyType $policyType)) {
                        $script:Stats.Failed++
                        continue
                    }
                }
                else {
                    Write-Log "Policy '$policyName' already exists. Use -Force to overwrite." -Level Warning
                    $script:Stats.Skipped++
                    continue
                }
            }
        }

        # Import based on policy type
        $success = switch ($policyType) {
            "SettingsCatalog" {
                Import-SettingsCatalogPolicy -PolicyJson $policyJson -DryRun:$DryRun
            }
            "EndpointSecurity" {
                Import-EndpointSecurityPolicy -PolicyJson $policyJson -DryRun:$DryRun
            }
            "DeviceConfiguration" {
                Import-DeviceConfigurationProfile -PolicyJson $policyJson -DryRun:$DryRun
            }
            default {
                Write-Log "Unknown policy type for: $($file.Name)" -Level Error
                $false
            }
        }

        if ($success) {
            $script:Stats.Success++
        }
        else {
            $script:Stats.Failed++
        }
    }

    # Summary
    Write-Host ""
    Write-Log "========================================" -Level Info
    Write-Log "Deployment Summary" -Level Info
    Write-Log "========================================" -Level Info
    Write-Log "  Successful: $($script:Stats.Success)" -Level Success
    Write-Log "  Failed:     $($script:Stats.Failed)" -Level $(if ($script:Stats.Failed -gt 0) { "Error" } else { "Info" })
    Write-Log "  Skipped:    $($script:Stats.Skipped)" -Level $(if ($script:Stats.Skipped -gt 0) { "Warning" } else { "Info" })
    Write-Log "  Total:      $($policyFiles.Count)" -Level Info
    Write-Host ""
    Write-Log "Log file: $LogPath" -Level Info

    if (-not $DryRun) {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Log "Disconnected from Microsoft Graph."
    }
}

# Run main
Main
