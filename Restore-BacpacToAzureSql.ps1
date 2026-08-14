#Requires -Modules Az.Sql, Az.Storage, Az.Network

<#
.SYNOPSIS
    Restores a .bacpac file from Azure Blob Storage to an Azure SQL Database.

.DESCRIPTION
    Imports a .bacpac file stored in an Azure Storage Account blob container
    into a new Azure SQL Database. Designed to run from Azure Cloud Shell.

.PARAMETER ResourceGroupName
    Resource group containing the target SQL Server.

.PARAMETER SqlServerName
    Name of the Azure SQL Server (without .database.windows.net).

.PARAMETER DatabaseName
    Name of the database to create from the bacpac.

.PARAMETER SqlAdminUser
    SQL Server admin username. For SQL auth, this is the SQL admin login.
    For Entra ID auth (-AuthenticationType ADPassword), this is the Entra ID admin UPN (e.g. user@domain.com).

.PARAMETER SqlAdminPassword
    SQL Server admin password (SecureString). For Entra ID auth, this is the Entra ID user's password.

.PARAMETER AuthenticationType
    Authentication type for the import operation.
    - SQL (default): Use SQL Server admin credentials.
    - ADPassword:    Use Microsoft Entra ID (Azure AD) admin credentials.
      Requires an Entra ID admin to be configured on the SQL Server.

.PARAMETER StorageAccountName
    Name of the storage account containing the bacpac.

.PARAMETER StorageContainerName
    Blob container name where the bacpac file is stored.

.PARAMETER BacpacFileName
    Name of the .bacpac file in the container.

.PARAMETER StorageResourceGroupName
    Resource group of the storage account. Defaults to ResourceGroupName if not specified.

.PARAMETER Edition
    Azure SQL Database edition. Default: GeneralPurpose.

.PARAMETER ServiceObjectiveName
    Service objective (SKU). Default: GP_Gen5_2.

.PARAMETER StorageAuthMethod
    How to authenticate to the storage account for the import.
    - Auto (default): Uses SAS token when storage firewall is active (Deny), storage key otherwise.
    - Key:  Always use the storage account access key (StorageAccessKey).
    - SAS:  Always generate a SAS token (SharedAccessKey).

.PARAMETER ImportTimeoutMinutes
    Maximum time to wait for the import to complete, in minutes. Default: 60.
    If the timeout is reached, the script exits but the import continues server-side.

.PARAMETER PreflightOnly
    When specified, runs only the permission and network access checks without performing the actual import.
    SqlAdminUser and SqlAdminPassword are not required in this mode.

.PARAMETER SkipNetworkIsolation
    When specified, forces the import to use public connectivity even when private endpoints are detected.
    Useful when both SQL Server and Storage Account allow Azure services access and network isolation
    imports are slow or stuck.

.PARAMETER MaxSizeBytes
    Max database size in bytes. Default: 5GB.

.PARAMETER ValidateBacpac
    When specified, downloads the BACPAC file and performs comprehensive structural validation:
    - Verifies the file is a valid ZIP archive
    - Checks for required BACPAC internal files (model.xml, Origin.xml, [Content_Types].xml)
    - Detects TDE (Transparent Data Encryption) indicators that may cause import failures
    - Validates the checksum if specified via -ExpectedHash
    - Checks for Azure SQL DB unsupported features (FileStream, Linked Servers, Service Broker, etc.)
    - Extracts compatibility level and collation settings
    - Inventories database objects (tables, views, procs, functions, triggers, indexes)
    - Inventories security principals (users, roles, logins) with Windows/AD user warnings
    - Detects large tables that may slow import
    - Identifies temporal tables, change tracking, and Always Encrypted usage
    This adds processing time but catches corrupt or incompatible files before import.
    Highly recommended for AWS RDS to Azure SQL DB migrations.

.PARAMETER ExpectedHash
    SHA256 hash to verify the BACPAC file against. Use with -ValidateBacpac for full integrity check.
    Get the expected hash with: Get-FileHash -Path "file.bacpac" -Algorithm SHA256

.EXAMPLE
    # Run pre-flight checks only (no import)
    .\Restore-BacpacToAzureSql.ps1 `
        -ResourceGroupName "rg-sql-prod" `
        -SqlServerName "sql-prod-001" `
        -DatabaseName "MyRestoredDB" `
        -StorageAccountName "stbackups001" `
        -StorageContainerName "bacpacs" `
        -BacpacFileName "mydb-2026-03-06.bacpac" `
        -PreflightOnly

.EXAMPLE
    $securePassword = Read-Host -AsSecureString -Prompt "SQL Admin Password"
    .\Restore-BacpacToAzureSql.ps1 `
        -ResourceGroupName "rg-sql-prod" `
        -SqlServerName "sql-prod-001" `
        -DatabaseName "MyRestoredDB" `
        -SqlAdminUser "sqladmin" `
        -SqlAdminPassword $securePassword `
        -StorageAccountName "stbackups001" `
        -StorageContainerName "bacpacs" `
        -BacpacFileName "mydb-2026-03-06.bacpac"

.EXAMPLE
    # Import using Entra ID (Azure AD) admin authentication
    $securePassword = Read-Host -AsSecureString -Prompt "Entra ID Password"
    .\Restore-BacpacToAzureSql.ps1 `
        -ResourceGroupName "rg-sql-prod" `
        -SqlServerName "sql-prod-001" `
        -DatabaseName "MyRestoredDB" `
        -SqlAdminUser "admin@contoso.com" `
        -SqlAdminPassword $securePassword `
        -AuthenticationType ADPassword `
        -StorageAccountName "stbackups001" `
        -StorageContainerName "bacpacs" `
        -BacpacFileName "mydb-2026-03-06.bacpac"

.EXAMPLE
    # Validate BACPAC integrity before import (checks structure, TDE, and optional hash)
    $securePassword = Read-Host -AsSecureString -Prompt "SQL Admin Password"
    .\Restore-BacpacToAzureSql.ps1 `
        -ResourceGroupName "rg-sql-prod" `
        -SqlServerName "sql-prod-001" `
        -DatabaseName "MyRestoredDB" `
        -SqlAdminUser "sqladmin" `
        -SqlAdminPassword $securePassword `
        -StorageAccountName "stbackups001" `
        -StorageContainerName "bacpacs" `
        -BacpacFileName "mydb-2026-03-06.bacpac" `
        -ValidateBacpac `
        -ExpectedHash "A1B2C3D4E5F6..."

.EXAMPLE
    # PARALLEL IMPORT WRAPPER SCRIPT
    # Use this wrapper to import multiple bacpac files in parallel.
    # Requires PowerShell 7+ for ForEach-Object -Parallel.
    # Save as Invoke-ParallelBacpacImport.ps1 or run inline.
    
    # --- BEGIN WRAPPER SCRIPT ---
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory)]
        [string]$SqlServerName,
        
        [Parameter(Mandatory)]
        [string]$StorageAccountName,
        
        [Parameter(Mandatory)]
        [string]$StorageContainerName,
        
        [Parameter(Mandatory)]
        [SecureString]$SqlAdminPassword,
        
        [Parameter()]
        [string]$SqlAdminUser = "sqladmin",
        
        [Parameter()]
        [ValidateSet("SQL", "ADPassword")]
        [string]$AuthenticationType = "SQL",
        
        [Parameter()]
        [int]$ThrottleLimit = 4,  # Azure typically limits ~5 concurrent imports per server
        
        [Parameter()]
        [string]$ScriptPath = ".\Restore-BacpacToAzureSql.ps1"
    )
    
    # Define imports - either inline or load from CSV:
    # $imports = Import-Csv ".\imports.csv"  # Columns: BacpacFileName, TargetDatabaseName
    $imports = @(
        @{ BacpacFileName = "db1-backup.bacpac"; TargetDatabaseName = "DB1_Restored" }
        @{ BacpacFileName = "db2-backup.bacpac"; TargetDatabaseName = "DB2_Restored" }
        @{ BacpacFileName = "db3-backup.bacpac"; TargetDatabaseName = "DB3_Restored" }
    )
    
    # Convert SecureString to exportable format for parallel runspaces
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SqlAdminPassword)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    
    $results = $imports | ForEach-Object -Parallel {
        $import = $_
        $secPwd = ConvertTo-SecureString $using:plainPassword -AsPlainText -Force
        
        try {
            & $using:ScriptPath `
                -ResourceGroupName $using:ResourceGroupName `
                -SqlServerName $using:SqlServerName `
                -DatabaseName $import.TargetDatabaseName `
                -SqlAdminUser $using:SqlAdminUser `
                -SqlAdminPassword $secPwd `
                -AuthenticationType $using:AuthenticationType `
                -StorageAccountName $using:StorageAccountName `
                -StorageContainerName $using:StorageContainerName `
                -BacpacFileName $import.BacpacFileName `
                -ErrorAction Stop
            
            [PSCustomObject]@{
                Database = $import.TargetDatabaseName
                BacpacFile = $import.BacpacFileName
                Status = "Success"
                Error = $null
            }
        }
        catch {
            [PSCustomObject]@{
                Database = $import.TargetDatabaseName
                BacpacFile = $import.BacpacFileName
                Status = "Failed"
                Error = $_.Exception.Message
            }
        }
    } -ThrottleLimit $ThrottleLimit
    
    # Summary report
    $results | Format-Table -AutoSize
    $succeeded = ($results | Where-Object Status -eq "Success").Count
    $failed = ($results | Where-Object Status -eq "Failed").Count
    Write-Host "`nCompleted: $succeeded succeeded, $failed failed" -ForegroundColor $(if ($failed -gt 0) { "Yellow" } else { "Green" })
    # --- END WRAPPER SCRIPT ---

.NOTES
    Parallel Import Considerations:
    - Azure typically allows ~5 concurrent imports per SQL Server
    - Network isolation mode requires PE approval for each import (handled automatically)
    - If using temporary storage firewall changes, all parallel imports share that window
    - Use -ThrottleLimit to control concurrency based on your Azure quotas
    - For large batches, consider staggering starts to avoid PE approval bottlenecks
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$SqlServerName,

    [Parameter(Mandatory)]
    [string]$DatabaseName,

    [Parameter()]
    [string]$SqlAdminUser,

    [Parameter()]
    [SecureString]$SqlAdminPassword,

    [Parameter(Mandatory)]
    [string]$StorageAccountName,

    [Parameter(Mandatory)]
    [string]$StorageContainerName,

    [Parameter()]
    [string]$BacpacFileName,

    [Parameter()]
    [string]$StorageResourceGroupName,

    [Parameter()]
    [ValidateSet("Basic", "Standard", "Premium", "GeneralPurpose", "BusinessCritical", "Hyperscale")]
    [string]$Edition = "GeneralPurpose",

    [Parameter()]
    [string]$ServiceObjectiveName = "GP_Gen5_2",

    [Parameter()]
    [long]$MaxSizeBytes = 5GB,

    [Parameter()]
    [ValidateSet("SQL", "ADPassword")]
    [string]$AuthenticationType = "SQL",

    [Parameter()]
    [ValidateSet("Auto", "Key", "SAS")]
    [string]$StorageAuthMethod = "Auto",

    [Parameter()]
    [ValidateRange(1, 1440)]
    [int]$ImportTimeoutMinutes = 60,

    [Parameter()]
    [switch]$PreflightOnly,

    [Parameter()]
    [switch]$SkipNetworkIsolation,

    [Parameter()]
    [switch]$ValidateBacpac,

    [Parameter()]
    [string]$ExpectedHash
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $StorageResourceGroupName) {
    $StorageResourceGroupName = $ResourceGroupName
}

# === HELPER FUNCTIONS ===

function Restore-StorageNetworkSettings {
    <#
    .SYNOPSIS
        Restores storage firewall and PublicNetworkAccess to their original state.
    #>
    param(
        [string]$RG,
        [string]$AccountName,
        [bool]$RestoreFirewall,
        [bool]$RestorePNA,
        [string]$OriginalBypass,
        [bool]$IsTimedOut
    )
    if ($RestoreFirewall) {
        if ($IsTimedOut) {
            Write-Warning "  Cannot restore firewall automatically — import is still running."
            Write-Warning "  IMPORTANT: Manually restore the firewall after the import completes:"
            Write-Warning "    Update-AzStorageAccountNetworkRuleSet -ResourceGroupName '$RG' -Name '$AccountName' -DefaultAction Deny -Bypass $OriginalBypass"
        } else {
            Write-Host "`nRestoring storage firewall to DENY (Bypass=$OriginalBypass)..." -ForegroundColor Cyan
            Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $RG -Name $AccountName -DefaultAction Deny -Bypass $OriginalBypass | Out-Null
            Write-Host "  Storage firewall restored" -ForegroundColor Green
        }
    }
    if ($RestorePNA) {
        if ($IsTimedOut) {
            Write-Warning "  Cannot restore PublicNetworkAccess automatically — import is still running."
            Write-Warning "  IMPORTANT: Manually restore after the import completes:"
            Write-Warning "    Set-AzStorageAccount -ResourceGroupName '$RG' -Name '$AccountName' -PublicNetworkAccess Disabled"
        } else {
            Write-Host "Restoring PublicNetworkAccess to Disabled..." -ForegroundColor Cyan
            Set-AzStorageAccount -ResourceGroupName $RG -Name $AccountName -PublicNetworkAccess Disabled | Out-Null
            Write-Host "  PublicNetworkAccess restored to Disabled" -ForegroundColor Green
        }
    }
}

function Get-PeNetworkDetails {
    <#
    .SYNOPSIS
        Retrieves VNet, Subnet, and private IP details for a private endpoint.
    #>
    param([string]$PeResourceId, [string]$Label)

    $parts = $PeResourceId -split '/'
    $peName = $parts[-1]
    $peRg = $parts[4]
    $pe = Get-AzPrivateEndpoint -Name $peName -ResourceGroupName $peRg -ErrorAction SilentlyContinue
    if (-not $pe) { return $null }

    $subnetId = $pe.Subnet.Id
    $vnetName = ($subnetId -split '/')[8]
    $subnetName = ($subnetId -split '/')[-1]
    $vnetId = ($subnetId -split '/subnets/')[0]

    Write-Host "`n  $Label PE: $($pe.Name)" -ForegroundColor White
    Write-Host "    VNet/Subnet:  $vnetName / $subnetName" -ForegroundColor White
    Write-Host "    Resource Group: $peRg" -ForegroundColor White

    # Check NIC and private IP
    $nicId = $pe.NetworkInterfaces[0].Id
    $nicParts = $nicId -split '/'
    $nic = Get-AzNetworkInterface -Name $nicParts[-1] -ResourceGroupName $nicParts[4] -ErrorAction SilentlyContinue
    $privateIp = $null
    if ($nic) {
        $privateIp = $nic.IpConfigurations[0].PrivateIpAddress
        Write-Host "    Private IP:   $privateIp" -ForegroundColor Green
    }

    # Check group IDs for storage PEs
    $groupIds = $pe.PrivateLinkServiceConnections.GroupIds
    if ($groupIds) {
        Write-Host "    Sub-resource:  $($groupIds -join ', ')" -ForegroundColor White
        if ($groupIds -notcontains "blob" -and $Label -eq 'Storage') {
            Write-Warning "    The storage PE targets '$($groupIds -join ', ')' — import requires a 'blob' sub-resource PE."
        }
    }

    [PSCustomObject]@{
        Name       = $pe.Name
        SubnetId   = $subnetId
        VNetName   = $vnetName
        SubnetName = $subnetName
        VNetId     = $vnetId
        PrivateIp  = $privateIp
        RG         = $peRg
    }
}

function Wait-StorageAccessPropagation {
    <#
    .SYNOPSIS
        Polls storage access until it succeeds or times out (5 min).
    #>
    param(
        [string]$AccountName,
        [string]$AccountKey,
        [string]$ContainerName,
        [string]$BlobName,
        [int]$TimeoutMinutes = 5,
        [int]$IntervalSeconds = 15
    )
    $start = Get-Date
    while (((Get-Date) - $start).TotalMinutes -lt $TimeoutMinutes) {
        try {
            $ctx = New-AzStorageContext -StorageAccountName $AccountName -StorageAccountKey $AccountKey
            if ($BlobName) {
                $null = Get-AzStorageBlob -Container $ContainerName -Blob $BlobName -Context $ctx -ErrorAction Stop
            } else {
                $null = Get-AzStorageContainer -Name $ContainerName -Context $ctx -ErrorAction Stop
            }
            return $true
        } catch {
            $elapsed = [math]::Round(((Get-Date) - $start).TotalSeconds)
            $msg = $_.Exception.Message -replace "`n", " "
            if ($msg.Length -gt 120) { $msg = $msg.Substring(0, 120) + "..." }
            Write-Host "    [$($elapsed)s] $msg" -ForegroundColor Yellow
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
    return $false
}

function Test-BacpacStructure {
    <#
    .SYNOPSIS
        Validates BACPAC ZIP structure and performs comprehensive Azure SQL DB compatibility checks.
    .DESCRIPTION
        Performs full structural validation of a BACPAC file including:
        - ZIP archive integrity and required files (model.xml, Origin.xml, [Content_Types].xml)
        - TDE/encryption detection
        - Azure SQL DB unsupported feature detection
        - Database size estimation
        - Compatibility level and collation checks
        - User/login inventory with Windows auth warnings
        - Object count summary
        - Large table detection
        - Temporal table detection
    .OUTPUTS
        PSCustomObject with validation results, warnings, and metadata.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$LocalFilePath
    )
    $result = [PSCustomObject]@{
        IsValid               = $false
        HasTdeIndicators      = $false
        MissingFiles          = @()
        Messages              = @()
        Warnings              = @()
        FileCount             = 0
        EstimatedDataSizeMB   = 0
        CompatibilityLevel    = $null
        Collation             = $null
        DatabaseSchemaProvider = $null
        ObjectCounts          = @{}
        UserCounts            = @{}
        UnsupportedFeatures   = @()
        LargeTables           = @()
    }
    $requiredFiles = @('model.xml', 'Origin.xml', '[Content_Types].xml')
    
    # Azure SQL DB unsupported feature patterns
    $unsupportedPatterns = @(
        @{ Pattern = 'Type="SqlFilegroup".*Relationship.*FileStream|Type="SqlFileTable"'; Message = 'FileStream/FileTable not supported in Azure SQL DB' }
        @{ Pattern = 'Type="SqlLinkedServer"'; Message = 'Linked Servers not supported in Azure SQL DB' }
        @{ Pattern = 'Type="SqlBrokerService"|Type="SqlServiceBroker"'; Message = 'Service Broker has limited support in Azure SQL DB' }
        @{ Pattern = 'Type="SqlExtendedStoredProcedure"'; Message = 'Extended Stored Procedures (xp_) not supported in Azure SQL DB' }
        @{ Pattern = 'Type="SqlClrAssembly".*PERMISSION_SET.*"(UNSAFE|EXTERNAL_ACCESS)"'; Message = 'CLR assemblies with UNSAFE/EXTERNAL_ACCESS require extra configuration' }
        @{ Pattern = 'Type="SqlCryptographicProvider"'; Message = 'External Cryptographic Providers not supported in Azure SQL DB' }
        @{ Pattern = 'Type="SqlCredential".*aws|s3|rds'; Message = 'AWS-specific credentials detected — will need removal or replacement' }
        @{ Pattern = 'Type="SqlDatabaseMail"'; Message = 'Database Mail not supported (use SendGrid/Logic Apps instead)' }
        @{ Pattern = 'Type="SqlFullTextCatalog"'; Message = 'Full-Text Search (verify configuration for Azure SQL DB)' }
        @{ Pattern = 'CONTAINMENT\s*=\s*PARTIAL'; Message = 'Contained database users detected' }
    )
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($LocalFilePath)
        $entryNames = $zip.Entries | ForEach-Object { $_.FullName }
        $result.FileCount = $zip.Entries.Count
        
        # Check required files
        foreach ($reqFile in $requiredFiles) {
            $found = $entryNames | Where-Object { $_ -eq $reqFile -or $_ -like "*/$reqFile" }
            if (-not $found) {
                $result.MissingFiles += $reqFile
            }
        }
        
        if ($result.MissingFiles.Count -eq 0) {
            $result.IsValid = $true
            $result.Messages += "BACPAC structure is valid ($($result.FileCount) entries)"
        } else {
            $result.Messages += "BACPAC is missing required files: $($result.MissingFiles -join ', ')"
        }
        
        # --- Data Size Estimation ---
        $dataFiles = $zip.Entries | Where-Object { $_.FullName -like 'Data/*' }
        if ($dataFiles) {
            $totalDataSize = ($dataFiles | Measure-Object -Property Length -Sum).Sum
            $result.EstimatedDataSizeMB = [math]::Round($totalDataSize / 1MB, 2)
            $result.Messages += "Estimated data size: $($result.EstimatedDataSizeMB) MB (compressed in BACPAC)"
            
            # --- Large Table Detection ---
            $largeDataFiles = $dataFiles | Where-Object { $_.Length -gt 104857600 } | ForEach-Object {
                # Extract table name from path like "Data/dbo.TableName/TableName.BCP"
                $tablePath = $_.FullName -replace '^Data/', '' -replace '/[^/]+$', ''
                [PSCustomObject]@{
                    Table  = $tablePath
                    SizeMB = [math]::Round($_.Length / 1MB, 1)
                }
            }
            if ($largeDataFiles) {
                $result.LargeTables = $largeDataFiles
                $result.Warnings += "Large tables detected (>100MB, may slow import): $($largeDataFiles.Count) tables"
                foreach ($lt in $largeDataFiles | Select-Object -First 5) {
                    $result.Messages += "  - $($lt.Table): $($lt.SizeMB) MB"
                }
                if ($largeDataFiles.Count -gt 5) {
                    $result.Messages += "  - ... and $($largeDataFiles.Count - 5) more large tables"
                }
            }
        }
        
        # --- Origin.xml Analysis ---
        $originEntry = $zip.Entries | Where-Object { $_.FullName -eq 'Origin.xml' }
        if ($originEntry) {
            $stream = $originEntry.Open()
            $reader = New-Object System.IO.StreamReader($stream)
            $originContent = $reader.ReadToEnd()
            $reader.Close()
            $stream.Close()
            
            # Check for TDE encryption enabled flag
            if ($originContent -match 'Property.*Name="EncryptionEnabled".*Value="True"' -or 
                $originContent -match '<EncryptionEnabled>true</EncryptionEnabled>' -or
                $originContent -match 'EncryptionEnabled.*True') {
                $result.HasTdeIndicators = $true
                $result.Warnings += "TDE encryption indicators found — import may fail if encryption keys are unavailable"
            }
            
            # Check for master key references
            if ($originContent -match 'DatabaseMasterKey|ColumnMasterKey|ColumnEncryptionKey') {
                $result.Messages += "NOTE: Database contains encryption key references (DMK/CMK/CEK)"
            }
            
            # Extract compatibility level
            if ($originContent -match 'CompatibilityLevel[">](\d+)' -or
                $originContent -match 'Property.*Name="CompatibilityLevel".*Value="(\d+)"') {
                $result.CompatibilityLevel = $Matches[1]
                if ([int]$result.CompatibilityLevel -lt 130) {
                    $result.Warnings += "Compatibility level $($result.CompatibilityLevel) is older (SQL 2016=130) — consider upgrading post-import"
                } else {
                    $result.Messages += "Compatibility level: $($result.CompatibilityLevel)"
                }
            }
            
            # Extract collation
            if ($originContent -match 'Collation[">]([^"<]+)' -or
                $originContent -match 'Property.*Name="Collation".*Value="([^"]+)"') {
                $result.Collation = $Matches[1]
                if ($result.Collation -ne 'SQL_Latin1_General_CP1_CI_AS') {
                    $result.Messages += "Collation: $($result.Collation) (non-default — ensure target server supports it)"
                } else {
                    $result.Messages += "Collation: $($result.Collation) (Azure SQL DB default)"
                }
            }
        }
        
        # --- model.xml Analysis ---
        $modelEntry = $zip.Entries | Where-Object { $_.FullName -eq 'model.xml' }
        if ($modelEntry) {
            $stream = $modelEntry.Open()
            $reader = New-Object System.IO.StreamReader($stream)
            $modelContent = $reader.ReadToEnd()
            $reader.Close()
            $stream.Close()
            
            # Extract Database Schema Provider (DSP) version
            if ($modelContent -match 'DataSchemaModel.*DatabaseSchemaProvider="([^"]+)"') {
                $result.DatabaseSchemaProvider = $Matches[1]
                if ($result.DatabaseSchemaProvider -notmatch 'SqlAzure|Sql1[3456]0|Sql160') {
                    $result.Warnings += "Database Schema Provider '$($result.DatabaseSchemaProvider)' may indicate older SQL version"
                } else {
                    $result.Messages += "Schema Provider: $($result.DatabaseSchemaProvider)"
                }
            }
            
            # Check for Always Encrypted columns
            if ($modelContent -match 'ColumnEncryptionKeyStoreProviderName|ENCRYPTION_TYPE') {
                $result.Messages += "NOTE: Database uses Always Encrypted columns — ensure column master keys are accessible"
            }
            
            # Check for Temporal Tables
            if ($modelContent -match 'SystemVersioningEnabled|HistoryTable|SYSTEM_TIME|Type="SqlTableTemporalType"') {
                $result.Messages += "NOTE: Temporal (system-versioned) tables detected — verify history retention settings post-import"
            }
            
            # Check for Change Tracking
            if ($modelContent -match 'CHANGE_TRACKING|Type="SqlChangeTrackingTable"') {
                $result.Messages += "NOTE: Change Tracking enabled — verify configuration post-import"
            }
            
            # --- Unsupported Feature Detection ---
            foreach ($pattern in $unsupportedPatterns) {
                if ($modelContent -match $pattern.Pattern) {
                    $result.UnsupportedFeatures += $pattern.Message
                    $result.Warnings += $pattern.Message
                }
            }
            
            # --- Object Count Summary ---
            $result.ObjectCounts = @{
                Tables       = ([regex]::Matches($modelContent, 'Type="SqlTable"')).Count
                Views        = ([regex]::Matches($modelContent, 'Type="SqlView"')).Count
                StoredProcs  = ([regex]::Matches($modelContent, 'Type="SqlProcedure"')).Count
                Functions    = ([regex]::Matches($modelContent, 'Type="Sql(Scalar|Table|Inline)Function"')).Count
                Triggers     = ([regex]::Matches($modelContent, 'Type="SqlDmlTrigger"')).Count
                Indexes      = ([regex]::Matches($modelContent, 'Type="SqlIndex"')).Count
                Constraints  = ([regex]::Matches($modelContent, 'Type="Sql(PrimaryKey|ForeignKey|UniqueConstraint|CheckConstraint|DefaultConstraint)"')).Count
                Schemas      = ([regex]::Matches($modelContent, 'Type="SqlSchema"')).Count
            }
            $objSummary = "Objects: $($result.ObjectCounts.Tables) tables, $($result.ObjectCounts.Views) views, " +
                          "$($result.ObjectCounts.StoredProcs) procs, $($result.ObjectCounts.Functions) funcs, " +
                          "$($result.ObjectCounts.Triggers) triggers, $($result.ObjectCounts.Indexes) indexes"
            $result.Messages += $objSummary
            
            # --- User/Login Inventory ---
            $sqlUserMatches = [regex]::Matches($modelContent, 'Type="SqlUser"')
            $roleMatches = [regex]::Matches($modelContent, 'Type="SqlRole"')
            $windowsUserMatches = [regex]::Matches($modelContent, 'AuthenticationType.*Windows|Type="SqlUser"[^>]*ExternalUser')
            $loginMatches = [regex]::Matches($modelContent, 'Type="SqlLogin"')
            
            $result.UserCounts = @{
                SqlUsers      = $sqlUserMatches.Count
                Roles         = $roleMatches.Count
                WindowsUsers  = $windowsUserMatches.Count
                Logins        = $loginMatches.Count
            }
            
            $userSummary = "Security principals: $($result.UserCounts.SqlUsers) users, $($result.UserCounts.Roles) roles, $($result.UserCounts.Logins) logins"
            $result.Messages += $userSummary
            
            if ($result.UserCounts.WindowsUsers -gt 0) {
                $result.Warnings += "$($result.UserCounts.WindowsUsers) Windows/AD users found — will need Entra ID mapping or recreation"
            }
            
            # Check for orphaned users (users without corresponding logins)
            if ($result.UserCounts.SqlUsers -gt $result.UserCounts.Logins + 2) {  # +2 for dbo and guest
                $result.Messages += "NOTE: More users than logins — some may be contained database users or orphans"
            }
            
            # Check for problematic database roles referencing external resources
            if ($modelContent -match 'SqlDatabaseCredential|ExternalDataSource|ExternalFileFormat') {
                $result.Messages += "NOTE: External data sources/credentials detected — may need reconfiguration for Azure"
            }
        }
        
        $zip.Dispose()
        
        # --- Final Summary ---
        if ($result.Warnings.Count -gt 0) {
            $result.Messages += ""
            $result.Messages += "=== WARNINGS ($($result.Warnings.Count)) ==="
            foreach ($warn in $result.Warnings) {
                $result.Messages += "  ! $warn"
            }
        }
        
        if ($result.UnsupportedFeatures.Count -gt 0) {
            $result.Messages += ""
            $result.Messages += "=== UNSUPPORTED FEATURES ($($result.UnsupportedFeatures.Count)) ==="
            $result.Messages += "These features may cause import failures or require post-import remediation:"
            foreach ($feat in $result.UnsupportedFeatures) {
                $result.Messages += "  - $feat"
            }
        }
        
    } catch {
        $result.IsValid = $false
        $result.Messages += "Failed to read BACPAC as ZIP archive: $($_.Exception.Message)"
    }
    
    return $result
}

function Get-BacpacFileHash {
    <#
    .SYNOPSIS
        Computes SHA256 hash of a local file.
    #>
    param([string]$FilePath)
    $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
    return $hash.Hash
}

function Resolve-EndpointDns {
    <#
    .SYNOPSIS
        Resolves a hostname and reports whether it points to a private or public IP.
    #>
    param([string]$Hostname, [string]$Label)
    try {
        $dnsResult = Resolve-DnsName $Hostname -ErrorAction SilentlyContinue
        $resolvedIp = ($dnsResult | Where-Object { $_.Type -eq 'A' }).IPAddress
        if ($resolvedIp) {
            $isPrivate = $resolvedIp | Where-Object { $_ -match '^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\.' }
            if ($isPrivate) {
                Write-Host "    $Hostname -> $($resolvedIp -join ', ') (PRIVATE)" -ForegroundColor Green
            } else {
                Write-Host "    $Hostname -> $($resolvedIp -join ', ') (PUBLIC)" -ForegroundColor Yellow
                Write-Host "    (From this host, $Label resolves to public IP. The import service will use its own managed PE.)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "    Could not resolve $Hostname" -ForegroundColor Yellow
    }
}

function Approve-ManagedPrivateEndpoint {
    <#
    .SYNOPSIS
        Approves pending managed PEs for a resource, filtering by import request ID.
    #>
    param(
        [string]$ResourceId,
        [string]$Label,
        [string]$ImportRequestId,
        [ref]$ElapsedStr,
        [datetime]$ImportStartTime
    )
    $peFilter = {
        $_.PrivateLinkServiceConnectionState.Status -eq 'Pending' -and
        $_.PrivateEndpoint.Id -match 'ImportExportPrivateLink' -and
        (-not $ImportRequestId -or $_.PrivateEndpoint.Id -match $ImportRequestId)
    }
    $pendingPEs = @(Get-AzPrivateEndpointConnection -PrivateLinkResourceId $ResourceId -ErrorAction SilentlyContinue |
        Where-Object $peFilter)
    $approved = $false
    foreach ($pe in $pendingPEs) {
        $peName = ($pe.PrivateEndpoint.Id -split '/')[-1]
        Write-Host "  [$($ElapsedStr.Value)] Found pending $Label PE: $peName — waiting 30s before approving..." -ForegroundColor Cyan
        Start-Sleep -Seconds 30
        $ElapsedStr.Value = '{0:mm\:ss}' -f ((Get-Date) - $ImportStartTime)
        try {
            Approve-AzPrivateEndpointConnection -ResourceId $pe.Id -Description "Auto-approved for import" -ErrorAction Stop | Out-Null
            Write-Host "  [$($ElapsedStr.Value)] $Label managed PE approved: $peName" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -match 'StatusNotPending|already approved|not Pending') {
                Write-Host "  [$($ElapsedStr.Value)] $Label PE already approved (auto-approved by Azure): $peName" -ForegroundColor Green
            } else { throw }
        }
        $approved = $true
    }
    return $approved
}

# === PRE-FLIGHT: PERMISSION & NETWORK CHECKS ===
Write-Host "`n=== Pre-flight checks ===" -ForegroundColor Cyan

# --- Get current identity context ---
$currentContext = Get-AzContext
$currentUser = $currentContext.Account.Id
$accountType = $currentContext.Account.Type  # User, ServicePrincipal, ManagedService, etc.
Write-Host "Running as: $currentUser (Type: $accountType)" -ForegroundColor White

# Build the appropriate parameter for Get-AzRoleAssignment based on identity type
$roleAssignmentParams = @{ ErrorAction = 'SilentlyContinue' }
switch ($accountType) {
    'User' {
        $roleAssignmentParams['SignInName'] = $currentUser
    }
    'ServicePrincipal' {
        $sp = Get-AzADServicePrincipal -ApplicationId $currentUser -ErrorAction SilentlyContinue
        if ($sp) {
            $roleAssignmentParams['ObjectId'] = $sp.Id
        }
    }
    default {
        # ManagedService (Cloud Shell MSI) — the Account.Id is not a GUID.
        # Skip identity-scoped lookup; query all assignments on the resource group and
        # let the user review from the output.
        Write-Host "  Managed identity detected — RBAC check will show all assignments on the resource group." -ForegroundColor Yellow
    }
}

# --- Check RBAC permissions on SQL Server resource group ---
Write-Host "`nChecking RBAC permissions on SQL Server resource group '$ResourceGroupName'..." -ForegroundColor Cyan
$sqlRoleAssignments = Get-AzRoleAssignment @roleAssignmentParams -ResourceGroupName $ResourceGroupName
$sqlRequiredRoles = @("Contributor", "Owner", "SQL DB Contributor", "SQL Server Contributor")
$sqlMatchedRoles = $sqlRoleAssignments | Where-Object { $sqlRequiredRoles -contains $_.RoleDefinitionName }
if ($sqlMatchedRoles) {
    $uniqueSqlRoles = ($sqlMatchedRoles.RoleDefinitionName | Select-Object -Unique) -join ', '
    Write-Host "  SQL RG roles present: $uniqueSqlRoles" -ForegroundColor Green
} else {
    $uniqueAllSqlRoles = ($sqlRoleAssignments.RoleDefinitionName | Select-Object -Unique) -join ', '
    Write-Warning "  No standard SQL contributor/owner role found on resource group '$ResourceGroupName'. Import may fail if permissions are insufficient. Roles found: $uniqueAllSqlRoles"
}

# --- Check RBAC permissions on Storage Account resource group ---
Write-Host "Checking RBAC permissions on Storage Account resource group '$StorageResourceGroupName'..." -ForegroundColor Cyan
$storageRoleAssignments = Get-AzRoleAssignment @roleAssignmentParams -ResourceGroupName $StorageResourceGroupName
$storageRequiredRoles = @("Contributor", "Owner", "Storage Account Contributor", "Reader and Data Access", "Storage Blob Data Reader", "Storage Blob Data Contributor")
$storageMatchedRoles = $storageRoleAssignments | Where-Object { $storageRequiredRoles -contains $_.RoleDefinitionName }
if ($storageMatchedRoles) {
    $uniqueStorageRoles = ($storageMatchedRoles.RoleDefinitionName | Select-Object -Unique) -join ', '
    Write-Host "  Storage RG roles present: $uniqueStorageRoles" -ForegroundColor Green
} else {
    $uniqueAllStorageRoles = ($storageRoleAssignments.RoleDefinitionName | Select-Object -Unique) -join ', '
    Write-Warning "  No standard storage contributor/reader role found on resource group '$StorageResourceGroupName'. You need at least key-list access or a data-plane role. Roles found: $uniqueAllStorageRoles"
}

# --- Validate the SQL Server exists (and detect SQL MI) ---
Write-Host "`nValidating SQL Server '$SqlServerName' in resource group '$ResourceGroupName'..." -ForegroundColor Cyan
$sqlServer = Get-AzSqlServer -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -ErrorAction SilentlyContinue
if (-not $sqlServer) {
    # Check if this is a SQL Managed Instance instead
    $sqlMi = Get-AzSqlInstance -ResourceGroupName $ResourceGroupName -Name $SqlServerName -ErrorAction SilentlyContinue
    if ($sqlMi) {
        Write-Host "  Found SQL Managed Instance: $($sqlMi.FullyQualifiedDomainName)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  NOTE: '$SqlServerName' is a SQL Managed Instance, not an Azure SQL Server." -ForegroundColor Yellow
        Write-Host "  SQL MI does not support New-AzSqlDatabaseImport. To restore a bacpac to SQL MI, use one of:" -ForegroundColor Yellow
        Write-Host "" 
        Write-Host "  1. SqlPackage (recommended):" -ForegroundColor White
        Write-Host "     sqlpackage /Action:Import /TargetServerName:\"$($sqlMi.FullyQualifiedDomainName)\"`` " -ForegroundColor White
        Write-Host "       /TargetDatabaseName:\"$DatabaseName\" /TargetUser:\"<admin>\" /TargetPassword:\"<password>\"`` " -ForegroundColor White
        Write-Host "       /SourceFile:\"https://$StorageAccountName.blob.core.windows.net/$StorageContainerName/<file.bacpac>\"" -ForegroundColor White
        Write-Host ""
        Write-Host "  2. Azure CLI:" -ForegroundColor White
        Write-Host "     az sql midb restore --mi '$SqlServerName' -g '$ResourceGroupName' ..." -ForegroundColor White
        Write-Host ""
        Write-Host "  3. SSMS Import Data-tier Application wizard" -ForegroundColor White
        throw "This script supports Azure SQL Database (logical server) only. '$SqlServerName' is a SQL Managed Instance."
    } else {
        throw "SQL Server '$SqlServerName' not found in resource group '$ResourceGroupName'. Verify the server name and resource group are correct."
    }
}
Write-Host "  Found SQL Server: $($sqlServer.FullyQualifiedDomainName)" -ForegroundColor Green

# --- Check SQL Server private endpoints ---
Write-Host "Checking SQL Server private endpoint connections..." -ForegroundColor Cyan
$sqlPrivateEndpointId = $null
$sqlPrivateEndpoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $sqlServer.ResourceId -ErrorAction SilentlyContinue
$sqlApprovedPEs = @($sqlPrivateEndpoints | Where-Object { $_.PrivateLinkServiceConnectionState.Status -eq "Approved" })
if ($sqlApprovedPEs) {
    Write-Host "  SQL Server private endpoints found ($($sqlApprovedPEs.Count) approved):" -ForegroundColor Green
    foreach ($pe in $sqlApprovedPEs) {
        $peId = ($pe.PrivateEndpoint.Id -split '/')[-1]
        Write-Host "    - $peId (Status: $($pe.PrivateLinkServiceConnectionState.Status))" -ForegroundColor Green
    }
    # Use the first approved private endpoint for network isolation
    $sqlPrivateEndpointId = $sqlApprovedPEs[0].PrivateEndpoint.Id
} else {
    Write-Host "  No approved private endpoints found on SQL Server" -ForegroundColor Yellow
}

# --- Check SQL Server public network access ---
Write-Host "Checking SQL Server public network access..." -ForegroundColor Cyan
if ($sqlServer.PublicNetworkAccess -eq "Disabled") {
    if ($sqlPrivateEndpointId) {
        Write-Host "  Public network access is DISABLED but a private endpoint is available — import will use network isolation." -ForegroundColor Green
    } else {
        throw "SQL Server '$SqlServerName' has public network access DISABLED and no approved private endpoints were found. Enable public access or create a private endpoint before retrying."
    }
} else {
    Write-Host "  Public network access: $($sqlServer.PublicNetworkAccess)" -ForegroundColor Green
}

# --- Check SQL Server firewall rules (only relevant when public access is enabled) ---
if ($sqlServer.PublicNetworkAccess -ne "Disabled") {
    Write-Host "Checking SQL Server firewall rules..." -ForegroundColor Cyan
    $firewallRules = Get-AzSqlServerFirewallRule -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName
    $allowAzureServices = $firewallRules | Where-Object {
        $_.StartIpAddress -eq "0.0.0.0" -and $_.EndIpAddress -eq "0.0.0.0"
    }
    if ($allowAzureServices) {
        Write-Host "  'Allow Azure services' firewall rule is ENABLED (required for import service)" -ForegroundColor Green
    } else {
        Write-Warning "  'Allow Azure services and resources to access this server' firewall rule is NOT found."
        Write-Warning "  The Azure SQL import service connects from Azure-internal IPs. This rule is typically required unless using private endpoints."
        Write-Warning "  Firewall rules present: $($firewallRules.FirewallRuleName -join ', ')"
        if (-not $sqlPrivateEndpointId) {
            $proceed = Read-Host "  Do you want to continue anyway? (y/N)"
            if ($proceed -notin @('y', 'Y', 'yes')) {
                throw "Aborted. Add the 'Allow Azure services' firewall rule: Set-AzSqlServerFirewallRule -ResourceGroupName '$ResourceGroupName' -ServerName '$SqlServerName' -FirewallRuleName 'AllowAllAzureIps' -StartIpAddress '0.0.0.0' -EndIpAddress '0.0.0.0'"
            }
        } else {
            Write-Host "  Private endpoint is available — firewall rule is not strictly required." -ForegroundColor Green
        }
    }
}

# --- Check that target database does not already exist ---
$existingDb = Get-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -DatabaseName $DatabaseName -ErrorAction SilentlyContinue
if ($existingDb -and $existingDb.DatabaseName -ne 'master') {
    Write-Warning "Database '$DatabaseName' already exists on server '$SqlServerName'."
    Write-Warning "  Edition: $($existingDb.Edition), Status: $($existingDb.Status), Size: $($existingDb.MaxSizeBytes / 1GB) GB"
    $overwrite = Read-Host "  Do you want to DROP and recreate it from the bacpac? (yes/N)"
    if ($overwrite -notin @('yes')) {
        throw "Aborted. Database '$DatabaseName' already exists. Choose a different name or confirm overwrite by typing 'yes'."
    }
    Write-Host "  Removing existing database '$DatabaseName'..." -ForegroundColor Yellow
    Remove-AzSqlDatabase -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -DatabaseName $DatabaseName -Force
    Write-Host "  Database '$DatabaseName' removed." -ForegroundColor Green
}

# --- Check Storage Account network access ---
Write-Host "`nValidating Storage Account '$StorageAccountName' in resource group '$StorageResourceGroupName'..." -ForegroundColor Cyan
$storageAccount = Get-AzStorageAccount -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-not $storageAccount) {
    # Check if the resource group itself exists
    $rgExists = Get-AzResourceGroup -Name $StorageResourceGroupName -ErrorAction SilentlyContinue
    if (-not $rgExists) {
        throw "Resource group '$StorageResourceGroupName' not found. Verify the -StorageResourceGroupName parameter."
    }
    throw "Storage account '$StorageAccountName' not found in resource group '$StorageResourceGroupName'. Verify the -StorageAccountName and -StorageResourceGroupName parameters."
}
Write-Host "  Found Storage Account: $($storageAccount.PrimaryEndpoints.Blob)" -ForegroundColor Green

Write-Host "Checking Storage Account network access..." -ForegroundColor Cyan
# Check if public network access is disabled (overrides all firewall rules)
$restorePublicNetworkAccess = $false
if ($storageAccount.PublicNetworkAccess -eq 'Disabled') {
    Write-Warning "  Storage account '$StorageAccountName' has PublicNetworkAccess DISABLED."
    Write-Warning "  When disabled, ALL public endpoint access is blocked — firewall rules have NO effect."
    Write-Warning "  The SQL import service requires public endpoint access (even with 'Allow Azure services')."
    if ($SkipNetworkIsolation) {
        $enablePna = Read-Host "  Temporarily enable PublicNetworkAccess for the import? It will be restored after. (y/N)"
        if ($enablePna -in @('y', 'Y', 'yes')) {
            Write-Host "  Enabling PublicNetworkAccess on '$StorageAccountName'..." -ForegroundColor Cyan
            Set-AzStorageAccount -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName -PublicNetworkAccess Enabled | Out-Null
            $restorePublicNetworkAccess = $true
            # Refresh the storage account object to reflect the change
            $storageAccount = Get-AzStorageAccount -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName
            Write-Host "  PublicNetworkAccess enabled (will be restored to Disabled after import)" -ForegroundColor Green

            # Also ensure the firewall DefaultAction is Allow — needed for the import service
            $currentRuleSet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageResourceGroupName -AccountName $StorageAccountName
            if ($currentRuleSet.DefaultAction -eq 'Deny') {
                Write-Host "  Firewall DefaultAction is Deny — setting to Allow for import..." -ForegroundColor Cyan
                Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName `
                    -DefaultAction Allow -Bypass $currentRuleSet.Bypass | Out-Null
                Write-Host "  Firewall DefaultAction set to Allow" -ForegroundColor Green
            }

            # Wait for PublicNetworkAccess change to propagate (can take up to 5 minutes)
            Write-Host "  Waiting for PublicNetworkAccess change to propagate..." -ForegroundColor Cyan
            $pnaTempKeys = Get-AzStorageAccountKey -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName
            $pnaVerified = Wait-StorageAccessPropagation -AccountName $StorageAccountName -AccountKey $pnaTempKeys[0].Value `
                -ContainerName $StorageContainerName
            if ($pnaVerified) {
                Write-Host "  PublicNetworkAccess verified — storage is accessible." -ForegroundColor Green
            } else {
                Write-Warning "  Could not verify access after 5 minutes. Proceeding anyway..."
            }
        } else {
            throw "Import cannot proceed with PublicNetworkAccess Disabled. Enable it or remove -SkipNetworkIsolation to use network isolation."
        }
    } else {
        Write-Host "  Network isolation will use managed private endpoints — PublicNetworkAccess does not need to be enabled." -ForegroundColor Green
    }
} else {
    Write-Host "  PublicNetworkAccess: $($storageAccount.PublicNetworkAccess ?? 'Enabled (default)')" -ForegroundColor Green
}
$storagePrivateEndpointId = $null

# Check for private endpoints on storage account
Write-Host "Checking Storage Account private endpoint connections..." -ForegroundColor Cyan
$storagePrivateEndpoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $storageAccount.Id -ErrorAction SilentlyContinue
$storageApprovedPEs = @($storagePrivateEndpoints | Where-Object { $_.PrivateLinkServiceConnectionState.Status -eq "Approved" })
if ($storageApprovedPEs) {
    Write-Host "  Storage private endpoints found ($($storageApprovedPEs.Count) approved):" -ForegroundColor Green
    foreach ($pe in $storageApprovedPEs) {
        $peId = ($pe.PrivateEndpoint.Id -split '/')[-1]
        Write-Host "    - $peId (Status: $($pe.PrivateLinkServiceConnectionState.Status))" -ForegroundColor Green
    }
    $storagePrivateEndpointId = $storageApprovedPEs[0].PrivateEndpoint.Id
} else {
    Write-Host "  No approved private endpoints found on Storage Account" -ForegroundColor Yellow
}

$networkRuleSet = $storageAccount.NetworkRuleSet
if ($networkRuleSet.DefaultAction -eq "Deny") {
    Write-Warning "  Storage account '$StorageAccountName' default network rule is DENY (firewall enabled)."
    $trustedServices = $networkRuleSet.Bypass
    if ($trustedServices -match "AzureServices") {
        Write-Host "  'Allow trusted Microsoft services' bypass is ENABLED — SQL import service can access the storage." -ForegroundColor Green
    } elseif ($storagePrivateEndpointId) {
        Write-Host "  Trusted services bypass is not enabled, but a private endpoint is available — import will use network isolation." -ForegroundColor Green
    } else {
        Write-Warning "  'Allow trusted Microsoft services' bypass is NOT enabled and no private endpoints found."
        Write-Warning "  The SQL import service may not be able to reach the bacpac file."
        Write-Warning "  Current bypass: $trustedServices"
        $proceed = Read-Host "  Do you want to continue anyway? (y/N)"
        if ($proceed -notin @('y', 'Y', 'yes')) {
            throw "Aborted. Enable trusted services bypass: Update-AzStorageAccountNetworkRuleSet -ResourceGroupName '$StorageResourceGroupName' -Name '$StorageAccountName' -Bypass AzureServices"
        }
    }
} else {
    Write-Host "  Storage account network default action: Allow (no firewall restrictions)" -ForegroundColor Green
}

# --- Determine if network isolation is needed ---
$useNetworkIsolation = $false
if ($SkipNetworkIsolation) {
    Write-Host "`nNetwork isolation mode: SKIPPED (user requested -SkipNetworkIsolation)" -ForegroundColor Yellow
    if ($sqlServer.PublicNetworkAccess -eq 'Disabled') {
        Write-Warning "  SQL Server public access is DISABLED — import may fail without network isolation."
    }
    if ($networkRuleSet.DefaultAction -eq 'Deny' -and $networkRuleSet.Bypass -notmatch 'AzureServices') {
        Write-Warning "  Storage firewall is DENY without trusted services bypass — import may fail without network isolation."
    }
} elseif ($sqlPrivateEndpointId -or $storagePrivateEndpointId) {
    $useNetworkIsolation = $true
    Write-Host "`nNetwork isolation mode: ENABLED" -ForegroundColor Cyan
    if ($sqlPrivateEndpointId) {
        Write-Host "  SQL private endpoint:     $($sqlPrivateEndpointId -split '/' | Select-Object -Last 1)" -ForegroundColor White
    } else {
        Write-Warning "  No SQL private endpoint detected — only storage side will use private connectivity."
        Write-Warning "  For full network isolation, ensure the SQL Server also has a private endpoint."
    }
    if ($storagePrivateEndpointId) {
        Write-Host "  Storage private endpoint:  $($storagePrivateEndpointId -split '/' | Select-Object -Last 1)" -ForegroundColor White
    } else {
        Write-Warning "  No Storage private endpoint detected — only SQL side will use private connectivity."
        Write-Warning "  For full network isolation, ensure the Storage Account also has a private endpoint."
    }
}

# --- Network connectivity diagnostics between Blob and SQL DB ---
if ($sqlPrivateEndpointId -or $storagePrivateEndpointId) {
    Write-Host "`n--- Private Endpoint Connectivity Diagnostics ---" -ForegroundColor Cyan

    $sqlPeInfo = $null
    $storagePeInfo = $null

    if ($sqlPrivateEndpointId) {
        $sqlPeInfo = Get-PeNetworkDetails -PeResourceId $sqlPrivateEndpointId -Label 'SQL Server'
    }
    if ($storagePrivateEndpointId) {
        $storagePeInfo = Get-PeNetworkDetails -PeResourceId $storagePrivateEndpointId -Label 'Storage'
    }

    # Check VNet alignment between the two PEs
    if ($sqlPeInfo -and $storagePeInfo) {
        if ($sqlPeInfo.VNetId -eq $storagePeInfo.VNetId) {
            Write-Host "`n  VNet alignment: SAME VNet ($($sqlPeInfo.VNetName))" -ForegroundColor Green
        } else {
            Write-Host "`n  VNet alignment: DIFFERENT VNets" -ForegroundColor Yellow
            Write-Host "    SQL PE VNet:     $($sqlPeInfo.VNetName)" -ForegroundColor White
            Write-Host "    Storage PE VNet: $($storagePeInfo.VNetName)" -ForegroundColor White

            # Check for VNet peering
            $sqlVnet = Get-AzVirtualNetwork -Name $sqlPeInfo.VNetName -ResourceGroupName ($sqlPeInfo.VNetId -split '/')[4] -ErrorAction SilentlyContinue
            if ($sqlVnet) {
                $peerToStorage = $sqlVnet.VirtualNetworkPeerings | Where-Object { $_.RemoteVirtualNetwork.Id -eq $storagePeInfo.VNetId }
                if ($peerToStorage) {
                    if ($peerToStorage.PeeringState -eq "Connected") {
                        Write-Host "    VNet peering:    CONNECTED ($($peerToStorage.Name))" -ForegroundColor Green
                    } else {
                        Write-Warning "    VNet peering found but state is: $($peerToStorage.PeeringState)"
                    }
                } else {
                    Write-Warning "    No VNet peering found between '$($sqlPeInfo.VNetName)' and '$($storagePeInfo.VNetName)'."
                    Write-Warning "    The import service uses managed PEs (independent of yours), but if you also need"
                    Write-Warning "    cross-VNet private DNS resolution, ensure peering or DNS forwarding is configured."
                }
            }
        }
    }

    # Check Private DNS Zone configuration
    Write-Host "`n  Checking Private DNS Zones..." -ForegroundColor Cyan
    foreach ($zoneName in @('privatelink.database.windows.net', 'privatelink.blob.core.windows.net')) {
        $dnsZone = Get-AzPrivateDnsZone -Name $zoneName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($dnsZone) {
            Write-Host "    $zoneName — FOUND (RG: $($dnsZone.ResourceGroupName))" -ForegroundColor Green
            $dnsLinks = @(Get-AzPrivateDnsVirtualNetworkLink -ZoneName $dnsZone.Name -ResourceGroupName $dnsZone.ResourceGroupName -ErrorAction SilentlyContinue)
            if ($dnsLinks) {
                $linkedVnets = $dnsLinks | ForEach-Object { ($_.VirtualNetworkId -split '/')[-1] }
                Write-Host "    Linked VNets: $($linkedVnets -join ', ')" -ForegroundColor White
            }
        } else {
            Write-Host "    $zoneName — NOT FOUND" -ForegroundColor Yellow
            Write-Host "    (Not required for -UseNetworkIsolation, but needed for direct private endpoint access)" -ForegroundColor Yellow
        }
    }

    # DNS resolution check from current host
    Write-Host "`n  DNS resolution from this host:" -ForegroundColor Cyan
    Resolve-EndpointDns -Hostname "$SqlServerName.database.windows.net" -Label "SQL"
    Resolve-EndpointDns -Hostname "$StorageAccountName.blob.core.windows.net" -Label "blob"

    # Summary
    Write-Host "`n  --- Connectivity Summary ---" -ForegroundColor Cyan
    if ($useNetworkIsolation) {
        Write-Host "  The import will use -UseNetworkIsolation. Azure's import service creates its own" -ForegroundColor White
        Write-Host "  managed private endpoints to both SQL and Storage during the operation." -ForegroundColor White
        Write-Host "  Your existing PEs are used for validation above, but the data transfer itself" -ForegroundColor White
        Write-Host "  flows through Microsoft-managed PEs (approved automatically)." -ForegroundColor White
    }
    Write-Host ""
}

# --- Check if storage account allows shared key access ---
if ($storageAccount.AllowSharedKeyAccess -eq $false) {
    throw "Storage account '$StorageAccountName' has shared key access DISABLED. The import operation uses a storage key. Enable shared key access or use a different authentication method."
}
Write-Host "  Shared key access: Allowed" -ForegroundColor Green

# --- Get storage account key ---
Write-Host "`nRetrieving storage account key for '$StorageAccountName'..." -ForegroundColor Cyan
$storageKeys = Get-AzStorageAccountKey -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName
$storageKey = $storageKeys[0].Value

# --- Verify the blob exists (if BacpacFileName provided) ---
if ($BacpacFileName) {
    Write-Host "  Bacpac URI: https://${StorageAccountName}.blob.core.windows.net/${StorageContainerName}/${BacpacFileName}" -ForegroundColor Green

    Write-Host "Verifying bacpac blob exists..." -ForegroundColor Cyan
    $storageContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageKey
    try {
        $blob = Get-AzStorageBlob -Container $StorageContainerName -Blob $BacpacFileName -Context $storageContext -ErrorAction Stop
        $blobSizeMB = [math]::Round($blob.Length / 1MB, 2)
        Write-Host "  Bacpac file found (Size: $blobSizeMB MB)" -ForegroundColor Green

        # Integrity checks
        if ($blob.Length -eq 0) {
            throw "Bacpac file '$BacpacFileName' is 0 bytes — the file is empty or upload failed."
        }
        if (-not $BacpacFileName.EndsWith('.bacpac', [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning "  File does not have a .bacpac extension — make sure this is the correct file."
        }

        # Bacpac files are ZIP archives — download first few bytes to verify the header (PK signature)
        try {
            $blobClient = $blob.BlobClient
            $downloadOptions = [Azure.Storage.Blobs.Models.BlobDownloadOptions]::new()
            $downloadOptions.Range = [Azure.HttpRange]::new(0, 4)
            $response = $blobClient.DownloadStreamingAsync($downloadOptions).GetAwaiter().GetResult()
            $stream = $response.Value.Content
            $headerBytes = [byte[]]::new(4)
            $stream.Read($headerBytes, 0, 4) | Out-Null
            $stream.Dispose()

            # ZIP/bacpac magic bytes: PK (0x50 0x4B)
            if ($headerBytes[0] -ne 0x50 -or $headerBytes[1] -ne 0x4B) {
                $hexHeader = ($headerBytes | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' '
                Write-Warning "  BACPAC FILE MAY BE CORRUPT — file header ($hexHeader) does not match ZIP/bacpac format (expected 0x50 0x4B ...)."
                Write-Warning "  The import service will reject this file. Re-export or re-upload the bacpac."
            } else {
                Write-Host "  Bacpac header: valid ZIP/bacpac format" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Could not verify bacpac header (non-fatal): $($_.Exception.Message)" -ForegroundColor Yellow
        }

        # --- Full BACPAC structure validation (if requested) ---
        if ($ValidateBacpac) {
            Write-Host "`n  Performing full BACPAC validation (downloading file)..." -ForegroundColor Cyan
            $tempFile = Join-Path $env:TEMP "bacpac_validate_$([Guid]::NewGuid().ToString('N').Substring(0,8)).bacpac"
            try {
                Write-Host "    Downloading '$BacpacFileName' to temp file..." -ForegroundColor White
                $downloadStart = Get-Date
                Get-AzStorageBlobContent -Container $StorageContainerName -Blob $BacpacFileName `
                    -Context $storageContext -Destination $tempFile -Force | Out-Null
                $downloadTime = [math]::Round(((Get-Date) - $downloadStart).TotalSeconds, 1)
                Write-Host "    Downloaded in $downloadTime seconds" -ForegroundColor Green

                # Hash verification (if expected hash provided)
                if ($ExpectedHash) {
                    Write-Host "    Verifying SHA256 hash..." -ForegroundColor White
                    $actualHash = Get-BacpacFileHash -FilePath $tempFile
                    if ($actualHash -eq $ExpectedHash.ToUpper()) {
                        Write-Host "    SHA256 hash MATCHES: $actualHash" -ForegroundColor Green
                    } else {
                        Write-Warning "    SHA256 HASH MISMATCH!"
                        Write-Warning "      Expected: $($ExpectedHash.ToUpper())"
                        Write-Warning "      Actual:   $actualHash"
                        Write-Warning "    The bacpac file may be corrupted or tampered with."
                        $continue = Read-Host "    Continue anyway? (y/N)"
                        if ($continue -notin @('y', 'Y', 'yes')) {
                            throw "Hash verification failed. Aborting import."
                        }
                    }
                }

                # Full structure validation
                Write-Host "    Validating BACPAC internal structure..." -ForegroundColor White
                $validation = Test-BacpacStructure -LocalFilePath $tempFile

                foreach ($msg in $validation.Messages) {
                    if ($msg -match '^===') {
                        Write-Host "`n    $msg" -ForegroundColor Cyan
                    } elseif ($msg -match '^\s*!') {
                        Write-Warning "    $msg"
                    } elseif ($msg -match '^\s*-') {
                        Write-Host "    $msg" -ForegroundColor Yellow
                    } elseif ($msg -match '^WARNING') {
                        Write-Warning "    $msg"
                    } elseif ($msg -match '^NOTE') {
                        Write-Host "    $msg" -ForegroundColor Yellow
                    } elseif ($msg -match 'Objects:|Security principals:|Schema Provider:|Collation:|Compatibility level:|Estimated data') {
                        Write-Host "    $msg" -ForegroundColor White
                    } else {
                        Write-Host "    $msg" -ForegroundColor Green
                    }
                }

                # Display unsupported features summary
                if ($validation.UnsupportedFeatures.Count -gt 0) {
                    Write-Host "`n    " -NoNewline
                    Write-Host "ACTION REQUIRED: " -ForegroundColor Red -NoNewline
                    Write-Host "$($validation.UnsupportedFeatures.Count) unsupported feature(s) detected" -ForegroundColor Yellow
                    Write-Host "    Consider using SqlPackage with /p:IgnoreExtendedProperties=True or editing model.xml" -ForegroundColor Yellow
                }

                if (-not $validation.IsValid) {
                    Write-Warning "    BACPAC structure validation FAILED"
                    Write-Warning "    Missing files: $($validation.MissingFiles -join ', ')"
                    $continue = Read-Host "    Continue with import anyway? (y/N)"
                    if ($continue -notin @('y', 'Y', 'yes')) {
                        throw "BACPAC validation failed. Missing required files: $($validation.MissingFiles -join ', ')"
                    }
                }

                if ($validation.HasTdeIndicators) {
                    Write-Warning "    TDE encryption detected in source database!"
                    Write-Warning "    The import may fail unless:"
                    Write-Warning "      1. The database was exported with TDE disabled, OR"
                    Write-Warning "      2. You have access to the original encryption keys"
                    Write-Warning "    Consider re-exporting after running: ALTER DATABASE [db] SET ENCRYPTION OFF"
                    $continue = Read-Host "    Continue anyway? (y/N)"
                    if ($continue -notin @('y', 'Y', 'yes')) {
                        throw "Import aborted due to TDE encryption concerns."
                    }
                }

                Write-Host "    BACPAC validation complete" -ForegroundColor Green
            } catch {
                if ($_.Exception.Message -notmatch 'validation failed|aborted|Hash verification') {
                    Write-Warning "    Full validation failed (non-fatal): $($_.Exception.Message)"
                    Write-Warning "    Continuing with basic header validation only."
                } else {
                    throw
                }
            } finally {
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                }
            }
        } elseif ($ExpectedHash) {
            Write-Warning "  -ExpectedHash requires -ValidateBacpac to download and verify the file."
            Write-Warning "  Skipping hash verification. Add -ValidateBacpac to enable."
        }

        if ($blobSizeMB -lt 0.5) {
            Write-Warning "  Bacpac file is only $blobSizeMB MB — this is unusually small."
            Write-Warning "  If the import fails with 'package file provided was not able to be opened', the file may be corrupt or truncated."
            Write-Warning "  Verify the bacpac locally: sqlpackage /Action:Report /SourceFile:""$BacpacFileName"""
        }
    } catch [Microsoft.WindowsAzure.Commands.Storage.Common.ResourceNotFoundException] {
        throw "Bacpac file '$BacpacFileName' not found in container '$StorageContainerName' of storage account '$StorageAccountName'."
    } catch {
        $errMsg = $_.Exception.Message
        Write-Warning "  Blob verification failed: $errMsg"
        if ($errMsg -match 'AuthorizationFailure|Forbidden|403|NetworkError|firewall') {
            Write-Warning "  Storage data plane access is blocked from this host."
            Write-Warning "  The SQL import service runs server-side and may still be able to access the blob."
            Write-Warning "  Make sure the file '$BacpacFileName' exists in container '$StorageContainerName'."
        } elseif ($errMsg -match 'CORRUPT|not able to be opened') {
            throw $_
        } elseif ($restorePublicNetworkAccess) {
            # PublicNetworkAccess was just enabled — propagation may still be in progress
            Write-Warning "  PublicNetworkAccess was just enabled — access may not have propagated to this host yet."
            Write-Warning "  The import service runs server-side and should be able to access the blob."
            Write-Warning "  Make sure the file '$BacpacFileName' exists in container '$StorageContainerName'."
        } else {
            Write-Warning "  Attempting secondary blob check..."
            $blobCheck = Get-AzStorageBlob -Container $StorageContainerName -Blob $BacpacFileName -Context $storageContext -ErrorAction SilentlyContinue
            if (-not $blobCheck) {
                throw "Bacpac file '$BacpacFileName' not found in container '$StorageContainerName' of storage account '$StorageAccountName'. Error: $errMsg"
            }
            Write-Host "  Blob exists (secondary check passed)" -ForegroundColor Green
        }
    }
} else {
    Write-Host "  BacpacFileName not specified — skipping blob verification." -ForegroundColor Yellow
}

Write-Host "`n=== Pre-flight checks passed ===" -ForegroundColor Green

if ($PreflightOnly) {
    Write-Host "`nPre-flight only mode — skipping import. All checks completed." -ForegroundColor Cyan
    return
}

# --- Validate import parameters ---
if (-not $BacpacFileName) {
    throw "BacpacFileName is required for import. Use -PreflightOnly to run checks without specifying a bacpac file."
}
# Show the server's configured admin login to help the user
$serverAdminLogin = $sqlServer.SqlAdministratorLogin
Write-Host "  SQL admin login: $serverAdminLogin" -ForegroundColor White

# Detect Entra ID admin on the SQL Server
$entraAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $ResourceGroupName -ServerName $SqlServerName -ErrorAction SilentlyContinue
if ($entraAdmin) {
    Write-Host "  Entra ID admin:  $($entraAdmin.DisplayName) ($($entraAdmin.ObjectId))" -ForegroundColor White
} else {
    Write-Host "  Entra ID admin:  Not configured" -ForegroundColor Yellow
    if ($AuthenticationType -eq 'ADPassword') {
        throw "AuthenticationType is 'ADPassword' but no Entra ID admin is configured on server '$SqlServerName'. Set an Entra ID admin first: Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName '$ResourceGroupName' -ServerName '$SqlServerName' -DisplayName '<user-or-group>'"
    }
}

Write-Host "  Auth type:       $AuthenticationType" -ForegroundColor White

if ($AuthenticationType -eq 'ADPassword') {
    # For Entra ID auth, default to the configured Entra admin
    $defaultUser = if ($entraAdmin) { $entraAdmin.DisplayName } else { '' }
    if (-not $SqlAdminUser) {
        $SqlAdminUser = Read-Host -Prompt "Entra ID Admin UPN [$defaultUser]"
        if (-not $SqlAdminUser) {
            $SqlAdminUser = $defaultUser
        }
    }
    if (-not $SqlAdminUser) {
        throw "SqlAdminUser (Entra ID admin UPN) is required for ADPassword authentication."
    }
} else {
    if (-not $SqlAdminUser) {
        $SqlAdminUser = Read-Host -Prompt "SQL Admin Username [$serverAdminLogin]"
        if (-not $SqlAdminUser) {
            $SqlAdminUser = $serverAdminLogin
        }
    }
    if ($SqlAdminUser -ne $serverAdminLogin) {
        Write-Warning "  Provided username '$SqlAdminUser' does not match server admin login '$serverAdminLogin'."
        Write-Warning "  The import API requires the server admin credentials. Proceeding anyway..."
    }
}
if (-not $SqlAdminPassword) {
    $promptLabel = if ($AuthenticationType -eq 'ADPassword') { 'Entra ID Password' } else { 'SQL Admin Password' }
    $SqlAdminPassword = Read-Host -AsSecureString -Prompt $promptLabel
    if ($SqlAdminPassword.Length -eq 0) {
        throw "SqlAdminPassword is required for import."
    }
}
$bacpacUri = "https://${StorageAccountName}.blob.core.windows.net/${StorageContainerName}/${BacpacFileName}"

# --- Determine storage credential type ---
$storageKeyType = "StorageAccessKey"
$storageCredential = $storageKey

$useSas = switch ($StorageAuthMethod) {
    'Key' { $false }
    'SAS' { $true }
    default { $false }  # Default to key — simpler and works when firewall is open
}

if ($useSas) {
    Write-Host "  Generating SAS token for storage authentication..." -ForegroundColor Cyan
    $sasContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $storageKey
    $sasToken = New-AzStorageContainerSASToken -Name $StorageContainerName -Context $sasContext `
        -Permission rl -ExpiryTime (Get-Date).AddHours(4) -Protocol HttpsOnly
    # Strip leading '?' — the import API expects the raw token
    $sasToken = $sasToken.TrimStart('?')
    $storageKeyType = "SharedAccessKey"
    $storageCredential = $sasToken
    Write-Host "  SAS token generated (expires in 4 hours)" -ForegroundColor Green
} else {
    Write-Host "  Using storage account key for authentication" -ForegroundColor Green
}

# --- Temporarily open storage firewall if needed ---
$restoreFirewall = $false
$originalBypass = $networkRuleSet.Bypass
$hasTrustedBypass = $originalBypass -match 'AzureServices'
if ($networkRuleSet.DefaultAction -eq "Deny" -and -not $useNetworkIsolation) {
    if ($hasTrustedBypass) {
        Write-Host "`n  Storage firewall is DENY, but 'Allow trusted Microsoft services' bypass is enabled." -ForegroundColor Cyan
        Write-Host "  Note: The bypass may not cover import credential validation. If import fails with" -ForegroundColor Yellow
        Write-Host "  InvalidImportExportStorageCredentials, the firewall must be temporarily opened." -ForegroundColor Yellow
    } else {
        Write-Host "`n  Storage firewall is DENY and trusted services bypass is NOT enabled." -ForegroundColor Yellow
    }
    Write-Host "  The storage firewall must be temporarily opened for the import service to validate credentials." -ForegroundColor Yellow
    $openFw = Read-Host "  Temporarily set storage firewall to 'Allow' for the import? It will be restored after. (y/N)"
    if ($openFw -in @('y', 'Y', 'yes')) {
        Write-Host "  Opening storage firewall (setting DefaultAction to Allow, preserving Bypass=$originalBypass)..." -ForegroundColor Cyan
        Update-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName `
            -DefaultAction Allow -Bypass $originalBypass | Out-Null
        $restoreFirewall = $true

        # Verify the change actually took effect by reading back the rule set
        $verifyRuleSet = Get-AzStorageAccountNetworkRuleSet -ResourceGroupName $StorageResourceGroupName -AccountName $StorageAccountName
        if ($verifyRuleSet.DefaultAction -eq 'Allow') {
            Write-Host "  Storage firewall confirmed open (DefaultAction=Allow, Bypass=$($verifyRuleSet.Bypass))" -ForegroundColor Green
        } else {
            Write-Warning "  Firewall update may not have taken effect! DefaultAction is still '$($verifyRuleSet.DefaultAction)'"
            Write-Warning "  IP rules count: $(@($verifyRuleSet.IpRules).Count), VNet rules count: $(@($verifyRuleSet.VirtualNetworkRules).Count)"
        }

        # Verify propagation by actually trying to access the blob (up to 5 minutes)
        Write-Host "  Verifying storage access (firewall changes can take up to 5 minutes to propagate)..." -ForegroundColor Cyan
        $fwVerified = Wait-StorageAccessPropagation -AccountName $StorageAccountName -AccountKey $storageKey `
            -ContainerName $StorageContainerName -BlobName $BacpacFileName
        if ($fwVerified) {
            Write-Host "  Storage access verified — firewall change has propagated." -ForegroundColor Green
        } else {
            Write-Warning "  Could not verify storage access after 5 minutes."
            Write-Warning "  The import service runs server-side and may have different network access. Proceeding with import..."
        }
    } else {
        Write-Warning "  Proceeding without opening firewall — import may fail with InvalidImportExportStorageCredentials."
    }
} elseif ($networkRuleSet.DefaultAction -eq "Deny" -and $useNetworkIsolation) {
    Write-Host "`n  Storage firewall is DENY, but network isolation is enabled." -ForegroundColor Cyan
    Write-Host "  The import service will use managed private endpoints to access storage — no firewall change needed." -ForegroundColor Green
}

# --- Clean up stale managed PE connections from previous imports ---
if ($useNetworkIsolation) {
    Write-Host "`nCleaning up stale managed private endpoints from previous imports..." -ForegroundColor Cyan
    $cleanedUp = 0
    try {
        foreach ($linkResourceId in @($sqlServer.ResourceId, $storageAccount.Id)) {
            $resourceLabel = if ($linkResourceId -eq $sqlServer.ResourceId) { 'SQL' } else { 'Storage' }
            $existingPEs = @(Get-AzPrivateEndpointConnection -PrivateLinkResourceId $linkResourceId -ErrorAction SilentlyContinue)
            foreach ($pe in $existingPEs) {
                if ($pe.PrivateEndpoint.Id -match 'ImportExportPrivateLink') {
                    $peName = ($pe.PrivateEndpoint.Id -split '/')[-1]
                    Write-Host "  Removing stale $resourceLabel PE: $peName ($($pe.PrivateLinkServiceConnectionState.Status))" -ForegroundColor Yellow
                    Remove-AzPrivateEndpointConnection -ResourceId $pe.Id -Force -ErrorAction SilentlyContinue
                    $cleanedUp++
                }
            }
        }
        if ($cleanedUp -gt 0) {
            Write-Host "  Removed $cleanedUp stale managed PE(s). Waiting 15 seconds for cleanup to propagate..." -ForegroundColor Green
            Start-Sleep -Seconds 15
        } else {
            Write-Host "  No stale managed PEs found." -ForegroundColor Green
        }
    } catch {
        Write-Host "  PE cleanup failed (non-fatal): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# --- Start the import ---
Write-Host "`nStarting database import..." -ForegroundColor Cyan
Write-Host "  Server:    $SqlServerName" -ForegroundColor White
Write-Host "  Database:  $DatabaseName" -ForegroundColor White
Write-Host "  Edition:   $Edition" -ForegroundColor White
Write-Host "  SKU:       $ServiceObjectiveName" -ForegroundColor White
Write-Host "  Auth:      $storageKeyType (SQL auth: $AuthenticationType)" -ForegroundColor White
Write-Host "  Timeout:   $ImportTimeoutMinutes minutes" -ForegroundColor White
Write-Host "" -ForegroundColor White
Write-Host "  Tip: To use more cores, pass -ServiceObjectiveName with a higher vCore count:" -ForegroundColor DarkGray
Write-Host "    GP_Gen5_2, GP_Gen5_4, GP_Gen5_8, GP_Gen5_16, GP_Gen5_32, GP_Gen5_80" -ForegroundColor DarkGray
Write-Host "    BC_Gen5_2..80 (BusinessCritical), HS_Gen5_2..80 (Hyperscale)" -ForegroundColor DarkGray

# --- Submit the import ---
$useRestApi = $false
if ($useNetworkIsolation) {
    Write-Host "  Using REST API for import (network isolation requires it)..." -ForegroundColor Cyan
    $useRestApi = $true
} else {
    Write-Host "  Using New-AzSqlDatabaseImport cmdlet..." -ForegroundColor Cyan
}

try {
    if ($useRestApi) {
        # --- REST API path (required for network isolation) ---
        $subscriptionId = $currentContext.Subscription.Id
        $importApiPath = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$SqlServerName/import?api-version=2021-02-01-preview"

        # Convert SecureString to plaintext for the JSON body
        # PtrToStringBSTR (not PtrToStringAuto) — PtrToStringAuto uses 1-byte chars on Linux,
        # truncating the password at the first \0 in the UTF-16LE BSTR.
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SqlAdminPassword)
        try {
            $plainPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }

        $requestBodyHash = @{
            databaseName               = $DatabaseName
            edition                    = $Edition
            serviceObjectiveName       = $ServiceObjectiveName
            maxSizeBytes               = $MaxSizeBytes.ToString()
            storageKeyType             = $storageKeyType
            storageKey                 = $storageCredential
            storageUri                 = $bacpacUri
            administratorLogin         = $SqlAdminUser
            administratorLoginPassword = $plainPwd
            authenticationType         = $AuthenticationType
            networkIsolation           = @{
                sqlServerResourceId      = $sqlServer.ResourceId
                storageAccountResourceId = $storageAccount.Id
            }
        }
        $requestBody = $requestBodyHash | ConvertTo-Json -Depth 5
        $plainPwd = $null  # Clear from memory

        $restResponse = Invoke-AzRestMethod -Path $importApiPath -Method POST -Payload $requestBody

        if ($restResponse.StatusCode -notin @(200, 202)) {
            throw "Import REST API returned HTTP $($restResponse.StatusCode): $($restResponse.Content)"
        }

        # Extract operation status link from response headers or body
        $operationLink = $null
        foreach ($hdr in @('Azure-AsyncOperation', 'Location')) {
            if ($restResponse.Headers.Contains($hdr)) {
                $operationLink = @($restResponse.Headers.GetValues($hdr))[0]
                break
            }
        }
        if (-not $operationLink -and $restResponse.Content) {
            try {
                $respObj = $restResponse.Content | ConvertFrom-Json
                if ($respObj.PSObject.Properties['properties'] -and $respObj.properties.PSObject.Properties['operationStatusLink']) {
                    $operationLink = $respObj.properties.operationStatusLink
                }
            } catch {}
        }
        if (-not $operationLink) {
            Write-Host "  Import accepted (HTTP $($restResponse.StatusCode)) but no operation status link found." -ForegroundColor Yellow
            throw "Import accepted but no operation tracking link returned. Check the Azure portal."
        }
        Write-Host "  Import request accepted via REST API." -ForegroundColor Green
        $importRequest = [PSCustomObject]@{ OperationStatusLink = $operationLink; IsRestApi = $true }
    } else {
        # --- Cmdlet path (standard import without network isolation) ---
        $importParams = @{
            ResourceGroupName          = $ResourceGroupName
            ServerName                 = $SqlServerName
            DatabaseName               = $DatabaseName
            Edition                    = $Edition
            ServiceObjectiveName       = $ServiceObjectiveName
            DatabaseMaxSizeBytes       = $MaxSizeBytes
            StorageKeyType             = $storageKeyType
            StorageKey                 = $storageCredential
            StorageUri                 = $bacpacUri
            AdministratorLogin         = $SqlAdminUser
            AdministratorLoginPassword = $SqlAdminPassword   # SecureString — cmdlet handles it natively
            AuthenticationType         = $AuthenticationType
        }
        $importRequest = New-AzSqlDatabaseImport @importParams
        Write-Host "  Import request accepted via cmdlet." -ForegroundColor Green
    }
} catch {
    Restore-StorageNetworkSettings -RG $StorageResourceGroupName -AccountName $StorageAccountName `
        -RestoreFirewall $restoreFirewall -RestorePNA $restorePublicNetworkAccess `
        -OriginalBypass $originalBypass -IsTimedOut $false

    Write-Host "`nImport request FAILED:" -ForegroundColor Red
    Write-Host "  Message: $($_.Exception.Message)" -ForegroundColor Red

    # Try multiple ways to extract Azure error details
    $errorBody = $null
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
        $errorBody = $_.ErrorDetails.Message
    } elseif ($_.Exception.PSObject.Properties['Body'] -and $_.Exception.Body) {
        $errorBody = $_.Exception.Body | ConvertTo-Json -Depth 5
    } elseif ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
        try {
            $respStream = $_.Exception.Response.Content.ReadAsStringAsync().Result
            if ($respStream) { $errorBody = $respStream }
        } catch {}
    }
    if ($errorBody) {
        Write-Host "  Error detail:" -ForegroundColor Red
        try {
            $errorJson = $errorBody | ConvertFrom-Json
            if ($errorJson.error) {
                Write-Host "    Code:    $($errorJson.error.code)" -ForegroundColor Red
                Write-Host "    Message: $($errorJson.error.message)" -ForegroundColor Red
            } else {
                Write-Host "    $errorBody" -ForegroundColor Red
            }
        } catch {
            Write-Host "    $errorBody" -ForegroundColor Red
        }
    }
    if ($_.Exception.InnerException) {
        Write-Host "  Inner: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }

    Write-Host "`n  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "    Server admin login: $serverAdminLogin" -ForegroundColor Yellow
    Write-Host "    Provided username:  $SqlAdminUser" -ForegroundColor Yellow
    Write-Host "    SKU: $Edition / $ServiceObjectiveName" -ForegroundColor Yellow
    Write-Host "    MaxSizeBytes: $MaxSizeBytes" -ForegroundColor Yellow
    Write-Host "    StorageUri: $bacpacUri" -ForegroundColor Yellow
    Write-Host "`n  To get verbose error details, run in Cloud Shell:" -ForegroundColor Yellow
    Write-Host "    `$DebugPreference = 'Continue'" -ForegroundColor White
    Write-Host "    Then re-run the script — look for the HTTP response body in debug output." -ForegroundColor White
    throw
}

# --- Extract import request ID for managed PE matching ---
$importRequestId = $null
if ($importRequest.OperationStatusLink -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') {
    # The URL may contain subscriptionId (also a GUID) — prefer the one after importExport
    if ($importRequest.OperationStatusLink -match '[iI]mport[eE]xport\w*/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') {
        $importRequestId = $Matches[1]
    } else {
        # Fall back to last GUID in the URL (skip subscriptionId which is typically first)
        $allGuids = [regex]::Matches($importRequest.OperationStatusLink, '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
        if ($allGuids.Count -ge 2) {
            $importRequestId = $allGuids[-1].Value
        } elseif ($allGuids.Count -eq 1) {
            $importRequestId = $allGuids[0].Value
        }
    }
}

Write-Host "`nImport operation started. Monitoring progress (timeout: $ImportTimeoutMinutes min)..." -ForegroundColor Cyan
if ($importRequestId) {
    Write-Host "  Import Request ID: $importRequestId" -ForegroundColor White
}

# --- Auto-approve managed private endpoints created by the import service ---
# Track each side independently — both SQL and Storage may need approval at different times.
$sqlManagedPeApproved = $false
$storageManagedPeApproved = $false
$peApprovalWaitDone = $false
if ($useNetworkIsolation) {
    Write-Host "  Watching for managed private endpoints that need approval..." -ForegroundColor Cyan
}

# --- Poll for completion ---
$pollIntervalSeconds = 15
$importStartTime = Get-Date
$timeoutSeconds = $ImportTimeoutMinutes * 60
$lastProgress = ''
do {
    Start-Sleep -Seconds $pollIntervalSeconds
    $elapsed = (Get-Date) - $importStartTime
    $elapsedStr = '{0:mm\:ss}' -f $elapsed

    # Auto-approve managed PEs during the first 10 minutes of the import.
    # Keep checking BOTH sides independently — they may appear at different times.
    if ($useNetworkIsolation -and $elapsed.TotalMinutes -lt 10) {
        try {
            if (-not $sqlManagedPeApproved) {
                $result = Approve-ManagedPrivateEndpoint -ResourceId $sqlServer.ResourceId -Label 'SQL Server' `
                    -ImportRequestId $importRequestId -ElapsedStr ([ref]$elapsedStr) -ImportStartTime $importStartTime
                if ($result) { $sqlManagedPeApproved = $true }
            }
            if (-not $storageManagedPeApproved) {
                $result = Approve-ManagedPrivateEndpoint -ResourceId $storageAccount.Id -Label 'Storage' `
                    -ImportRequestId $importRequestId -ElapsedStr ([ref]$elapsedStr) -ImportStartTime $importStartTime
                if ($result) { $storageManagedPeApproved = $true }
            }
            # After all PEs are approved, one final wait for activation
            if ($sqlManagedPeApproved -and $storageManagedPeApproved -and -not $peApprovalWaitDone) {
                Write-Host "  [$elapsedStr] Both managed PEs approved. Waiting 30 seconds for activation..." -ForegroundColor Cyan
                Start-Sleep -Seconds 30
                $peApprovalWaitDone = $true
                $elapsed = (Get-Date) - $importStartTime
                $elapsedStr = '{0:mm\:ss}' -f $elapsed
                Write-Host "  [$elapsedStr] PE activation wait complete. Resuming status polling." -ForegroundColor Green
            }
        } catch {
            Write-Host "  [$elapsedStr] PE approval check failed (non-fatal): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    if ($elapsed.TotalHours -ge 1) {
        $elapsedStr = '{0}h {1:mm\:ss}' -f [math]::Floor($elapsed.TotalHours), $elapsed
    }
    try {
        if ($useRestApi) {
            # Poll REST API async operation
            $pollResp = Invoke-AzRestMethod -Uri $importRequest.OperationStatusLink -Method GET
            $pollObj = $pollResp.Content | ConvertFrom-Json
            # ARM async operations use 'status' (Succeeded/Failed/Running)
            $armStatus = if ($pollObj.PSObject.Properties['status']) { $pollObj.status } else { $null }
            if ($armStatus) {
                $mappedStatus = switch ($armStatus) {
                    'Running'   { 'InProgress' }
                    'Succeeded' { 'Succeeded' }
                    'Failed'    { 'Failed' }
                    default     { $armStatus }
                }
                $msg = if ($pollObj.PSObject.Properties['properties'] -and $pollObj.properties.PSObject.Properties['message']) {
                    $pollObj.properties.message
                } elseif ($pollObj.PSObject.Properties['error'] -and $pollObj.error.PSObject.Properties['message']) {
                    $pollObj.error.message
                } else { $armStatus }
                $status = [PSCustomObject]@{ Status = $mappedStatus; StatusMessage = $msg }
            } else {
                $status = [PSCustomObject]@{ Status = 'InProgress'; StatusMessage = 'Polling...' }
            }
        } else {
            # Poll via cmdlet
            $status = Get-AzSqlDatabaseImportExportStatus -OperationStatusLink $importRequest.OperationStatusLink
        }
    } catch {
        # The cmdlet throws when the operation failed server-side instead of returning a status object
        $failMsg = $_.Exception.Message
        Write-Host "`n  [$elapsedStr] Import FAILED" -ForegroundColor Red
        Write-Host "  $failMsg" -ForegroundColor Red
        # Create a synthetic status object so downstream logic works
        $status = [PSCustomObject]@{ Status = 'Failed'; StatusMessage = $failMsg }
        break
    }
    $currentProgress = $status.StatusMessage
    # Only print when progress changes or every 60 seconds to reduce noise
    if ($currentProgress -ne $lastProgress -or $elapsed.TotalSeconds % 60 -lt $pollIntervalSeconds) {
        Write-Host "  [$elapsedStr] $($status.Status) — $currentProgress" -ForegroundColor Yellow
        $lastProgress = $currentProgress
    }
    # Timeout check
    if ($elapsed.TotalSeconds -ge $timeoutSeconds) {
        Write-Warning "  Import monitoring timed out after $ImportTimeoutMinutes minutes."
        Write-Warning "  The import is still running server-side. Check status with:"
        Write-Warning "    Get-AzSqlDatabaseImportExportStatus -OperationStatusLink '$($importRequest.OperationStatusLink)'"
        break
    }
} while ($status.Status -eq "InProgress")

$timedOut = $status.Status -eq "InProgress"  # True if we broke out via timeout

# Restore storage network settings if we modified them
Restore-StorageNetworkSettings -RG $StorageResourceGroupName -AccountName $StorageAccountName `
    -RestoreFirewall $restoreFirewall -RestorePNA $restorePublicNetworkAccess `
    -OriginalBypass $originalBypass -IsTimedOut $timedOut

$totalElapsed = (Get-Date) - $importStartTime
$totalStr = '{0:mm\:ss}' -f $totalElapsed
if ($totalElapsed.TotalHours -ge 1) {
    $totalStr = '{0}h {1:mm\:ss}' -f [math]::Floor($totalElapsed.TotalHours), $totalElapsed
}

if ($timedOut) {
    Write-Warning "Script exited after $totalStr. The import continues server-side."
} elseif ($status.Status -eq "Succeeded") {
    Write-Host "`nImport completed successfully in $totalStr!" -ForegroundColor Green
    Write-Host "Database '$DatabaseName' is now available on '$($sqlServer.FullyQualifiedDomainName)'." -ForegroundColor Green
} else {
    Write-Error "Import failed after $totalStr. Status: $($status.Status). Message: $($status.StatusMessage)"
}
