#Requires -Version 5.1

<#
.SYNOPSIS
Generate an Excel report from Azure SQL SKU Recommendation JSON files.

.NOTES
Author : ChatGPT
Version: 1.0

Prerequisite:
PowerShell Gallery access (first run only)
#>

#--------------------------------------------------------
# Install ImportExcel Module (if not installed)
#--------------------------------------------------------

if (!(Get-Module -ListAvailable -Name ImportExcel))
{
    Write-Host "ImportExcel module not found. Installing..." -ForegroundColor Yellow

    Install-PackageProvider NuGet -MinimumVersion 2.8.5.201 -Force
    Set-PSRepository PSGallery -InstallationPolicy Trusted

    Install-Module ImportExcel `
        -Scope CurrentUser `
        -Force `
        -AllowClobber
}

Import-Module ImportExcel

#--------------------------------------------------------
# Load Folder Browser
#--------------------------------------------------------

Add-Type -AssemblyName System.Windows.Forms

#--------------------------------------------------------
# Select JSON Folder
#--------------------------------------------------------

$jsonFolder = New-Object System.Windows.Forms.FolderBrowserDialog
$jsonFolder.Description = "C:\DMS\Project\Elasticpool\JSON"

if($jsonFolder.ShowDialog() -ne "OK")
{
    Write-Host "Operation cancelled."
    return
}

$JsonPath = $jsonFolder.SelectedPath

#--------------------------------------------------------
# Select Output Folder
#--------------------------------------------------------

$outputFolder = New-Object System.Windows.Forms.FolderBrowserDialog
$outputFolder.Description = "Select Output Folder"

if($outputFolder.ShowDialog() -ne "OK")
{
    Write-Host "Operation cancelled."
    return
}

$OutputPath = $outputFolder.SelectedPath

#--------------------------------------------------------
# Find JSON Files
#--------------------------------------------------------

$jsonFiles = Get-ChildItem `
                -Path $JsonPath `
                -Filter *.json

if($jsonFiles.Count -eq 0)
{
    Write-Host "No JSON files found." -ForegroundColor Red
    return
}

$Results = @()

#--------------------------------------------------------
# Process each JSON
#--------------------------------------------------------

foreach($file in $jsonFiles)
{
    Write-Host "Processing $($file.Name)..." -ForegroundColor Cyan

    $json = Get-Content $file.FullName -Raw | ConvertFrom-Json

    foreach($server in $json.Servers)
    {
        $serverName = $server.ServerName

        foreach($db in $server.Requirements.DatabaseLevelRequirements)
        {
            $Results += [PSCustomObject]@{

                "Server Name" = $serverName

                "Database Name" = $db.DatabaseName

                "CPU Requirement (vCores)" =
                    [math]::Round($db.CpuRequirementInCores,2)

                "Memory Requirement (GB)" =
                    [math]::Round($db.MemoryRequirementInMB/1024,2)

                "Data Storage (GB)" =
                    [math]::Round($db.DataStorageRequirementInMB/1024,2)

                "Log Storage (GB)" =
                    [math]::Round($db.LogStorageRequirementInMB/1024,2)

                "Total Storage (GB)" =
                    [math]::Round(
                        ($db.DataStorageRequirementInMB +
                        $db.LogStorageRequirementInMB)/1024,2)

                "Data IOPS" =
                    [math]::Round($db.DataIOPSRequirement,2)

                "Log IOPS" =
                    [math]::Round($db.LogIOPSRequirement,2)

                "Total IOPS" =
                    [math]::Round(
                        $db.DataIOPSRequirement +
                        $db.LogIOPSRequirement,2)

                "IO Latency (ms)" =
                    [math]::Round($db.IOLatencyRequirementInMs,2)
            }
        }
    }
}

#--------------------------------------------------------
# Export to Excel
#--------------------------------------------------------

$ExcelFile = Join-Path $OutputPath "Database_Requirements_Report.xlsx"

$Results |
Sort-Object "Server Name","Database Name" |
Export-Excel `
    -Path $ExcelFile `
    -WorksheetName "Database Requirements" `
    -TableName DatabaseRequirements `
    -TableStyle Medium2 `
    -AutoSize `
    -FreezeTopRow `
    -BoldTopRow `
    -AutoFilter `
    -ClearSheet

Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Report Generated Successfully!" -ForegroundColor Green
Write-Host "Output File:" -ForegroundColor Green
Write-Host $ExcelFile -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Green