# SAP-HANA-GapAssessment.ps1
# Uses modern Get-AzSecurityAssessment (Defender for Cloud)
# Runs with Reader access + Log Analytics

param(
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [string]$LogAnalyticsWorkspaceResourceId
)

# Stop on error
$ErrorActionPreference = "Stop"

# Ensure required modules
$requiredModules = @("Az.Accounts", "Az.Compute", "Az.Network", "Az.OperationalInsights", "Az.RecoveryServices", "Az.Security")
foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Host "[!] Module '$mod' is not installed. Run: Install-Module $mod -Scope CurrentUser -Force -AllowClobber" -ForegroundColor Red
        exit 1
    }
    Import-Module $mod -Force
}

# Connect to Azure
Write-Host "[+] Authenticating to Azure..." -ForegroundColor Cyan
Connect-AzAccount -ErrorAction Stop
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

# Auto-detect Log Analytics workspace if not provided
if (-not $LogAnalyticsWorkspaceResourceId) {
    Write-Host "[+] Auto-detecting Log Analytics workspace..." -ForegroundColor Cyan
    $vms = Get-AzVM -ErrorAction SilentlyContinue
    if ($vms) {
        foreach ($vm in $vms) {
            $diag = Get-AzDiagnosticSetting -ResourceId $vm.Id -ErrorAction SilentlyContinue
            if ($diag.WorkspaceId) {
                $LogAnalyticsWorkspaceResourceId = $diag.WorkspaceId
                break
            }
        }
    }
}

# Fetch all VMs
Write-Host "[+] Fetching VMs..." -ForegroundColor Cyan
$vms = Get-AzVM

# Fetch Defender for Cloud assessments (non-healthy only)
Write-Host "[+] Fetching Defender for Cloud assessments..." -ForegroundColor Cyan
$defenderAssessments = $null
if (Get-Command Get-AzSecurityAssessment -ErrorAction SilentlyContinue) {
    try {
        $allAssessments = Get-AzSecurityAssessment -ErrorAction Stop
        $defenderAssessments = $allAssessments | Where-Object { $_.Status.Code -ne "Healthy" }
        Write-Host "    → Found $($defenderAssessments.Count) non-healthy assessments" -ForegroundColor Green
    } catch {
        Write-Host "    → Failed to get assessments: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"

# SAP HANA certified VM sizes (common ones - expand if needed)
$SAPHANACertifiedSizes = @(
    "Standard_M64ms", "Standard_M64s", "Standard_M128ms", "Standard_M128s",
    "Standard_M32ms", "Standard_M32ls", "Standard_M192ims", "Standard_M192is",
    "Standard_E32ds_v4", "Standard_E48ds_v4", "Standard_E64ds_v4", "Standard_E96ds_v4"
)

# Start HTML report
$htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>SAP HANA VM Security Gap Assessment</title>
    <style>
        body { font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f9fbfd; }
        h1, h2 { color: #1a365d; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        th, td { border: 1px solid #cbd5e0; padding: 12px; text-align: left; }
        th { background-color: #2b6cb0; color: white; }
        .high { background-color: #fee; color: #c53030; font-weight: bold; }
        .medium { background-color: #fff8e1; color: #d88c00; }
        .low { background-color: #f0fff4; color: #2f855a; }
        .info { background-color: #ebf8ff; color: #2a4365; }
        .unknown { background-color: #f7fafc; color: #718096; }
        pre { background: #2d3748; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; }
        .summary-box { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); margin-bottom: 25px; }
        footer { margin-top: 30px; color: #a0aec0; font-size: 0.9em; }
    </style>
</head>
<body>
<h1>🛡️ SAP HANA VM Security Gap Assessment</h1>
<div class='summary-box'>
    <p><strong>Subscription ID:</strong> $SubscriptionId</p>
    <p><strong>Assessment Time:</strong> $timestamp</p>
    <p><strong>Total VMs Scanned:</strong> $($vms.Count)</p>
    <p><strong>Defender Assessments Loaded:</strong> $(if ($defenderAssessments) { $defenderAssessments.Count } else { "0 (skipped)" })</p>
</div>
<h2>🔍 Detailed Findings</h2>
<table>
    <tr>
        <th>VM Name</th>
        <th>Resource Group</th>
        <th>Location</th>
        <th>Size (SAP-Certified?)</th>
        <th>OS</th>
        <th>Encryption</th>
        <th>Backup</th>
        <th>JIT Enabled</th>
        <th>NSG Risks</th>
        <th>Missing Patches</th>
        <th>Defender Gaps</th>
        <th>SAP HANA Checks</th>
    </tr>
"@

if ($vms.Count -eq 0) {
    $htmlReport += "<tr><td colspan='12' style='color: red;'>No VMs found in subscription.</td></tr>"
} else {
    foreach ($vm in $vms) {
        $vmName = $vm.Name
        $rg = $vm.ResourceGroupName
        $location = $vm.Location
        $osType = $vm.StorageProfile.OsDisk.OsType
        $vmSize = $vm.HardwareProfile.VmSize

        # Initialize
        $encryptionStatus = "<span class='unknown'>❓ Unknown</span>"
        $backupStatus = "<span class='unknown'>❓ Unknown</span>"
        $jitStatus = "<span class='unknown'>❓ Unknown</span>"
        $nsgRisks = "<span class='low'>✅ None detected</span>"
        $patchStatus = "<span class='unknown'>❓ Not checked</span>"
        $defenderGaps = "<span class='low'>✅ None</span>"
        $sapHANAChecks = @()

        # --- 1. Disk Encryption ---
        try {
            $osDisk = Get-AzDisk -ResourceGroupName $rg -DiskName $vm.StorageProfile.OsDisk.Name -ErrorAction Stop
            if ($osDisk.Encryption.Type -like "*Customer*") {
                $encryptionStatus = "<span class='low'>✅ Customer-managed</span>"
            } elseif ($osDisk.Encryption.Type -eq "EncryptionAtRestWithPlatformKey") {
                $encryptionStatus = "<span class='medium'>⚠️ Platform-managed only</span>"
            } else {
                $encryptionStatus = "<span class='high'>❌ Not encrypted</span>"
            }
        } catch {
            $encryptionStatus = "<span class='unknown'>❓ Check failed</span>"
        }

        # --- 2. Backup Status ---
        try {
            $vaults = Get-AzRecoveryServicesVault -ErrorAction SilentlyContinue
            $protected = $false
            foreach ($vault in $vaults) {
                Set-AzRecoveryServicesVaultContext -Vault $vault | Out-Null
                $item = Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType VM -ErrorAction SilentlyContinue |
                        Where-Object { $_.ContainerName -like "*$vmName*" -and $_.ProtectionStatus -eq "Healthy" }
                if ($item) { $protected = $true; break }
            }
            $backupStatus = if ($protected) { "<span class='low'>✅ Protected</span>" } else { "<span class='high'>❌ Not backed up</span>" }
        } catch {
            $backupStatus = "<span class='unknown'>❓ Backup check failed</span>"
        }

        # --- 3. JIT Access ---
        try {
            $jitPolicies = Get-AzJitNetworkAccessPolicy -ResourceGroupName $rg -ErrorAction SilentlyContinue
            $jitEnabled = $false
            foreach ($policy in $jitPolicies) {
                if ($policy.VirtualMachines.Id -contains $vm.Id) {
                    $jitEnabled = $true; break
                }
            }
            $jitStatus = if ($jitEnabled) { "<span class='low'>✅ Enabled</span>" } else { "<span class='medium'>⚠️ Disabled</span>" }
        } catch {
            $jitStatus = "<span class='unknown'>❓ JIT check failed</span>"
        }

        # --- 4. NSG Rules (SAP ports) ---
        try {
            $nics = Get-AzNetworkInterface | Where-Object { $_.VirtualMachine.Id -eq $vm.Id }
            $riskyRules = @()
            foreach ($nic in $nics) {
                if ($nic.NetworkSecurityGroup) {
                    $nsg = Get-AzNetworkSecurityGroup -ResourceId $nic.NetworkSecurityGroup.Id
                    foreach ($rule in $nsg.SecurityRules) {
                        if ($rule.Direction -eq "Inbound" -and ($rule.SourceAddressPrefix -eq "*" -or $rule.SourceAddressPrefix -eq "Internet")) {
                            $ports = if ($rule.DestinationPortRange -match "^\d+$") { @($rule.DestinationPortRange) } else { $rule.DestinationPortRange.Split(",") }
                            $sapPorts = @(22, 3389, 1433, 3000, 3001, 3002, 3100, 3200, 3300, 50000, 50001, 50013, 50014, 30303, 30304)
                            $risky = $ports | Where-Object { $_ -in $sapPorts }
                            if ($risky) {
                                $riskyRules += "'$($rule.Name)': $($risky -join ',')"
                            }
                        }
                    }
                }
            }
            if ($riskyRules.Count -gt 0) {
                $nsgRisks = "<span class='high'>❌ " + ($riskyRules -join '; ') + "</span>"
            }
        } catch {
            $nsgRisks = "<span class='unknown'>❓ NSG check failed</span>"
        }

        # --- 5. Patch Status (Log Analytics) ---
        if ($LogAnalyticsWorkspaceResourceId) {
            try {
                $workspace = Get-AzOperationalInsightsWorkspace -ResourceId $LogAnalyticsWorkspaceResourceId
                $wsName = $workspace.Name
                $wsRG = $workspace.ResourceGroupName

                if ($osType -eq "Windows") {
                    $query = "Update | where Computer has '$vmName' and UpdateState == 'Needed' | summarize Missing=count()"
                } else {
                    $query = "UpdateSummary | where Computer has '$vmName' | project Missing = CriticalUpdatesMissing + SecurityUpdatesMissing"
                }

                $result = Invoke-AzOperationalInsightsQuery -WorkspaceName $wsName -ResourceGroupName $wsRG -Query $query -Timespan (New-TimeSpan -Days 7)
                if ($result.Results) {
                    $missing = if ($osType -eq "Windows") { $result.Results[0].Missing } else { $result.Results[0].Missing }
                    if ([int]$missing -gt 0) {
                        $patchStatus = "<span class='medium'>⚠️ $missing missing</span>"
                    } else {
                        $patchStatus = "<span class='low'>✅ Up to date</span>"
                    }
                } else {
                    $patchStatus = "<span class='low'>✅ No missing patches</span>"
                }
            } catch {
                $patchStatus = "<span class='unknown'>❓ Patch query failed</span>"
            }
        }

        # --- 6. Defender for Cloud Gaps (via Assessments) ---
        if ($defenderAssessments) {
            $vmAssessments = $defenderAssessments | Where-Object { $_.ResourceId -eq $vm.Id }
            if ($vmAssessments) {
                $names = ($vmAssessments.DisplayName | Sort-Object -Unique) -join '; '
                $defenderGaps = "<span class='high'>⚠️ $names</span>"
            }
        }

        # --- 7. SAP HANA Checks ---
        if ($vmSize -in $SAPHANACertifiedSizes) {
            $sapHANAChecks += "✅ VM size SAP-certified"
        } else {
            $sapHANAChecks += "❌ VM size NOT SAP-certified"
        }

        if ($osType -eq "Linux") {
            $sapHANAChecks += "ℹ️ OS: Linux (expected for HANA)"
        } else {
            $sapHANAChecks += "⚠️ OS: Windows (not typical for HANA)"
        }

        if ($vm.StorageProfile.OsDisk.ManagedDisk.StorageAccountType -like "*Premium*") {
            $sapHANAChecks += "✅ Premium SSD used"
        } else {
            $sapHANAChecks += "❌ Standard disk used (HANA requires Premium SSD)"
        }

        $accNetEnabled = $false
        foreach ($nic in $nics) {
            if ($nic.EnableAcceleratedNetworking -eq $true) {
                $accNetEnabled = $true; break
            }
        }
        if ($accNetEnabled) {
            $sapHANAChecks += "✅ Accelerated Networking enabled"
        } else {
            $sapHANAChecks += "⚠️ Accelerated Networking disabled (recommended for HANA)"
        }

        $sapHANAHTML = ($sapHANAChecks -join '<br>')

        # --- Add row to HTML ---
        $htmlReport += @"
    <tr>
        <td>$vmName</td>
        <td>$rg</td>
        <td>$location</td>
        <td>$vmSize</td>
        <td>$osType</td>
        <td>$encryptionStatus</td>
        <td>$backupStatus</td>
        <td>$jitStatus</td>
        <td>$nsgRisks</td>
        <td>$patchStatus</td>
        <td>$defenderGaps</td>
        <td>$sapHANAHTML</td>
    </tr>
"@
    }
}

# Close HTML
$htmlReport += @"
</table>

<h2>📌 Notes</h2>
<div class='summary-box'>
    <ul>
        <li><strong>Red (❌)</strong>: High-risk gap – immediate action recommended.</li>
        <li><strong>Orange (⚠️)</strong>: Medium-risk or deviation from SAP/Azure best practices.</li>
        <li><strong>Green (✅)</strong>: Compliant or low risk.</li>
        <li>Assessment uses <strong>Reader role</strong> and <strong>Log Analytics</strong> data only.</li>
        <li>SAP HANA checks align with <a href='https://learn.microsoft.com/en-us/azure/virtual-machines/workloads/sap/sap-hana-vm-operations-storage' target='_blank'>Microsoft SAP HANA on Azure guidance</a>.</li>
    </ul>
</div>

<footer>
    Generated by SAP HANA Gap Assessment Script | $(Get-Date -Format 'yyyy-MM-dd HH:mm')
</footer>
</body>
</html>
"@

# Save report
$reportPath = "SAP-HANA-GapAssessment-$(Get-Date -Format 'yyyyMMdd-HHmm').html"
$htmlReport | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "[+] Assessment complete!" -ForegroundColor Green
Write-Host "📄 Report saved to: $reportPath" -ForegroundColor Cyan
Write-Host "💡 Open in browser to view interactive, color-coded results." -ForegroundColor Yellow