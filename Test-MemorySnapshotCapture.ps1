#requires -Version 7.4
#requires -Modules VMware.VimAutomation.Core

<#
    Test-MemorySnapshotCapture.ps1

    Stripped-down version of the full capture script, for testing SNAPSHOT
    CREATION ONLY. All download/copy/hash-verification logic has been
    removed since that part depends on datastore file-download privileges
    you may not have yet.

    This still:
      - Runs the same pre-flight safety checks (powered-on, consolidation,
        encryption, independent disks, existing snapshot count, datastore
        free space)
      - Creates the memory snapshot
      - Confirms the .vmem/.vmsn files actually appear on the datastore
        (proves the memory capture itself worked, without copying anything)
      - Removes the snapshot afterward (unless -KeepSnapshot is passed)

    Once this runs cleanly end-to-end, the download/copy portion can be
    reintroduced once you've sorted out datastore file-access permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Server,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$VMName,

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9_.-]+$')]
    [string]$SnapshotPrefix = 'hp-mem-test',

    [Parameter()]
    [ValidateRange(0, 2)]
    [int]$MaximumExistingSnapshots = 1,

    [Parameter()]
    [ValidateRange(0, 1000000)]
    [double]$MinimumDatastoreFreeGB = 20,

    [Parameter()]
    [ValidateRange(10, 1800)]
    [int]$FileDiscoveryTimeoutSeconds = 180,

    [Parameter()]
    [switch]$AllowEncryptedMemory,

    [Parameter()]
    [switch]$KeepSnapshot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-CaptureLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $now = [DateTimeOffset]::UtcNow.ToString('o')
    Write-Host "[$now] [$Level] $Message"
}

function ConvertFrom-VsphereDatastorePath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^\[(?<datastore>[^\]]+)\]\s*(?<relative>.*)$') {
        throw "Unsupported vSphere datastore path: $Path"
    }
    [pscustomobject]@{
        DatastoreName = $Matches.datastore
        RelativePath  = $Matches.relative.Trim('/', '\')
    }
}

function Get-DatastoreRelativeDirectory {
    param([Parameter(Mandatory)][string]$RelativePath)
    $slash = $RelativePath.LastIndexOf('/')
    if ($slash -lt 0) { return '' }
    return $RelativePath.Substring(0, $slash)
}

function Get-DatastoreForVm {
    param(
        [Parameter(Mandatory)]$VM,
        [Parameter(Mandatory)][string]$DatastoreName,
        [Parameter(Mandatory)]$VIServer
    )
    $matches = @(Get-Datastore -RelatedObject $VM -Server $VIServer | Where-Object { $_.Name -eq $DatastoreName })
    if ($matches.Count -eq 0) {
        $matches = @(Get-Datastore -Name $DatastoreName -Server $VIServer | Where-Object { $_.Name -eq $DatastoreName })
    }
    if ($matches.Count -ne 1) {
        throw "Expected one datastore named '$DatastoreName' for VM '$($VM.Name)', found $($matches.Count)."
    }
    return $matches[0]
}

function New-CaptureDatastoreDrive {
    param(
        [Parameter(Mandatory)]$Datastore,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$DriveNames
    )
    $driveName = 'capds' + ([Guid]::NewGuid().ToString('N').Substring(0, 8))
    New-PSDrive -Name $driveName -PSProvider VimDatastore -Root '\' -Location $Datastore -Scope Script | Out-Null
    $DriveNames.Add($driveName)
    return $driveName
}

function ConvertTo-ProviderPath {
    param([Parameter(Mandatory)][string]$DriveName, [AllowEmptyString()][string]$RelativePath = '')
    $providerRelative = $RelativePath.Trim('/', '\').Replace('/', '\')
    if ([string]::IsNullOrWhiteSpace($providerRelative)) { return "${DriveName}:\" }
    return "${DriveName}:\$providerRelative"
}

function Get-DatastoreFileRecords {
    param([Parameter(Mandatory)][string]$DirectoryPath)
    return @(
        Get-ChildItem -LiteralPath $DirectoryPath |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object {
                $lastWriteUtc = $null
                if ($null -ne $_.PSObject.Properties['LastWriteTime'] -and $null -ne $_.LastWriteTime) {
                    $lastWriteUtc = $_.LastWriteTime.ToUniversalTime().ToString('o')
                }
                [pscustomobject]@{
                    Name             = $_.Name
                    Length           = [int64]$_.Length
                    LastWriteTimeUtc = $lastWriteUtc
                    ProviderPath     = Join-Path -Path $DirectoryPath -ChildPath $_.Name
                }
            }
    )
}

function Get-FileFingerprintMap {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records)
    $result = [hashtable]::new([StringComparer]::Ordinal)
    foreach ($record in $Records) {
        $result[$record.Name] = "$($record.Length)|$($record.LastWriteTimeUtc)"
    }
    return $result
}

function Get-SnapshotManagedObjectReference {
    param([Parameter(Mandatory)]$Snapshot)
    $reference = $null
    $extensionProperty = $Snapshot.PSObject.Properties['ExtensionData']
    if ($null -ne $extensionProperty -and $null -ne $extensionProperty.Value) {
        $extensionData = $extensionProperty.Value
        if ($null -ne $extensionData.PSObject.Properties['Snapshot']) {
            $reference = $extensionData.Snapshot
        }
        elseif ($null -ne $extensionData.PSObject.Properties['MoRef']) {
            $reference = $extensionData.MoRef
        }
    }
    if ($null -eq $reference -or
        $null -eq $reference.PSObject.Properties['Type'] -or
        $null -eq $reference.PSObject.Properties['Value'] -or
        $reference.Type -cne 'VirtualMachineSnapshot' -or
        [string]::IsNullOrWhiteSpace([string]$reference.Value)) {
        throw 'Cannot determine a valid VirtualMachineSnapshot reference from PowerCLI ExtensionData.'
    }
    return $reference
}

function Get-SnapshotMemoryFileNames {
    param(
        [Parameter(Mandatory)]$VM,
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$DatastoreName,
        [AllowEmptyString()][string]$RelativeDirectory = ''
    )
    $snapshotReference = Get-SnapshotManagedObjectReference -Snapshot $Snapshot
    $VM.ExtensionData.UpdateViewData('LayoutEx')
    $layout = $VM.ExtensionData.LayoutEx
    if ($null -eq $layout) { return }
    $snapshotLayout = @($layout.Snapshot | Where-Object {
        $null -ne $_ -and $null -ne $_.Key -and
            $_.Key.Type -ceq $snapshotReference.Type -and
            $_.Key.Value -ceq $snapshotReference.Value
    })
    if ($snapshotLayout.Count -eq 0) { return }
    if ($snapshotLayout.Count -ne 1) { throw 'Ambiguous snapshot file layout.' }

    $keys = @($snapshotLayout[0].DataKey)
    if ($null -ne $snapshotLayout[0].PSObject.Properties['MemoryKey'] -and $snapshotLayout[0].MemoryKey -ge 0) {
        $keys += $snapshotLayout[0].MemoryKey
    }
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($key in @($keys | Select-Object -Unique)) {
        $files = @($layout.File | Where-Object { $null -ne $_ -and $_.Key -eq $key })
        if ($files.Count -ne 1) { return }
        $parts = ConvertFrom-VsphereDatastorePath -Path $files[0].Name
        $slash = $parts.RelativePath.LastIndexOf('/')
        $directory = if ($slash -ge 0) { $parts.RelativePath.Substring(0, $slash) } else { '' }
        $name = $parts.RelativePath.Substring($slash + 1)
        if ($parts.DatastoreName -cne $DatastoreName -or $directory -cne $RelativeDirectory.TrimEnd('/')) {
            throw "Snapshot memory file '$($files[0].Name)' is outside the expected snapshot directory."
        }
        if ([System.IO.Path]::GetExtension($name).ToLowerInvariant() -notin @('.vmsn', '.vmem')) {
            throw "Unexpected snapshot memory file '$name'."
        }
        $names.Add($name)
    }
    return $names.ToArray()
}

function Find-NewMemoryStateFiles {
    param(
        [Parameter(Mandatory)][string]$DirectoryPath,
        [Parameter(Mandatory)][hashtable]$BeforeFingerprint,
        [Parameter(Mandatory)][int]$TimeoutSeconds,
        [Parameter(Mandatory)]$VM,
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$DatastoreName,
        [AllowEmptyString()][string]$RelativeDirectory = ''
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $previousCandidateFingerprint = $null
    $stablePolls = 0
    do {
        $expectedNames = @(Get-SnapshotMemoryFileNames -VM $VM -Snapshot $Snapshot `
            -DatastoreName $DatastoreName -RelativeDirectory $RelativeDirectory)
        $current = @(Get-DatastoreFileRecords -DirectoryPath $DirectoryPath)
        $candidates = @(
            $current | Where-Object {
                $extension = [System.IO.Path]::GetExtension($_.Name).ToLowerInvariant()
                $isMemoryState = $extension -in @('.vmem', '.vmsn')
                $fingerprint = "$($_.Length)|$($_.LastWriteTimeUtc)"
                $isNewOrChanged = (-not $BeforeFingerprint.ContainsKey($_.Name)) -or ($BeforeFingerprint[$_.Name] -ne $fingerprint)
                $isMemoryState -and $isNewOrChanged -and ($expectedNames -ccontains $_.Name) -and $_.Length -gt 0
            }
        )
        if ($expectedNames.Count -gt 0 -and $candidates.Count -eq $expectedNames.Count -and
            @($candidates | Where-Object { $_.Name.EndsWith('.vmsn', [StringComparison]::OrdinalIgnoreCase) }).Count -eq 1) {
            $candidateFingerprint = @($candidates | Sort-Object Name | ForEach-Object { "$($_.Name)|$($_.Length)|$($_.LastWriteTimeUtc)" }) -join ';'
            if ($candidateFingerprint -eq $previousCandidateFingerprint) { $stablePolls++ }
            else { $stablePolls = 0; $previousCandidateFingerprint = $candidateFingerprint }
            if ($stablePolls -ge 2) { return $candidates }
        }
        else {
            $previousCandidateFingerprint = $null
            $stablePolls = 0
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "The complete, stable memory file set for snapshot '$($Snapshot.Name)' was not found in '$DirectoryPath' within $TimeoutSeconds seconds."
}

$viConnection = $null
$snapshot = $null
$temporaryDriveNames = [System.Collections.Generic.List[string]]::new()

try {
    $connectParameters = @{ Server = $Server; ErrorAction = 'Stop' }
    if ($null -ne $Credential) { $connectParameters.Credential = $Credential }

    Write-CaptureLog "Connecting to '$Server'."
    $viConnection = Connect-VIServer @connectParameters

    $matchingVms = @(Get-VM -Name $VMName -Server $viConnection | Where-Object { $_.Name -eq $VMName })
    if ($matchingVms.Count -ne 1) {
        throw "Expected exactly one VM named '$VMName', found $($matchingVms.Count)."
    }
    $vm = $matchingVms[0]

    if ($vm.PowerState -ne 'PoweredOn') {
        throw "VM '$VMName' must be powered on for a useful memory capture; current state is '$($vm.PowerState)'."
    }
    $vm.ExtensionData.UpdateViewData('Runtime.ConsolidationNeeded')
    if ($null -eq $vm.ExtensionData.Runtime.ConsolidationNeeded -or $vm.ExtensionData.Runtime.ConsolidationNeeded) {
        throw "VM '$VMName' needs consolidation, or its consolidation state could not be verified. Resolve it before capturing."
    }

    $existingSnapshots = @(Get-Snapshot -VM $vm)
    if ($existingSnapshots.Count -gt $MaximumExistingSnapshots) {
        throw "VM '$VMName' already has $($existingSnapshots.Count) snapshots; the configured limit before capture is $MaximumExistingSnapshots."
    }
    $unfinishedCaptures = @($existingSnapshots | Where-Object { $_.Name -like "$SnapshotPrefix-*" })
    if ($unfinishedCaptures.Count -gt 0) {
        throw "VM '$VMName' has an earlier capture snapshot ('$($unfinishedCaptures[0].Name)'). Resolve it before creating another."
    }

    $encrypted = $null -ne $vm.ExtensionData.Config.KeyId
    if ($encrypted -and -not $AllowEncryptedMemory) {
        throw "VM '$VMName' is encrypted. Re-run with -AllowEncryptedMemory if you intend to proceed anyway."
    }

    $independentDisks = @(
        Get-HardDisk -VM $vm | Where-Object {
            $null -ne $_.ExtensionData.Backing -and
            $null -ne $_.ExtensionData.Backing.PSObject.Properties['DiskMode'] -and
            $null -ne $_.ExtensionData.Backing.DiskMode -and
            $_.ExtensionData.Backing.DiskMode.ToString().StartsWith('independent', [StringComparison]::OrdinalIgnoreCase)
        }
    )
    if ($independentDisks.Count -gt 0) {
        throw "VM '$VMName' has independent-mode disks, which are incompatible with a memory snapshot."
    }

    $snapshotDirectoryText = $vm.ExtensionData.Config.Files.SnapshotDirectory
    if ([string]::IsNullOrWhiteSpace($snapshotDirectoryText)) {
        $vmxPathParts = ConvertFrom-VsphereDatastorePath -Path $vm.ExtensionData.Config.Files.VmPathName
        $vmxRelativeDirectory = Get-DatastoreRelativeDirectory -RelativePath $vmxPathParts.RelativePath
        $snapshotDirectoryText = "[$($vmxPathParts.DatastoreName)] $vmxRelativeDirectory"
    }
    $snapshotPathParts = ConvertFrom-VsphereDatastorePath -Path $snapshotDirectoryText
    $snapshotDatastore = Get-DatastoreForVm -VM $vm -DatastoreName $snapshotPathParts.DatastoreName -VIServer $viConnection

    $requiredSnapshotDatastoreGB = [Math]::Max($MinimumDatastoreFreeGB, [Math]::Ceiling(([double]$vm.MemoryGB * 1.25) + 5))
    if ([double]$snapshotDatastore.FreeSpaceGB -lt $requiredSnapshotDatastoreGB) {
        throw "Snapshot datastore '$($snapshotDatastore.Name)' has $([Math]::Round($snapshotDatastore.FreeSpaceGB, 2)) GB free; the guardrail requires $requiredSnapshotDatastoreGB GB."
    }

    $captureId = [Guid]::NewGuid().ToString('N')
    $timestamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')
    $snapshotName = "$SnapshotPrefix-$timestamp-$($captureId.Substring(0, 8))"

    $snapshotDriveName = New-CaptureDatastoreDrive -Datastore $snapshotDatastore -DriveNames $temporaryDriveNames
    $snapshotProviderDirectory = ConvertTo-ProviderPath -DriveName $snapshotDriveName -RelativePath $snapshotPathParts.RelativePath
    $beforeFiles = @(Get-DatastoreFileRecords -DirectoryPath $snapshotProviderDirectory)
    $beforeFingerprint = Get-FileFingerprintMap -Records $beforeFiles

    Write-CaptureLog "Creating memory snapshot '$snapshotName' for '$VMName'."
    $snapshot = New-Snapshot -VM $vm -Name $snapshotName -Description "Snapshot-only test. CaptureId=$captureId" -Memory -Quiesce:$false -Server $viConnection -Confirm:$false
    Write-CaptureLog "Snapshot created: Id=$($snapshot.Id), Created=$($snapshot.Created)"

    if ($snapshot.PowerState -ne 'PoweredOn') {
        throw 'The snapshot does not report a powered-on state. The VM may have powered off during capture.'
    }

    Write-CaptureLog "Waiting for .vmem/.vmsn files to appear on the datastore..."
    $memoryFiles = @(
        Find-NewMemoryStateFiles `
            -DirectoryPath $snapshotProviderDirectory `
            -BeforeFingerprint $beforeFingerprint `
            -TimeoutSeconds $FileDiscoveryTimeoutSeconds `
            -VM $vm -Snapshot $snapshot `
            -DatastoreName $snapshotPathParts.DatastoreName `
            -RelativeDirectory $snapshotPathParts.RelativePath
    )

    Write-CaptureLog "Found $($memoryFiles.Count) memory-related file(s):"
    foreach ($f in $memoryFiles) {
        Write-CaptureLog "  - $($f.Name) ($([Math]::Round($f.Length / 1MB, 2)) MiB)"
    }
    if (@($memoryFiles | Where-Object { $_.Name.EndsWith('.vmem', [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) {
        Write-CaptureLog 'No separate .vmem file was found; memory state may be embedded in the .vmsn on this configuration.' 'WARN'
    }

    if ($KeepSnapshot) {
        Write-CaptureLog "Snapshot test succeeded. Keeping snapshot '$snapshotName' because -KeepSnapshot was specified." 'WARN'
    }
    else {
        Write-CaptureLog "Snapshot test succeeded. Removing snapshot '$snapshotName'."
        Remove-Snapshot -Snapshot $snapshot -Confirm:$false | Out-Null
        Write-CaptureLog "Snapshot removed."
    }

    [pscustomobject]@{
        VM           = $vm.Name
        SnapshotName = $snapshotName
        MemoryFiles  = $memoryFiles.Name
        KeptSnapshot = [bool]$KeepSnapshot
    }
}
catch {
    Write-CaptureLog $_.Exception.Message 'ERROR'
    throw
}
finally {
    foreach ($driveName in $temporaryDriveNames) {
        if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) {
            Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
        }
    }
    if ($null -ne $viConnection) {
        Disconnect-VIServer -Server $viConnection -Confirm:$false -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
