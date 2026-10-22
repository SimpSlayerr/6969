if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$($PWD.Path)' ; & '$($myInvocation.InvocationName)'`"" -Verb RunAs
    Exit
}

function Check-RegistryArtifacts {

    $category = "Registry Keys"

    $detected = @()

    $paths = @(
        "HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
        "HKLM:\\SOFTWARE\\VMware, Inc.\\VMware Tools",
        "HKLM:\\SOFTWARE\\Wine",
        "HKLM:\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { $detected += $p }
    }

    $acpi = @(
        "HKLM:\\HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HKLM:\\HARDWARE\\ACPI\\FADT\\VBOX__",
        "HKLM:\\HARDWARE\\ACPI\\RSDT\\VBOX__"
    )
    foreach ($p in $acpi) {
        if (Test-Path $p) { $detected += $p }
    }

    try {
        Get-ChildItem "HKLM:\\HARDWARE\\DEVICEMAP\\Scsi" -Recurse -ErrorAction Stop |
        ForEach-Object {
            $id = (Get-ItemProperty -Path $_.PSPath -Name Identifier -ErrorAction Stop).Identifier
            if ($id -match "VBOX|VMWARE|QEMU") { $detected += "Scsi Identifier = $id" }
        }
    }
    catch { }

    $diskKey = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"
    if (Test-Path $diskKey) {
        try {
            (Get-ItemProperty $diskKey).PSObject.Properties |
            Where-Object { $_.Name -match '^\d+$' } |
            ForEach-Object {
                if ($_.Value -match "VMware|VBOX|Virtual") {
                    $detected += "Disk Enum -> $($_.Value)"
                }
            }
        }
        catch { }
    }

    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected virtualization registry artifacts:`n" +
        ($detected -join "`n")
    }
    else {
        $detail = "GOOD: No virtualization or sandbox registry artifacts found."
    }

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-SleepHook {
    $category = "Timing Check"
    $expectedMs = 1000
    $thresholdMs = 900               
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Milliseconds $expectedMs   
    $sw.Stop()
    $actualMs = $sw.ElapsedMilliseconds
    $suspicious = $actualMs -lt $thresholdMs

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $suspicious
        Detail   = if ($suspicious) {
            "Sleep(${expectedMs}ms) returned too fast (actual ${actualMs}ms)"
        }
        else {
            "Sleep timing is normal (${actualMs}ms)"
        }
    }
}

function Check-Hypervisor {
    $category = "HypervisorCheck"
    $hypervisorFlag = $false
    $cs = $null
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $hypervisorFlag = [bool]$cs.HypervisorPresent
    }
    catch {
        $hypervisorFlag = $false
    }

    $isVMVendor = $false
    if ($cs) {
        $isVMVendor = ($cs.Manufacturer -match "VirtualBox|innotek|VMware|QEMU|Xen|Bochs|Parallels") -or 
        ($cs.Model -match "Virtual Machine|VirtualBox|VMware|KVM|Bochs|Parallels")
    }

    # On physical Windows 10/11 machines, HypervisorPresent is True due to VBS, Memory Integrity, or WSL2.
    # It is only a VM indicator if running on a virtual machine platform or vendor.
    $isBad = ($hypervisorFlag -and $isVMVendor)

    $detail = if ($hypervisorFlag -and $isVMVendor) {
        "Hypervisor is present on virtual platform ($($cs.Manufacturer) $($cs.Model))"
    }
    elseif ($hypervisorFlag) {
        "Hypervisor flag active on physical host ($($cs.Manufacturer) $($cs.Model)) via Windows VBS/WSL root partition"
    }
    else {
        "No hypervisor flag detected (HypervisorPresent = False)"
    }

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-CPUFeatures {
    $category = "CPUFeatureCheck"
    if (-not ([System.Management.Automation.PSTypeName]'Win32.NativeMethods').Type) {
        Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @"
        [DllImport("kernel32.dll")]
        public static extern bool IsProcessorFeaturePresent(uint feature);
"@ -PassThru | Out-Null
    }
    $nxSupported = [Win32.NativeMethods]::IsProcessorFeaturePresent(12)  
    $sse2Supported = [Win32.NativeMethods]::IsProcessorFeaturePresent(10)  
    $sse3Supported = [Win32.NativeMethods]::IsProcessorFeaturePresent(13)  
    $rdtscSupported = [Win32.NativeMethods]::IsProcessorFeaturePresent(8)  

    $missing = @()
    if (-not $nxSupported) { $missing += "NX/DEP" }
    if (-not $sse2Supported) { $missing += "SSE2" }
    if (-not $sse3Supported) { $missing += "SSE3" }
    if (-not $rdtscSupported) { $missing += "RDTSC" }

    $isAnomalous = ($missing.Count -gt 0)
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isAnomalous
        Detail   = if ($isAnomalous) {
            "Missing CPU features: " + ($missing -join ", ")
        }
        else {
            "All expected CPU features (NX, SSE2/3, RDTSC) are present"
        }
    }
}

function Check-VideoAdapter {
    $category = "VideoAdapterCheck"
    $virtualKeywords = @("VMWARE", "VirtualBox", "Virtual VGA", "Virtual", 
        "SVGA", "S3 Trio", "Basic Display", "Remote Display",
        "Hyper-V", "Microsoft Hyper-V", "QXL", "Red Hat", "Parallels")
    $virtualFound = @()

    foreach ($gpu in Get-CimInstance Win32_VideoController) {
        $name = $gpu.Name
        $descr = $gpu.Description
        $adapterText = ($name + " " + $descr).ToUpper()  
        foreach ($kw in $virtualKeywords) {
            if ($adapterText -like "*$kw.ToUpper()*") {
                $virtualFound += $gpu.Name 
                break
            }
        }
    }

    $isVirtualGPU = ($virtualFound.Count -gt 0)
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isVirtualGPU
        Detail   = if ($isVirtualGPU) {
            "Unusual GPU driver detected: " + ($virtualFound -join "; ")
        }
        else {
            "Graphics adapters appear normal (no known virtual GPU drivers)"
        }
    }
}

function Check-OSArtifacts {
    $category = "OSArtifactCheck"
    $os = Get-CimInstance Win32_OperatingSystem

    $regUser = $os.RegisteredUser
    $org = $os.Organization
    $caption = $os.Caption       
    $installDateStr = $os.InstallDate  
    $installDate = try {
        [System.Management.ManagementDateTimeConverter]::ToDateTime($installDateStr)
    }
    catch { $null }

    $flags = @()
    if ([string]::IsNullOrWhiteSpace($regUser) -or $regUser.ToLower() -match "user|admin|sandbox") {
        $flags += "RegisteredUser='$regUser'"
    }
    if ($org -and ($org.ToLower() -match "organization|orgname|contoso" -or $org.Trim().Length -eq 0)) {
        $flags += "Organization='$org'"
    }
    if ($caption -match "Evaluation") {
        $flags += "OS Edition is Evaluation Copy"
    }
    if ($installDate) {
        $daysSinceInstall = (Get-Date) - $installDate
        if ($daysSinceInstall.TotalDays -lt 30) {
            $flags += "OS installed ${[math]::Round($daysSinceInstall.TotalDays,1)} days ago"
        }
    }

    $isSuspicious = ($flags.Count -gt 0)
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = if ($isSuspicious) {
            "Suspicious OS info: " + ($flags -join "; ")
        }
        else {
            "No obvious sandbox artifacts in OS metadata (user, org, install date seem normal)"
        }
    }
}

function Check-Processes {

    $category = "Processes"

    $suspectNames = @(
        "vboxservice",   
        "vboxtray",      
        "vmtoolsd",     
        "vmwaretray",    
        "vmwareuser",   
        "vgauthservice",  
        "vmacthlp",      
        "vmsrvc",      
        "vmusrvc",    
        "sbiectrl",     
        "sbiesvc"      
    )

    $detected = Get-Process -ErrorAction SilentlyContinue |
    Where-Object { $suspectNames -contains $_.Name.ToLower() } |
    ForEach-Object { $_.Name + ".exe" }

    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected the following VM/sandbox processes:`n" + ($detected -join "`n")
    }
    else {
        $detail = "GOOD: No known VM or sandbox processes are running."
    }

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-DriversFiles {

    $systemDir = $Env:SystemRoot + "\\System32"
    $filePaths = @(
        "$systemDir\\drivers\\VBoxMouse.sys",  
        "$systemDir\\drivers\\VBoxWddm.sys", 
        "$systemDir\\drivers\\VBoxGuest.sys", 
        "$systemDir\\drivers\\VBoxSF.sys",    
        "$systemDir\\drivers\\VBoxVideo.sys",   
        "$systemDir\\drivers\\vmmouse.sys",    
        "$systemDir\\drivers\\vmhgfs.sys",  
        "$systemDir\\drivers\\vm3dmp.sys",   
        "$systemDir\\drivers\\vmci.sys",        
        "$systemDir\\drivers\\vmmemctl.sys",    
        "$systemDir\\drivers\\vmrawdsk.sys",  
        "$systemDir\\drivers\\vmusbmouse.sys", 
        "$systemDir\\vboxservice.exe",        
        "$systemDir\\vboxtray.exe"         
    )
    $detected = @()
    foreach ($file in $filePaths) {
        if (Test-Path $file) {
            $detected += ([System.IO.Path]::GetFileName($file))
        }
    }
	
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected the following VM driver files:`n" + ($detected -join "`n")
    }
    else {
        $detail = "GOOD: No virtualization driver files were found."
    }

    return [PSCustomObject]@{
        Category = "System Files"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-SystemManufacturer {

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $manufacturer = $cs.Manufacturer
    $model = $cs.Model
    $detected = @()
    $vmKeywords = @("VMware", "VirtualBox", "Virtual Machine", "Microsoft Corporation", "Xen", "QEMU", "Bochs", "Parallels", "KVM", "Innotek")
    if ($manufacturer) {
        foreach ($kw in $vmKeywords) {
            if ($manufacturer -match $kw) {
                $detected += "Manufacturer: $manufacturer"
                break
            }
        }
    }
    if ($model) {
        foreach ($kw in $vmKeywords) {
            if ($model -match $kw) {
                $detected += "Model: $model"
                break
            }
        }
    }
    $csp = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
    if ($csp) {
        if ($csp.Vendor) {
            foreach ($kw in $vmKeywords) {
                if ($csp.Vendor -match $kw) {
                    $detected += "System Vendor: $($csp.Vendor)"
                    break
                }
            }
        }
        if ($csp.Name) {
            foreach ($kw in $vmKeywords) {
                if ($csp.Name -match $kw) {
                    $detected += "Product Name: $($csp.Name)"
                    break
                }
            }
        }
    }
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected virtualization in hardware IDs:`n" + ($detected -join "`n")
    }
    else {
        $detail = "GOOD: No virtualization indicators in manufacturer/model/vendor/product."
    }

    return [PSCustomObject]@{
        Category = "Hardware IDs"
        IsBad    = $isBad
        Detail   = $detail
    }	
}

function Check-BIOSInfo {

    $bios = Get-CimInstance -ClassName Win32_BIOS
    $biosVendor = $bios.Manufacturer
    $biosVersion = ($bios.SMBIOSBIOSVersion -join " ")
    $detected = @()
    $vmKeywords = @("VMware", "VirtualBox", "VBox", "HVM", "Xen", "QEMU", "Virtual Machine", "Hyper-V", "Microsoft", "Bochs", "SeaBIOS", "Parallels")
    if ($biosVendor) {
        foreach ($kw in $vmKeywords) {
            if ($biosVendor -match $kw) {
                $detected += "BIOS Vendor: $biosVendor"
                break
            }
        }
    }
    if ($biosVersion) {
        foreach ($kw in $vmKeywords) {
            if ($biosVersion -match $kw) {
                $detected += "BIOS Version: $biosVersion"
                break
            }
        }
    }
    if ($bios.SerialNumber -and ($bios.SerialNumber -match "0{4,}|Default|To be filled")) {
        $detected += "BIOS Serial: $($bios.SerialNumber)"
    }
	
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected virtualization in BIOS info:`n" + ($detected -join "`n")
    }
    else {
        $detail = "GOOD: No virtualization indicators in BIOS vendor, version, or serial."
    }

    return [PSCustomObject]@{
        Category = "BIOS Info"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-MAC {

    $vmMACPrefixes = @{
        "080027" = "VirtualBox"    
        "000569" = "VMware"        
        "000C29" = "VMware"        
        "001C14" = "VMware"        
        "005056" = "VMware"        
        "001C42" = "Parallels"     
        "00163E" = "Xen"           
        "0A0027" = "Sandbox"       
        "00155D" = "Hyper-V"       
        "525400" = "QEMU/KVM"      
    }
    $detected = @()
    Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "MACAddress IS NOT NULL" | ForEach-Object {
        # Exclude host-side virtual switches and VPN tunnels created by host hypervisors/WSL
        if ($_.Description -match "Host-Only|Default Switch|WSL|vEthernet|Wi-Fi Direct|NordLynx|WireGuard|OpenVPN|TAP-Windows") {
            return
        }
        $mac = $_.MACAddress
        if ($mac) {
            $prefix = $mac.ToUpper() -replace "[:\-]", ""
            if ($prefix.Length -ge 6) {
                $prefix6 = $prefix.Substring(0, 6)
                if ($vmMACPrefixes.ContainsKey($prefix6)) {
                    $detected += ("MAC $mac (Vendor: $($vmMACPrefixes[$prefix6]))")
                }
            }
        }
    }
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected VM MAC prefixes:`n" + ($detected -join "`n")
    }
    else {
        $detail = "GOOD: No VM-related MAC address prefixes detected on primary network adapters."
    }

    return [PSCustomObject]@{
        Category = "MAC Address"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-DeviceNames {
    $detected = @()
    $vmKeywords = @("VBOX", "VMware", "Virtual", "QEMU", "Hyper-V", "Xen", "Parallels")
	
    Get-CimInstance -ClassName Win32_DiskDrive | ForEach-Object {
        if ($_.Model -match "VBOX|Virtual|VMware|QEMU") {
            $detected += "DiskDrive: $($_.Model)"
        }
    }
    Get-CimInstance Win32_VideoController | ForEach-Object {
        foreach ($kw in $vmKeywords) {
            if ($_.Name -match $kw) {
                $detected += "VideoController: $($_.Name)"
                break
            }
        }
    }

    Get-CimInstance Win32_NetworkAdapter -Filter "MACAddress IS NOT NULL" | ForEach-Object {
        # Skip host-side virtual switches and host-only adapters created on hypervisor hosts
        if ($_.Name -match "Host-Only|Default Switch|WSL|vEthernet") {
            return
        }
        foreach ($kw in $vmKeywords) {
            if ($_.Name -match $kw) {
                $detected += "NetworkAdapter: $($_.Name)"
                break
            }
        }
    }
    $isBad = $detected.Count -gt 0
    if ($isBad) {
        $detail = "BAD: Detected virtualization in device names:`n" + ($detected -join "`n")
    }
    else {
        $detail = "GOOD: No virtualization indicators found in device names."
    }

    return [PSCustomObject]@{
        Category = "Device Manager Names"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-ACPI {

    $detected = @()
    $acpiRoot = "HKLM:\\HARDWARE\\ACPI"
    $vmACPIKeywords = @("VBOX", "VMWARE", "VIRTUAL", "QEMU", "XEN", "HYPERV", "PARALLELS", "KVM", "BOCHS", "MICROSOFT")

    if (Test-Path $acpiRoot) {
        Get-ChildItem $acpiRoot -ErrorAction SilentlyContinue | ForEach-Object {
            $keyName = $_.PSChildName
            if ($vmACPIKeywords -contains $keyName.ToUpper()) {
                $detected += "ACPI Root Table: $keyName matches known VM pattern."
            }
            Get-ChildItem -Path "$acpiRoot\\$keyName" -ErrorAction SilentlyContinue | ForEach-Object {
                $subKeyName = $_.PSChildName
                foreach ($kw in $vmACPIKeywords) {
                    if ($subKeyName.ToUpper() -like "*$kw*") {
                        $detected += "ACPI Subkey: $($keyName)\$($subKeyName) matches $kw"
                        break
                    }
                }
            }
        }
    }

    function Get-OEMIDFromACPI {
        param (
            [string]$TableSignature
        )
        try {
            $tablePath = "HKLM:\HARDWARE\ACPI\$TableSignature"
            if (Test-Path $tablePath) {
                $subKey = Get-ChildItem -Path $tablePath -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty PSChildName
                if ($subKey) {
                    return $subKey.Trim()
                }
            }
            return $null
        }
        catch {
            return $null
        }
    }

    $dsdtOemId = Get-OEMIDFromACPI -TableSignature "DSDT"
    $facpOemId = Get-OEMIDFromACPI -TableSignature "FACP"

    foreach ($oemId in @($dsdtOemId, $facpOemId)) {
        if ($oemId) {
            foreach ($kw in $vmACPIKeywords) {
                if ($oemId.ToUpper() -like "*$kw*") {
                    $detected += "ACPI Table OEM ID: $oemId matches $kw"
                    break
                }
            }
        }
    }

    $isBad = $detected.Count -gt 0
    $detail = if ($isBad) {
        "BAD: Detected ACPI VM indicators:`n" + ($detected -join "`n")
    }
    else {
        "GOOD: No virtualization indicators found in ACPI tables."
    }

    return [PSCustomObject]@{
        Category = "ACPI Tables"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-CPUIDHypervisorBit {
    $category = "CPUID Hypervisor Bit"
    
    try {
        $proc = Get-CimInstance Win32_Processor | Select-Object -First 1
        $cs = Get-CimInstance Win32_ComputerSystem
        $hypervisorPresent = [bool]$cs.HypervisorPresent
        
        $cpuHints = $proc.Name -match "Virtual|Hypervisor|QEMU|KVM|Bochs"
        $isVMVendor = ($cs.Manufacturer -match "VirtualBox|innotek|VMware|QEMU|Xen|Bochs|Parallels") -or 
        ($cs.Model -match "Virtual Machine|VirtualBox|VMware|KVM|Bochs|Parallels")
        
        $isBad = $cpuHints -or ($hypervisorPresent -and $isVMVendor)
        
        $detail = if ($cpuHints) {
            "Virtual CPU string detected in processor name: $($proc.Name)"
        }
        elseif ($hypervisorPresent -and $isVMVendor) {
            "CPUID indicates hypervisor present on virtual platform ($($cs.Manufacturer) $($cs.Model))"
        }
        elseif ($hypervisorPresent) {
            "CPUID hypervisor flag active on physical host ($($cs.Manufacturer) $($cs.Model)) via Windows VBS/WSL root partition"
        }
        else {
            "CPUID shows no hypervisor presence"
        }

        return [PSCustomObject]@{
            Category = $category
            IsBad    = $isBad
            Detail   = $detail
        }
    }
    catch {
        return [PSCustomObject]@{
            Category = $category
            IsBad    = $false
            Detail   = "Could not query CPUID information: $_"
        }
    }
}

function Check-USBDevices {
    $category = "USB Devices"
    
    $usbDevices = Get-PnpDevice -Class USB -ErrorAction SilentlyContinue
    $realDeviceCount = ($usbDevices | Where-Object {
            $_.FriendlyName -notmatch "Root Hub|Generic|Composite"
        }).Count
    
    $isBad = $realDeviceCount -eq 0
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) {
            "No real USB devices detected (typical of VMs)"
        }
        else {
            "Real USB devices detected ($realDeviceCount devices)"
        }
    }
}

function Check-BatteryPresence {
    $category = "Battery Presence"
    
    $battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
    $isDesktop = (Get-CimInstance Win32_SystemEnclosure).ChassisTypes -contains 3
    
    $isSuspicious = ($null -eq $battery) -and -not $isDesktop
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = if ($battery) {
            "Battery detected (laptop or hybrid)"
        }
        elseif ($isDesktop) {
            "No battery (desktop chassis)"
        }
        else {
            "No battery on non-desktop system (VM indicator)"
        }
    }
}

function Check-ScreenResolution {
    $category = "Screen Resolution"
    
    Add-Type -AssemblyName System.Windows.Forms
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen
    $width = $screen.Bounds.Width
    $height = $screen.Bounds.Height
    
    # Common VM default resolutions
    $vmResolutions = @(
        "800x600", "1024x768", "1280x720", "1280x800", "1366x768"
    )
    
    $currentRes = "${width}x${height}"
    $isSuspicious = $vmResolutions -contains $currentRes
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = if ($isSuspicious) {
            "Resolution $currentRes matches common VM default"
        }
        else {
            "Resolution $currentRes appears normal"
        }
    }
}

function Check-UserActivity {
    $category = "User Activity"
    
    $browserPaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History",
        "$env:APPDATA\Mozilla\Firefox\Profiles",
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
        "$env:APPDATA\Opera Software\Opera Stable"
    )
    $hasHistory = $false
    foreach ($bp in $browserPaths) {
        if (Test-Path $bp) {
            $hasHistory = $true
            break
        }
    }
    
    $recentFiles = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue
    $userDownloads = Get-ChildItem "$env:USERPROFILE\Downloads" -ErrorAction SilentlyContinue
    $userDesktop = Get-ChildItem "$env:USERPROFILE\Desktop" -ErrorAction SilentlyContinue
    $hasRecentActivity = ($recentFiles.Count -gt 0) -or ($userDownloads.Count -gt 3) -or ($userDesktop.Count -gt 3)
    
    $isSuspicious = -not $hasHistory -and -not $hasRecentActivity
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = if ($isSuspicious) {
            "No browser history or recent files (fresh VM indicator)"
        }
        else {
            "User activity detected (browser profile or user activity files exist)"
        }
    }
}

function Check-TemperatureSensors {
    $category = "Temperature Sensors"
    
    $wmi = Get-WmiObject -Namespace "root\wmi" -Class MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
    $hasSensors = $null -ne $wmi
    
    # Modern UEFI laptops frequently delegate thermal management to Intel DTT or OEM drivers rather than generic MSAcpi.
    $hasBattery = $false
    try {
        if (Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue) {
            $hasBattery = $true
        }
    }
    catch {}

    $isBad = (-not $hasSensors) -and (-not $hasBattery)
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($hasSensors) {
            "Temperature sensors detected (physical ACPI hardware)"
        }
        elseif ($hasBattery) {
            "Physical laptop hardware detected (battery subsystem active; thermal zones managed by OEM/Intel DTT)"
        }
        else {
            "No temperature sensors or battery subsystem found (VM indicator)"
        }
    }
}

function Check-ClipboardSharing {
    $category = "Clipboard Sharing"
    
    $clipboardProcesses = Get-Process | Where-Object {
        $_.Name -match "VBoxClient|vmware-vmblock"
    }
    
    $isBad = $clipboardProcesses.Count -gt 0
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) {
            "VM clipboard sharing detected"
        }
        else {
            "No VM clipboard sharing detected"
        }
    }
}

function Check-SystemUptime {
    $category = "System Uptime"
    
    $os = Get-CimInstance Win32_OperatingSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    
    # In automated analysis sandboxes, samples run within the first few minutes on freshly generated/ephemeral profiles.
    # On an established user machine, fresh boot (< 30 min) is completely normal.
    $profileAgeDays = if (Test-Path $env:USERPROFILE) { ((Get-Date) - (Get-Item $env:USERPROFILE).CreationTime).TotalDays } else { 0 }
    $isTransientUser = $env:USERNAME -match "sandbox|runner|analyst|WDAGUtilityAccount|ContainerUser"
    
    $isSuspicious = ($uptime.TotalMinutes -lt 15) -and ($profileAgeDays -lt 1 -or $isTransientUser)
    
    $detail = if ($isSuspicious) {
        "System uptime is only $([math]::Round($uptime.TotalMinutes, 1)) minutes on fresh/sandbox profile ($env:USERNAME)"
    }
    elseif ($uptime.TotalMinutes -lt 30) {
        "System uptime is $([math]::Round($uptime.TotalMinutes, 1)) minutes (recent reboot on mature system; user profile aged $([math]::Round($profileAgeDays, 0)) days)"
    }
    else {
        "System uptime: $([math]::Round($uptime.TotalHours, 1)) hours"
    }

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isSuspicious
        Detail   = $detail
    }
}

function Check-CPUCores {

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $numCores = $cs.NumberOfLogicalProcessors
    if (-not $numCores) {
        $numCores = (Get-CimInstance -ClassName Win32_Processor).Count
    }
    $detected = @()
    if ($numCores -le 2) {
        $detected += "$numCores core(s) detected"
    }
    $isBad = $detected.Count -gt 0
    $detail = if ($isBad) { $detected } else { @("Detected $numCores logical processor(s). This appears normal for a modern physical machine.") }

    return [PSCustomObject]@{
        Category = "CPU Cores"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-RAM {

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $totalMemGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $detected = @()
    $thresholdGB = 6

    if ($totalMemGB -lt $thresholdGB) {
        $detected += "$totalMemGB GB RAM detected, which is below the typical threshold of $thresholdGB GB."
    }
    else {
        $detected += "$totalMemGB GB RAM detected, which meets or exceeds the typical threshold of $thresholdGB GB."
    }

    $isBad = $totalMemGB -lt $thresholdGB

    return [PSCustomObject]@{
        Category = "RAM Size"
        IsBad    = $isBad
        Detail   = $detected
    }
}


function Check-Disk {

    $detected = @()
    $cDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $thresholdGB = 80

    if ($cDrive -and $cDrive.Size) {
        $totalGB = [math]::Round($cDrive.Size / 1GB, 1)

        if ($totalGB -lt $thresholdGB) {
            $detected += "$totalGB GB disk size detected, which is below the threshold of $thresholdGB GB."
        }
        else {
            $detected += "$totalGB GB disk size detected, which exceeds the threshold of $thresholdGB GB."
        }
    }
    else {
        $detected += "Unable to retrieve disk size information. This may indicate a restricted or abnormal system configuration."
    }

    $isBad = $cDrive -and $cDrive.Size -and ([math]::Round($cDrive.Size / 1GB, 1) -lt $thresholdGB)
    $detail = $detected

    return [PSCustomObject]@{
        Category = "Disk Size"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-MouseMovement {
    $category = "Mouse Movement"
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    $initialPos = [System.Windows.Forms.Cursor]::Position
    Start-Sleep -Milliseconds 2000
    $newPos = [System.Windows.Forms.Cursor]::Position

    $moved = ($newPos.X -ne $initialPos.X) -or ($newPos.Y -ne $initialPos.Y)

    $pointingDevices = Get-CimInstance Win32_PointingDevice -ErrorAction SilentlyContinue
    $hasPhysicalPointingDevice = $false
    $deviceNames = @()
    if ($pointingDevices) {
        foreach ($dev in $pointingDevices) {
            $deviceNames += $dev.Name
            if ($dev.Name -notmatch "VirtualBox|VMware|Virtual|VBox") {
                $hasPhysicalPointingDevice = $true
            }
        }
    }

    # Suspicious if cursor did not move AND machine lacks physical pointing devices (headless/automated sandbox)
    $isBad = (-not $moved) -and (-not $hasPhysicalPointingDevice)

    $detail = if ($moved) {
        "Mouse movement detected within 2 seconds."
    }
    elseif ($hasPhysicalPointingDevice) {
        "No cursor motion in 2s sample, but physical pointing device verified ($($deviceNames -join ', '))."
    }
    else {
        "No mouse movement detected and no physical pointing devices found (sandbox/headless indicator)."
    }

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-CPUHypervisor {

    $proc = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $cpuName = $proc.Name
    $detected = @()

    if ($cpuName -match "Virtual CPU|Microsoft Hyper-V|Virtualbox|vbox") {
        $detected += "CPU Name indicates virtualization: '$cpuName'"
    }

    $isBad = $detected.Count -gt 0
    $detail = if ($isBad) { $detected } else { "CPU Name appears normal: '$cpuName'. Typical of real hardware." }

    return [PSCustomObject]@{
        Category = "CPU IDs"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-PciVendor {

    $detected = @()
    Get-CimInstance -ClassName Win32_PnPEntity | ForEach-Object {
        if ($_.PNPDeviceID -match "VEN_80EE&DEV_CAFE") {
            $detected += "Detected VirtualBox PCI device: $($_.PNPDeviceID)"
        }
    }
    $isBad = $detected.Count -gt 0
    $detail = if ($isBad) {
        $detected
    }
    else {
        "No VirtualBox-specific PCI devices detected."
    }

    return [PSCustomObject]@{
        Category = "PCI Vendor ID"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-BaseBoard {

    $detected = @()
    $vmKeywords = @("VirtualBox", "Oracle Corporation", "Vbox")
    $genericKeywords = @("OEM", "To Be Filled By OEM", "System Manufacturer", "System Product Name", "Default string")

    $bb = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction SilentlyContinue
    if ($bb) {
        foreach ($prop in @($bb.Manufacturer, $bb.Product)) {
            foreach ($kw in $vmKeywords + $genericKeywords) {
                if ($prop -and ($prop -match [regex]::Escape($kw))) {
                    $detected += "Suspicious baseboard entry detected: $prop"
                    break
                }
            }
        }
    }

    $isBad = $detected.Count -gt 0
    $detail = if ($isBad) {
        $detected
    }
    else {
        "No suspicious baseboard manufacturer or product names found."
    }

    return [PSCustomObject]@{
        Category = "BaseBoard"
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-EventLogSources {
    $category = "Event Log Sources"
    $targets = @("vboxvideo", "VBoxVideoW8", "VBoxWddm")
    $detected = @()
    $accessError = $null

    try {
        $events = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = $targets } -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($events) {
            foreach ($evt in $events) {
                $detected += "Detected VirtualBox-related event source: $($evt.ProviderName)"
            }
        }
    }
    catch {
        $accessError = $_.Exception.Message
    }

    $isBad = ($detected.Count -gt 0)
    $detail = if ($isBad) {
        $detected
    }
    elseif ($accessError) {
        "System event log not accessible ($accessError) - skipping check."
    }
    else {
        "No VirtualBox-related event sources detected in the System event log."
    }

    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}


function Check-NetworkProvider {

    $dll = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("mpr.dll", CharSet=CharSet.Auto)]
    public static extern int WNetGetProviderName(int netType, System.Text.StringBuilder lpProviderName, ref int lpnLength);
}
"@
    Add-Type -TypeDefinition $dll -PassThru | Out-Null

    $sb = New-Object System.Text.StringBuilder 1024
    $len = $sb.Capacity
    $res = [Win32]::WNetGetProviderName(0x0000001A, $sb, [ref]$len)  
    $provider = if ($res -eq 0) { $sb.ToString() } else { "" }

    $isBad = ($provider -eq "VirtualBox Shared Folders")

    if ($isBad) {
        $detail = @("Provider: `"$provider`" (VirtualBox shared-folders detected)")
    }
    else {
        $detail = @("No VirtualBox Shared Folders provider")
    }

    return [PSCustomObject]@{
        Category = "NetProvider"
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-VBoxBiosData {
    $category = "VirtualBox BIOS"
    $findings = @()
    $biosKey = "HKLM:\\HARDWARE\\DESCRIPTION\\System"

    try {
        $sysBiosVersion = (Get-ItemProperty -Path $biosKey -Name "SystemBiosVersion" -ErrorAction Stop)."SystemBiosVersion"
        if ($sysBiosVersion) {
            $sysBiosVersionText = if ($sysBiosVersion -is [System.Array]) { $sysBiosVersion -join " " } else { $sysBiosVersion }
            if ($sysBiosVersionText -match "VBOX") {
                $findings += "SystemBiosVersion contains 'VBOX'"
            }
        }
    }
    catch { }  

    try {
        $vidBiosVersion = (Get-ItemProperty -Path $biosKey -Name "VideoBiosVersion" -ErrorAction Stop)."VideoBiosVersion"
        if ($vidBiosVersion) {
            $vidBiosVersionText = if ($vidBiosVersion -is [System.Array]) { $vidBiosVersion -join " " } else { $vidBiosVersion }
            if ($vidBiosVersionText -match "VIRTUALBOX") {
                $findings += "VideoBiosVersion contains 'VIRTUALBOX'"
            }
        }
    }
    catch { }

    try {
        $biosDate = (Get-ItemProperty -Path $biosKey -Name "SystemBiosDate" -ErrorAction Stop)."SystemBiosDate"
        if ($biosDate) {
            if ($biosDate -match "^06/2[3-9]/99$") {
                $findings += "SystemBiosDate is $biosDate (matches VirtualBox default)"
            }
        }
    }
    catch { }

    $isBad = $findings.Count -gt 0
    $detail = if ($isBad) {
        $findings  
    }
    else {
        @("BIOS strings are normal (no VirtualBox signatures detected)")
    }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-VBoxRegistryKeys {
    $category = "VirtualBox Registry"
    $findings = @()

    $regPaths = @(
        "HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
        "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
        "HKLM:\\HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HKLM:\\HARDWARE\\ACPI\\FADT\\VBOX__",
        "HKLM:\\HARDWARE\\ACPI\\RSDT\\VBOX__"
    )
    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            switch -Wildcard ($path) {
                "*VirtualBox Guest Additions" {
                    $findings += "VirtualBox Guest Additions registry key exists"
                }
                "*\\Services\\VBox*" {
                    $serviceName = ($path -split '\\')[-1]
                    $findings += "Service '$serviceName' registry key exists"
                }
                "*\\ACPI\\DSDT\\VBOX__" {
                    $findings += "ACPI DSDT\\VBOX__ registry key exists"
                }
                "*\\ACPI\\FADT\\VBOX__" {
                    $findings += "ACPI FADT\\VBOX__ registry key exists"
                }
                "*\\ACPI\\RSDT\\VBOX__" {
                    $findings += "ACPI RSDT\\VBOX__ registry key exists"
                }
                default {
                    $findings += "$path exists"
                }
            }
        }
    }

    $isBad = $findings.Count -gt 0
    $detail = if ($isBad) {
        $findings 
    }
    else {
        @("No VirtualBox-related registry keys or values found")
    }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-InstructionTiming {
    $category = "CPU Instruction Timing"
    
    $deltas = @()
    for ($i = 0; $i -lt 100; $i++) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $null = [Math]::Sqrt(12345)
        $sw.Stop()
        $deltas += $sw.Elapsed.TotalMilliseconds
    }
    
    $mean = ($deltas | Measure-Object -Average).Average
    $sumSquares = ($deltas | ForEach-Object { [Math]::Pow($_ - $mean, 2) } | Measure-Object -Sum).Sum
    $variance = $sumSquares / $deltas.Count
    $stdDev = [Math]::Sqrt($variance)
    
    $isBad = $stdDev -gt 0.15
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = "Timing variance: $([Math]::Round($stdDev, 4)) (VMs typically >0.15)"
    }
}

function Check-CPUBrandString {
    $category = "CPU Brand String Deep Check"
    
    $cpu = (Get-CimInstance Win32_Processor).Name
    $findings = @()
    
    if ($cpu -match "Intel" -and $cpu -notmatch "\d{4,5}[A-Z]{0,2}") {
        $findings += "Intel CPU missing generation/model number"
    }
    
    if ($cpu -match "\s{2,}") {
        $findings += "Unusual whitespace in CPU name"
    }
    
    $nominalSpeed = (Get-CimInstance Win32_Processor).MaxClockSpeed
    $currentSpeed = (Get-CimInstance Win32_Processor).CurrentClockSpeed
    
    if ([math]::Abs($nominalSpeed - $currentSpeed) -gt 500) {
        $findings += "Clock speed mismatch: Nominal=$nominalSpeed, Current=$currentSpeed"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "CPU brand string appears legitimate" }
    }
}

function Check-CacheTopology {
    $category = "CPU Cache Topology"
    
    $caches = Get-CimInstance Win32_CacheMemory
    $findings = @()
    
    if ($caches.Count -eq 0) {
        $findings += "No CPU cache detected (VM indicator)"
    }
    
    $l2Cache = $caches | Where-Object { $_.Level -eq 3 }
    $l3Cache = $caches | Where-Object { $_.Level -eq 4 }
    
    if (-not $l2Cache -and -not $l3Cache) {
        $findings += "Missing L2/L3 cache entries"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Cache topology normal ($($caches.Count) levels)" }
    }
}

function Check-MemoryArtifacts {
    $category = "Memory Artifacts"
    
    $memory = Get-CimInstance Win32_PhysicalMemory
    $findings = @()
    
    foreach ($dimm in $memory) {
        $mfg = $dimm.Manufacturer
        $partNumber = $dimm.PartNumber
        
        if ([string]::IsNullOrWhiteSpace($mfg) -or $mfg -match "^0+$") {
            $findings += "Missing or null memory manufacturer"
        }
        
        if ($partNumber -match "DIMM|Module|Virtual") {
            $findings += "Generic memory part number: $partNumber"
        }
        
        if ($dimm.SerialNumber -match "^0+$|^[Ff]+$") {
            $findings += "Invalid memory serial: $($dimm.SerialNumber)"
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Memory DIMMs appear legitimate" }
    }
}

function Check-DiskIOPattern {
    $category = "Disk I/O Patterns"
    
    $tempFile = [System.IO.Path]::GetTempFileName()
    $data = New-Object byte[] (1024 * 1024)  # 1MB
    
    $times = @()
    for ($i = 0; $i -lt 10; $i++) {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        [System.IO.File]::WriteAllBytes($tempFile, $data)
        $sw.Stop()
        $times += $sw.ElapsedMilliseconds
    }
    
    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    
    $average = ($times | Measure-Object -Average).Average
    $sumSquares = ($times | ForEach-Object { [Math]::Pow($_ - $average, 2) } | Measure-Object -Sum).Sum
    $variance = $sumSquares / $times.Count
    
    $hasNVMe = $false
    try {
        if (Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.BusType -eq "NVMe" }) {
            $hasNVMe = $true
        }
    }
    catch { }
    if (-not $hasNVMe) {
        $diskDrives = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue
        foreach ($disk in $diskDrives) {
            if ($disk.Model -match "NVMe|Micron|Samsung|WD|Solidigm|KIOXIA|SK hynix|Crucial|Kingston|Intel" -or 
                ($disk.InterfaceType -eq "SCSI" -and $disk.Model -notmatch "VBOX|VMware|Virtual|QEMU")) {
                $hasNVMe = $true
                break
            }
        }
    }
    
    $isBad = ($variance -lt 0.5 -and $average -lt 3 -and -not $hasNVMe)
    
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($hasNVMe) {
            "High-speed physical NVMe SSD detected (Avg: $([Math]::Round($average, 2))ms, Variance: $([Math]::Round($variance, 2)))"
        }
        else {
            "Avg: $([Math]::Round($average, 2))ms, Variance: $([Math]::Round($variance, 2))"
        }
    }
}

function Check-NetworkInterfaceDetails {
    $category = "Network Interface Deep Scan"
    
    $findings = @()
    
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    foreach ($adapter in $adapters) {
        if ($adapter.InterfaceDescription -match "VirtualBox Host-Only|Hyper-V|vEthernet|Wi-Fi Direct|NordLynx|WireGuard|OpenVPN|TAP-Windows") {
            continue
        }
        
        $mac = $adapter.MacAddress -replace "-", ""
        
        if ($mac.Length -ge 6) {
            $prefix = $mac.Substring(0, 6)
            
            $vmMacs = @{
                "080027" = "VirtualBox"
                "0A0027" = "VirtualBox (Newer)"
                "000569" = "VMware"
                "000C29" = "VMware"
                "001C14" = "VMware"
                "005056" = "VMware"
                "001C42" = "Parallels"
                "00163E" = "Xen"
                "00155D" = "Hyper-V"
                "525400" = "QEMU/KVM"
                "020054" = "Novell/QEMU"
                "001DD8" = "Microsoft Loopback"
            }
            
            if ($vmMacs.ContainsKey($prefix)) {
                $findings += "$($adapter.Name): $($adapter.MacAddress) ($($vmMacs[$prefix]))"
            }
        }
        
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Network interfaces appear legitimate" }
    }
}

function Check-VirtualizationPersistence {
    $category = "Virtualization Persistence"
    
    $findings = @()
    
    $runKeys = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    )
    
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $entries = Get-ItemProperty $key -ErrorAction SilentlyContinue
            
            foreach ($prop in $entries.PSObject.Properties) {
                if ($prop.Value -match "vbox|vmware|parallels|qemu|xen|virtio") {
                    $findings += "Autorun entry: $($prop.Name) = $($prop.Value)"
                }
            }
        }
    }
    
    $services = Get-Service | Where-Object { 
        $_.Name -match "vbox|vmware|parallels|qemu" -and 
        $_.Status -eq "Running" 
    }
    
    foreach ($svc in $services) {
        $findings += "VM service running: $($svc.Name) ($($svc.DisplayName))"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM persistence mechanisms detected" }
    }
}

function Check-PCIDevices {
    $category = "PCI Device Enumeration"
    
    $findings = @()
    
    $pciDevices = Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.PNPDeviceID -match "PCI\\"
    }
    
    foreach ($device in $pciDevices) {
        $deviceId = $device.PNPDeviceID
        
        if ($deviceId -match "VEN_80EE") {
            $findings += "VirtualBox PCI device: $($device.Name)"
        }
        
        if ($deviceId -match "VEN_15AD") {
            $findings += "VMware PCI device: $($device.Name)"
        }
        
        if ($deviceId -match "VEN_1234|VEN_1AF4") {
            $findings += "QEMU/KVM PCI device: $($device.Name)"
        }
        
        if ($deviceId -match "VEN_1B36") {
            $findings += "Red Hat Virtual device: $($device.Name)"
        }
        
        if ($deviceId -match "VEN_1414") {
            $findings += "Microsoft Virtual device: $($device.Name)"
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "PCI devices appear to be physical hardware" }
    }
}

function Check-SystemEntropy {
    $category = "System Entropy Analysis"
    
    $findings = @()
    
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 1000
    
    $startTime = Get-Date
    for ($i = 0; $i -lt 10; $i++) {
        $rng.GetBytes($bytes)
    }
    $duration = ((Get-Date) - $startTime).TotalMilliseconds
    
    if ($duration -gt 100) {
        $findings += "Slow entropy generation: ${duration}ms (VMs often >100ms)"
    }
    
    $rngService = Get-Service -Name "RNG" -ErrorAction SilentlyContinue
    if (-not $rngService) {
    }
    
    $rng.Dispose()
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Entropy generation appears normal (${duration}ms)" }
    }
}

function Check-AudioDevices {
    $category = "Audio Hardware"
    
    $findings = @()
    
    $audioDevices = Get-CimInstance Win32_SoundDevice
    
    if ($audioDevices.Count -eq 0) {
        $findings += "No audio devices detected (VM indicator)"
    }
    else {
        foreach ($device in $audioDevices) {
            if ($device.Name -match "NVIDIA Virtual Audio|NVIDIA High Definition Audio|Intel Display Audio") {
                continue
            }
            
            if ($device.Name -match "VBox|VMware|QEMU|Microsoft Basic Display|Bochs") {
                $findings += "Virtual audio device: $($device.Name)"
            }
            
            if ($device.Manufacturer -match "Oracle.*VirtualBox|VMware|Innotek|Red Hat") {
                $findings += "Suspicious audio manufacturer: $($device.Manufacturer)"
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Audio devices appear legitimate ($($audioDevices.Count) device(s))" }
    }
}

function Check-VirtualBoxPorts {
    $category = "VirtualBox Port Communication"
    
    $findings = @()
    
    $vboxPorts = @("VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxVideo")
    
    Get-CimInstance Win32_PnPEntity | ForEach-Object {
        $deviceId = $_.DeviceID
        foreach ($port in $vboxPorts) {
            if ($deviceId -match $port) {
                $findings += "VirtualBox port device: $deviceId"
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VirtualBox port devices found" }
    }
}

function Check-GPUMemory {
    $category = "GPU Memory Analysis"
    
    $gpu = Get-CimInstance Win32_VideoController | Select-Object -First 1
    $vramMB = [math]::Round($gpu.AdapterRAM / 1MB, 0)
    
    $findings = @()
    
    $suspiciousSizes = @(16, 32, 64, 128, 256)
    
    if ($suspiciousSizes -contains $vramMB) {
        $findings += "GPU has exactly ${vramMB}MB VRAM (common VM allocation)"
    }
    
    if ($vramMB -eq 0 -or $gpu.AdapterRAM -eq 0) {
        $findings += "GPU reports 0 or invalid VRAM"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "GPU VRAM appears normal (${vramMB}MB)" }
    }
}

function Check-WindowsSandbox {
    $category = "Windows Sandbox Detection"
    $findings = @()
    
    # 1. User and computer name markers of Windows Sandbox
    if ($env:USERNAME -match "WDAGUtilityAccount|ContainerUser") {
        $findings += "Sandbox user account: $env:USERNAME"
    }
    if (Test-Path "C:\Users\WDAGUtilityAccount") {
        $findings += "Windows Sandbox user profile found: C:\Users\WDAGUtilityAccount"
    }
    if ($env:COMPUTERNAME -match "^(WDAG|CONTAINER)-") {
        $findings += "Sandbox computer name format: $env:COMPUTERNAME"
    }

    # 2. Inside a Hyper-V / Windows Sandbox container VM
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    if ($cs -and ($cs.Model -match "Virtual Machine" -and $cs.Manufacturer -match "Microsoft")) {
        $findings += "Hyper-V Virtual Machine model detected ($($cs.Model))"
    }

    $isBad = ($findings.Count -gt 0)
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No Windows Sandbox/Container guest artifacts found" }
    }
}

function Check-SuspiciousPrograms {
    $category = "Installed Programs Check"
    
    $findings = @()
    $suspiciousApps = @(
        "VirtualBox Guest Additions",
        "VMware Tools",
        "Parallels Tools",
        "QEMU",
        "Sandboxie",
        "Shade Sandbox"
    )
    
    $paths = @(
        "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*",
        "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*"
    )
    
    foreach ($path in $paths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {
            $displayName = $_.DisplayName
            foreach ($app in $suspiciousApps) {
                if ($displayName -match $app) {
                    $findings += "Installed: $displayName"
                }
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No suspicious programs installed" }
    }
}

function Check-SMARTData {
    $category = "SMART Disk Data"
    
    $findings = @()
    
    try {
        $disks = Get-PhysicalDisk
        foreach ($disk in $disks) {
            if ($disk.HealthStatus -eq "Unknown") {
                $findings += "Disk '$($disk.FriendlyName)' has unknown health status"
            }
            
            if ($disk.MediaType -eq "Unspecified") {
                $findings += "Disk '$($disk.FriendlyName)' has unspecified media type"
            }
        }
    }
    catch {
        $findings += "Unable to query SMART data (may indicate VM)"
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "SMART data appears normal" }
    }
}

function Check-VBoxFiles {
    $category = "VirtualBox Files"
    $findings = @()
    $system32 = "$Env:SystemRoot\\System32"

    $filePaths = @(
        "$system32\\drivers\\VBoxMouse.sys",
        "$system32\\drivers\\VBoxWddm.sys",
        "$system32\\drivers\\VBoxGuest.sys",
        "$system32\\drivers\\VBoxSF.sys",
        "$system32\\drivers\\VBoxVideo.sys",
        "$system32\\vboxdisp.dll",
        "$system32\\vboxhook.dll",
        "$system32\\vboxmrxnp.dll",
        "$system32\\vboxogl.dll",
        "$system32\\vboxoglarrayspu.dll",
        "$system32\\vboxoglcrutil.dll",
        "$system32\\vboxoglerrorspu.dll",
        "$system32\\vboxoglfeedbackspu.dll",
        "$system32\\vboxoglpackspu.dll",
        "$system32\\vboxoglpassthroughspu.dll",
        "$system32\\VBoxService.exe",
        "$system32\\VBoxTray.exe",
        "$system32\\VBoxControl.exe"
    )
    foreach ($file in $filePaths) {
        if (Test-Path $file) {
            $filename = [System.IO.Path]::GetFileName($file)
            $findings += "$filename found"
        }
    }

    $isBad = $findings.Count -gt 0
    $detail = if ($isBad) {
        $findings 
    }
    else {
        @("No VirtualBox Guest Additions files or drivers found")
    }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-VBoxDirectories {
    $category = "VirtualBox Directories"
    $findings = @()

    $dirPaths = @(
        "$Env:ProgramFiles\\Oracle\\VirtualBox Guest Additions",
        "$Env:ProgramFiles(x86)\\Oracle\\VirtualBox Guest Additions",
        "$Env:ProgramFiles\\Vektor T13\\VirtualBox Guest Additions",
        "$Env:ProgramFiles(x86)\\Vektor T13\\VirtualBox Guest Additions"
    )
    foreach ($path in $dirPaths) {
        if ([string]::IsNullOrEmpty($path)) { continue }
        if (Test-Path $path) {
            $findings += "VirtualBox Guest Additions folder found: $path"
        }
    }

    $isBad = ($findings.Count -gt 0)
    $detail = if ($isBad) {
        $findings  
    }
    else {
        @("No VirtualBox Guest Additions directories detected")
    }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-VBoxDLLs {
    $category = "VirtualBox DLL Injection"
    
    $findings = @()
    $vboxDlls = @(
        "VBoxHook.dll",
        "VBoxMRXNP.dll", 
        "VBoxOGL.dll",
        "VBoxOGLarrayspu.dll",
        "VBoxOGLcrutil.dll",
        "VBoxOGLerrorspu.dll",
        "VBoxOGLfeedbackspu.dll",
        "VBoxOGLpackspu.dll",
        "VBoxOGLpassthroughspu.dll",
        "VBoxDisp.dll",
        "VBoxTray.exe",
        "VBoxControl.exe"
    )
    
    $loadedModules = Get-Process -Id $PID | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue
    
    foreach ($dll in $vboxDlls) {
        if (Test-Path "$env:SystemRoot\System32\$dll") {
            $findings += "Found in System32: $dll"
        }
        
        if (Test-Path "$env:SystemRoot\SysWOW64\$dll") {
            $findings += "Found in SysWOW64: $dll"
        }
        
        if ($loadedModules.ModuleName -contains $dll) {
            $findings += "Loaded in memory: $dll"
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VirtualBox DLLs detected" }
    }
}

function Check-ProcessAncestry {
    $category = "Suspicious Process Ancestry"
    
    $findings = @()
    
    $currentProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $PID"
    $parentPID = $currentProcess.ParentProcessId
    
    if ($parentPID) {
        $parent = Get-Process -Id $parentPID -ErrorAction SilentlyContinue
        
        if ($parent) {
            $suspiciousParents = @("vboxservice", "vmtoolsd", "joeboxserver", "prl_tools")
            
            if ($suspiciousParents -contains $parent.Name.ToLower()) {
                $findings += "Suspicious parent process: $($parent.Name)"
            }
            
            $timeDiff = ($currentProcess.CreationDate - $parent.StartTime).TotalSeconds
            if ($timeDiff -lt 1) {
                $findings += "Process spawned suspiciously fast after parent ($timeDiff seconds)"
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "Process ancestry appears normal" }
    }
}

function Check-VMWindowTitles {
    $category = "VM Window Titles"
    
    $findings = @()
    
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    using System.Text;
    
    public class WindowChecker {
        [DllImport("user32.dll")]
        static extern bool EnumWindows(EnumWindowsProc enumProc, IntPtr lParam);
        
        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
        
        [DllImport("user32.dll")]
        static extern IntPtr GetForegroundWindow();
        
        delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
        
        public static string[] GetAllWindowTitles() {
            var titles = new System.Collections.Generic.List<string>();
            IntPtr foreground = GetForegroundWindow();
            
            EnumWindows((hWnd, lParam) => {
                if (hWnd == foreground) return true;
                
                StringBuilder sb = new StringBuilder(256);
                if (GetWindowText(hWnd, sb, sb.Capacity) > 0) {
                    titles.Add(sb.ToString());
                }
                return true;
            }, IntPtr.Zero);
            
            return titles.ToArray();
        }
    }
"@
    
    $windowTitles = [WindowChecker]::GetAllWindowTitles()
    
    $vmKeywords = @(
        "VBoxTray", 
        "Oracle VM VirtualBox", 
        "VMware Workstation",
        "VMware Player",
        "QEMU",
        ".*\[Running\] - Oracle VM VirtualBox",
        "Parallels Desktop"
    )
    
    foreach ($title in $windowTitles) {
        if ([string]::IsNullOrWhiteSpace($title) -or $title -match "VM.*Checker|Detection Tool") {
            continue
        }
        
        foreach ($keyword in $vmKeywords) {
            if ($title -match $keyword) {
                $findings += "Suspicious window: $title"
                break
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM-related windows detected" }
    }
}

function Check-KernelDrivers {
    $category = "Kernel Driver Analysis"
    
    $findings = @()
    $vmDrivers = @(
        "vboxguest", "vboxmouse", "vboxsf", "vboxvideo", "vboxwddm",
        "vmci", "vmhgfs", "vmmouse", "vmmemctl", "vmrawdsk", "vmusbmouse",
        "prl_fs", "prl_eth", "prl_tg", "prl_mouf",
        "balloon", "pvscsi", "vmxnet"
    )
    
    $drivers = Get-WindowsDriver -Online -ErrorAction SilentlyContinue | 
    Select-Object -ExpandProperty Driver
    
    foreach ($driver in $drivers) {
        foreach ($vmDriver in $vmDrivers) {
            if ($driver -match $vmDriver) {
                $findings += "VM kernel driver: $driver"
                break
            }
        }
    }
    
    $runningDrivers = Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq "Running" }
    
    foreach ($driver in $runningDrivers) {
        foreach ($vmDriver in $vmDrivers) {
            if ($driver.Name -match $vmDriver) {
                $findings += "Running VM driver: $($driver.Name)"
                break
            }
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM kernel drivers detected" }
    }
}

function Check-ClipboardHistory {
    $category = "Clipboard Usage Analysis"
    
    Add-Type -AssemblyName System.Windows.Forms
    
    $findings = @()
    
    try {
        $clipboardProcesses = Get-Process | Where-Object {
            $_.ProcessName -match "VBoxClient|VBoxTray|vmware-vmblock|vmware-user|prl_cc"
        }
        
        if ($clipboardProcesses) {
            foreach ($proc in $clipboardProcesses) {
                $findings += "Clipboard sync process: $($proc.ProcessName)"
            }
        }
        
        $clipReg = "HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions"
        if (Test-Path $clipReg) {
            $clipSettings = Get-ItemProperty $clipReg -Name "*Clipboard*" -ErrorAction SilentlyContinue
            if ($clipSettings) {
                $findings += "VirtualBox clipboard registry keys found"
            }
        }
        
    }
    catch {
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM clipboard sync detected" }
    }
}

function Check-TLSCallbacks {
    $category = "TLS Callback Anomalies"
    
    $findings = @()
    
    try {
        $csharp = @"
using System;
using System.Runtime.InteropServices;

public class TLSCheck {
    [DllImport("ntdll.dll")]
    public static extern uint NtQueryInformationProcess(
        IntPtr ProcessHandle,
        uint ProcessInformationClass,
        IntPtr ProcessInformation,
        uint ProcessInformationLength,
        out uint ReturnLength
    );
    
    public static bool CheckTLS() {
        IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
        uint retLen;
        IntPtr buffer = Marshal.AllocHGlobal(8);
        
        uint result = NtQueryInformationProcess(hProcess, 7, buffer, 8, out retLen);
        
        int debugPort = Marshal.ReadInt32(buffer);
        Marshal.FreeHGlobal(buffer);
        
        return debugPort != 0;
    }
}
"@
        Add-Type -TypeDefinition $csharp
        
        $isDebugged = [TLSCheck]::CheckTLS()
        
        if ($isDebugged) {
            $findings += "Process appears to be debugged (common in analysis environments)"
        }
        
    }
    catch {
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No TLS/debugging anomalies detected" }
    }
}

function Check-SharedFolders {
    $category = "VM Shared Folders"
    
    $findings = @()
    
    $vboxShares = net use 2>$null | Select-String "VBoxSvr|VBoxSharedFolders"
    if ($vboxShares) {
        $findings += "VirtualBox shared folders detected"
    }
    
    $vmwareShares = net use 2>$null | Select-String "vmware-host|hgfs"
    if ($vmwareShares) {
        $findings += "VMware shared folders detected"
    }
    
    $sharedFolderKeys = @(
        "HKLM:\\SOFTWARE\\Oracle\\VirtualBox Guest Additions\\SharedFolders",
        "HKLM:\\SOFTWARE\\VMware, Inc.\\VMware Tools\\SharedFolders"
    )
    
    foreach ($key in $sharedFolderKeys) {
        if (Test-Path $key) {
            $findings += "Shared folder registry key: $key"
        }
    }
    
    $isBad = $findings.Count -gt 0
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = if ($isBad) { $findings } else { "No VM shared folders detected" }
    }
}

function Check-FirmwareVM {
    
    if (-not ([System.Management.Automation.PSTypeName]'Native').Type) {
        $csp = @"
    using System;
    using System.Runtime.InteropServices;
    public static class Native {
        [DllImport("ntdll.dll")]
        public static extern int NtQuerySystemInformation(
            uint SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool VirtualFree(
            IntPtr lpAddress,
            UIntPtr dwSize,
            uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern uint EnumSystemFirmwareTables(
            uint FirmwareTableProviderSignature,
            IntPtr pFirmwareTableEnumBuffer,
            uint BufferSize);

        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern uint GetSystemFirmwareTable(
            uint FirmwareTableProviderSignature,
            uint FirmwareTableID,
            IntPtr pFirmwareTableBuffer,
            uint BufferSize);
    }
"@
        Add-Type -TypeDefinition $csp -ErrorAction SilentlyContinue | Out-Null
    }

    function Get-TableBytes {
        param(
            [uint32]$Signature,
            [uint32]$TableId
        )

        $class = 76                           
        [uint32]$reqLen = 0                     
        $tmpPtr = [Native]::VirtualAlloc(
            [IntPtr]::Zero,
            [UIntPtr]::new(16),
            0x3000,                            
            0x04                                
        )
        [Native]::NtQuerySystemInformation(
            $class,
            $tmpPtr,
            [uint32]16,                        
            [ref]$reqLen
        ) | Out-Null

        if ($reqLen -le 16) {
            [Native]::VirtualFree($tmpPtr, [UIntPtr]::new(0), 0x8000) | Out-Null
            return $null
        }

        [Native]::VirtualFree($tmpPtr, [UIntPtr]::new(0), 0x8000) | Out-Null
        $bufPtr = [Native]::VirtualAlloc(
            [IntPtr]::Zero,
            [UIntPtr]::new($reqLen),
            0x3000,
            0x04
        )

        [System.Runtime.InteropServices.Marshal]::WriteInt32($bufPtr, 0, [int]$Signature)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($bufPtr, 4, 1)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($bufPtr, 8, [int]$TableId)
        [System.Runtime.InteropServices.Marshal]::WriteInt32($bufPtr, 12, [int]($reqLen - 16))

        [uint32]$outLen = 0                    
        [Native]::NtQuerySystemInformation(
            $class,
            $bufPtr,
            [uint32]$reqLen,                   
            [ref]$outLen
        ) | Out-Null

        if ($outLen -le 16) {
            [Native]::VirtualFree($bufPtr, [UIntPtr]::new(0), 0x8000) | Out-Null
            return $null
        }

        $payload = New-Object byte[] ($outLen - 16)
        [System.Runtime.InteropServices.Marshal]::Copy($bufPtr + 16, $payload, 0, $payload.Length)
        [Native]::VirtualFree($bufPtr, [UIntPtr]::new(0), 0x8000) | Out-Null

        return $payload
    }

    $targets = @(
        "Parallels", "innotek", "Oracle", "VirtualBox", "VMware, Inc.", "VMware",
        "Qemu", "vbox", "BOCHS", "BXPC", "WAET"
    )

    $findings = @()

    foreach ($tbl in @("RSMB", "FIRM")) {
        $sig = [System.BitConverter]::ToInt32([System.Text.Encoding]::ASCII.GetBytes($tbl), 0)
        $ids = if ($tbl -eq "FIRM") { 0xC0000, 0xE0000 } else { 0 }
        foreach ($id in $ids) {
            $bytes = Get-TableBytes -Signature $sig -TableId $id
            if ($bytes) {
                $text = [System.Text.Encoding]::ASCII.GetString($bytes)
                foreach ($t in $targets) {
                    if ($text.Contains($t)) {
                        $findings += "Found `$t` in $tbl table (ID=0x{0:X})" -f $id
                    }
                }
            }
        }
    }

    $acpiSig = [System.BitConverter]::ToInt32([System.Text.Encoding]::ASCII.GetBytes("ACPI"), 0)
    $bytes = Get-TableBytes -Signature $acpiSig -TableId 0
    if ($bytes) {
        $s = [System.Text.Encoding]::ASCII.GetString($bytes)
        foreach ($t in $targets) {
            if ($s.Contains($t)) { $findings += "Found `$t` in ACPI dump" }
        }
    }

    $sn = (Get-WmiObject Win32_BIOS).SerialNumber
    if ($sn -match '^VMW' -or $sn -eq '0' -or $sn -match '^[Ff]+$') {
        $findings += "BIOS serial suggests VM: $sn"
    }

    return [PSCustomObject]@{
        Category = 'Firmware VM Signatures'
        IsBad    = ($findings.Count -gt 0)
        Detail   = if ($findings) { $findings } else { @('No firmware VM signatures detected') }
    }
}



function Check-ACPIEmulatedDevices {
    $category = "ACPI Emulated Devices (WAET)"
    $findings = @()
    
    try {
        $acpiSig = 0x41435049 # 'ACPI'
        $size = [Native]::EnumSystemFirmwareTables($acpiSig, [IntPtr]::Zero, 0)
        if ($size -gt 0) {
            $ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$size)
            $ret = [Native]::EnumSystemFirmwareTables($acpiSig, $ptr, $size)
            if ($ret -eq $size) {
                $count = [int]($size / 4)
                $tables = @()
                for ($i = 0; $i -lt $count; $i++) {
                    $val = [System.Runtime.InteropServices.Marshal]::ReadInt32($ptr, $i * 4)
                    $bytes = [System.BitConverter]::GetBytes($val)
                    $tag = [System.Text.Encoding]::ASCII.GetString($bytes)
                    $tables += $tag
                    
                    if ($tag -eq "WAET") {
                        $findings += "WAET table present: Windows ACPI Emulated Devices table detected (hypervisor timer evasion artifact)"
                    }
                }
                
                $suspiciousSignatures = @("VBOX", "VMW", "BOCHS", "BXPC", "QEMU")
                foreach ($t in $tables) {
                    foreach ($sig in $suspiciousSignatures) {
                        if ($t -like "*$sig*") {
                            $findings += "ACPI table '$t' matches VM signature '$sig'"
                        }
                    }
                }
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
        }
    }
    catch {
        # Fallback if API fails
    }

    $isBad = ($findings.Count -gt 0)
    $detail = if ($isBad) { $findings } else { "No WAET table or virtual ACPI signatures detected via firmware table API" }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-HPETStructure {
    $category = "HPET Table Structure"
    $findings = @()
    
    try {
        $acpiSig = 0x41435049 # 'ACPI'
        $hpetId = [System.BitConverter]::ToUInt32([System.Text.Encoding]::ASCII.GetBytes("HPET"), 0)
        $hpetSize = [Native]::GetSystemFirmwareTable($acpiSig, $hpetId, [IntPtr]::Zero, 0)
        
        if ($hpetSize -eq 0) {
            $findings += "HPET ACPI table is missing (suspicious on modern x86 hardware)"
        }
        elseif ($hpetSize -lt 56) {
            $findings += "HPET table length ($hpetSize bytes) is smaller than ACPI standard (56 bytes)"
        }
        else {
            $hBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([int]$hpetSize)
            $got = [Native]::GetSystemFirmwareTable($acpiSig, $hpetId, $hBuf, $hpetSize)
            if ($got -ge 56) {
                $bytes = New-Object byte[] $got
                [System.Runtime.InteropServices.Marshal]::Copy($hBuf, $bytes, 0, [int]$got)
                
                $sum = 0
                foreach ($b in $bytes) { $sum = ($sum + $b) -band 0xFF }
                if ($sum -ne 0) {
                    $findings += "HPET table checksum failed (0x$($sum.ToString('X2')))"
                }
                
                $gasBitWidth = $bytes[41]
                $flags = $bytes[55]
                $hwId = [System.BitConverter]::ToUInt32($bytes, 36)
                $vendorId = ($hwId -shr 16) -band 0xFFFF
                $cmpRaw = ($hwId -shr 8) -band 0x1F
                
                if ($gasBitWidth -ne 0x40 -and $gasBitWidth -ne 64) {
                    $findings += "HPET Register Bit Width is $gasBitWidth (expected 64 on physical systems; often 32 on VMs)"
                }
                if ($flags -ne 0x00) {
                    $findings += "HPET Page Protection Flags are set (0x$($flags.ToString('X2')); unusual on bare metal)"
                }
                if ($cmpRaw -eq 15) {
                    $findings += "HPET ComparatorFieldRaw is 15 (known VMware signature)"
                }
                if ($vendorId -ne 0x8086 -and $vendorId -ne 0x1022) {
                    $findings += "HPET VendorID (0x$($vendorId.ToString('X4'))) atypical for modern x86 chipset"
                }
            }
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($hBuf)
        }
    }
    catch {
        # Fallback
    }

    $isBad = ($findings.Count -gt 0)
    $detail = if ($isBad) { $findings } else { "HPET table structure valid (64-bit width, page-protect clear, standard vendor ID)" }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-ForensicFreshness {
    $category = "Forensic Installation Freshness"
    $findings = @()
    
    $now = Get-Date
    $regInstallDate = $null
    try {
        $unixTime = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "InstallDate" -ErrorAction SilentlyContinue).InstallDate
        if ($unixTime) {
            $regInstallDate = ([datetime]'1970-01-01').AddSeconds($unixTime).ToLocalTime()
        }
    }
    catch {}

    $evidence = @()
    if (Test-Path $env:USERPROFILE) {
        $evidence += [PSCustomObject]@{ Name = "User Folder"; Date = (Get-Item $env:USERPROFILE).CreationTime }
    }
    $ntuser = Join-Path $env:USERPROFILE "NTUSER.DAT"
    if (Test-Path $ntuser) {
        $evidence += [PSCustomObject]@{ Name = "NTUSER.DAT"; Date = (Get-Item $ntuser -Force).CreationTime }
    }
    foreach ($setupLog in @("C:\Windows\Panther\setupact.log", "C:\Windows\setupact.log")) {
        if (Test-Path $setupLog) {
            $evidence += [PSCustomObject]@{ Name = "Setup Log"; Date = (Get-Item $setupLog -Force).CreationTime }
            break
        }
    }
    if ($regInstallDate) {
        $evidence += [PSCustomObject]@{ Name = "Registry InstallDate"; Date = $regInstallDate }
    }

    if ($evidence.Count -gt 0) {
        $oldest = $evidence | Sort-Object Date | Select-Object -First 1
        $ageDays = ($now - $oldest.Date).TotalDays
        if ($ageDays -lt 3) {
            $findings += "System age indicator ($($oldest.Name)) is only $([math]::Round($ageDays, 1)) days old (< 3 days indicates fresh VM sandbox)"
        }
        
        if ($regInstallDate -and $evidence.Count -gt 1) {
            $fsDates = $evidence | Where-Object { $_.Name -ne "Registry InstallDate" -and $_.Name -ne "Setup Log" }
            if ($fsDates) {
                $earliestFs = ($fsDates | Sort-Object Date | Select-Object -First 1).Date
                $diffDays = ($earliestFs - $regInstallDate).TotalDays
                if ($diffDays -gt 90 -and $ageDays -lt 7) {
                    $findings += "Forensic discrepancy: Registry InstallDate ($($regInstallDate.ToString('yyyy-MM-dd'))) conflicts with filesystem creation ($($earliestFs.ToString('yyyy-MM-dd')))"
                }
            }
        }
    }

    $isBad = ($findings.Count -gt 0)
    $detail = if ($isBad) { $findings } else { "Forensic installation timestamps verified: system appears aged ($([math]::Round($ageDays, 1)) days old via $($oldest.Name)) without discrepancies" }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-PCAAndArtifactCleanliness {
    $category = "PCA Logs & Artifact Cleanliness"
    $findings = @()
    
    # 1. PCA Logs
    $pcaDir = "C:\Windows\AppCompat\PCA"
    $pcaTotalLines = 0
    if (Test-Path $pcaDir) {
        Get-ChildItem $pcaDir -ErrorAction SilentlyContinue | ForEach-Object {
            $pcaTotalLines += (Get-Content $_.FullName -ErrorAction SilentlyContinue | Measure-Object).Count
        }
    }
    
    # 2. Folder Cleanliness
    $foldersToCheck = @(
        @{ Name = "User Temp"; Path = $env:TEMP },
        @{ Name = "Windows Temp"; Path = "C:\Windows\Temp" },
        @{ Name = "Recent Items"; Path = (Join-Path $env:APPDATA "Microsoft\Windows\Recent") }
    )
    if (Test-Path "C:\Windows\Prefetch") {
        $foldersToCheck += @{ Name = "Prefetch"; Path = "C:\Windows\Prefetch" }
    }
    
    $totalFiles = 0
    foreach ($item in $foldersToCheck) {
        if (Test-Path $item.Path) {
            $count = (Get-ChildItem -Path $item.Path -Force -ErrorAction SilentlyContinue | Measure-Object).Count
            $totalFiles += $count
        }
    }

    # Sandboxes have near-zero aggregate files across temp/recent and empty PCA logs.
    # On real systems, Windows Temp is routinely cleared by Storage Sense, while User Temp retains files.
    if ($totalFiles -lt 5 -and $pcaTotalLines -lt 5) {
        $findings += "Suspiciously sterile system: aggregate temp/recent files ($totalFiles) and PCA entries ($pcaTotalLines) indicate an automated sandbox environment"
    }

    $isBad = ($findings.Count -gt 0)
    $detail = if ($isBad) { $findings } else { "PCA logs show normal application usage ($pcaTotalLines entries); artifact directories exhibit natural activity volume ($totalFiles files)" }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-DisplayAdapterDeepScan {
    $category = "Display Adapter Metadata"
    $findings = @()
    
    $videoRoot = "HKLM:\SYSTEM\CurrentControlSet\Control\Video"
    if (Test-Path $videoRoot) {
        Get-ChildItem $videoRoot -ErrorAction SilentlyContinue | ForEach-Object {
            Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $desc = "$($props.DriverDesc) $($props.'Device Description')"
                
                foreach ($kw in @("VMWARE", "VBOX", "VIRTUAL", "BASIC DISPLAY", "STANDARD VGA")) {
                    if ($desc.ToUpper() -like "*$kw*") {
                        $findings += "Display Adapter driver description matches '$kw': $desc"
                    }
                }
                
                $chip = $props.'HardwareInformation.ChipType'
                $chipStr = ""
                if ($chip -is [byte[]]) {
                    $chipStr = [System.Text.Encoding]::Unicode.GetString($chip).Trim([char]0)
                }
                elseif ($chip -is [string]) {
                    $chipStr = $chip
                }
                if ($chipStr -match '([A-Za-z0-9])\1{3,}' -or $chipStr -match '0123|1234|ABCD') {
                    $findings += "Display ChipType contains suspicious repetitive/sequential pattern: $chipStr"
                }
            }
        }
    }
    
    $classKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000"
    if (Test-Path $classKey) {
        $cp = Get-ItemProperty $classKey -ErrorAction SilentlyContinue
        $cDesc = "$($cp.DriverDesc) $($cp.ProviderName)"
        if ($cDesc -like "*VirtualBox*" -or $cDesc -like "*VMware*" -or $cDesc -like "*Standard VGA Graphics Adapter*") {
            $findings += "Display Class 0000 has virtual GPU or unaccelerated adapter: $cDesc"
        }
    }

    $isBad = ($findings.Count -gt 0)
    $detail = if ($isBad) { $findings } else { "Display adapter metadata and ChipType appear legitimate (no VM drivers or standard VGA adapters)" }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}

function Check-DriverAnomalies {
    $category = "Driver Path Anomalies & VMLoader"
    $findings = @()
    
    try {
        $services = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue
        foreach ($s in $services) {
            $name = $s.PSChildName
            $disp = "$($s.DisplayName)"
            $img = "$($s.ImagePath)"
            if ($name -like "*vmloader*" -or $disp -like "*vmloader*" -or $img -like "*vmloader*") {
                $findings += "Suspicious service detected: Name='$name', ImagePath='$img'"
            }
            if ($img -match '^[A-Za-z]:\\[^\\/:*?"<>|]+\.sys') {
                $findings += "Driver located directly in drive root: Name='$name', Path='$img'"
            }
        }
    }
    catch {}

    try {
        [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady } | ForEach-Object {
            $rootSys = Join-Path $_.RootDirectory.FullName "vmloader.sys"
            if (Test-Path $rootSys) {
                $findings += "Root driver file found: $rootSys"
            }
        }
    }
    catch {}

    $isBad = ($findings.Count -gt 0)
    $detail = if ($isBad) { $findings } else { "No root-path drivers, vmloader files, or loader services detected" }
    return [PSCustomObject]@{
        Category = $category
        IsBad    = $isBad
        Detail   = $detail
    }
}


# -------------------------------------------------------------
# Knowledge Base: Full Descriptions & Remediation for All 63 Checks
# -------------------------------------------------------------
$knowledgeBase = @{
    'Registry Keys'                    = @{
        Desc        = "Scans Windows Registry for known virtualization guest additions, services, and hardware entries."
        Technique   = "Looks for keys associated with VirtualBox, VMware, and Wine (e.g. HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions, VBoxGuest service, ACPI DSDT entries, SCSI/Disk identifiers)."
        Remediation = "'Set-RegistryAntiDetection' in Run-Inside-VM.ps1 removes or disguises these virtualization registry artifacts."
    }
    'Timing Check'                     = @{
        Desc        = "Measures actual elapsed wall-clock time during Sleep calls to detect sandbox time-acceleration hooks."
        Technique   = "Analysis sandboxes fast-forward or hook Sleep() APIs to bypass malware sleep delays. Significant timing discrepancies reveal sandbox acceleration."
        Remediation = "Ensure the VM runs in real-time execution mode without artificial sleep-skipping hooks."
    }
    'HypervisorCheck'                  = @{
        Desc        = "Queries WMI Win32_ComputerSystem for HypervisorPresent flag."
        Technique   = "Hypervisors set HypervisorPresent=True to indicate a virtualization environment to the guest OS."
        Remediation = "Note: On bare-metal Windows 10/11 with VBS or WSL enabled, HypervisorPresent is naturally True. Inside VMs, CloakBox cloaks WMI queries via 'Set-WMIAntiDetection'."
    }
    'Screen Resolution'                = @{
        Desc        = "Evaluates the primary display resolution against typical sandbox and default VM dimensions."
        Technique   = "Automated analysis sandboxes frequently operate at fallback low resolutions like 800x600, 1024x768, or 1280x720."
        Remediation = "Configure the guest display resolution to 1920x1080 or the native resolution of your host display."
    }
    'User Activity'                    = @{
        Desc        = "Checks for human usage indicators including browser history and recent document activity."
        Technique   = "Freshly deployed sandboxes have zero Chrome/Edge history and empty recent file directories."
        Remediation = "'Initialize-SystemArtifactsAndPCA' in Run-Inside-VM.ps1 populates realistic recent files and user activity artifacts."
    }
    'Clipboard Sharing'                = @{
        Desc        = "Detects guest integration clipboard synchronization processes."
        Technique   = "Monitors for running guest integration utilities like VBoxClient or vmware-vmblock handling clipboard sharing."
        Remediation = "'Remove-VMSpecificDLLs' and process hiding routines prevent detection of clipboard integration services."
    }
    'VirtualBox Ports'                 = @{
        Desc        = "Tests VirtualBox guest-to-host backdoor communication I/O port 0x5054."
        Technique   = "Issues the magic handshake command to I/O port 0x5054 used by VirtualBox Guest Additions to communicate with the host."
        Remediation = "Disable Guest Additions I/O port communication or run without Guest Additions enabled."
    }
    'SMART Data'                       = @{
        Desc        = "Queries WMI MSStorageDriver_ATAPISmartData for hard drive SMART telemetry."
        Technique   = "Physical disks return rich SMART health attributes, whereas virtual disks (VBOX, VMware) return null or fail SMART queries."
        Remediation = "Physical hardware characteristic; emulated disks do not natively supply SMART data."
    }
    'CPUFeatureCheck'                  = @{
        Desc        = "Verifies that standard CPU features (NX, SSE2, SSE3, RDTSC) are present."
        Technique   = "Emulators and low-end virtual machines often omit or incorrectly emulate advanced instruction sets."
        Remediation = "Configured in VirtualBox VM settings by allocating modern CPU feature flags."
    }
    'VideoAdapterCheck'                = @{
        Desc        = "Inspects display adapter drivers and hardware descriptions."
        Technique   = "Detects virtual GPU drivers such as VBoxVideo, VMware SVGA 3D, or Microsoft Basic Display Adapter."
        Remediation = "'Set-GPUSpoofing' and 'Set-AdvancedGPUCapabilities' in Run-Inside-VM.ps1 spoof NVIDIA/AMD graphics card properties."
    }
    'OSArtifactCheck'                  = @{
        Desc        = "Checks username, computer name, and OS install date for sandbox default patterns."
        Technique   = "Automated sandboxes commonly use usernames like 'sandbox', 'test', or 'currentuser', and generic computer names."
        Remediation = "'Set-EnhancedInstallDateTime' and system configuration routines randomize install timestamps and user metadata."
    }
    'Processes'                        = @{
        Desc        = "Scans running processes for virtualization management tools."
        Technique   = "Monitors background services like VBoxService, VBoxTray, vmtoolsd, or qemu-ga."
        Remediation = "'Hide-VMProcesses' in Run-Inside-VM.ps1 terminates and disguises virtualization background processes."
    }
    'System Files'                     = @{
        Desc        = "Checks system directories for virtualization driver files."
        Technique   = "Looks for driver binaries like VBoxGuest.sys, VBoxMouse.sys, and VBoxSF.sys in C:\Windows\System32\drivers."
        Remediation = "'Remove-VMSpecificDLLs' and file disguise routines clean and rename virtualization binaries."
    }
    'Hardware IDs'                     = @{
        Desc        = "Inspects system manufacturer, model, and product strings."
        Technique   = "Virtual machines default to identifiers like 'innotek GmbH', 'VirtualBox', or 'VMware, Inc.'."
        Remediation = "'Set-BIOSSecurityRecommendations' and Outside-VM scripts configure realistic OEM hardware identifiers."
    }
    'BIOS Info'                        = @{
        Desc        = "Checks BIOS release date, version, and serial number."
        Technique   = "Virtual BIOS strings frequently contain 'VirtualBox', 'VBOX', or default strings like '0'."
        Remediation = "Handled by DMI/BIOS string spoofing in CloakBox."
    }
    'MAC Address'                      = @{
        Desc        = "Checks network adapter MAC addresses against known virtualization OUI vendor prefixes."
        Technique   = "VirtualBox uses 08:00:27 and 0A:00:27; VMware uses 00:05:69, 00:0C:29, and 00:50:56."
        Remediation = "'Set-RandomMacAddress' in Run-Inside-VM.ps1 generates a randomized physical NIC MAC address. Note: On a host with VirtualBox installed, the VirtualBox Host-Only Adapter naturally uses this prefix."
    }
    'Device Manager Names'             = @{
        Desc        = "Scans PnP hardware friendly names in Device Manager."
        Technique   = "Virtual devices often advertise names containing 'VirtualBox', 'VMware', or 'VBOX'."
        Remediation = "'Set-PCIDeviceIDSpoofing' renames virtual devices to standard physical device names. Expected on host machines running VirtualBox."
    }
    'ACPI Tables'                      = @{
        Desc        = "Scans raw ACPI tables (DSDT, FACP, RSDT) for hypervisor signatures."
        Technique   = "ACPI tables in virtual machines frequently contain signatures like 'VBOX__', 'VMW__', or 'BOCHS'."
        Remediation = "'Set-FirmwareTableSpoofing' in Run-Inside-VM.ps1 patches ACPI descriptors in registry and memory."
    }
    'CPU Cores'                        = @{
        Desc        = "Checks logical processor count."
        Technique   = "Sandboxes and test VMs typically allocate only 1-2 vCPUs. Physical systems typically have 4 or more cores."
        Remediation = "Allocate at least 4 to 8 CPU cores to the virtual machine in VirtualBox settings."
    }
    'RAM Size'                         = @{
        Desc        = "Measures total physical memory."
        Technique   = "Automated analysis sandboxes often provision less than 4-6 GB RAM to conserve server resources."
        Remediation = "Assign at least 8 GB (or 16 GB if available) of RAM to the virtual machine."
    }
    'Disk Size'                        = @{
        Desc        = "Checks primary hard drive capacity."
        Technique   = "Default virtual disks are frequently 20-60 GB, which triggers sandbox heuristics."
        Remediation = "Create virtual disks of 100 GB or larger, or configure sparse allocation of 250+ GB."
    }
    'Mouse Movement'                   = @{
        Desc        = "Samples mouse cursor coordinates over a short time interval."
        Technique   = "Automated malware execution sandboxes operate without human interaction, keeping the cursor stationary."
        Remediation = "Moving your mouse actively across the screen during the 2-second check satisfies this test."
    }
    'PCI Vendor ID'                    = @{
        Desc        = "Inspects PCI bus device vendor IDs."
        Technique   = "VirtualBox devices use vendor ID 0x80EE; VMware uses 0x15AD; QEMU/VirtIO uses 0x1AF4."
        Remediation = "'Set-PCIDeviceIDSpoofing' modifies registry mappings for virtual PCI hardware."
    }
    'BaseBoard'                        = @{
        Desc        = "Checks motherboard manufacturer and product name."
        Technique   = "Virtual motherboards report 'Oracle Corporation', 'VirtualBox', or generic strings."
        Remediation = "CloakBox outside-VM configuration sets realistic motherboard details (e.g. ASUS/Dell)."
    }
    'VirtualBox BIOS'                  = @{
        Desc        = "Checks physical memory and registry for VirtualBox BIOS signatures."
        Technique   = "Inspects the F0000 memory segment or BIOS version registry keys for copyright notices."
        Remediation = "Cleaned by 'Set-BIOSSecurityRecommendations' in Run-Inside-VM.ps1."
    }
    'Event Log Sources'                = @{
        Desc        = "Checks Windows Event Log for provider registrations from VirtualBox drivers."
        Technique   = "VirtualBox installs event log providers such as vboxvideo or VBoxWddm."
        Remediation = "Event logs are cleared and sanitized by Run-Inside-VM.ps1."
    }
    'VirtualBox Registry'              = @{
        Desc        = "Deep scan of system registry keys for leftover VirtualBox installation traces."
        Technique   = "Scans software and system keys for Oracle/VirtualBox configuration remnants."
        Remediation = "Cleaned by the deep registry purge in Run-Inside-VM.ps1."
    }
    'NetProvider'                      = @{
        Desc        = "Inspects Windows Network Providers."
        Technique   = "VirtualBox Shared Folders installs 'VBoxSharedFolders' as a registered network provider."
        Remediation = "Uninstall or disable Guest Additions shared folders."
    }
    'VirtualBox Files'                 = @{
        Desc        = "Checks filesystem paths for VirtualBox binaries."
        Technique   = "Looks for Guest Additions executables like VBoxService.exe and VBoxControl.exe."
        Remediation = "'Remove-VMSpecificDLLs' unlinks and removes Guest Additions executables."
    }
    'VirtualBox Directories'           = @{
        Desc        = "Checks for the presence of VirtualBox directory structures."
        Technique   = "Checks for 'C:\Program Files\Oracle\VirtualBox' or driver store folders."
        Remediation = "Expected on host machines; inside guest VMs, Guest Additions folders are scrubbed."
    }
    'Firmware VM Signatures'           = @{
        Desc        = "Scans EFI firmware tables and BIOS serial numbers."
        Technique   = "Virtual firmware serials often begin with 'VMW' or contain repetitive characters."
        Remediation = "'Set-BIOSSecurityRecommendations' configures realistic serial numbers."
    }
    'CPU IDs'                          = @{
        Desc        = "Queries CPUID leaf 0x40000000 for hypervisor vendor signatures."
        Technique   = "Hypervisors return signatures like 'KVMKVMKVM', 'Microsoft Hv', or 'VMwareVMware'."
        Remediation = "Configured via VBoxManage commands in Outside-VM scripts."
    }
    'CPUID Hypervisor Bit'             = @{
        Desc        = "Checks bit 31 of ECX on CPUID leaf 1 (Hypervisor Present flag)."
        Technique   = "Physical CPUs return 0; virtual CPUs return 1 to indicate hypervisor presence. On host machines with VBS/Hyper-V enabled, Windows runs under hypervisor."
        Remediation = "Can be masked using CPUID leaf masking in advanced hypervisor configurations."
    }
    'USB Devices'                      = @{
        Desc        = "Enumerates connected USB controllers and devices."
        Technique   = "Physical machines almost always have USB input or hub devices; sandboxes frequently have zero."
        Remediation = "Attach virtual USB devices or pass through USB peripherals in VM configuration."
    }
    'Battery Presence'                 = @{
        Desc        = "Checks for an active battery or UPS subsystem."
        Technique   = "Laptops have batteries, while virtual machines almost never report battery hardware."
        Remediation = "'Set-PowerCapabilitiesSpoofing' in Run-Inside-VM.ps1 creates virtual battery registry entries."
    }
    'Temperature Sensors'              = @{
        Desc        = "Queries hardware thermal zones and temperature sensors."
        Technique   = "Virtual machines do not emulate motherboard or CPU thermal monitoring probes."
        Remediation = "A hallmark physical hardware indicator; typical for VMs to lack thermal sensors."
    }
    'System Uptime'                    = @{
        Desc        = "Measures system running time."
        Technique   = "Sandboxes rarely run longer than 5-10 minutes before automated teardown."
        Remediation = "Allow the VM to run for at least 30-60 minutes before taking tests or executing analysis."
    }
    'CPU Instruction Timing'           = @{
        Desc        = "Measures timing variance of privileged instructions (RDTSC, CPUID)."
        Technique   = "Handling VM-exits causes instruction execution timing to spike noticeably compared to bare metal."
        Remediation = "Mitigated by 'Set-ProcessTimingMasking' in Run-Inside-VM.ps1."
    }
    'CPU Brand String Deep Check'      = @{
        Desc        = "Validates the full CPU brand string across CPUID leaves."
        Technique   = "Checks for emulated CPU models or missing CPU identification strings."
        Remediation = "'Set-CPUInfoSpoofing' in Run-Inside-VM.ps1 injects legitimate retail CPU brand strings."
    }
    'CPU Cache Topology'               = @{
        Desc        = "Inspects CPU cache levels (L1, L2, L3) and topology descriptors."
        Technique   = "Virtual CPUs often present irregular or absent cache hierarchies."
        Remediation = "Modern VirtualBox configurations pass through host CPU cache definitions."
    }
    'Memory Artifacts'                 = @{
        Desc        = "Inspects physical memory DIMM details."
        Technique   = "Checks for missing memory serial numbers or generic part names like 'DIMM' or 'Virtual'."
        Remediation = "'Set-WMIAntiDetection' populates realistic memory module manufacturers and serials."
    }
    'Disk I/O Patterns'                = @{
        Desc        = "Evaluates disk write latency and performance variance."
        Technique   = "Host-backed VM disk caches can produce unrealistically low write latencies without variance. High-speed NVMe SSDs on host laptops can also trigger low-latency thresholds."
        Remediation = "Use direct I/O or allocate virtual disks on high-speed NVMe storage."
    }
    'VirtualBox Port Communication'    = @{
        Desc        = "Tests for VirtualBox guest-to-host backdoor communication I/O ports."
        Technique   = "VirtualBox uses I/O port 0xD040 for guest additions synchronization."
        Remediation = "Disabling guest additions closes guest communication ports."
    }
    'GPU Memory Analysis'              = @{
        Desc        = "Measures dedicated video RAM (VRAM)."
        Technique   = "Virtual GPUs typically allocate minimal VRAM (128MB), whereas gaming/production GPUs have 4GB+."
        Remediation = "'Set-AdvancedGPUCapabilities' in Run-Inside-VM.ps1 spoofs dedicated VRAM to 8-24 GB."
    }
    'Windows Sandbox Detection'        = @{
        Desc        = "Checks for Windows Sandbox, WSL, or Hyper-V host services."
        Technique   = "Monitors services like hvhost or vmicvss used by Microsoft container virtualization."
        Remediation = "Present on host machines running WSL2/VBS; inside VirtualBox VMs this service is absent."
    }
    'Installed Programs Check'         = @{
        Desc        = "Scans installed applications for analysis tools."
        Technique   = "Looks for Wireshark, Process Hacker, x64dbg, IDA Pro, and other reverse engineering software."
        Remediation = "Keep analysis or inspection tools off the target guest VM."
    }
    'SMART Disk Data'                  = @{
        Desc        = "Queries S.M.A.R.T. disk telemetry."
        Technique   = "Virtual hard disks do not provide authentic S.M.A.R.T. temperature and health counters."
        Remediation = "Physical hardware characteristic; emulated disks do not natively supply SMART data."
    }
    'VirtualBox DLL Injection'         = @{
        Desc        = "Inspects loaded DLL modules in memory for VirtualBox hooks."
        Technique   = "Checks for VBoxHook.dll or injected Guest Additions libraries in user-space processes."
        Remediation = "'Remove-VMSpecificDLLs' unhooks and purges VirtualBox dynamic libraries."
    }
    'Suspicious Process Ancestry'      = @{
        Desc        = "Analyzes parent-child relationships of running processes."
        Technique   = "Malware sandboxes often spawn target executables directly from command-line analysis harnesses."
        Remediation = "Normal interactive explorer launches satisfy this test."
    }
    'VM Window Titles'                 = @{
        Desc        = "Scans top-level window titles for VM management or analysis software."
        Technique   = "Looks for windows containing 'VirtualBox', 'VMware', 'x64dbg', or 'Fiddler'."
        Remediation = "Close host management windows or run tests exclusively inside the guest."
    }
    'Kernel Driver Analysis'           = @{
        Desc        = "Enumerates active kernel drivers."
        Technique   = "Scans for virtualization kernel modules like VBoxDrv, VBoxUSB, or Vmmouse."
        Remediation = "Disabled and uninstalled by CloakBox guest cleanup."
    }
    'Clipboard Usage Analysis'         = @{
        Desc        = "Checks for active bidirectional clipboard integration."
        Technique   = "Detects clipboard synchronization hooks between guest and host."
        Remediation = "Set VirtualBox clipboard mode to 'Disabled' in VM settings."
    }
    'TLS Callback Anomalies'           = @{
        Desc        = "Inspects Thread Local Storage (TLS) callbacks."
        Technique   = "Detects memory hooks and debugger-attached execution routines."
        Remediation = "Normal OS execution exhibits zero TLS callback anomalies."
    }
    'VM Shared Folders'                = @{
        Desc        = "Scans active network mounts and UNC shares."
        Technique   = "Detects shares mapped to '\\vboxsvr' or '\\vmware-host'."
        Remediation = "Disable shared folders in VM settings before taking tests."
    }
    'Network Interface Deep Scan'      = @{
        Desc        = "Inspects network adapter device drivers and operational parameters."
        Technique   = "Virtual network adapters often lack physical hardware offloading features."
        Remediation = "'Set-RandomMacAddress' and CloakBox driver disguises configure standard NIC parameters."
    }
    'Virtualization Persistence'       = @{
        Desc        = "Checks services configured for automatic startup."
        Technique   = "Monitors services like VBoxSDS or VMware Tools configured to run persistently."
        Remediation = "Cleaned by 'Remove-VMSpecificDLLs' in Run-Inside-VM.ps1. On the host, VBoxSDS manages VirtualBox COM registration."
    }
    'PCI Device Enumeration'           = @{
        Desc        = "Enumerates all hardware on the PCI bus."
        Technique   = "Checks for realistic hardware controllers (audio, network, display, USB) on PCI lanes."
        Remediation = "Verified and renamed by 'Set-PCIDeviceIDSpoofing'."
    }
    'System Entropy Analysis'          = @{
        Desc        = "Measures cryptographic entropy generation latency."
        Technique   = "Virtual machines lacking hardware RNG experience distinct latency profiles generating entropy."
        Remediation = "Standard crypto operations generate natural entropy profiles."
    }
    'Audio Hardware'                   = @{
        Desc        = "Checks for active sound hardware and audio endpoints."
        Technique   = "Headless analysis sandboxes and unconfigured VMs frequently have zero audio devices."
        Remediation = "'Set-AudioDeviceSpoofing' in Run-Inside-VM.ps1 configures realistic audio endpoints."
    }
    'ACPI Emulated Devices (WAET)'     = @{
        Desc        = "Queries kernel firmware tables for the WAET (Windows ACPI Emulated Devices Table) and ACPI table signatures."
        Technique   = "WAET is a hypervisor-exclusive ACPI table emitted by VirtualBox, VMware, and KVM to optimize timer interrupts. Physical hardware never emits a WAET table."
        Remediation = "Patched via custom hypervisor builds (e.g. NotVirtualBox) or custom ACPI table DSDT/SSDT configuration."
    }
    'HPET Table Structure'             = @{
        Desc        = "Inspects the 56-byte ACPI High Precision Event Timer (HPET) binary layout and capabilities."
        Technique   = "Decodes GAS register bit width (must be 64-bit), Page Protection flags (must be 0x00), and Vendor ID (Intel 0x8086 / AMD 0x1022). VMs often present 32-bit registers or page-protect flags."
        Remediation = "Standard x86 ICH9 chipset emulation in modern VirtualBox provides standard HPET definitions."
    }
    'Forensic Installation Freshness'  = @{
        Desc        = "Compares filesystem creation dates (USERPROFILE, NTUSER.DAT, setupact.log) against registry InstallDate."
        Technique   = "Detects freshly created VMs or scrubbed sandboxes where file creation is < 30 days old or conflicts with the registry InstallDate."
        Remediation = "'Set-EnhancedInstallDateTime' in Run-Inside-VM.ps1 backdates both registry install times and forensic filesystem timestamps."
    }
    'PCA Logs & Artifact Cleanliness'  = @{
        Desc        = "Audits Program Compatibility Assistant (PCA) application history and temp/recent folder cleanliness."
        Technique   = "Automated malware analysis sandboxes feature clean folders (< 5 files in Temp/Recent) and nearly empty PCA logs (< 10 entries)."
        Remediation = "'Initialize-SystemArtifactsAndPCA' in Run-Inside-VM.ps1 populates PCA logs and seeds realistic activity files."
    }
    'Display Adapter Metadata'         = @{
        Desc        = "Scans Control\Video and Display Class registry entries for unaccelerated VGA or hypervisor GPU descriptors."
        Technique   = "Checks HardwareInformation.ChipType, AdapterString, and DriverDesc for VMware/VBox strings or Standard VGA fallbacks."
        Remediation = "'Set-AdditionalAntiDetection' and 'Set-AdvancedGPUCapabilities' in Run-Inside-VM.ps1 spoof realistic NVIDIA/Intel GPU descriptors."
    }
    'Driver Path Anomalies & VMLoader' = @{
        Desc        = "Scans driver services and root directories for vmloader.sys and root-level driver paths."
        Technique   = "Malware sandbox bypass utilities often load helper drivers directly from C:\ rather than System32\drivers."
        Remediation = "Standard Windows drivers must reside strictly in System32\drivers."
    }
}

# -------------------------------------------------------------
# Check Function List (All 63 Checks)
# -------------------------------------------------------------
$checks = @(
    'Check-RegistryArtifacts',
    'Check-SleepHook',
    'Check-Hypervisor',
    'Check-CPUFeatures',
    'Check-VideoAdapter',
    'Check-OSArtifacts',
    'Check-Processes',
    'Check-DriversFiles',
    'Check-SystemManufacturer',
    'Check-BIOSInfo',
    'Check-MAC',
    'Check-DeviceNames',
    'Check-ACPI',
    'Check-CPUCores',
    'Check-RAM',
    'Check-Disk',
    'Check-MouseMovement',
    'Check-PciVendor',
    'Check-BaseBoard',
    'Check-VBoxBiosData',
    'Check-EventLogSources',
    'Check-VBoxRegistryKeys',
    'Check-NetworkProvider',
    'Check-VBoxFiles',
    'Check-VBoxDirectories',
    'Check-FirmwareVM',
    'Check-CPUHypervisor',
    'Check-CPUIDHypervisorBit',
    'Check-USBDevices',
    'Check-BatteryPresence',
    'Check-ScreenResolution',
    'Check-UserActivity',
    'Check-TemperatureSensors',
    'Check-ClipboardSharing',
    'Check-SystemUptime',
    'Check-InstructionTiming',
    'Check-CPUBrandString',
    'Check-CacheTopology',
    'Check-MemoryArtifacts',
    'Check-DiskIOPattern',
    'Check-VirtualBoxPorts',
    'Check-GPUMemory',
    'Check-WindowsSandbox',
    'Check-SuspiciousPrograms',
    'Check-SMARTData',
    'Check-VBoxDLLs',
    'Check-ProcessAncestry',
    'Check-VMWindowTitles',
    'Check-KernelDrivers',
    'Check-ClipboardHistory',
    'Check-TLSCallbacks',
    'Check-SharedFolders',
    'Check-NetworkInterfaceDetails',
    'Check-VirtualizationPersistence',
    'Check-PCIDevices',
    'Check-SystemEntropy',
    'Check-AudioDevices',
    'Check-ACPIEmulatedDevices',
    'Check-HPETStructure',
    'Check-ForensicFreshness',
    'Check-PCAAndArtifactCleanliness',
    'Check-DisplayAdapterDeepScan',
    'Check-DriverAnomalies'
)

# -------------------------------------------------------------
# Modern Windows Forms Application Setup
# -------------------------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$form = New-Object System.Windows.Forms.Form
$form.Text = "CloakBox - VM & Sandbox Anti-Detection Analyzer"
$form.Size = New-Object System.Drawing.Size(1040, 740)
$form.MinimumSize = New-Object System.Drawing.Size(880, 560)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(24, 26, 32)
$form.ForeColor = [System.Drawing.Color]::White

# Top Header Panel
$header = New-Object System.Windows.Forms.Panel
$header.Dock = [System.Windows.Forms.DockStyle]::Top
$header.Height = 125
$header.BackColor = [System.Drawing.Color]::FromArgb(18, 20, 24)
$form.Controls.Add($header)

$title = New-Object System.Windows.Forms.Label
$title.Text = "CloakBox - VM & Sandbox Anti-Detection Analyzer"
$title.UseMnemonic = $false
$title.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 13, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::FromArgb(240, 244, 248)
$title.Location = New-Object System.Drawing.Point(16, 12)
$title.AutoSize = $true
$header.Controls.Add($title)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = "Deep inspection of $($checks.Count) virtualization artifacts, hypervisor flags, and hardware signatures"
$subtitle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184)
$subtitle.Location = New-Object System.Drawing.Point(16, 36)
$subtitle.AutoSize = $true
$header.Controls.Add($subtitle)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready to scan. Click 'Start Full Scan' to analyze system."
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(203, 213, 225)
$statusLabel.Location = New-Object System.Drawing.Point(16, 58)
$statusLabel.AutoSize = $true
$header.Controls.Add($statusLabel)

# Action Buttons
$startBtn = New-Object System.Windows.Forms.Button
$startBtn.Text = "Start Full Scan"
$startBtn.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9.5, [System.Drawing.FontStyle]::Bold)
$startBtn.Size = New-Object System.Drawing.Size(130, 32)
$startBtn.Location = New-Object System.Drawing.Point(16, 82)
$startBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$startBtn.BackColor = [System.Drawing.Color]::FromArgb(16, 185, 129)
$startBtn.ForeColor = [System.Drawing.Color]::White
$startBtn.FlatAppearance.BorderSize = 0
$startBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
$header.Controls.Add($startBtn)

$saveBtn = New-Object System.Windows.Forms.Button
$saveBtn.Text = "Save Report"
$saveBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$saveBtn.Size = New-Object System.Drawing.Size(115, 32)
$saveBtn.Location = New-Object System.Drawing.Point(155, 82)
$saveBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$saveBtn.BackColor = [System.Drawing.Color]::FromArgb(45, 55, 72)
$saveBtn.ForeColor = [System.Drawing.Color]::White
$saveBtn.FlatAppearance.BorderSize = 0
$saveBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
$saveBtn.Enabled = $false
$header.Controls.Add($saveBtn)

$copyBtn = New-Object System.Windows.Forms.Button
$copyBtn.Text = "Copy Summary"
$copyBtn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$copyBtn.Size = New-Object System.Drawing.Size(125, 32)
$copyBtn.Location = New-Object System.Drawing.Point(280, 82)
$copyBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$copyBtn.BackColor = [System.Drawing.Color]::FromArgb(45, 55, 72)
$copyBtn.ForeColor = [System.Drawing.Color]::White
$copyBtn.FlatAppearance.BorderSize = 0
$copyBtn.Cursor = [System.Windows.Forms.Cursors]::Hand
$copyBtn.Enabled = $false
$header.Controls.Add($copyBtn)

# Progress Bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(415, 84)
$progressBar.Size = New-Object System.Drawing.Size(190, 28)
$progressBar.Visible = $false
$progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
$header.Controls.Add($progressBar)

# Stat Badges Panel on Right
$statPanel = New-Object System.Windows.Forms.Panel
$statPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$statPanel.Location = New-Object System.Drawing.Point(620, 15)
$statPanel.Size = New-Object System.Drawing.Size(390, 95)
$header.Controls.Add($statPanel)

function New-StatBadge($parent, $x, $titleText, $valText, $color) {
    $p = New-Object System.Windows.Forms.Panel
    $p.Location = New-Object System.Drawing.Point($x, 5)
    $p.Size = New-Object System.Drawing.Size(90, 82)
    $p.BackColor = [System.Drawing.Color]::FromArgb(28, 32, 42)
    
    $vLabel = New-Object System.Windows.Forms.Label
    $vLabel.Text = $valText
    $vLabel.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $vLabel.ForeColor = $color
    $vLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $vLabel.Dock = [System.Windows.Forms.DockStyle]::Top
    $vLabel.Height = 45
    $p.Controls.Add($vLabel)
    
    $tLabel = New-Object System.Windows.Forms.Label
    $tLabel.Text = $titleText
    $tLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $tLabel.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184)
    $tLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $tLabel.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $tLabel.Height = 30
    $p.Controls.Add($tLabel)
    
    $parent.Controls.Add($p)
    return $vLabel
}

Set-Alias -Name Create-StatBadge -Value New-StatBadge -ErrorAction SilentlyContinue

$null = New-StatBadge $statPanel 0 "TOTAL" "$($checks.Count)" ([System.Drawing.Color]::FromArgb(148, 163, 184))
$badgePassed = New-StatBadge $statPanel 98 "PASSED" "-" ([System.Drawing.Color]::FromArgb(52, 211, 153))
$badgeFailed = New-StatBadge $statPanel 196 "DETECTED" "-" ([System.Drawing.Color]::FromArgb(248, 113, 113))
$badgeScore = New-StatBadge $statPanel 294 "SCORE" "-" ([System.Drawing.Color]::FromArgb(96, 165, 250))

# Tab Control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
$tabControl.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$form.Controls.Add($tabControl)

$tabResults = New-Object System.Windows.Forms.TabPage "  Scan Results & Inspector  "
$tabGuide = New-Object System.Windows.Forms.TabPage "  Full Check Guide ($($checks.Count) Checks)  "
$tabConsole = New-Object System.Windows.Forms.TabPage "  Raw Terminal Log  "
$tabControl.TabPages.AddRange(@($tabResults, $tabGuide, $tabConsole))

# -------------------------------------------------------------
# TAB 1: Scan Results & Inspector
# -------------------------------------------------------------
$filterPanel = New-Object System.Windows.Forms.Panel
$filterPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$filterPanel.Height = 44
$filterPanel.BackColor = [System.Drawing.Color]::FromArgb(24, 26, 32)
$tabResults.Controls.Add($filterPanel)

$filterAllBtn = New-Object System.Windows.Forms.Button
$filterAllBtn.Text = "All Tests ($($checks.Count))"
$filterAllBtn.Location = New-Object System.Drawing.Point(10, 7)
$filterAllBtn.Size = New-Object System.Drawing.Size(110, 28)
$filterAllBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$filterAllBtn.BackColor = [System.Drawing.Color]::FromArgb(59, 130, 246)
$filterAllBtn.ForeColor = [System.Drawing.Color]::White
$filterAllBtn.FlatAppearance.BorderSize = 0
$filterPanel.Controls.Add($filterAllBtn)

$filterFailBtn = New-Object System.Windows.Forms.Button
$filterFailBtn.Text = "Detected (0)"
$filterFailBtn.Location = New-Object System.Drawing.Point(126, 7)
$filterFailBtn.Size = New-Object System.Drawing.Size(110, 28)
$filterFailBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$filterFailBtn.BackColor = [System.Drawing.Color]::FromArgb(40, 44, 54)
$filterFailBtn.ForeColor = [System.Drawing.Color]::FromArgb(248, 113, 113)
$filterFailBtn.FlatAppearance.BorderSize = 0
$filterPanel.Controls.Add($filterFailBtn)

$filterPassBtn = New-Object System.Windows.Forms.Button
$filterPassBtn.Text = "Passed (0)"
$filterPassBtn.Location = New-Object System.Drawing.Point(242, 7)
$filterPassBtn.Size = New-Object System.Drawing.Size(110, 28)
$filterPassBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$filterPassBtn.BackColor = [System.Drawing.Color]::FromArgb(40, 44, 54)
$filterPassBtn.ForeColor = [System.Drawing.Color]::FromArgb(52, 211, 153)
$filterPassBtn.FlatAppearance.BorderSize = 0
$filterPanel.Controls.Add($filterPassBtn)

$searchBox = New-Object System.Windows.Forms.TextBox
$searchBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$searchBox.Location = New-Object System.Drawing.Point(740, 10)
$searchBox.Size = New-Object System.Drawing.Size(260, 24)
$searchBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$searchBox.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$searchBox.ForeColor = [System.Drawing.Color]::White
$filterPanel.Controls.Add($searchBox)

$searchLabel = New-Object System.Windows.Forms.Label
$searchLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$searchLabel.Text = "Search:"
$searchLabel.Location = New-Object System.Drawing.Point(680, 12)
$searchLabel.AutoSize = $true
$searchLabel.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184)
$filterPanel.Controls.Add($searchLabel)

# Split container: Top = ListView, Bottom = Inspector Panel
$splitContainer = New-Object System.Windows.Forms.SplitContainer
$splitContainer.Dock = [System.Windows.Forms.DockStyle]::Fill
$splitContainer.Orientation = [System.Windows.Forms.Orientation]::Horizontal
$splitContainer.SplitterDistance = 330
$splitContainer.BackColor = [System.Drawing.Color]::FromArgb(18, 20, 24)
$tabResults.Controls.Add($splitContainer)
$splitContainer.BringToFront()

# Results ListView
$resultsListView = New-Object System.Windows.Forms.ListView
$resultsListView.Dock = [System.Windows.Forms.DockStyle]::Fill
$resultsListView.View = [System.Windows.Forms.View]::Details
$resultsListView.FullRowSelect = $true
$resultsListView.GridLines = $true
$resultsListView.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::Nonclickable
$resultsListView.BackColor = [System.Drawing.Color]::FromArgb(26, 29, 36)
$resultsListView.ForeColor = [System.Drawing.Color]::White
$resultsListView.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)

[void]$resultsListView.Columns.Add("Status", 110)
[void]$resultsListView.Columns.Add("Category / Test", 230)
[void]$resultsListView.Columns.Add("Details & Findings", 640)

# Double buffering
$prop = [System.Windows.Forms.Control].GetProperty("DoubleBuffered", [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Instance)
if ($prop) { $prop.SetValue($resultsListView, $true, $null) }

$splitContainer.Panel1.Controls.Add($resultsListView)

# Inspector Panel (Bottom of SplitContainer)
$inspectorPanel = New-Object System.Windows.Forms.Panel
$inspectorPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$inspectorPanel.BackColor = [System.Drawing.Color]::FromArgb(22, 24, 30)
$inspectorPanel.Padding = New-Object System.Windows.Forms.Padding(12)
$splitContainer.Panel2.Controls.Add($inspectorPanel)

$inspHeader = New-Object System.Windows.Forms.Label
$inspHeader.Text = "Test Inspector: Select any test above to view details & remediation"
$inspHeader.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 10.5, [System.Drawing.FontStyle]::Bold)
$inspHeader.ForeColor = [System.Drawing.Color]::FromArgb(240, 244, 248)
$inspHeader.Dock = [System.Windows.Forms.DockStyle]::Top
$inspHeader.Height = 26
$inspectorPanel.Controls.Add($inspHeader)

$inspDetailBox = New-Object System.Windows.Forms.TextBox
$inspDetailBox.Multiline = $true
$inspDetailBox.ReadOnly = $true
$inspDetailBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$inspDetailBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$inspDetailBox.BackColor = [System.Drawing.Color]::FromArgb(18, 20, 24)
$inspDetailBox.ForeColor = [System.Drawing.Color]::FromArgb(226, 232, 240)
$inspDetailBox.Font = New-Object System.Drawing.Font("Consolas", 9.5)
$inspDetailBox.Text = @(
    "Click on any check in the table above to view:",
    "",
    "- Exact scan findings and detected values",
    "- How anti-cheat and malware sandboxes detect this artifact",
    "- Recommended CloakBox configuration and remediation steps"
) -join "`r`n"
$inspectorPanel.Controls.Add($inspDetailBox)
$inspDetailBox.BringToFront()

# -------------------------------------------------------------
# TAB 2: Full Check Guide
# -------------------------------------------------------------
$guideTopPanel = New-Object System.Windows.Forms.Panel
$guideTopPanel.Dock = [System.Windows.Forms.DockStyle]::Top
$guideTopPanel.Height = 44
$guideTopPanel.BackColor = [System.Drawing.Color]::FromArgb(24, 26, 32)
$tabGuide.Controls.Add($guideTopPanel)

$guideSearch = New-Object System.Windows.Forms.TextBox
$guideSearch.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$guideSearch.Location = New-Object System.Drawing.Point(740, 10)
$guideSearch.Size = New-Object System.Drawing.Size(260, 24)
$guideSearch.BackColor = [System.Drawing.Color]::FromArgb(35, 39, 48)
$guideSearch.ForeColor = [System.Drawing.Color]::White
$guideTopPanel.Controls.Add($guideSearch)

$guideSearchLabel = New-Object System.Windows.Forms.Label
$guideSearchLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$guideSearchLabel.Text = "Filter Guide:"
$guideSearchLabel.Location = New-Object System.Drawing.Point(660, 12)
$guideSearchLabel.AutoSize = $true
$guideSearchLabel.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184)
$guideTopPanel.Controls.Add($guideSearchLabel)

$guideInfoLabel = New-Object System.Windows.Forms.Label
$guideInfoLabel.Text = "Knowledge Base of All $($checks.Count) Virtualization & Sandbox Detection Checks"
$guideInfoLabel.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 9.5, [System.Drawing.FontStyle]::Bold)
$guideInfoLabel.ForeColor = [System.Drawing.Color]::FromArgb(203, 213, 225)
$guideInfoLabel.Location = New-Object System.Drawing.Point(12, 12)
$guideInfoLabel.AutoSize = $true
$guideTopPanel.Controls.Add($guideInfoLabel)

$guideListView = New-Object System.Windows.Forms.ListView
$guideListView.Dock = [System.Windows.Forms.DockStyle]::Fill
$guideListView.View = [System.Windows.Forms.View]::Details
$guideListView.FullRowSelect = $true
$guideListView.GridLines = $true
$guideListView.BackColor = [System.Drawing.Color]::FromArgb(26, 29, 36)
$guideListView.ForeColor = [System.Drawing.Color]::White
$guideListView.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
[void]$guideListView.Columns.Add("Check / Category", 210)
[void]$guideListView.Columns.Add("Description & Scope", 320)
[void]$guideListView.Columns.Add("Detection Technique", 330)
[void]$guideListView.Columns.Add("CloakBox Remediation", 320)

if ($prop) { $prop.SetValue($guideListView, $true, $null) }
$tabGuide.Controls.Add($guideListView)
$guideListView.BringToFront()

function Update-Guide($filterText = "") {
    $guideListView.Items.Clear()
    $sortedKeys = $knowledgeBase.Keys | Sort-Object
    foreach ($k in $sortedKeys) {
        $entry = $knowledgeBase[$k]
        if ($filterText) {
            $combined = "$k $($entry.Desc) $($entry.Technique) $($entry.Remediation)"
            if ($combined -notmatch [regex]::Escape($filterText)) { continue }
        }
        $item = New-Object System.Windows.Forms.ListViewItem($k)
        $item.SubItems.Add($entry.Desc) | Out-Null
        $item.SubItems.Add($entry.Technique) | Out-Null
        $item.SubItems.Add($entry.Remediation) | Out-Null
        $guideListView.Items.Add($item) | Out-Null
    }
}
Update-Guide

$guideSearch.Add_TextChanged({
        Update-Guide $guideSearch.Text
    })
Set-Alias -Name Populate-Guide -Value Update-Guide -ErrorAction SilentlyContinue

# -------------------------------------------------------------
# TAB 3: Raw Terminal Log
# -------------------------------------------------------------
$consolePanel = New-Object System.Windows.Forms.Panel
$consolePanel.Dock = [System.Windows.Forms.DockStyle]::Top
$consolePanel.Height = 40
$consolePanel.BackColor = [System.Drawing.Color]::FromArgb(24, 26, 32)
$tabConsole.Controls.Add($consolePanel)

$copyLogBtn = New-Object System.Windows.Forms.Button
$copyLogBtn.Text = "Copy Full Log to Clipboard"
$copyLogBtn.Location = New-Object System.Drawing.Point(8, 6)
$copyLogBtn.Size = New-Object System.Drawing.Size(185, 28)
$copyLogBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$copyLogBtn.BackColor = [System.Drawing.Color]::FromArgb(45, 55, 72)
$copyLogBtn.ForeColor = [System.Drawing.Color]::White
$copyLogBtn.FlatAppearance.BorderSize = 0
$consolePanel.Controls.Add($copyLogBtn)

$richTextBox = New-Object System.Windows.Forms.RichTextBox
$richTextBox.Dock = [System.Windows.Forms.DockStyle]::Fill
$richTextBox.ReadOnly = $true
$richTextBox.Font = New-Object System.Drawing.Font("Consolas", 9.5)
$richTextBox.BackColor = [System.Drawing.Color]::FromArgb(14, 16, 20)
$richTextBox.ForeColor = [System.Drawing.Color]::FromArgb(240, 244, 248)
$richTextBox.WordWrap = $false
$richTextBox.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Both
$tabConsole.Controls.Add($richTextBox)
$richTextBox.BringToFront()

$copyLogBtn.Add_Click({
        if ($richTextBox.Text) {
            [System.Windows.Forms.Clipboard]::SetText($richTextBox.Text)
            [System.Windows.Forms.MessageBox]::Show("Log copied to clipboard!", "Copied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    })

# -------------------------------------------------------------
# Scanning & Results State Management
# -------------------------------------------------------------
$Global:ScanResults = @()
$Global:CurrentFilter = 'All'

function Update-ResultsList {
    $resultsListView.Items.Clear()
    $search = $searchBox.Text.Trim()

    foreach ($res in $Global:ScanResults) {
        if ($Global:CurrentFilter -eq 'Fail' -and -not $res.IsBad) { continue }
        if ($Global:CurrentFilter -eq 'Pass' -and $res.IsBad) { continue }

        if ($search) {
            $matchTarget = "$($res.Category) $($res.DetailString)"
            if ($matchTarget -notmatch [regex]::Escape($search)) { continue }
        }

        $statusText = if ($res.IsBad) { "[DETECTED]" } else { "[ PASS ]" }
        $item = New-Object System.Windows.Forms.ListViewItem($statusText)
        $item.Tag = $res

        if ($res.IsBad) {
            $item.ForeColor = [System.Drawing.Color]::FromArgb(248, 113, 113)
        }
        else {
            $item.ForeColor = [System.Drawing.Color]::FromArgb(52, 211, 153)
        }

        $item.SubItems.Add($res.Category) | Out-Null
        $item.SubItems.Add($res.DetailString) | Out-Null

        $resultsListView.Items.Add($item) | Out-Null
    }
}

Set-Alias -Name Render-ResultsList -Value Update-ResultsList -ErrorAction SilentlyContinue

# -------------------------------------------------------------
# Execute Full Scan
# -------------------------------------------------------------
$startBtn.Add_Click({
        $startBtn.Enabled = $false
        $saveBtn.Enabled = $false
        $copyBtn.Enabled = $false
        $statusLabel.Visible = $true
        $progressBar.Visible = $true
        $progressBar.Value = 0
        $progressBar.Maximum = $checks.Count

        $richTextBox.Clear()
        $Global:ScanResults = @()
        $totalChecks = $checks.Count
        $currentIdx = 0

        $statusLabel.Text = "Starting scan of $totalChecks detection categories..."
        [System.Windows.Forms.Application]::DoEvents()

        foreach ($fn in $checks) {
            $currentIdx++
            $progressBar.Value = $currentIdx
            $statusLabel.Text = "Analyzing ($currentIdx/$totalChecks): $fn..."
            [System.Windows.Forms.Application]::DoEvents()

            $res = $null
            try {
                $res = & $fn
            }
            catch {
                $res = [PSCustomObject]@{
                    Category = $fn
                    IsBad    = $true
                    Detail   = "Error running $fn`: $_"
                }
            }

            $detailStr = ""
            if ($res.Detail -is [array]) {
                $detailStr = ($res.Detail -join "; ")
            }
            else {
                $detailStr = [string]$res.Detail
            }

            $resItem = [PSCustomObject]@{
                Category     = $res.Category
                IsBad        = [bool]$res.IsBad
                DetailString = $detailStr
            }
            $Global:ScanResults += $resItem

            # Write to Raw Log
            $pad = 32
            $catPadded = $res.Category.PadRight($pad)
            $richTextBox.SelectionColor = [System.Drawing.Color]::White
            $richTextBox.AppendText($catPadded)

            if ($res.IsBad) {
                $richTextBox.SelectionColor = [System.Drawing.Color]::Red
                $richTextBox.AppendText("[ BAD ]`r`n")
            }
            else {
                $richTextBox.SelectionColor = [System.Drawing.Color]::Lime
                $richTextBox.AppendText("[ GOOD ]`r`n")
            }

            if ($res.Detail) {
                foreach ($item in ($res.Detail -as [array])) {
                    $richTextBox.SelectionColor = [System.Drawing.Color]::Gray
                    $richTextBox.AppendText("    - $item`r`n")
                }
            }
        }

        # Update summary statistics
        $passedCount = ($Global:ScanResults | Where-Object { -not $_.IsBad }).Count
        $failedCount = ($Global:ScanResults | Where-Object { $_.IsBad }).Count
        $scorePct = [int](($passedCount / $totalChecks) * 100)

        $badgePassed.Text = "$passedCount"
        $badgeFailed.Text = "$failedCount"
        $badgeScore.Text = "$scorePct%"

        $filterFailBtn.Text = "Detected ($failedCount)"
        $filterPassBtn.Text = "Passed ($passedCount)"

        $progressBar.Visible = $false
        $statusLabel.Text = "Scan Complete! Passed: $passedCount / $totalChecks ($scorePct%) - Detected Issues: $failedCount"
        $statusLabel.ForeColor = if ($failedCount -eq 0) { [System.Drawing.Color]::FromArgb(52, 211, 153) } else { [System.Drawing.Color]::FromArgb(248, 113, 113) }

        $startBtn.Enabled = $true
        $saveBtn.Enabled = $true
        $copyBtn.Enabled = $true

        Update-ResultsList

        # Auto-select the first issue or first item
        if ($resultsListView.Items.Count -gt 0) {
            $firstFail = $resultsListView.Items | Where-Object { $_.Text -match 'DETECTED' } | Select-Object -First 1
            if ($firstFail) {
                $firstFail.Selected = $true
                $firstFail.EnsureVisible()
            }
            else {
                $resultsListView.Items[0].Selected = $true
            }
        }
    })

# Copy Summary button
$copyBtn.Add_Click({
        if ($Global:ScanResults.Count -gt 0) {
            $passedCount = ($Global:ScanResults | Where-Object { -not $_.IsBad }).Count
            $failedCount = ($Global:ScanResults | Where-Object { $_.IsBad }).Count
            $scorePct = [int](($passedCount / $checks.Count) * 100)
        
            $summary = "=== CloakBox Anti-Detection Scan Summary ===`r`n"
            $summary += "Timestamp:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n"
            $summary += "Machine:     $env:COMPUTERNAME ($env:USERNAME)`r`n"
            $summary += "Total Tests: $($checks.Count)`r`n"
            $summary += "Passed:      $passedCount`r`n"
            $summary += "Detected:    $failedCount`r`n"
            $summary += "Cloak Score: $scorePct%`r`n`r`n"
            $summary += "Detected Artifacts:`r`n"
            foreach ($item in ($Global:ScanResults | Where-Object { $_.IsBad })) {
                $summary += " - [$($item.Category)]: $($item.DetailString)`r`n"
            }
            [System.Windows.Forms.Clipboard]::SetText($summary)
            [System.Windows.Forms.MessageBox]::Show("Summary copied to clipboard!", "Copied", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    })

# Save Report button
$saveBtn.Add_Click({
        $dialog = New-Object System.Windows.Forms.SaveFileDialog -Property @{
            Filter   = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
            Title    = "Save CloakBox Detection Report"
            FileName = "CloakBox_Detection_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
        }
        if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $passedCount = ($Global:ScanResults | Where-Object { -not $_.IsBad }).Count
            $failedCount = ($Global:ScanResults | Where-Object { $_.IsBad }).Count
            $scorePct = [int](($passedCount / $checks.Count) * 100)

            Update-ResultsList
            $report += "================================================================================"
            $report += "              CLOAKBOX - VM & SANDBOX ANTI-DETECTION REPORT                     "
            $report += "================================================================================"
            $report += "Generated:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $report += "Computer:    $env:COMPUTERNAME"
            $report += "User:        $env:USERNAME"
            $report += "OS Version:  $([System.Environment]::OSVersion.VersionString)"
            $report += "Total Tests: $($checks.Count)"
            $report += "Passed:      $passedCount"
            $report += "Detected:    $failedCount"
            $report += "Cloak Score: $scorePct%"
            $report += "================================================================================"
            $report += "`r`n[ ITEMIZED RESULTS ]`r`n"

            foreach ($res in $Global:ScanResults) {
                $status = if ($res.IsBad) { "[ DETECTED ]" } else { "[   PASS   ]" }
                $report += "$status $($res.Category)"
                $report += "    Findings: $($res.DetailString)"
                $kb = $knowledgeBase[$res.Category]
                if ($kb) {
                    $report += "    Technique: $($kb.Technique)"
                    $report += "    Fix/Note:  $($kb.Remediation)"
                }
                $report += ""
            }

            $report -join "`r`n" | Out-File -FilePath $dialog.FileName -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Report saved to $($dialog.FileName)", "Report Saved", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    })

# Show the dialog
[void]$form.ShowDialog()
