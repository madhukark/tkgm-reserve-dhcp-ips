#-----------------------------------------------------------------------------
#
# Script to reserve IPs assigned via DHCP
#
# TKGm requires that the control plane VMs gets IPs assigned via DHCP. However
# if IP reservation is not available, then the IP assigned to the control
# plane VM can be read and a static DHCP entry on the NSX-T Segment can be
# created.
#
# This script does the following:
#   - Connect to vCenter Server
#   - Get the TKGm VMs and read its IP and MAC
#   - Remove any dhcp_ranges configured on the Segment
#   - Configure static DHCP binding on the NSX-T Segment via NSX-T APIs
#
# Usage:
# Edit the variables below to match your environment and run the script
#
# CAUTION:
# The script changes the NSX Segment DHCP config
#
# NOTE:
# The dhcp_ranges that get removed from the Segment dhcp config is written
# in the log for reference
#
# To revert, first delete the dhcp static binding and then add the
# dhcp_ranges back to the Subnet
#
#-----------------------------------------------------------------------------

Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $true -Confirm:$false
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false


#-----------------------------------------------------------------------------
# Variables
#-----------------------------------------------------------------------------

# vCenter Credentials. Accepts IP or FQDN
$vcenter_ip = "192.168.209.230"
$vcenter_user = "administrator@domain.com"
$vcenter_pass = "myPassword1!"

# NSX Manager login details. Accepts FQDN/IP
$nsx_ip = "192.168.209.237"
$nsx_user = "admin"
$nsx_pass = "myPassword1!myPassword1!"

# NSX Segment Path on which all TKGm nodes are connected
$segment_path = "/infra/segments/K8s-Nodes"

# TKGm cluster name as defined in TKGm config
$tkgm_name = "mgmt-1"

#-----------------------------------------------------------------------------
# Do NOT edit beyond this point
#-----------------------------------------------------------------------------

# Create the Authorization header based on NSX Username and Password
$pair = "$($nsx_user):$($nsx_pass)"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$headers = @{
    "Authorization" = "basic $base64"
    "Content-Type" = "application/json"
}

function Write-Log {
# Credit: https://adamtheautomator.com/powershell-log-function/
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
 
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information','Warning','Error')]
        [string]$Severity = 'Information'
    )
 
    if ($Severity -eq 'Error') {
        $msg = "Error - " + (Get-Date -f g) +  " - " + $Message
        $msg | Out-File -FilePath "./reserve-dhcp-ip-tkgm.log" -Append
        Write-Error $Message
        exit
    } else {
        $msg = $Severity + " - " + (Get-Date -f g) +  " - " + $Message
        $msg | Out-File -FilePath "./reserve-dhcp-ip-tkgm.log" -Append
        Write-Host $Message
    }
}

$start_time = Get-Date

Write-Log "Starting Run"
$vc = Connect-VIServer -Server $vcenter_ip -User $vcenter_user -Password $vcenter_pass -WarningAction SilentlyContinue
Write-Log "Connection to vCenter $vcenter_ip successful"

if (! $vc) {
    Write-Log "Unable to connect to vCenter Server" -Severity Error
}

# Get all VMs that start with the TKGm cluster name
Write-Log -Message "Searching for VMs with TKGm cluster name: $tkgm_name"
$vms = Get-VM -Server $vc -Name $tkgm_name*

$vm_hash = @{}

# Iterate through the TKGm VMs and get their MAC and IP
foreach ($vm in $vms) {
    $vm_name = $vm.Name
    $na = $vm | Get-NetworkAdapter
    $vm_mac = $na.MacAddress
    $vm_ip = $vm.guest.IPaddress[0]

    # Vlidate if IPv4 address was received
    if (! $vm_ip -as [IPAddress] -as [Bool]) {
        Write-Log -Message "VM IP: $vm_ip for VM: $vm_name not a valid IPv4 Address" -Severity Error
    }

    $hash = @{
        "mac" = $vm_mac
        "ip" = $vm_ip
    }
    $vm_hash[$vm_name] = $hash
}

# GET existing Subnet config
$url = "https://" + $nsx_ip + "/policy/api/v1" + $segment_path
try {
    $result = Invoke-WebRequest -Uri $url -Body $body -Headers $headers -Method GET -SkipCertificateCheck
    $res = $result.Content | ConvertFrom-Json -Depth 10
} catch {
    Write-Log -Message $_ -Severity Error
}

# Run a PATCH API to delete DHCP Range. Required so that DHCP static binding can be set
$subnets = @(
    [PSCustomObject]@{
        "gateway_address" = $res.subnets.gateway_address
        "dhcp_config" = $res.subnets.dhcp_config
    }
)
$json = [PSCustomObject]@{
    "dhcp_config_path" = $res.dhcp_config_path
    "subnets" = $subnets
}
$body = $json | ConvertTo-Json -Depth 10
$dhcp_ranges = $res.subnets.dhcp_ranges
Write-Log -Message "Removing DHCP range $dhcp_ranges from Subnet configuration"
Write-Log -Message "Invoking PATCH $url"
Write-Log -Message "Request Body: $body"
$url = "https://" + $nsx_ip + "/policy/api/v1" + $segment_path
try {
    $result = Invoke-WebRequest -Uri $url -Body $body -Method PATCH -Headers $headers -SkipCertificateCheck
    $status = $result.StatusCode
    Write-Log -Message "Successful. Response: $status"
} catch {
    Write-Log -Message $_ -Severity Error
}

# For each VM, do a PATCH API to create/update the static dhcp binding
foreach ($k in $vm_hash.keys) {
    $vm_name = $k
    $vm_mac = $vm_hash[$k].mac
    $vm_ip = $vm_hash[$k].ip
    Write-Log  -Message "Found VM: $vm_name with MAC: $vm_mac and IP: $vm_ip"

    # The request body for the dhcp-static-binding-config PATCH API
    $binding_name = $vm_name + "_binding"
    $url = "https://" + $nsx_ip + "/policy/api/v1" + $segment_path + "/dhcp-static-binding-configs" + "/" + $binding_name
    $json = [PSCustomObject]@{
        "display_name" = $binding_name
        "ip_address" = $vm_ip
        "mac_address" = $vm_mac
        "resource_type" = "DhcpV4StaticBindingConfig"
    }
    $body = $json | ConvertTo-Json -Depth 10
    Write-Log -Message "Invoking PATCH $url"
    Write-Log -Message "Request Body: $body"
    try {
        $request = Invoke-WebRequest -Uri $url -Body $body -Method PATCH -Headers $headers -SkipCertificateCheck
        $response = $request.StatusCode
        Write-Log -Message "Successful. Response: $response"
    } catch {
        Write-Log -Message "$_" -Severity Error
    }
}

$end_time = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $start_time -End $end_time).TotalMinutes,2)
Write-Log "-------------------------------------------"
Write-Log "Static DHCP bindings created on NSX Segment"
Write-Log "StartTime: $start_time"
Write-Log "  EndTime: $end_time"
Write-Log " Duration: $duration minutes"
Write-Log "-------------------------------------------"
