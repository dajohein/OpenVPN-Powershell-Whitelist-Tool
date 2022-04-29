
<#
.SYNOPSIS
    .
.DESCRIPTION
    Generates a white-list of Microsoft and Google ip-addresses for OpenVPN
.NOTES
    Author: Dajo Hein, April 29, 2022
#>

function ConvertTo-IPv4MaskString {
    param(
      [Parameter(Mandatory = $true)]
      [ValidateRange(0, 32)]
      [Int] $MaskBits
    )
    $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
    $bytes = [BitConverter]::GetBytes([UInt32] $mask)
    (($bytes.Count - 1)..0 | ForEach-Object { [String] $bytes[$_] }) -join "."
  }

Function Get-RoutingRuleForIPv4Range($allowedIP) {
    [IPAddress] $ip, $maskLength = $allowedIP.Split("/")
    $netmask = ConvertTo-IPv4MaskString $maskLength

    return "route $ip $netmask net_gateway"
}

$googleIpRangeUri = "https://www.gstatic.com/ipranges/goog.json"
$microsoftIpRangeUri = ("https://endpoints.office.com/endpoints/worldwide?clientRequestId="+[GUID]::NewGuid().Guid)

Write-Host 
Write-Host "# openvpn whitelist generated on " (Get-Date)

Write-Host
Write-Host "# IPv4 Address required to be allowed for Microsoft"
Write-Host "# retrieved from: $microsoftIpRangeUri"

$endpointSets = Invoke-RestMethod -Uri ($microsoftIpRangeUri)

$Allow = $endpointSets | Where-Object { ($_.category -eq "Optimize" -or $_.category -eq "Allow") }
$AllowIps = $Allow.ips | Where-Object { ($_).contains(".") } | Sort-Object -Unique

foreach ($allowedIP in $allowIps) {
    Write-Host (Get-RoutingRuleForIPv4Range $allowedIP)
}

Write-Host
Write-Host "# IPv4 Address required to be allowed for Google"
Write-Host "# retrieve from: $googleIpRangeUri"

$endpointSets = Invoke-RestMethod -Uri ($googleIpRangeUri)
$AllowIps = $endpointSets.prefixes | ForEach-Object {$_.ipv4Prefix} | Sort-Object -Unique

foreach ($allowedIP in $AllowIps) {
    Write-Host (Get-RoutingRuleForIPv4Range $allowedIP)
}