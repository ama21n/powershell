# TODO:
# Ignore (or optional for $dom), or exclude certain domains
# Integrate all Administrators checks
# Separate check from count output (ie colors)
# Limit to forest option

# Alternate/relevant tools/scripts:
# https://github.com/sense-of-security/ADRecon
# https://hausec.com/2019/03/12/penetration-testing-active-directory-part-ii/

# DONE:
# Remove DCs from unconstrained
# Write 0 for 0's
# Combine stuff into domain_ALL

# Required DC comms: ADSI uses LDAP (TCP/389), ADModule uses ADWS (TCP/9389)
# Preference PowerView (dev) over ADModule

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [String]$dcip
#   ,
#  [Parameter(Mandatory=$false)]
#  [String]$dom
)

# Domain Discovery
#Install ActiveDirectory module here, or manually prior to running
#Import-Module ActiveDirectory
$ErrorActionPreference= 'silentlycontinue'
$dn = ([ADSI]"LDAP://$dcip").distinguishedName
$dom = (($dn).replace('DC=', '')).replace(',', '.')
$tmp = "_members.txt"

# Not required with domain discovery above:
#mkdir -Force $dom > $null
#Write-Host "`nDomain: $dom`n"

# Domains:
$file = "domains.txt"
$check = "Domains: "
echo $dom > $file
#(Get-DomainTrustMapping).TargetName | Sort -uniq >> $file
#$a = Get-DomainTrustMapping | select -ExpandProperty SourceName; $a += Get-DomainTrustMapping | select -ExpandProperty TargetName; $a | Sort -uniq >> $file
Get-DomainTrustMapping | Foreach { $_.SourceName,$_.TargetName } | Sort -uniq > $file
$count = (gc $file).count
if ($count -gt 0) { Write-Output "`n$check $count" } else { del "$file"; exit }


foreach ($dom in gc .\domains.txt) {

    Write-Host "`n[+] $dom"
    mkdir -Force domain_$dom > $null

    # Users:
    $file = "domain_$dom\users.txt"
    $check = "Domain Users:      "
    (Get-DomainUser -Domain $dom).samaccountname > $file
    $count = (gc $file).count
    Write-Host "$check $count"
    if ($count -eq 0) { del "$file" }
 
    # Descriptions:
    $file = "domain_$dom\userdesc.txt"
    $check = "Description p/w:   "
    Get-DomainUser -Domain $dom | where {$_.description -ne $null} | select samaccountname,description | sls "pw|p/w|passw" > $file
    $count = (gc $file).count
    if ($count -gt 0) { Write-Host -Fore red "$check $count" } else { Write-Host "$check $count"; del "$file" }

    # Domain Admins:
    $file = "domain_$dom\group_DAs.txt"
    $check = "Domain Admins:     "
    (Get-DomainGroupMember "Domain Admins" -Domain $dom -Recurse).MemberName | Sort -uniq > $file
    $count = (gc $file).count
    if ($count -gt 0) { Write-Host "$check $count" } else { del "$file" }

    # Administrators:
    $file = "domain_$dom\group_Administrators.txt"
    $check = "Administrators:    "
    (Get-DomainGroupMember "Administrators" -Domain $dom -Recurse).MemberName | Sort -uniq > $file
    $count = (gc $file).count
    if ($count -gt 0) { Write-Host "$check $count" } else { del "$file" }


    # Domain Controllers:
    $file = "domain_$dom\DCs.txt"
    $check = "Domain Controllers:"
    (Get-DomainController -Domain $dom).name > $file
    $count = (gc $file).count
    Write-Host "$check $count"
    if ($count -eq 0) { del "$file" }

    # Computers:
    $file = "domain_$dom\computers.txt"
    $check = "Computers:         "
    (Get-DomainComputer -Domain $dom).dnshostname > $file
    $count = (gc $file).count
    Write-Host "$check $count"
    if ($count -eq 0) { del "$file" }
    
    # Kerberoast:
    $file = "domain_$dom\krb.txt"
    $check = "Kerberoast Hashes: "
    (Invoke-Kerberoast -Domain $dom).hash > $file
    $count = (gc $file).count
    if ($count -gt 0) { Write-Host -Fore red "$check $count" } else { Write-Host "$check $count"; del "$file" }

    # ASREProast:
    $file = "domain_$dom\asrep.txt"
    $check = "ASREP hashes:      "
    (Get-DomainUser -Domain $dom -Filter "(userAccountControl:1.2.840.113556.1.4.803:=4194304)").samaccountname > $file
    $count = (gc $file).count
    if ($count -gt 0) { Write-Host -Fore red "$check $count" } else { Write-Host "$check $count"; del "$file" }

    # Unconstrained Del:
    $file = "domain_$dom\unconstrained.txt"
    $check = "Unconstrained Del: "
    (Get-DomainComputer -Domain $dom -unconstrained).dnshostname > $file
    (Compare-Object (gc $file) (gc "domain_$dom\DCs.txt") | ?{$_.SideIndicator -eq '<='}).InputObject | sc $file
    $count = (gc $file).count
    if ($count -gt 0) { Write-Host -Fore red "$check $count" } else { Write-Host "$check $count"; del "$file" }

    # Constrained Del:
    $file = "domain_$dom\constrained.txt"
    $check = "Constrained Del:   "
    #Get-DomainUser -Domain $dom -TrustedToAuth | select name,msds-allowedtodelegateto > $file
    # Convert array to string:
    $constrained = Get-DomainUser -Domain $dom -TrustedToAuth | select name,"msds-allowedtodelegateto" | ft -HideTableHeaders
    $constrained | Out-String | sls '{' | ConvertTo-Csv -NoTypeInformation > $file
    gc $file | sls '{*}' > _tmp
    gc _tmp | where {$_ -ne ""} > $file
    del _tmp
    $count = (gc $file).count
    if ($count -gt 0) { Write-Host -Fore red "$check $count" } else { Write-Host "$check $count"; del "$file" }

    # Domain Hopping:
    $file = "domain_$dom\domainhoppers.txt"
    $check = "Domain Hoppers:    "
    $hoppers = Get-DomainForeignGroupMember -Domain $dom | ConvertTo-Csv -NoTypeInformation
    if ( $hoppers ) { ($hoppers).replace('"','') > $file }
    $count = (gc $file).count -1  # removes header count
    if ($count -gt 0) { Write-Host -Fore red "$check $count" } else { Write-Host "$check 0"; del "$file" }

    # GPP:
    # Find-InterestingDomainAcl
    # Admincount?
}
echo ""
echo ""

# Combine multiple domains:
if ((dir domain_*).count -gt 1) { 

    $path = "domain_ALL"
    Write-Host "Combining domain data under ${path}:"
    if (Test-Path -Path $path) { del $path -Force -Recurse }
    mkdir -Force $path > $null

    # Kerberoast:
    $file = "krb.txt"
    $check = "Kerberoast Hashes: "
    if (Test-Path -Path domain_*\$file) {gc domain_*\$file > $path\$file }
    $count = (gc $path\$file).count
    if ($count -gt 0) { Write-Host -Fore red "$check $count" } else { Write-Host "$check $count"; del "$path\$file" }

    # ASREProast:
    $file = "asrep.txt"
    $check = "ASREP hashes:      "
    if (Test-Path -Path domain_*\$file) {gc domain_*\$file > $path\$file }
    $count = (gc $path\$file).count
    if ($count -gt 0) { Write-Host -Fore red "$check $count" } else { Write-Host "$check $count"; del "$path\$file" }

    # Descriptions:
    $file = "userdesc.txt"
    $check = "Description p/w:   "
    if (Test-Path -Path domain_*\$file) {gc domain_*\$file > $path\$file }
    $count = (gc $path\$file).count
    if ($count -gt 0) { Write-Host -Fore red "$check $count" } else { Write-Host "$check $count"; del "$path\$file" }

}
echo ""
