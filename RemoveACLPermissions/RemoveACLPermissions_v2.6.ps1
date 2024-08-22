#Requires -Version 7.0

<#
 
.Synopsis
Script requires a JSON source file for custom RBAC Active Directory OU delegation of Security attribute changes

.Description
A JSON file is used as a golden source to delegation permissions on the region OUs for Users, Groups, and Computer objects

.Parameter JsonPath
This is a Mandatory parameter to the full path of the JSON delegation input file.

.Parameter SkipRemoval
This is an optional parameter that should only be used when delegating permissions for the first time as there have been no group delegations to remove.

.Example
RemoveACLPermissions -ADObject "service-01" -JsonFile C:\Files\Delegation.json
Delegates the Service Account ACLs to the OUs based on the JSON file as input

.Inputs
Requires a JSON file with specific objects for the script to execute properly

#>


Param(
    [Parameter(Mandatory = $false)]
    [string]$JsonPath,
	
	[Parameter(Mandatory = $True)]
	[String]$ADObject,

    [Parameter(Mandatory = $false)]
    [Switch]$SkipRemoval
)

# Transcript Variables
$LogDate = Get-Date -Format "yyyy-MM-dd_hh.mmtt"
$OutFile = "$env:USERPROFILE\Desktop\SetACL\Cleanup_Rollback\$LogDate.txt"

Start-Transcript -Path $OutFile -NoClobber
# Import required modules
Import-Module ActiveDirectory -SkipEditionCheck #-ErrorAction Stop
Import-Module "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdSchemaMap\AdGuidMap.psd1" -SkipEditionCheck -ErrorAction Stop

# Create Map Object GUID from the Schema for AD Delegation of objects scripts are not on GitHub but author can be found at https://github.com/constantinhager
$GuidMap = New-ADDGuidMap
$ExtendedRight = New-ADDExtendedRightMap

#Manual Path Testing
#$JsonPath = "$env:USERPROFILE\Desktop\SetACL\Cleanup_Rollback\Test.json"

# Read the JSON content from the file
$jsonContent = Get-Content -Raw -Path $JsonPath | ConvertFrom-Json

#Get Domain
$Netbios = $env:USERDOMAIN

#Get Domain Controller	
$Dc = Get-ADDomainController -Service ADWS -Discover | Select-Object -ExpandProperty Hostname

# AD User or Group Object
$ADObjectValue = @()
$ADObjectValue = Get-ADObject -Filter {samaccountname -eq $ADObject} -Server $DC -Properties objectSID,sAMAccountName

# Remove the ServiceAccount from the OU if SkipRemoval is not specified
if (-not $SkipRemoval) {
	write-host "Purging Existing Delegations.... " -ForegroundColor cyan
	Start-Sleep 1

    #Loop Service Account Delegation Removal
    Foreach ($OU in $jsonContent.OrganizationUnits) {
        #$OU = $OU.DN
        $ADOU = ("AD:\" + $OU)
        $RemoveACL = Get-ACL $ADOU
        $Ace = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        $RemoveAcl.PurgeAccessRules($Ace)
            write-host "[+]Removing $($ADObjectValue.sAMAccountName) from $($ADOU)" -ForegroundColor gray
            Set-Acl -Path $ADOU -AclObject $Removeacl
    }
}

Stop-Transcript
