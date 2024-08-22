#Requires -Version 7.0

<#
.NOTES
  Version:        v2.7
  Author:         https://github.com/VAsHachiRoku
  Creation Date:  April, 2023
  Purpose/Change: Using a JSON source file to set and reset ACL delegations for Users, Groups, and Computer objects

	v2.2 - May, 2023: Ben Ashlin & Abhinav Singh
-	Structured Loops by Object Type
-	Introduced Regional loops within Object Type loops
-	Structured Object Type loops by Delegations
-	Modified Group Naming Lines

	v2.3 - July, 2023: Abhinav Singh  
-	Added Create & Delete Computer Object Types

	v2.4 - August, 2023: Ben Ashlin  
-	Added Transcript logging to USERPROFILE\Desktop
-	Fixed Password-Users loop missing Regions

    v2.5 - August, 2023: Abhinav Singh 
-	Add Create/Delete Permissions within the same loop
-   Make changes to accomodate granting access to users or group objects with the same code

    v2.6 - November, 2023: Abhinav Singh 
-	Move descendant properties to an array

    v2.7 - December, 2023: Abhinav Singh 
-	Add Extended Properties in the permissions list
 
.Synopsis
Script requires a JSON source file for custom RBAC Active Directory OU delegation of Security attribute changes

.Description
A JSON file is used as a golden source to delegation permissions on the region OUs for Users, Groups, and Computer objects

.Parameter JsonPath
This is a Mandatory parameter to the full path of the JSON delegation input file.

.Parameter SkipRemoval
This is an optional parameter that should only be used when delegating permissions for the first time as there have been no group delegations to remove.

.Example
Set-OURBACDelegation_v2.6 -ADObject "service-01" -JsonFile C:\Files\Delegation.json
Delegates the Service Account ACLs to the OUs based on the JSON file as input

.Example
Set-OURBACDelegation_v2.6 -ADObject "service-01" -JsonFile C:\Files\Delegation.json -SkipRemoval
Used only during the first delegation execution to skip the removal of Service Account Delegations that have not been delegated on OUs previously.

.Inputs
Requires a JSON file with specific objects for the script to execute properly

.Outputs
Regional Organizational Units will have the correct ACL's applied to manage Users, Groups, and Computer objects

.Note
Laps Commandlets require Powershell console to be 'Run As Admin'
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

# Descendant Properties
$DescendantProperties = @('GenericAll','ReadProperty','WriteProperty','Delete','DeleteTree', `
                'ExtendedRight','GenericExecute','WriteDacl','WriteOwner','CreateAllChild','DeleteAllChild', `
                'GenericWrite','ListChildren')

# Extended Rights
$ExtendedRightProperties = $ExtendedRight.GetEnumerator() | Select-Object -ExpandProperty Name

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

#
#
#
#------------------------[User Object Delegations]------------------------#
#
#
#

write-host ""
Write-Host "#------------------------[User Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1

# Process User permissions
$UserDelegation = $jsonContent.Delegations[0].userObjects

# Begin Region User Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
    #$OU = $OU.DN
    $ADOU = ("AD:\" + $OU)
    $UserACE = Get-ACL -Path $ADOU
   
   
# Process each property for User permissions --------#
foreach ($property in $userDelegation) {

    # Set GenericAll Permissions
    if ($property -in $DescendantProperties) {
        # For Create/Delete All Child Rights
        if ($property -eq "CreateAllChild") {
            $property = "CreateChild"
        }
        elseif ($property -eq "DeleteAllChild") {
            $property = "DeleteChild"
        }
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
   
        # Create the Active Directory access rule for the property----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $permissionSID,
        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $UserACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $UserACE
    }
    # Set Extended Rights Properties including Password Change Permissions
    elseif ($property -in $ExtendedRightProperties) {
        # Process Create & Delete User Objects for User Security permissions --------#
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
        # Create the Active Directory access rule for password permissions----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$Property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $UserACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $UserACE
    }
    # Process Create & Delete User Objects for Group Security permissions --------#
    elseif (($property -eq "CreateChild") -or ($property -eq "DeleteChild") ) {
        # Process Create & Delete User Objects for User Security permissions --------#
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["User"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'User Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
        # Add the rule to the ACL
        $UserACE.AddAccessRule($permissionRule)
        Set-Acl -Path $ADOU -AclObject $UserACE
    }
    # Set other attribute permissions
    else {
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
    
            # Create the Active Directory access rule for the property----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$Property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
            )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $UserACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $UserACE
    }
}
}


#
#
#
#------------------------[Group Object Delegations]------------------------#
#
#
#
write-host ""
Write-Host "#------------------------[Group Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1

# Process Group permissions
$groupDelegation = $jsonContent.Delegations[0].GroupObjects


# Begin Region Group Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
#$OU = $OU.DN
$ADOU = ("AD:\" + $OU)
$GroupACE = Get-ACL -Path $ADOU

# Process each property for Group permissions
foreach ($property in $groupDelegation) {

    # Set GenericAll Permissions
    if ($property -in $DescendantProperties) {
        # For Create/Delete All Child Rights
        if ($property -eq "CreateAllChild") {
            $property = "CreateChild"
        }
        elseif ($property -eq "DeleteAllChild") {
            $property = "DeleteChild"
        }
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
   
        # Create the Active Directory access rule for the property----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $permissionSID,
        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["group"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $GroupACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $GroupACE
    }
    # Set Extended Rights Properties
    elseif ($property -in $ExtendedRightProperties) {
        # Process Extended Right Properties for Group Security permissions --------#
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
        # Create the Active Directory access rule for Add/Remove self as member permissions----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $permissionSID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$Property],
        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["group"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $GroupACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $GroupACE
    }
    # Process Create & Delete Group Objects for Group Security permissions --------#
    elseif (($property -eq "CreateChild") -or ($property -eq "DeleteChild")) {
        # Process Create & Delete User Objects for Group Security permissions --------#
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["Group"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'Group Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
        # Add the rule to the ACL
        $GroupACE.AddAccessRule($permissionRule)
        Set-Acl -Path $ADOU -AclObject $GroupACE
    }
    # Set other attribute permissions
    else {
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID

        # Create the Active Directory access rule for the property
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["group"]
        )
        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray


            # Add the rule to the ACL
            $GroupACE.AddAccessRule($permissionRule)
            Set-ACL -Path $ADOU -AclObject $GroupACE
    }
}
}
#
#
#
#------------------------[Computer Object Delegations]------------------------#
#
#
#
write-host ""
Write-Host "#------------------------[Computer Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1
# Process Computer permissions
$ComputerDelegation = $jsonContent.Delegations[0].ComputerObjects


# Begin Computer Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
#$OU = $OU.DN
$ADOU = ("AD:\" + $OU)
$ComputerACE = Get-ACL -Path $ADOU
   
# Process each property for Computer Allow permissions
foreach ($property in $ComputerDelegation) {

    # Set GenericAll Permissions
    if ($property -in $DescendantProperties) {
        # For Create/Delete All Child Rights
        if ($property -eq "CreateAllChild") {
            $property = "CreateChild"
        }
        elseif ($property -eq "DeleteAllChild") {
            $property = "DeleteChild"
        }
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
   
        # Create the Active Directory access rule for the property----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $permissionSID,
        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["computer"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $ComputerACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $ComputerACE
    }
    # Process Create & Delete Computer Objects for Group Security permissions --------#
    elseif (($property -eq "CreateChild") -or ($property -eq "DeleteChild")) {
        # Process Create & Delete User Objects for User Security permissions --------#
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["Computer"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'Computer Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
        # Add the rule to the ACL
        $ComputerACE.AddAccessRule($permissionRule)
        Set-Acl -Path $ADOU -AclObject $ComputerACE
    }
    # Set LAPS read permissions
    elseif (($property -eq "ms-Mcs-AdmPwd") -or ($property -eq "ms-Mcs-AdmPwdExpirationTime")) {
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
        # Create the Active Directory access rule for LAPS property
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["computer"]
    )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray

        # Add the rule to the ACL
        $ComputerACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $ComputerACE
    }
    # Set Extended Rights Properties
    elseif ($property -in $ExtendedRightProperties) {
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
        # Create the Active Directory access rule for the property
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["computer"]
    )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray

    # Add the rule to the ACL
    $ComputerACE.AddAccessRule($permissionRule)
    Set-ACL -Path $ADOU -AclObject $ComputerACE
}
    # Set other attribute permissions
    else {
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
            
            # Create the Active Directory access rule for the property
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $permissionSID,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["computer"]
        )

            write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray

        # Add the rule to the ACL
        $ComputerACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $ComputerACE
    }
}
}
#
#
#
#------------------------[Account Object Delegations]------------------------#
#
#
#
write-host ""
Write-Host "#------------------------[Account Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1
# Process Computer permissions
$AccountDelegation = $jsonContent.Delegations[0].AccountObjects


# Begin Computer Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
#$OU = $OU.DN
$ADOU = ("AD:\" + $OU)
$AccountACE = Get-ACL -Path $ADOU
   
# Process each property for Account Allow permissions
foreach ($property in $AccountDelegation) {

    # Set GenericAll Permissions
    if ($property -in $DescendantProperties) {
        # For Create/Delete All Child Rights
        if ($property -eq "CreateAllChild") {
            $property = "CreateChild"
        }
        elseif ($property -eq "DeleteAllChild") {
            $property = "DeleteChild"
        }
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
   
        # Create the Active Directory access rule for the property----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $permissionSID,
        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["account"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $AccountACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $AccountACE
    }
    # Process Create & Delete Account Objects for Group Security permissions --------#
    elseif (($property -eq "CreateChild") -or ($property -eq "DeleteChild") ) {
        # Process Create & Delete User Objects for User Security permissions --------#
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["account"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'Account Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
        # Add the rule to the ACL
        $AccountACE.AddAccessRule($permissionRule)
        Set-Acl -Path $ADOU -AclObject $AccountACE
    }
    # Set Extended Rights Properties
    elseif ($property -in $ExtendedRightProperties) {
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
        # Create the Active Directory access rule for the property
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["account"]
    )

        write-host "[+] Delegating $($property) 'Account Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
    
        # Add the rule to the ACL
        $AccountACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $AccountACE
    }
    # Set other attribute permissions
    else {
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
            
            # Create the Active Directory access rule for the property
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $permissionSID,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["account"]
        )

            write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray

        # Add the rule to the ACL
        $AccountACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $AccountACE
    }
}
}
#
#
#
#------------------------[OU Object Delegations]------------------------#
#
#
#
write-host ""
Write-Host "#------------------------[OU Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1
# Process OU permissions
$OUDelegation = $jsonContent.Delegations[0].OUObjects


# Begin OU Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
#$OU = $OU.DN
$ADOU = ("AD:\" + $OU)
$OUACE = Get-ACL -Path $ADOU
   
# Process each property for OU Allow permissions
foreach ($property in $OUDelegation) {

    # Set GenericAll or other Permissions
    if ($property -in $DescendantProperties) {

        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
   
        # Create the Active Directory access rule for the property----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $permissionSID,
        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["organizationalUnit"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $OUACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $OUACE
    }
    # Process Create & Delete Account Objects for Group Security permissions --------#
    elseif (($property -eq "CreateChild") -or ($property -eq "DeleteChild") ) {
        
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["organizationalUnit"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'OU Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
        # Add the rule to the ACL
        $OUACE.AddAccessRule($permissionRule)
        Set-Acl -Path $ADOU -AclObject $OUACE
    }
    # Set Extended Rights Properties
    elseif ($property -in $ExtendedRightProperties) {
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
        # Create the Active Directory access rule for the property
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["organizationalUnit"]
    )

        write-host "[+] Delegating $($property) 'OU Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
    
        # Add the rule to the ACL
        $OUACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $OUACE
    }
    # Set other attribute permissions
    else {
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
            
            # Create the Active Directory access rule for the property
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $permissionSID,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["organizationalUnit"]
        )

            write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray

        # Add the rule to the ACL
        $OUACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $OUACE
    }
}
}
#
#
#
#------------------------[inetOrgPerson Object Delegations]------------------------#
#
#
#
write-host ""
Write-Host "#------------------------[inetOrgPerson Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1
# Process inetOrgPerson permissions
$inetOrgPersonDelegation = $jsonContent.Delegations[0].inetOrgPersonObjects


# Begin inetOrgPerson Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
#$OU = $OU.DN
$ADOU = ("AD:\" + $OU)
$inetOrgPersonACE = Get-ACL -Path $ADOU
   
# Process each property for OU Allow permissions
foreach ($property in $inetOrgPersonDelegation) {

    # Set GenericAll or other Permissions
    if ($property -in $DescendantProperties) {

        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
   
        # Create the Active Directory access rule for the property----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $permissionSID,
        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["inetOrgPerson"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $inetOrgPersonACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $inetOrgPersonACE
    }
    # Process Create & Delete Account Objects for Group Security permissions --------#
    elseif (($property -eq "CreateChild") -or ($property -eq "DeleteChild") ) {
        
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["inetOrgPerson"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        
        # Add the rule to the ACL
        $inetOrgPersonACE.AddAccessRule($permissionRule)
        Set-Acl -Path $ADOU -AclObject $inetOrgPersonACE
    }
    # Set Extended Rights Properties
    elseif ($property -in $ExtendedRightProperties) {
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
        # Create the Active Directory access rule for the property
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["inetOrgPerson"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
    
        # Add the rule to the ACL
        $inetOrgPersonACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $inetOrgPersonACE
    }
    # Set other attribute permissions
    else {
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
            
            # Create the Active Directory access rule for the property
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $permissionSID,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["inetOrgPerson"]
        )

            write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray

        # Add the rule to the ACL
        $inetOrgPersonACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $inetOrgPersonACE
    }
}
}
#
#
#
#------------------------[Contact Object Delegations]------------------------#
#
#
#
write-host ""
Write-Host "#------------------------[Contact Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1
# Process Contact permissions
$ContactDelegation = $jsonContent.Delegations[0].ContactObjects


# Begin Contact Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
#$OU = $OU.DN
$ADOU = ("AD:\" + $OU)
$ContactACE = Get-ACL -Path $ADOU
   
# Process each property for OU Allow permissions
foreach ($property in $ContactDelegation) {

    # Set GenericAll or other Permissions
    if ($property -in $DescendantProperties) {

        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
   
        # Create the Active Directory access rule for the property----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $permissionSID,
        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["contact"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
        # Add the rule to the ACL
        $ContactACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $ContactACE
    }
    # Process Create & Delete Account Objects for Group Security permissions --------#
    elseif (($property -eq "CreateChild") -or ($property -eq "DeleteChild") ) {
        
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["contact"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'OU Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
        # Add the rule to the ACL
        $ContactACE.AddAccessRule($permissionRule)
        Set-Acl -Path $ADOU -AclObject $ContactACE
    }
    # Set Extended Rights Properties
    elseif ($property -in $ExtendedRightProperties) {
        $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
        # Create the Active Directory access rule for the property
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["contact"]
        )

        write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray
    
        # Add the rule to the ACL
        $ContactACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $ContactACE
    }
    # Set other attribute permissions
    else {
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
            
            # Create the Active Directory access rule for the property
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $permissionSID,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["contact"]
        )

            write-host "[+] Delegating WriteProperty to $($ADObjectValue.sAMAccountName) on $($ADOU) for attribute $($Property) " -f gray

        # Add the rule to the ACL
        $ContactACE.AddAccessRule($permissionRule)
        Set-ACL -Path $ADOU -AclObject $ContactACE
    }
}
}
#
#
#
#------------------------[All Descendant Object Delegations]------------------------#
#
#
#
write-host ""
Write-Host "#------------------------[All Descendant Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1
# Process AllObjects permissions
$AllDescendantDelegation = $jsonContent.Delegations[0].AllObjects


# Begin All Descendant Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
    #$OU = $OU.DN
    $ADOU = ("AD:\" + $OU)
    $AllDescendantACE = Get-ACL -Path $ADOU
    
    # Process each property for Account Allow permissions
    foreach ($property in $AllDescendantDelegation) {

        # Set Extended Rights Properties
        if ($property -in $ExtendedRightProperties) {
            # Process AllObject for Group Security permissions --------#
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$Property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'All Descendant Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
            
            # Add the rule to the ACL
            $AllDescendantACE.AddAccessRule($permissionRule)
            Set-Acl -Path $ADOU -AclObject $AllDescendantACE
        }
        elseif ($property -in $DescendantProperties) {
            # For Create/Delete All Child Rights
            if ($property -eq "CreateAllChild") {
                $property = "CreateChild"
            }
            elseif ($property -eq "DeleteAllChild") {
                $property = "DeleteChild"
            }
            # Process All Descendant Objects for Group Security permissions --------#
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'All Descendant Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
            # Add the rule to the ACL
            $AllDescendantACE.AddAccessRule($permissionRule)
            Set-Acl -Path $ADOU -AclObject $AllDescendantACE
        }
        else {
            # Process All Descendant Objects for Group Security permissions --------#
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID

            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'All Descendant Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
            # Add the rule to the ACL
            $AllDescendantACE.AddAccessRule($permissionRule)
            Set-Acl -Path $ADOU -AclObject $AllDescendantACE
        }
    }
}
#
#
#
#------------------------[This Object Delegations]------------------------#
#
#
#
write-host ""
Write-Host "#------------------------[This Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1
# Process ThisObject permissions
$ThisObjectDelegation = $jsonContent.Delegations[0].ThisObject


# Begin This Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
    #$OU = $OU.DN
    $ADOU = ("AD:\" + $OU)
    $ThisObjectACE = Get-ACL -Path $ADOU
    
    # Process each property for ThisObject Allow permissions
    foreach ($property in $ThisObjectDelegation) {

        # Set Extended Rights Properties
        if ($property -in $ExtendedRightProperties) {
            # Process ThisObjects for Group Security permissions --------#
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$Property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"None",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'This Objects' to $($ADGroup) on $($ADOU)" -f gray
        
            # Add the rule to the ACL
            $ThisObjectACE.AddAccessRule($permissionRule)
            Set-Acl -Path $ADOU -AclObject $ThisObjectACE
        }
        elseif ($property -in $DescendantProperties) {
            # For Create/Delete All Child Rights
            if ($property -eq "CreateAllChild") {
                $property = "CreateChild"
            }
            elseif ($property -eq "DeleteAllChild") {
                $property = "DeleteChild"
            }
            # Process ThisObjects for Group Security permissions --------#
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $permissionSID,
                [System.DirectoryServices.ActiveDirectoryRights]::$Property,
                [System.Security.AccessControl.AccessControlType]::Allow,
                [DirectoryServices.ActiveDirectorySecurityInheritance]::"None",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'This Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
            # Add the rule to the ACL
            $ThisObjectACE.AddAccessRule($permissionRule)
            Set-Acl -Path $ADOU -AclObject $ThisObjectACE
        }    
        else {
            # Process Write Property permissions
            $permissionSID = New-Object System.Security.Principal.SecurityIdentifier $ADObjectValue.objectSID
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $permissionSID,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
                [DirectoryServices.ActiveDirectorySecurityInheritance]::"None",$([GUID]::Empty)
            )
        
            Write-Host "[+] Delegating $($property) 'This Objects' to $($ADObjectValue.sAMAccountName) on $($ADOU)" -f gray
        
            # Add the rule to the ACL
            $ThisObjectACE.AddAccessRule($permissionRule)
            Set-Acl -Path $ADOU -AclObject $ThisObjectACE
        }
    }
}
Stop-Transcript