#Requires -Version 7.0

<#
.NOTES
  Version:        v2.9
  Author:         https://github.com/VAsHachiRoku
  Creation Date:  April, 2023
  Purpose/Change: Using a JSON source file to set and reset ACL delegations for Users, Groups, and Computer objects to deploy or maintain Region-Based Delegation model.

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

    v2.6 - November, 2023: Abhinav Singh 
-	Move descendant properties to an array

    v2.7 - December, 2023: Abhinav Singh 
-	Add Extended Properties in the permissions list

    v2.8 - May, 2024: Ben Ashlin
-	Add WriteDACL Properties for Users, Group & Computer Objects   

    v2.9 - August, 2024: Ben Ashlin
-   Added skipping AD Objects that are not populated in JSON File. E.g., Skipping Group Objects.
 
.Synopsis
Script requires a JSON source file for custom RBAC Active Directory OU delegation of Security attribute changes

.Description
A JSON file is used as a golden source to delegation permissions on the region OUs for Users, Groups, and Computer objects

.Parameter JsonPath
This is a Mandatory parameter to the full path of the JSON delegation input file.

.Parameter SkipRemoval
This is an optional parameter that should only be used when delegating permissions for the first time as there have been no group delegations to remove.

.Example
Set-OURbacDelegation -JsonFile C:\Files\Delegation.json
Delegation of ACLs to the Regional OUs based on the JSON file as input

.Example
Set-OURbacDelegation -JsonFile C:\Files\Delegation.json -SkipRemoval
Used only during the first delegation execution to skip the removal of groups that have not been delegated on the regional OUs

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

    [Parameter(Mandatory = $false)]
    [Switch]$SkipRemoval
)

# Transcript Variables
$LogDate = Get-Date -Format "yyyy-MM-dd_hh.mmtt"
#$OutFile = "$env:USERPROFILE\Desktop\Set-OURBACDelegation_$LogDate.txt"
$outfile = "C:\Scripts\RBAC\MaintainRBACPermissions\Logging\Set-OURBACDelegation_$LogDate.txt"

Start-Transcript -Path $OutFile -NoClobber
# Import required modules
Import-Module AdmPwd.PS -SkipEditionCheck -ErrorAction Stop #legacy laps
Import-Module ActiveDirectory -SkipEditionCheck #-ErrorAction Stop
Import-Module "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\AdSchemaMap\AdGuidMap.psd1" -SkipEditionCheck -ErrorAction Stop


# Create Map Object GUID from the Schema for AD Delegation of objects scripts are not on GitHub but author can be found at https://github.com/constantinhager
$GuidMap = New-ADDGuidMap
$ExtendedRight = New-ADDExtendedRightMap

#Manual Path Testing
#$JsonPath = "C:\Scripts\RBAC\MaintainRBACPermissions\Delegation_v2.8_template.json"

# Read the JSON content from the file
$jsonContent = Get-Content -Raw -Path $JsonPath | ConvertFrom-Json

#Get Domain
$Netbios = $env:USERDOMAIN


#
#
#
#------------------------[User Object Delegations]------------------------#
#
#
#

# Process User permissions
$userDelegationSecurity = $jsonContent.Delegations[0].UserSecurity
$userDelegationAllow = $jsonContent.Delegations[0].UserAllow
$userDelegationPassword = $jsonContent.Delegations[0].UserPassword
$userDelegationDACL = $jsonContent.Delegations[0].UserDACL

if($userDelegationSecurity -or $userDelegationAllow -or $userDelegationPassword -or $userDelegationDACL ) {

write-host ""
Write-Host "#------------------------[User Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1

# Remove the group from the Regional OU if SkipRemoval is not specified
if (-not $SkipRemoval) {
	write-host "Purging Existing Delegations.... " -ForegroundColor cyan
	Start-Sleep 1

#Loop User Group Permissions to Remove
foreach ($group in $jsonContent.Groups[0].UsersSAM){
Foreach ($OU in $jsonContent.OrganizationUnits) {
    $RegionOuDn = $OU.DN
    $RegionAdCode = $OU.Code
    $RegionAdOuDn = ("AD:\" + $RegionOuDn)
    $RemoveACL = Get-ACL $RegionAdOuDn
    $userGroupToRemove = $RegionAdCode + $group
    $usergroupAce = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $userGroupToRemove).SID
     $RemoveAcl.PurgeAccessRules($usergroupAce)
        write-host "[+]Removing $($userGroupToRemove) from $($RegionOuDn)" -ForegroundColor gray
        Set-Acl -Path $RegionAdOuDn -AclObject $Removeacl
    }
    }
}

# Begin Region User Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
    $RegionOuDn = $OU.DN
    $RegionAdCode = $OU.Code
    $RegionAdOuDn = ("AD:\" + $RegionOuDn)
    $UserACE = Get-ACL -Path $RegionAdOuDn
   
    # Process each property for User Security permissions --------#
    foreach ($property in $userDelegationSecurity) {
        $permissionGroup = $jsonContent.Groups[0].UsersSAM | Where-Object { $_ -like '*-Security-*' }
        $permissionGroup = $RegionAdCode + $permissionGroup 
        $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID
    
        # Process Create & Delete User Objects for User Security permissions --------#
        if (($property -eq "CreateChild") -or ($property -eq "DeleteChild")) {

            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["User"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
            
            Write-Host "[+] Delegating $($property) on $($RegionAdOuDn) to $($PermissionGroup) for 'User Objects'" -f gray

        
            # Add the rule to the ACL
            $UserACE.AddAccessRule($permissionRule)
            Set-Acl -Path $RegionAdOuDn -AclObject $UserACE
        }

        # Process DeleteTree User Objects for User Security permissions --------#
        elseif (($property -eq "DeleteTree") -or ($property -eq "DeleteAllChild") -or ($property -eq "Delete")) {
            # For Create/Delete All Child Rights
            if ($property -eq "DeleteAllChild") {
                $property = "DeleteChild"
            }
            # Create the Active Directory access rule for User Object Permissions----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["User"]
            )
            
            Write-Host "[+] Delegating $($property) on $($RegionAdOuDn) to $($PermissionGroup) for 'User Objects'" -f gray
            
            # Add the rule to the ACL
            $UserACE.AddAccessRule($permissionRule)
            Set-Acl -Path $RegionAdOuDn -AclObject $UserACE
        }
        else {
            # Create the Active Directory access rule for the property----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$Property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
            )

            write-host "[+] Delegating WriteProperty on $($RegionOuDn) to $($PermissionGroup) for attribute $($Property)" -f gray
            # Add the rule to the ACL
            $UserACE.AddAccessRule($permissionRule)
            Set-ACL -Path $RegionAdOuDn -AclObject $UserACE
        }
    }


    # Process each property for User Allow permissions --------#
    foreach ($property in $userDelegationAllow) {
        $permissionGroup = $jsonContent.Groups[0].UsersSAM | Where-Object { $_ -like '*-Allow-*' }
        $permissionGroup = $RegionAdCode | ForEach-Object {$_ + $permissionGroup}
        $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID

        # Create the Active Directory access rule for the property----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$Property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
            )
    
        write-host "[+] Delegating WriteProperty on $($RegionOuDn) to $($PermissionGroup) for attribute $($Property)" -f gray

        # Add the rule to the ACL
        $UserACE.AddAccessRule($permissionRule)
        Set-ACL -Path $RegionAdOuDn -AclObject $UserACE

    }


    # Process each property for User Password permissions --------#
    foreach ($property in $userDelegationPassword) {
        $permissionGroup = $jsonContent.Groups[0].UsersSAM | Where-Object { $_ -like '*-Password-*' }
        $permissionGroup = $RegionAdCode | ForEach-Object {$_ + $permissionGroup}
        $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID

        # Create the Active Directory access rule for the property----#
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AccessControlType]::Allow,$ExtendedRight[$Property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
            )


        write-host "[+] Delegating WriteProperty on $($RegionOuDn)to $($PermissionGroup) for attribute $($Property)" -f gray

        # Add the rule to the ACL
        $UserACE.AddAccessRule($permissionRule)
        Set-ACL -Path $RegionAdOuDn -AclObject $UserACE
    }

foreach ($property in $userDelegationDACL) {
    $permissionGroup = $jsonContent.Groups[0].UsersSAM | Where-Object { $_ -like '*-DACL-*'}
    $permissionGroup = $RegionAdCode | ForEach-Object {$_ + $permissionGroup}
    $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID

    # Create the Active Directory access rule for the property
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $permissionGroupSID,
        [System.DirectoryServices.ActiveDirectoryRights]::$Property,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["user"]
    )
    write-host "[+] Delegating WriteDACL on $($RegionOuDn)to $($PermissionGroup)" -f gray

        # Add the rule to the ACL
        $UserACE.AddAccessRule($permissionRule)
        Set-ACL -Path $RegionAdOuDn -AclObject $UserACE
    }
}
}
else {
write-host ""
    write-host "[+] Skipping User Object Delegation" -ForegroundColor DarkYellow
}

#
#
#
#------------------------[Group Object Delegations]------------------------#
#
#
#


# Process Group permissions
$groupDelegationSecurity = $jsonContent.Delegations[0].GroupSecurity
$groupDelegationAllow = $jsonContent.Delegations[0].GroupAllow
$groupDelegationDACL = $jsonContent.Delegations[0].GroupDACL

if($groupDelegationSecurity -or $groupDelegationAllow -or $groupDelegationDACL ) {


write-host ""
Write-Host "#------------------------[Group Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1

# Remove the group from the Regional OU if SkipRemoval is not specified
if (-not $SkipRemoval) {
	write-host "Purging Existing Delegations.... " -ForegroundColor Gray
	Start-Sleep 1
    #Loop Group Permissions to Remove
    foreach ($group in $jsonContent.Groups[0].GroupsSAM){
        Foreach ($OU in $jsonContent.OrganizationUnits) {
            $RegionOuDn = $OU.DN
            $RegionAdCode = $OU.Code
            $RegionAdOuDn = ("AD:\" + $RegionOuDn)
            $RemoveACL = Get-ACL $RegionAdOuDn
            $GroupToRemove = $RegionAdCode + $group
            $groupAce = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $GroupToRemove).SID
            $RemoveAcl.PurgeAccessRules($groupAce)
                write-host "[+]Removing $($GroupToRemove) from $($RegionOuDn)" -ForegroundColor gray
                Set-Acl -Path $RegionAdOuDn -AclObject $Removeacl
        }
    }
}

# Begin Region Group Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
$RegionOuDn = $OU.DN
$RegionAdCode = $OU.Code
$RegionAdOuDn = ("AD:\" + $RegionOuDn)
$GroupACE = Get-ACL -Path $RegionAdOuDn

    # Process each property for Group Security permissions
    foreach ($property in $groupDelegationSecurity) {
        $permissionGroup = $jsonContent.Groups[0].GroupsSAM | Where-Object { $_ -like '*-Security-*'}
        $permissionGroup = $RegionAdCode | ForEach-Object {$_ + $permissionGroup}
        $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID

        # Process Create & Delete Group Objects for Group Security permissions --------#
        if (($property -eq "CreateChild") -or ($property -eq "DeleteChild")) {
        
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["Group"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
            
                Write-Host "[+] Delegating $($property) on $($RegionAdOuDn) to $($PermissionGroup) for 'Group Objects'" -f gray

            
            # Add the rule to the ACL
            $GroupACE.AddAccessRule($permissionRule)
            Set-Acl -Path $RegionAdOuDn -AclObject $GroupACE
        }

        # Process Delete Group Objects for Group Security permissions --------#
        elseif (($property -eq "DeleteTree") -or ($property -eq "DeleteAllChild") -or ($property -eq "Delete")) {
            # For Create/Delete All Child Rights
            if ($property -eq "DeleteAllChild") {
                $property = "DeleteChild"
            }
            # Create the Active Directory access rule for Group Object Permissions----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["Group"]
            )
            
               Write-Host "[+] Delegating $($property) on $($RegionAdOuDn) to $($PermissionGroup) for 'Group Objects'" -f gray

            
            # Add the rule to the ACL
            $GroupACE.AddAccessRule($permissionRule)
            Set-Acl -Path $RegionAdOuDn -AclObject $GroupACE
        }

        # Create the Active Directory access rule for the property
        else {   
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["group"]
        )
        write-host "[+] Delegating WriteProperty on $($RegionOuDn) to $($PermissionGroup) for attribute $($Property)" -f gray

            # Add the rule to the ACL
            $GroupACE.AddAccessRule($permissionRule)
            Set-ACL -Path $RegionAdOuDn -AclObject $GroupACE
        }  
    }    

    # Process each property for Group Allow permissions
    foreach ($property in $groupDelegationAllow) {
        $permissionGroup = $jsonContent.Groups[0].GroupsSAM | Where-Object { $_ -like '*-Allow-*'}
        $permissionGroup = $RegionAdCode | ForEach-Object {$_ + $permissionGroup}
        $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID

        # Create the Active Directory access rule for the property
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$Property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["group"]
        )
        write-host "[+] Delegating WriteProperty on $($RegionOuDn)to $($PermissionGroup) for attribute $($Property)" -f gray

            # Add the rule to the ACL
            $GroupACE.AddAccessRule($permissionRule)
            Set-ACL -Path $RegionAdOuDn -AclObject $GroupACE
    }

        # Process each property for Group DACL permissions
        foreach ($property in $groupDelegationDACL) {
            $permissionGroup = $jsonContent.Groups[0].GroupsSAM | Where-Object { $_ -like '*-DACL-*'}
            $permissionGroup = $RegionAdCode | ForEach-Object {$_ + $permissionGroup}
            $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID
    
            # Create the Active Directory access rule for the property
                $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $permissionGroupSID,
                [System.DirectoryServices.ActiveDirectoryRights]::$Property,
                [System.Security.AccessControl.AccessControlType]::Allow,
                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["group"]
            )
            write-host "[+] Delegating WriteDACL on $($RegionOuDn)to $($PermissionGroup)" -f gray
    
                # Add the rule to the ACL
                $GroupACE.AddAccessRule($permissionRule)
                Set-ACL -Path $RegionAdOuDn -AclObject $GroupACE
        }

}
}
else {
write-host ""
write-host "[+] Skipping Group Object Delegation" -ForegroundColor DarkYellow

}
#
#>
#
#------------------------[Computer Object Delegations]------------------------#
#
#
#

# Process Computer permissions
$ComputerDelegationLaps = $jsonContent.Delegations[0].ComputerLaps
$ComputerDelegationAllow = $jsonContent.Delegations[0].ComputerAllow
$ComputerDelegationSecurity = $jsonContent.Delegations[0].ComputerSecurity
$ComputerDelegationDACL = $jsonContent.Delegations[0].ComputerDACL

if ($ComputerDelegationLaps -OR $ComputerDelegationAllow -OR $ComputerDelegationSecurity -oR $ComputerDelegationDACL ) {
write-host ""
Write-Host "#------------------------[Computer Object Delegations]------------------------#" -ForegroundColor Green
write-host ""
Start-Sleep 1


# Remove the group from the Regional OU if SkipRemoval is not specified
if (-not $SkipRemoval) {
	write-host "Purging Existing Delegations.... " -ForegroundColor Cyan
	Start-Sleep 1

    #Loop Group Permissions to Remove
    foreach ($group in $jsonContent.Groups[0].ComputersSAM){
        Foreach ($OU in $jsonContent.OrganizationUnits) {
            $RegionOuDn = $OU.DN
            $RegionAdCode = $OU.Code
            $RegionAdOuDn = ("AD:\" + $RegionOuDn)
            $RemoveACL = Get-ACL $RegionAdOuDn
            $ComputerGroupToRemove = $RegionAdCode + $group
            $groupAce = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $ComputerGroupToRemove).SID
            $RemoveAcl.PurgeAccessRules($groupAce)
                write-host "[+]Removing $($ComputerGroupToRemove) from $($RegionOuDn)" -ForegroundColor gray
                Set-Acl -Path $RegionAdOuDn -AclObject $Removeacl
        }
    } 
}

# Begin Region Computer Object Loop --------#
write-host ''
write-host "Writing New Delegations.... " -ForegroundColor cyan
Start-Sleep 1
Foreach ($OU in $jsonContent.OrganizationUnits) {
    $RegionOuDn = $OU.DN
    $RegionAdCode = $OU.Code
    $RegionAdOuDn = ("AD:\" + $RegionOuDn)
    $ComputerACE = Get-ACL -Path $RegionAdOuDn

    # Process each property for Group Security permissions
    foreach ($property in $ComputerDelegationSecurity) {
        $permissionGroup = $jsonContent.Groups[0].ComputersSAM | Where-Object { $_ -like '*-Security-*' }
        $permissionGroup = $RegionAdCode + $permissionGroup 
        $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID

        # Process Create & Delete Computer Objects for Computer Security permissions --------#
        if (($property -eq "CreateChild") -or ($property -eq "DeleteChild")) {
            
            # Create the Active Directory access rule for Create & Delete----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap["Computer"],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::"All",$([GUID]::Empty)
            )
            
                Write-Host "[+] Delegating $($property) on $($RegionAdOuDn) to $($PermissionGroup) for 'Computer Objects'" -f gray

            
            # Add the rule to the ACL
            $ComputerACE.AddAccessRule($permissionRule)
            Set-Acl -Path $RegionAdOuDn -AclObject $ComputerACE
        }

        # Process DeleteTree Computer Objects for Computer Security permissions --------#
        elseif (($property -eq "DeleteTree") -or ($property -eq "DeleteAllChild") -or ($property -eq "Delete")) {
            # For Create/Delete All Child Rights
            if ($property -eq "DeleteAllChild") {
                $property = "DeleteChild"
            }
            # Create the Active Directory access rule for Computer Object Permissions----#
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$property,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["Computer"]
            )
            
                Write-Host "[+] Delegating $($property) on $($RegionAdOuDn) to $($PermissionGroup) for 'Computer Objects'" -f gray

            
            # Add the rule to the ACL
            $ComputerACE.AddAccessRule($permissionRule)
            Set-Acl -Path $RegionAdOuDn -AclObject $ComputerACE
        }
        
        # Create the Active Directory access rule for the property
        else {
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $permissionGroupSID,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
                [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["computer"]
            )

                write-host "[+] Delegating WriteProperty to $($ADGroup) on $($RegionAdOuDn) for attribute $($Property) " -f gray

            # Add the rule to the ACL
            $ComputerACE.AddAccessRule($permissionRule)
            Set-ACL -Path $RegionAdOuDn -AclObject $ComputerACE
        }
    }
   
    # Process each property for Computer Allow permissions
    foreach ($property in $ComputerDelegationAllow) {
        $permissionGroup = $jsonContent.Groups[0].ComputersSAM | Where-Object { $_ -like '*-Allow-*'}
        $permissionGroup = $RegionAdCode | ForEach-Object {$_ + $permissionGroup}
        $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID
        

        # Create the Active Directory access rule for the property
        $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
            [System.Security.AccessControl.AccessControlType]::Allow,$GuidMap[$property],
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["computer"]
    )

        write-host "[+] Delegating WriteProperty to $($PermissionGroup) for attribute $($Property) on $($RegionOuDn)" -f gray

    # Add the rule to the ACL
    $ComputerACE.AddAccessRule($permissionRule)
    Set-ACL -Path $RegionAdOuDn -AclObject $ComputerACE
    }

    foreach ($property in $computerDelegationDACL) {
        $permissionGroup = $jsonContent.Groups[0].ComputersSAM | Where-Object { $_ -like '*-DACL-*'}
        $permissionGroup = $RegionAdCode | ForEach-Object {$_ + $permissionGroup}
        $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID
    
        # Create the Active Directory access rule for the property
            $permissionRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $permissionGroupSID,
            [System.DirectoryServices.ActiveDirectoryRights]::$Property,
            [System.Security.AccessControl.AccessControlType]::Allow,
            [DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,$GuidMap["computer"]
        )
        write-host "[+] Delegating WriteDACL on $($RegionOuDn)to $($PermissionGroup)" -f gray
    
            # Add the rule to the ACL
            $ComputerACE.AddAccessRule($permissionRule)
            Set-ACL -Path $RegionAdOuDn -AclObject $ComputerACE
    }
    
    # Process each property for Computer LAPs permissions

    write-host "Writing LAPs Delegations.... " -ForegroundColor cyan

    foreach ($property in $ComputerDelegationLaps) {
        $permissionGroup = $jsonContent.Groups[0].ComputersSAM | Where-Object { $_ -like '*-LAPS-*'}
        $permissionGroup = $RegionAdCode | ForEach-Object {$_ + $permissionGroup}
        $permissionGroupSID = New-Object System.Security.Principal.SecurityIdentifier (Get-ADGroup -Identity $permissionGroup).SID

        #Sets the read LAPS permission on the Computer Objects ------------------#
        Set-AdmPwdReadPasswordPermission -Identity $RegionOuDn -AllowedPrincipals $permissionGroup  
        #Sets the expire LAPS permission on the Computer Objects
        Set-AdmPwdResetPasswordPermission -Identity $RegionOuDn -AllowedPrincipals $permissionGroup 
    }

}
}
else {
write-host ""
 write-host "[+] Skipping Computer Object Delegation" -ForegroundColor DarkYellow
 
}

write-host ""
Stop-Transcript
