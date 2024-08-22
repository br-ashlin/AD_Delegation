# Technical Documentation for ACL Deployment and Removal Script (Single Principal)

## Overview

This script is designed to apply delegations for a single principal (e.g., service account or group) in Active Directory based on a JSON configuration file. The script allows for the delegation of specific attributes and permissions on User, Group, Computer, and other object types within the defined OUs.


## Prerequisites

- **PowerShell Version:** 7.0 or higher.
- **Modules Required:**
  - `ActiveDirectory`
  - `AdSchemaMap`
- **Permissions:** Run the PowerShell console with administrative privileges.
- **JSON Input File:** The JSON file must be structured to include specific delegations for Users, Groups, and Computers.

### Parameters

- **`-JsonPath`** *(Mandatory)*: Specifies the full path to the JSON delegation input file.
- **`-ADObject`** *(Mandatory)*: Specifies the AD Principal (SamAccountName) that will inherit the delegated rights from the JSON file.
- **`-SkipRemoval`** *(Optional)*: Skips the removal of existing delegations. This parameter is useful during the first execution to prevent removing delegations that haven't been applied yet.


### Usage Examples

1. **Apply Delegations Based on JSON:**
   ```powershell
   Set-OURbacDelegation -ADObject ServiceAccount01 -JsonFile C:\Files\Delegation.json
   ```
   This command reads the JSON file and applies ACLs to the specified OUs.

2. **Apply Delegations Without Removing Existing Ones:**
   ```powershell
   Set-OURbacDelegation -ADObject ServiceAccount01 -JsonFile C:\Files\Delegation.json -SkipRemoval
   ```
   This command applies new delegations without removing any existing group delegations.

## Configuration

The JSON file must be structured as follows:

```json
{
    "OrganizationUnits": [
        "OU=PROD,DC=contoso,DC=org"
    ],
    "Delegations": [{
        "UserObjects": [
            "accountExpires",
            "company",
            "cn",
            "department",
            "description",
            "displayName",
            "givenName",
            "initials",
            "ipPhone",
            "l",
            "lockoutTime",
            "manager",
            "mobile",
            "msNPAllowDialin",
            "Name",
            "name",
            "postalCode",
            "sAMAccountName",
            "sn",
            "streetAddress",
            "telephoneNumber",
            "userAccountControl",
            "userPrincipalName",
            "servicePrincipalName",
            "pwdLastSet",
            "Delete",
            "CreateChild",
            "DeleteChild",
            "DeleteTree",
            "DeleteAllChild",
            "Change Password",
            "Reset Password",
            "Mail",
            "proxyAddresses"
        ],
        "GroupObjects": [
            "cn",
            "Name",
            "name",
            "description",
            "displayName",
            "groupType",
            "notes",
            "mail",
            "sAMAccountName",
            "managedBy",
            "member",
            "Delete",
            "CreateChild",
            "DeleteChild",
            "DeleteTree",
            "DeleteAllChild"
        ],
        "ComputerObjects": [],
        "AccountObjects": [],
        "OUObjects": [],
        "inetOrgPersonObjects": [],
        "AllObjects": [],
        "ThisObject": []
    }]
}
```

### Key Fields

- **OrganizationUnits:** A list of OUs where the delegations should be applied.
  - Example: `"OU=PROD,DC=contoso,DC=org"`
- **Delegations:** A list of object types with the attributes and permissions to delegate.
  - **UserObjects:** Attributes and permissions to be delegated on User objects.
  - **GroupObjects:** Attributes and permissions to be delegated on Group objects.
  - **ComputerObjects:** Attributes and permissions to be delegated on Computer objects (empty in this example).
  - **AccountObjects:** Attributes and permissions to be delegated on Account objects (empty in this example).
  - **OUObjects:** Attributes and permissions to be delegated on Organizational Unit objects (empty in this example).
  - **inetOrgPersonObjects:** Attributes and permissions to be delegated on inetOrgPerson objects (empty in this example).
  - **AllObjects:** Attributes and permissions to be delegated on all object types (empty in this example).
  - **ThisObject:** Attributes and permissions to be delegated on the OU itself (empty in this example).

## Logging

The script generates a detailed log file in the script's directory. The log file includes information about:

- Successfully applied delegations.
- Errors encountered during execution.
- Summary of operations performed.

## Error Handling

- **Module Loading:** If a required module fails to load, the script will stop execution and display an error message.
- **JSON Parsing:** If the JSON file is improperly formatted or missing required fields, the script will terminate with an error message.

This documentation provides a comprehensive guide to using the ACL deployment and removal script. It is recommended to review and understand the script and JSON file structure before running the script in a production environment.


## Acknowledgments

- This script was inspired by best practices in Active Directory management.

## Contact

For any questions or issues, please contact:

- **Ben Ashlin** - Brashlin@outlook.com
```