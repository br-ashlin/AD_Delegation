# Technical Documentation for ACL Deployment and Removal Script (Multi Principal)

## Overview

This script is designed to deploy and remove Access Control Lists (ACLs) in Active Directory (AD) based on a JSON input file. The JSON file serves as the source of truth for configuring Role-Based Access Control (RBAC) permissions across Organizational Units (OUs) within a region-based delegation model. The script handles Users, Groups, and Computer objects and applies or removes specific security settings as outlined in the JSON file.

## Prerequisites

- **PowerShell Version:** 7.0 or higher.
- **Modules Required:**
  - `AdmPwd.PS` (Legacy LAPS)
  - `ActiveDirectory`
  - `AdSchemaMap`
- **Permissions:** Run the PowerShell console with administrative privileges.
- **JSON Input File:** The JSON file must be structured to include specific delegations for Users, Groups, and Computers.

## Parameters

- **`-JsonPath`** *(Mandatory)*: Specifies the full path to the JSON delegation input file.
- **`-SkipRemoval`** *(Optional)*: Skips the removal of existing delegations. This parameter is useful during the first execution to prevent removing delegations that haven't been applied yet.

## Usage Examples

1. **Apply Delegations Based on JSON:**
   ```powershell
   Set-OURbacDelegation -JsonFile C:\Files\Delegation.json
   ```
   This command reads the JSON file and applies ACLs to the specified OUs.

2. **Apply Delegations Without Removing Existing Ones:**
   ```powershell
   Set-OURbacDelegation -JsonFile C:\Files\Delegation.json -SkipRemoval
   ```
   This command applies new delegations without removing any existing group delegations.

## Script Workflow

1. **Initialization:**
   - Loads required PowerShell modules.
   - Reads and parses the JSON file to extract delegation rules.
   - Retrieves the domain information from the environment.

2. **User Object Delegations:**
   - **Removal:** If `-SkipRemoval` is not used, the script purges existing delegations for Users.
   - **Application:** Iterates over the User delegation settings in the JSON file, applying Create, Delete, WriteProperty, and ExtendedRights permissions to the specified OUs.

3. **Group Object Delegations:**
   - **Removal:** Similar to Users, the script purges existing delegations for Groups if `-SkipRemoval` is not specified.
   - **Application:** Applies the Group delegation settings, handling Create, Delete, WriteProperty permissions.

4. **Computer Object Delegations:**
   - **Removal:** Purges existing delegations for Computers unless `-SkipRemoval` is used.
   - **Application:** Configures permissions based on the JSON file for Computer objects, including LAPS, Create, Delete, WriteProperty.

5. **Logging:**
   - The script logs its actions to a transcript file located on the desktop or a specified directory, which helps in auditing and troubleshooting.

## JSON Structure

The JSON file must be structured to include the following objects:
- **OrganizationUnits**: List of OUs where the delegations will be applied.
- **Groups**: Contains User, Group, and Computer SAM accounts.
- **Delegations**: Defines security, allow, password, and DACL settings for Users, Groups, and Computers.

Example JSON structure:
```json
{
  "OrganizationUnits": [
    {
      "DN": "OU=Servers,DC=contoso,DC=org",
      "Code": "CONTOSO"
     }
],
"Groups": [
  {
    "ComputersSAM": [
      "-Allow-Computers",
      "-Security-Computers"
    ]
  }
],
"Delegations": [
  {
    "ComputerAllow": [
      "cn",
      "Name",
      "name",
      "description",
      "displayName",
      "managedBy",
      "memberof",
      "sAMAccountName",
      "userAccountControl"
    ],
    "ComputerSecurity": [
      "CreateChild",
      "DeleteChild",
      "DeleteTree",
      "DeleteAllChild"
    ]
  }
]
}
```

## Outputs

- **ACLs Applied:** The script applies the necessary permissions to the specified OUs.
- **Logs:** The actions performed by the script are logged in a transcript file for auditing.

## Notes

- Ensure that the JSON file is correctly formatted and contains all required fields.
- The script should be tested in a non-production environment before deploying it to live systems to ensure it works as expected.

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