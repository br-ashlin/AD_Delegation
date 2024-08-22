# Technical Documentation for ACL Removal Script (Single Principal)

## Overview

This script is designed to remove delegations for a single principal (e.g., service account or group) in Active Directory based on a JSON configuration file. The script allows for the removal of delegation of all attributes and permissions on User, Group, Computer, and other object types within the defined OUs.


## Prerequisites

- **PowerShell Version:** 7.0 or higher.
- **Modules Required:**
  - `ActiveDirectory`
  - `AdSchemaMap`
- **Permissions:** Run the PowerShell console with administrative privileges.
- **JSON Input File:** The JSON file must be structured to include specific delegations for each Object across multiple OUs. E.g., You can have multiple OUs selected, as long as the permissions on each object you are trying to remove are the same. See input templates.

### Parameters

- **`-JsonPath`** *(Mandatory)*: Specifies the full path to the JSON delegation input file.
- **`-ADObject`** *(Mandatory)*: Specifies the AD Principal (SamAccountName) that will have the delegated rights removed from the JSON file.
