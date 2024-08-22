# High-Level Overview: Active Directory Delegation Management Scripts

These scripts are designed to automate the delegation of permissions in Active Directory (AD) environments, streamlining the process of assigning rights to service accounts, groups, or other principals across specific Organizational Units (OUs). The scripts work by reading a JSON configuration file that defines the OUs and the permissions to be delegated to various AD objects.

## Key Features:
- **Automated Delegation:** The scripts simplify the process of assigning complex permissions to AD objects by automating the delegation process.
- **JSON-Driven Configuration:** The permissions and OUs are defined in a JSON file, making the process flexible and easy to manage.
- **Logging and Error Handling:** Both scripts provide detailed logs of the operations performed, including any errors encountered, ensuring transparency and ease of troubleshooting.

## Available Scripts:
### **[Single Principals Delegation Script](https://github.com/br-ashlin/AD_Delegation/tree/master/AddNew_Group_ServiceAccount_RBAC)**
   - **Purpose:** This script is tailored for scenarios where delegations need to be applied to a single principal, such as a specific service account or group.
   - **Use Case:** Ideal for environments where only one entity needs delegation rights across specified OUs.
   - **Execution:** The principal and the JSON configuration file are passed as parameters to the script, which then applies the specified permissions accordingly.

### **[Maintain Principals Delegation Script](https://github.com/br-ashlin/AD_Delegation/tree/master/MaintainRBACPermissions)**
   - **Purpose:** This script is designed for environments where Delegation groups are deployed and need to have delegations applied and 'maintained' across various OUs.
   - **Use Case:** Best suited for scenarios where Delegation groups with correct naming standard can be deployed sets of permissions across the AD structure. E.g., 'DOMAIN-Security-Users'
   - **Execution:** The JSON configuration file contains multiple principals, each with its specific permissions and target OUs. The script processes each principal and applies the relevant delegations.

### **[Remove Delegation Script](https://github.com/br-ashlin/AD_Delegation/tree/master/RemoveACLPermissions)**
   - **Purpose:** This script is designed to remove single principal identities from multiple OUs with the same delegations.
   - **Use Case:** Best suited for scenarios where the same permissions have been delegated across multiple OUs. Multiple JSONs will need to be created for different delegations
   - **Execution:** The JSON configuration file contains a single principal, each with its specific permissions and target OUs. The script processes the removal of the principal and on the selected OUs and Object Types.


## Summary
These scripts are essential tools for IT administrators and system engineers tasked with managing permissions in Active Directory environments. Whether you need to apply delegations to a single principal or multiple entities, these scripts provide a reliable, automated solution that ensures consistency and accuracy across your AD infrastructure.

## Acknowledgments

- This script was inspired by best practices in Active Directory management.

## Contact

For any questions or issues, please contact:

- **Ben Ashlin** - Brashlin@outlook.com
```