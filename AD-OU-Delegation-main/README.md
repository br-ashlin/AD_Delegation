# AD-OU-Delegation
Script will take input from Delegation source JSON file to control the delegation access to specific OUs, Users, Groups, and Computer objects.

Scenario are the regions are the scope of where an person is allowed to manage objects such as Users, Groups, and Computers. Naming convention is (4-Letter-Region)-(Access)-(ObjectType) example APAC-Allow-Users.

Access Types
============
Allow = Allow access to basic attributes with low risk such as updating a home address.\
Security = Allow access to security attributes with medium such as changing an employees id number, managedby, members\
Password = Allow access to changing ore reset another users password.\
LAPS = Allow access to computer object to retrieve the local Builtin\Administrator password of the endpoint
