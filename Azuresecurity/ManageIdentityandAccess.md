# Azure Security Engineer Associate (AZ-500)

## Manage Identity and Access

This section mostly deals with Azure Active Directory

### Managing Identities

1. Authentication and Authorization

AuthN and AuthZ

2. Identity Providers

3. UPN and SPN

4. Managing Users

Create 
    Required Privileges - User Administrator, Global Administrator
    Azure Powershell - New-AzADUser
    Azure CLI - az ad user create

Read
    Required Privileges - All members
    Azure Powershell - Get-AzADUser
    Azure CLI - az ad user list, az ad user show

Update
    Required Privileges - self update, User Administrator, Privileged Authentication Admin
    Azure Powershell - Update-AzADUser
    Azure CLI - az ad user update

Delete
    Required Privileges - User Administrator, Privileged Authentication Admin
    Azure Powershell - Remove-AzADUser
    Azure CLI - az ad user delete
    Users are retained 30 days as part of soft delete before getting deleted permanently

  Powershell - verb and prefixed noun - Remove-AzADUser

  Azure ClI - Reference command - az ad user delete  


  ### Flavors of AD services

  Active Directory Domain services - for onprem, syncs users with Azure Active Directory, bi-directional

  Azure Active Directory - for azure, syncs users with AD DS (bi-directional) and AAD DS (one-way)

  Azure Active Directory Domain Services - for azure, only sync happens from AAD, Accounts used here are to run services and these are local accounts

  Users created at specific source must be updated at the same specific source

  ### Managing Azure AD users

1. Create a backup Global admin account using Azure portal, or called asbreakglass account

2. Create account for a user to manage users using powershell (Add, update and delete)

Portal Create - AAD -> Users -> New user -> GlobalAdminBackup (AutoGen pwd) -> Create

##Command - PS##

Install-Module Az Force

connect-AzAccount

$Password = "xxxxxxxx" | ConvertTo-SecureString -AsPlainText -Force

$Username = "Adminxxxx"

Command to create user - 

New-AzADUser -DisplayName $Username -Password $Password -UserPrincipalName "user@company.com" -MailNickname $Username -AccountEnabled $true

### Summary

- To add users, you must have at least User Admin role

- To update ordelete privileged roles - you must be atleast Global Admin or Privileged Auth Admin

- Users should be managed where they are created



## Groups

Groups make management of users easier. SG - Users, SPNs.IT team, infra team, app team, security team etc. M365 Group - provides shared mailbox, calendar, Sharepoint site, Microsoft Teams workspace. only users can be members here.

- Azure AD Group Types

- Azure AD Group Membership

- Managing Group Members

- Group Lifecycle

# Group Membership

1. Manual

2. Automatic or Dynamic - based on properties or users and users. ex - India desktops to a ITservice group. SPN cannot be added and mixing and matching membership cannot happen. Needs Azure AD premium P1 license

M365 groups cannot contain devices

# Group Lifecycle

1. Create - Any AAD user

2. Read - Any AAD user

3. Update - User who is group owner, Privileged roles

4. Delete - Group Owners and Administrative roles, Deleted M365 groupsare retained for 30 days, SG get permanently deleted

# Managing Service Principals

- Understand SPN

- SPN Authentication

- Registering Applications

SPN - are for Applications and background processes only. created when an app is registered in Azure AD, for this a SPN is created asan identity for app. 

SPN is also created for a Managed Identity, SPN for Azure resources is referred to as managed identities.

Assign roles and permissions to SPNs asusers. Delegated permissions can also be assigned for SPNs. Managed Identity is recommended by Microsoft.

There are some resources which do not support Managed Identity, hence SPN can be used in those cases, SPNs can be used outside of Azure. SPNs can be created in multiple tenants.

# Authentication using SPN

1. Password based Auth (secret and app id)

2. Certificate based Auth - considered to be more secure than password based

Requirements for creating app registration

- By default, Any azure member can register an application which they are developing. This can be restricted by settings and a specific role will be required to manage applications (RBAC).

App Developer - can register apps and delegate permissions to the application on their behalf

Cloud App Administrator - can manage allapplication registration, request consent fir the application, and access all application credentials

Application Administrator - can approve non-Microsoft graph consent requests and manage Application proxy

# Creation of SPN

1. Portal

2. Powershell and Azcli commands

    1. Install-Module Az -Force
    2. Connect-AzAccount
    3. $SP = New-AzADServicePrincipal - DisplayName "CTApp"
    4. $SP.PasswordCredentials.SecretText

# Summary

- An app registration is a global identity for your app

- A SPN is used to authenticate and authorize your application in the home tenant

- SPNs are identities that are assigned to an application or background process

- SPNscan be applications running anywhere

- Certificate-based auth is recommended when usingself-managed SPNs

## Managing Identities for Azure Resources (MI)

- Understand MI, authN and authZ

- MI types - System-assigned (associated to single azure resource, shared lifecycle with the resource), User-Assigned (associated to many Azure Resources, multiple identities possible, independent lifecycle to associated resources, useful for a group of resourcesthat share a common function )

- MI Lifecycle - depends on system assigned or user-assigned identities

Example of permissions needed to create identities for VM
         System-Assigned(VM)     User-Assigned
Create    VM contributor
                                MI contributor, VM Contributor and MI Operator
Update    VM contributor

Read       Reader                   Reader

Delete    VM contributor         VM contributor



Azure Arc is a special resource which supports MI and helps in managing resources outsite Azure. Ex- onprem

Working with MI

1. Portal - Create MI, assign MI to VM -> Identity -> User assigned

2. Azure Powershell to remove, assign and maintain MI

      (Get-AzContext).Account.Type
      $VM = Get-AzVM -ResourceGroupName "xxxx" -Name "VM1"
Remove UserAssigned MI - Update-AzVM -VM $VM -IdentityType None
Assign systemAssigned MI - Update-AzVM -VM $VM -IdentityType SystemAssigned
MI are azure managed SPN
Retrieve MI - $VMSP = Get-AzADServicePrincipal -DisplayName "VM1"
Assign Role - New-AzRoleAssignment -ObjectId $VMSP.Id -ResourceGroupName "xxxx" -RoleDefinitionName "Virtual Machine Contributor"
Connect using MI - Connect-AzAccount -Identity
(Get-AzContext).Account.Type ---- output is ManagedService (old name)
Stop VM using MI
Stop-AzVN -Name "VM2" -ResourceGroupName "XXXX" - Force

3. Azure Powershell to log on using MI

Connect-AzAccount -Identity













