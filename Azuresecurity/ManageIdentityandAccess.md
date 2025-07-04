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



