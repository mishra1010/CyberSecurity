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

### Group Membership

1. Manual

2. Automatic or Dynamic - based on properties or users and users. ex - India desktops to a ITservice group. SPN cannot be added and mixing and matching membership cannot happen. Needs Azure AD premium P1 license

M365 groups cannot contain devices

#### Group Lifecycle

1. Create - Any AAD user

2. Read - Any AAD user

3. Update - User who is group owner, Privileged roles

4. Delete - Group Owners and Administrative roles, Deleted M365 groupsare retained for 30 days, SG get permanently deleted

##### Managing Service Principals

- Understand SPN

- SPN Authentication

- Registering Applications

SPN - are for Applications and background processes only. created when an app is registered in Azure AD, for this a SPN is created asan identity for app. 

SPN is also created for a Managed Identity, SPN for Azure resources is referred to as managed identities.

Assign roles and permissions to SPNs asusers. Delegated permissions can also be assigned for SPNs. Managed Identity is recommended by Microsoft.

There are some resources which do not support Managed Identity, hence SPN can be used in those cases, SPNs can be used outside of Azure. SPNs can be created in multiple tenants.

##### Authentication using SPN

1. Password based Auth (secret and app id)

2. Certificate based Auth - considered to be more secure than password based

Requirements for creating app registration

- By default, Any azure member can register an application which they are developing. This can be restricted by settings and a specific role will be required to manage applications (RBAC).

App Developer - can register apps and delegate permissions to the application on their behalf

Cloud App Administrator - can manage allapplication registration, request consent fir the application, and access all application credentials

Application Administrator - can approve non-Microsoft graph consent requests and manage Application proxy

#### Creation of SPN

1. Portal

2. Powershell and Azcli commands

    1. Install-Module Az -Force
    2. Connect-AzAccount
    3. $SP = New-AzADServicePrincipal - DisplayName "CTApp"
    4. $SP.PasswordCredentials.SecretText

#### Summary

- An app registration is a global identity for your app

- A SPN is used to authenticate and authorize your application in the home tenant

- SPNs are identities that are assigned to an application or background process

- SPNscan be applications running anywhere

- Certificate-based auth is recommended when usingself-managed SPNs

### Managing Identities for Azure Resources (MI)

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

### Managing External Identities

- Enabling External Identities

    1. Azure AD B2B - invite users as guests to Microsoft AAD to provide access to Azure and Azure AD

    Azure AD tenant <---- B2B Direct Connect----> Azure AD Tenant works with MS Teams
    Azure AD tenant - multi tenants in same org

    2. Using Azure AD B2C

    Access to apps using gmail, facebook etc.
    used to create  separate tenant for users to provide them access to company-developed apps

## Managing Authentication

### Enhancing Authentication

1. Leveling up Auth

2. Enabling MFA

3. Security Defaults

Bad Auth set up - If an org has ADDS service onprem or in Azure VM, and users access systems by using it, then SSO cannot be enabled, users need to use multiple logins, Identities might exist across a range of Identity providers and hence there is limited visibility into the identities used in the Org. Leads to unmanaged identities and also exposure of creds in the internet.

First step here is to 

1. Implement SSO for on-prem and cloud apps

2. Gain visibility into the identities used acrosso the org

3. Conditionally request multiple factors of auth based on policies and assist with identity remediation

Best is to have MFA, use passwordless auth, analyze sign-in attributes in real time


#### MFA

How to enable?

Depends on licenses you have for AAD

1. Free version of AAD - MFA can be enabled on a per user basis and its legacy now

2. Security defaults is the way to enable MFA and other best practices in free version of AAD now

3. M365 for business (E3, E5) for MFA - for all users unconditionally

4. Azure AD Premium P1 - Conditional access based on scenarios or events at login

5. Azure AD Premium P2 - Risk-based conditional Access policies to improve user experience

Security Defaults Enabled? what users get?

1. All users will be required to register for Azure AD MFA

2. Admins will need to perform MFA

3. Users will need to perform MFA when necessary

4. Legacy authentication protocols are blocked

5. Privilege management activities need MFA

For more control on MFA, you need premium licenses and conditional access

Summary -

1. Security Defaults provide a baseline level of protection for all Azure AD users.

2. When you enable security defaults, users will have 14 days after the first login to enable MFA

3. Azure AD premium p1 provides conditional access based on scenarios or events at login

4. Azure AD premium p2 provides risk-based conditional access policies to improve user experience

#### Implementing Conditional Access

1. Details about conditional access

2. Creating conditional access

CAP - is mainly if and else. if (user account, groups, devices, device location, application being accessed, Risks associated in case user has p2 license ) -> Then give access and based on what condition (MFA, Approved client app, compliant device, Azure AD joined device)

License Requirements

1. All CAP require atleast AAD Premium P1

2. Risk-based policies require atleast AAD Premium P2

User Requirements

1. Conditional Access Admin or Security Administrator at minimum

2. Test user account and group if required to test

AAD -> Security -> Conditional Access -> Create policy from template -> Require MFA for Admins

Click policies and assign users and under what conditions. Access controls define the control after access (MFA, Auth App)

Policy used to block legacy auth protocols -> Legacy access block template

Conditional Access -> Named locations -> Country or IP ranges

Test policies and then publish

#### protecting Identities

1. Identity Protection

2. Configuring Identity Protection

3. Password Protection

AAD is the primary security boundary for any organization. Ithas a few tools which can protect identities -

1. Azure AD Identity Protection - works with automatic detection of identity risks - user risk, sign-in risk

Risks are classified as high, medium, low

3 benefits -

1. Challenge Risky sign-ins - like enable MFA in cases

2. Time to respond by having self-remediation

3. Reduces IT teams overhead

Configure Identity Protection -

1. Need Azure AD premium P2 license

2. Conditional Access Admin or security administrator

3. Test user account

AzureAD also provides a mechanism to protect passwords and that is through Password Protection - detects and blocks weak and same version of passwords. Also blocks weak password based on your organization.

Users can use ADDS to make pwd changes if its being used also can happen in Domain controllers in On-prem. These have Azure AD password protection agent deployed

License requirements

1. Banned pwd list is included with all licenses

2. Custom banned pwd lists require atleast one Azure AD Premium P1 license

User Requirements -

1. Security Admin Role

2. Active Directory Domain Administrator for on-prem AD

3. Test user account

AAD -> Security -> Identity protection -> Risky users, configure alerts, weekly digest

Security -> Authentiction Methods -> Policies, Password Protection

#### Summary

1. User risk is the probability that an identity is compromised

2. Sign-in risk is the probability that a sign-in is compromised

3. To configure identity protection, you need conditional access administrator role and an Azure AD premium p2 license

4. Custom banned password lists require an Azure AD premium P1 license

5. Each AD DS domain controller requires 2 agents for complete protection


### Deploying Single Sign-on (SSO)

1. Hybrid Identity

2. Hybrid Identity Authentication Methods

3. Exploring Password Writeback

4. Azure AD connect cloud sync requirements

AD DS (on-prem has domain controller) can sync with AAD using AD connect

Sync Methods -

1. Azure AD connect sync - Legacy

2. Azure AD connect cloud sync

Authentication Methods

- Password hash synchronization
Good user experience, business continuity and supports identity protection. only issue is it does not sync back with AD DS and hence AD DS account restrictions are not applied

- pass-through authentication
Good user experience, AD DS account restrictions are applied. No support for Azure AD connect cloud sync

- Federation - All aithentication occurs on-premises, can be complex and difficult to maintain, requires password hash synchronization for business continuity

Password Writeback -

Once we deploy Azure AD connect in our env, we get another functionality to writeback passwords to AD DS from Azure AD. This needs Azure AD premium p1 license.

Password writeback provides several key features -

1. Ability for users to reset passwords from Azure portal and then write back these to AD DS

2. Ability for users to update their own passwords (self-service password reset sspr)

3. Password writeback also helps to meet ADDS password policy compliance when pwd is updated in AAD

4. SSPR using password writeback allows users to remediate user-risk and password risk issues even when connected to corporate AD DS network without any intervention from the IT team

Requirements for Azure AD connect cloud sync

Azure AD domain requirements

- Atleast one custom domain added

Azure AD user requirements

- cloud-only global admin or hybrid identity admin

AD DS User requirements

- AD DS domain administrator

Server requirements

- Atleast Windows Server 2016
- 4 GB RAM
- .NET 4.7.1 or later

Azure AD connect cloud sync uses provisioning agents deployed to AD DS member servers to synchronize identities to Azure AD. Atleast 2 agents are needed for HA (High Availability)

### Going Passwordless

1. Passwordless Authentication - best way

2. Authentication options

windows hello for business - uses pin
MS Authenticator
FIDO2-compliant security keys where mobiles are not available

3. Azure AD passwordless requirements

Azure AD role assignment - To configure registration and authentication methods we need

Authentication policy admin

Use passwordless wizard to determine additional requirements

https://aka.ma/passwordlesswizard


Summary 

- Passwordless authentication is easier to use and more secure than authentication that involves passwords

- Use Windows hello for business where users use a dedicated windows device everyday

- MS authenticator where user uses a non-windows device

- Use FIDO2-complint security keyswhere use of phones is restricted , such as call center or for high privilege
identities

### Decentralizing Identity

Next gen of identity - decentralized identity and how users can take their identity with themselves

Identities - user - facebook, github etc. we do not know how these identities are stored.

Decentralized concept takes identity of user from identity providers to users where they cantake it and store it themselves without depending on identity providers.

3 components -

1. Issuer -who issues the identity, User has digital wallet to verify.

Ex- MS entra can issue Decentralized identities

What do we need for this? AAD tenant -> Azure Sub -> KV, storage, webapp, dns. users can have MS Authenticator

Role - Global admin or Auth policy admin and App admin
Contributor access to manage app

## Managing Authorization

Access Management

Users -> AAD Tenant, Azure Subscription [Default permissions, No permissions]

Role Definition (defines which actions can be performed and where the actions can be performed (Scope)) - Helpdesk -> Add user, update user and Add groups

Access management hierarchy

Azure management hierarchy

AAD -> Apps, users, Groups 

Azure Subscription - owner, contributor

Management Group are used to group subscriptions together. There is a root management group under which more MGs can be created

AAD (AAD roles) -> /Root -> Root MG -> MG -> Azure Sub (Azure Roles) -> Resource Group -> Azure Resources

Administrative units

AAD resource used for managing other AAD resource

Azure Active Directory Premium P1 license is required for each administrative unit administrator

Administrative units cannot be nested

Only direct administrative group members can be managed

AU does not effect on default user permissions, user will have default permissions regardless of any admirole assignments to administrative units

Managing Azure AD Permission scopes


### Summary 

- A global admin must elevate access to manage the root management group

- Azure AD roles can be scoped to the tenant, an application reg, or an administrative unit

- Azure RBAC roles can be scoped to a management group, subscription, rg, or indivisudl resource

- An azure AD premium P1 license is needed for each administrative unit administrator

- Administrative units cannot be nested

## Using built-in Roles

Using built-in roles across Azure AD and Azure

- Differentiate Azure AD roles

- Azure Role types

- Differentiating Azure Roles

- Assigning roles using groups

Job function or service -> Access level

Access Level - Admin, Developer or operator, Reader

Admin - Most privileged

Reader - Least privileged

Azure Role Types -

1. Privileged Administrator Roles

Should be used sparingly, can manage access for other users, grant privileged access

2. Job function Roles

allow the management of specific azure resources

should be used whenever possible

3. Custom Roles

Enable granular permission assignment

can be used to effectively apply the principle of least privilege

4. Classic Subscription Admin Roles - Legacy

Account admin, service admin, co-admin


Control plane permissions - Manage Azure Resources

Follows the following convention

Resource -> Access Level

owner, contributor,operator, developer, reader

Ex- VM - contributor
storage - contributor

Least privilege needs to be followed

Data plane permissions - Manage data stored within Azure Resources

Convention

Resource -> Sub-resource(optional) -> Data -> Access Level

ex - Storage Blob Data Contributor

owner, Elevated/Privileged, contributor,reader mostly used

## Assigning roles using groups

Azure AD - 

Use role- assignable groups

Must be configured as role-assignable upon creation

Requires Premium P1

Requires at least the least privileged role admin role

Membership must be assigned

Both M365 and security group types can be used

Group nesting is not supported


Azure  - Using Rbac roles

Create group in azure ad

Assign the role to the group at desired scope in Azure management hierarchy

membership can be assigned or dynamic

Both M365 and security group types can be used

To assign Azure roles, you need at least the user access admin role

Azure roles can be assigned at either the control plane or the data plane










