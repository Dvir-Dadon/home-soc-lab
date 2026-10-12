<#
.SYNOPSIS
    Builds the Active Directory part of the Home SOC Lab on DC01.

.DESCRIPTION
    Configures DC01 (Windows Server 2025) as the Domain Controller of the
    lab domain "soclab.local" and creates a small, realistic OU structure
    with three standard (non-admin) users.

    The script runs in three stages, because promoting a server to a
    Domain Controller forces a reboot in the middle of the process:

        Stage 1 - Network   : static IP on the isolated lab network
        Stage 2 - Promote   : install AD DS and create the new forest (reboots)
        Stage 3 - Structure : create OUs and lab users (after the reboot)

    Lab network (VMware VMnet10, host-only, no internet):
        DC01      192.168.50.10
        WAZUH01   192.168.50.20
        CLIENT01  192.168.50.30

.EXAMPLE
    .\setup-ad.ps1 -Stage Network
    .\setup-ad.ps1 -Stage Promote
    # ...server reboots, sign in as SOCLAB\Administrator...
    .\setup-ad.ps1 -Stage Structure

.NOTES
    - Run in PowerShell as Administrator, on DC01 only.
    - No passwords are stored in this file. They are requested at runtime
      as SecureString, so they never appear on screen or in the repo.
    - Lab use only. In production, use a subdomain of a domain you own
      (e.g. ad.company.com) instead of a ".local" domain name.
#>

param(
    # Which stage to run. ValidateSet rejects any other value,
    # so a typo fails immediately instead of silently doing nothing.
    [Parameter(Mandatory = $true)]
    [ValidateSet("Network", "Promote", "Structure")]
    [string]$Stage
)

# ---------------------------------------------------------------------------
# Lab settings - change these in one place if the lab design changes
# ---------------------------------------------------------------------------
$InterfaceName = "Ethernet0"          # Check with: Get-NetAdapter
$DcIp          = "192.168.50.10"
$PrefixLength  = 24                   # 24 = subnet mask 255.255.255.0
$DomainName    = "soclab.local"
$NetbiosName   = "SOCLAB"
$DomainDN      = "DC=soclab,DC=local" # Distinguished Name of the domain root
$LabUsers      = @("dana.levi", "yossi.cohen", "avi.mizrahi")

# Stop on the first error instead of continuing with a half-built setup.
$ErrorActionPreference = "Stop"

switch ($Stage) {

    # -----------------------------------------------------------------------
    # STAGE 1: Static IP on the isolated lab network
    # -----------------------------------------------------------------------
    "Network" {
        # A Domain Controller must have a fixed IP, because every domain
        # member finds the domain through the DNS server running on it.

        # Remove any existing IPv4 address (DHCP or APIPA 169.254.x.x)
        # so the new static address doesn't conflict with it.
        Set-NetIPInterface -InterfaceAlias $InterfaceName -Dhcp Disabled
        Get-NetIPAddress -InterfaceAlias $InterfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Remove-NetIPAddress -Confirm:$false

        # No -DefaultGateway on purpose: the lab network is isolated and
        # has no route to the internet.
        New-NetIPAddress -InterfaceAlias $InterfaceName -IPAddress $DcIp -PrefixLength $PrefixLength

        # The DC is its own DNS server. 127.0.0.1 = "ask myself".
        Set-DnsClientServerAddress -InterfaceAlias $InterfaceName -ServerAddresses "127.0.0.1"

        Write-Host "Network configured. Verify with: ipconfig /all" -ForegroundColor Green
    }

    # -----------------------------------------------------------------------
    # STAGE 2: Install AD DS and create a new forest
    # -----------------------------------------------------------------------
    "Promote" {
        # Installs the Active Directory Domain Services role, plus the
        # management tools (ADUC, GPMC, AD PowerShell module).
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

        # Creates a brand-new forest with one domain, and installs DNS on
        # this server. You will be prompted for the DSRM password
        # (Directory Services Restore Mode) - a separate recovery password
        # used only if Active Directory itself needs to be repaired.
        # The server restarts automatically when this finishes.
        Install-ADDSForest `
            -DomainName $DomainName `
            -DomainNetbiosName $NetbiosName `
            -InstallDns
    }

    # -----------------------------------------------------------------------
    # STAGE 3: OU structure and lab users (run after the reboot)
    # -----------------------------------------------------------------------
    "Structure" {
        # Structure:
        #   soclab.local
        #    └── TLV                (branch office)
        #         ├── Users         (standard lab users)
        #         └── Workstations  (CLIENT01, after it joins the domain)
        #
        # Why custom OUs: Group Policy can only be linked to OUs, not to
        # the default "Users" / "Computers" containers. The audit policy
        # GPO for the workstation will be linked to OU=Workstations.

        $TlvOU = "OU=TLV,$DomainDN"

        New-ADOrganizationalUnit -Name "TLV"          -Path $DomainDN
        New-ADOrganizationalUnit -Name "Users"        -Path $TlvOU
        New-ADOrganizationalUnit -Name "Workstations" -Path $TlvOU

        # Ask for the users' initial password without showing it on screen.
        # SecureString keeps it encrypted in memory and out of the history.
        $Password = Read-Host "Initial password for lab users" -AsSecureString

        # Create each user. $_ is the current name in the loop.
        # The users are standard accounts: NOT added to any admin group.
        # Adding a user to Domain Admins is one of the security events we
        # will generate later and detect in Wazuh.
        $LabUsers | ForEach-Object {
            New-ADUser `
                -Name $_ `
                -SamAccountName $_ `
                -UserPrincipalName "$_@$DomainName" `
                -Path "OU=Users,$TlvOU" `
                -AccountPassword $Password `
                -Enabled $true
        }

        # Show the result for verification / screenshot.
        Get-ADUser -Filter * -SearchBase "OU=Users,$TlvOU" |
            Select-Object Name, UserPrincipalName, Enabled
    }
}
