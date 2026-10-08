<#
.SYNOPSIS
    Invoke-NetLogicSignal - modular, read-only Windows endpoint audit tool (NetLogic).

.DESCRIPTION
    Audits a Windows endpoint driven by PROFILES (what the technician wants to learn) and MODULES, and writes one JSON
    per endpoint: snake_case keys nested by module + meta + structured findings + per-module errors.

    *** READ-ONLY: nothing is installed or changed. The only writes are %TEMP% files deleted on the spot
        (secedit .inf, powercfg battery .xml, msinfo32 report, and the csc.exe temp files .NET uses to compile the
        small console-mode helper) and the output JSON. ***

    Contract (schema_version 9) follows the Xerix "libro sagrado" LAW - see CONVENTIONS.md: English US snake_case keys,
    is_/has_ booleans, _at = ISO 8601 timestamp with offset, _date = ISO date, kind/status (never type/state).
    Findings = { code, severity, category, message (client language), compliance_refs.oea }. Compliance frameworks
    (e.g. OEA) are a LENS of the report generator, not a capture profile: they need a Full capture.

.PARAMETER Profile
    Full (default) | Hardware | Inventory | Performance | Security.  'core' always runs.
    Legacy aliases: Base, OEA -> Full (recorded in meta.requested_profile).

.PARAMETER Module
    Fine-grained override of the module list (e.g. -Module core,security,hardening). Ignores -Profile.

.PARAMETER AssignedUser
    Person who uses this PC (goes into identity.assigned_user and the file name).

.PARAMETER Organization
    Audited company (identity.organization).

.PARAMETER OutputPath
    Folder for the JSON output. Defaults to the script folder.

.PARAMETER MeasureUserProfiles
    Measure the size of each C:\Users profile (slower). Used by the backup module.

.PARAMETER Consolidate
    Merge every audit JSON in -Path into a single CSV (tolerates JSON from older tool versions).

.PARAMETER Path
    Input folder for -Consolidate.

.EXAMPLE
    .\Invoke-NetLogicSignal.ps1                      # interactive menu
.EXAMPLE
    .\Invoke-NetLogicSignal.ps1 -Profile Full -AssignedUser "Juan Perez" -Organization "Acme"
.EXAMPLE
    .\Invoke-NetLogicSignal.ps1 -Profile Performance -AssignedUser "Juan Perez" -Organization "Acme"
.EXAMPLE
    .\Invoke-NetLogicSignal.ps1 -Consolidate -Path "C:\audits\Acme"
.EXAMPLE
    # Scheduled Task ("Run whether user is logged on or not", highest privileges): never blocks on input.
    .\Invoke-NetLogicSignal.ps1 -Profile Full -Organization "Acme" -Silent -OutputPath "C:\_NetLogic\audit"
.EXAMPLE
    # What changed on this PC between two audits (fleet monitoring: recurring capture + drift report).
    .\Invoke-NetLogicSignal.ps1 -Compare -Baseline "C:\audits\2026-08.json" -Current "C:\audits\2026-09.json"

.NOTES
    Unattended use (scheduled monthly/bimonthly/quarterly audits): pass -Silent. Without it, the engine still
    prompts for AssignedUser and waits for ENTER at the end even when called with flags — fine for a technician
    at the keyboard, fatal for a Scheduled Task with no console attached (it would hang forever).
    -Compare needs no "authorized software list": new/removed software IS the signal (diff against the PC's own
    prior state), not a list someone has to maintain. Works across tool versions (older JSON with plain-string
    findings instead of {code,severity,...} -> findings section marked "not comparable", everything else still
    diffs normally).
#>
[CmdletBinding()]
param(
    [ValidateSet('Full', 'Hardware', 'Inventory', 'Performance', 'Security', 'Base', 'OEA')]   # Base/OEA = legacy aliases of Full
    [string]$Profile = 'Full',
    [string[]]$Module,
    [string]$AssignedUser = '',
    [string]$Organization = '',
    [string]$OutputPath = '',
    [switch]$MeasureUserProfiles,
    [switch]$Consolidate,
    [string]$Path = '',
    [switch]$Silent,   # unattended (Scheduled Task): never Read-Host, never show the interactive menu
    [switch]$Compare,          # -Compare -Baseline <old.json> -Current <new.json>: what changed between two audits
    [string]$Baseline = '',
    [string]$Current = '',
    [switch]$IncludeMsinfo     # also run msinfo32 in -Silent runs (it shows a progress window on the user's screen)
)

$ErrorActionPreference = 'Continue'

# ============================ TOOL METADATA / STATE ================================
$script:ToolVersion   = '3.4.0'
$script:SchemaVersion = 9
$script:Findings = New-Object System.Collections.ArrayList
$script:Errors   = New-Object System.Collections.ArrayList
$script:AssignedUser = "$AssignedUser".Trim()
$script:Organization = "$Organization".Trim()
$script:MeasureUserProfiles = [bool]$MeasureUserProfiles
$script:RamMounting = $null; $script:RamEmptyPositions = 0; $script:RamMountingConfirmed = $false; $script:RamGb = $null; $script:RamTableConsistent = $null   # set by core, read by performance
# Interactive menu unless a "direct mode" flag was passed. -OutputPath/-Organization alone still show the menu
# (the portable .bat passes -OutputPath and must still land on the menu).
$script:Interactive = -not ($Silent -or $Compare -or $PSBoundParameters.ContainsKey('Profile') -or $PSBoundParameters.ContainsKey('Module') -or $PSBoundParameters.ContainsKey('Consolidate') -or $PSBoundParameters.ContainsKey('AssignedUser'))

# SMBIOS Type 17 "Memory Type" byte -> generation (DSP0134 3.9.0 Table 77; Win32_PhysicalMemory.SMBIOSMemoryType carries
# the same byte). NOT the CIM MemoryType enum (20=DDR there): mixing both tables mislabeled LPDDR4 as 'LPDDR2' before 3.3.3.
$script:DdrMap = @{ 0='unknown'; 1='other'; 2='unknown'; 3='DRAM'; 15='SDRAM'; 18='DDR'; 19='DDR2'; 20='DDR2 FB-DIMM'; 24='DDR3'; 25='FBD2'; 26='DDR4'; 27='LPDDR'; 28='LPDDR2'; 29='LPDDR3'; 30='LPDDR4'; 34='DDR5'; 35='LPDDR5'; 37='MRDIMM' }
# SMBIOS Type 17 "Form Factor" byte -> enum (DSP0134 3.9.0 Table 76). Read from the RAW table: Win32_PhysicalMemory.FormFactor
# uses another (CIM) enum with no 'row of chips', and soldered LPDDR5 shows there as 'Other' with locator 'DIMM 0' (measured).
$script:MemoryFormFactorMap = @{ 1='other'; 2='unknown'; 3='simm'; 4='sip'; 5='chip'; 6='dip'; 7='zip'; 8='proprietary_card'; 9='dimm'; 10='tsop'; 11='row_of_chips'; 12='rimm'; 13='sodimm'; 14='srimm'; 15='fb_dimm'; 16='die'; 17='camm'; 18='cudimm'; 19='csodimm' }
$script:SocketedFormFactors = @(3, 9, 12, 13, 14, 15, 17, 18, 19)   # a module in a socket: SIMM/DIMM/RIMM/SODIMM/SRIMM/FB-DIMM/CAMM/CUDIMM/CSODIMM
$script:SolderedFormFactors = @(5, 11, 16)                           # chip / row of chips / die: on the board
$script:LpddrMemoryTypes    = @(27, 28, 29, 30, 35)                  # LPDDR* is board-mounted; its only socketed form (CAMM) reports form factor 17
# SMBIOS Type 4 "Processor Upgrade" byte -> spec name (DSP0134 3.9.0 Table 25). Raw standard names (technical values).
$script:CpuUpgradeMap = @{ 1 = 'Other'; 2 = 'Unknown'; 3 = 'Daughter Board'; 4 = 'ZIF Socket'; 5 = 'Replaceable Piggy Back'; 6 = 'None'; 7 = 'LIF Socket'
    8 = 'Slot 1'; 9 = 'Slot 2'; 10 = '370-pin socket'; 11 = 'Slot A'; 12 = 'Slot M'; 13 = 'Socket 423'; 14 = 'Socket A (Socket 462)'; 15 = 'Socket 478'
    16 = 'Socket 754'; 17 = 'Socket 940'; 18 = 'Socket 939'; 19 = 'Socket mPGA604'; 20 = 'Socket LGA771'; 21 = 'Socket LGA775'; 22 = 'Socket S1'
    23 = 'Socket AM2'; 24 = 'Socket F (1207)'; 25 = 'Socket LGA1366'; 26 = 'Socket G34'; 27 = 'Socket AM3'; 28 = 'Socket C32'; 29 = 'Socket LGA1156'
    30 = 'Socket LGA1567'; 31 = 'Socket PGA988A'; 32 = 'Socket BGA1288'; 33 = 'Socket rPGA988B'; 34 = 'Socket BGA1023'; 35 = 'Socket BGA1224'
    36 = 'Socket LGA1155'; 37 = 'Socket LGA1356'; 38 = 'Socket LGA2011'; 39 = 'Socket FS1'; 40 = 'Socket FS2'; 41 = 'Socket FM1'; 42 = 'Socket FM2'
    43 = 'Socket LGA2011-3'; 44 = 'Socket LGA1356-3'; 45 = 'Socket LGA1150'; 46 = 'Socket BGA1168'; 47 = 'Socket BGA1234'; 48 = 'Socket BGA1364'
    49 = 'Socket AM4'; 50 = 'Socket LGA1151'; 51 = 'Socket BGA1356'; 52 = 'Socket BGA1440'; 53 = 'Socket BGA1515'; 54 = 'Socket LGA3647-1'
    55 = 'Socket SP3'; 56 = 'Socket SP3r2'; 57 = 'Socket LGA2066'; 58 = 'Socket BGA1392'; 59 = 'Socket BGA1510'; 60 = 'Socket BGA1528'
    61 = 'Socket LGA4189'; 62 = 'Socket LGA1200'; 63 = 'Socket LGA4677'; 64 = 'Socket LGA1700'; 65 = 'Socket BGA1744'; 66 = 'Socket BGA1781'
    67 = 'Socket BGA1211'; 68 = 'Socket BGA2422'; 69 = 'Socket LGA1211'; 70 = 'Socket LGA2422'; 71 = 'Socket LGA5773'; 72 = 'Socket BGA5773'
    73 = 'Socket AM5'; 74 = 'Socket SP5'; 75 = 'Socket SP6'; 76 = 'Socket BGA883'; 77 = 'Socket BGA1190'; 78 = 'Socket BGA4129'; 79 = 'Socket LGA4710'
    80 = 'Socket LGA7529'; 81 = 'Socket BGA1964'; 82 = 'Socket BGA1792'; 83 = 'Socket BGA2049'; 84 = 'Socket BGA2551'; 85 = 'Socket LGA1851'
    86 = 'Socket BGA2114'; 87 = 'Socket BGA2833' }

# Windows LicenseStatus code -> canonical English enum (regla 16: enum values in English).
$script:LicenseStatusMap = @{ 0='unlicensed'; 1='activated'; 2='oob_grace'; 3='oot_grace'; 4='non_genuine_grace'; 5='notification'; 6='extended_grace' }

# END OF SUPPORT (offline table). Source: learn.microsoft.com/lifecycle (verified 2026-09-27). Value = LAST supported day
# (Microsoft lists the retirement as next-day 06:59:59 PT). Update this table when Microsoft publishes new releases.
#   Windows: keyed by OS build number -> release + last day, per edition family (home_pro | enterprise).
$script:WindowsEol = @{
    '19045' = @{ release = '22H2 (Windows 10)'; home_pro = '2025-10-14'; enterprise = '2025-10-14' }
    '22000' = @{ release = '21H2'; home_pro = '2023-10-10'; enterprise = '2024-10-08' }
    '22621' = @{ release = '22H2'; home_pro = '2024-10-08'; enterprise = '2025-10-14' }
    '22631' = @{ release = '23H2'; home_pro = '2025-11-11'; enterprise = '2026-11-10' }
    '26100' = @{ release = '24H2'; home_pro = '2026-10-13'; enterprise = '2027-10-12' }
    '26200' = @{ release = '25H2'; home_pro = '2027-10-12'; enterprise = '2028-10-10' }
    '28000' = @{ release = '26H1'; home_pro = '2028-03-14'; enterprise = '2029-03-13' }   # new devices only (not an in-place update)
    '26300' = @{ release = '26H2'; home_pro = '2028-10-10'; enterprise = '2029-10-09' }
}
# Windows LTSC/LTSB: fixed lifecycle per build, last supported day (learn.microsoft.com lifecycle pages + Windows 11
# release information, checked 2026-10-01). 'enterprise' = Enterprise LTSC/LTSB, 'iot' = IoT Enterprise LTSC.
$script:WindowsLtscEol = @{
    '10240' = @{ release = 'LTSB 2015'; enterprise = '2025-10-14'; iot = '2025-10-14' }
    '14393' = @{ release = 'LTSB 2016'; enterprise = '2026-10-13'; iot = '2026-10-13' }
    '17763' = @{ release = 'LTSC 2019'; enterprise = '2029-01-09'; iot = '2029-01-09' }
    '19044' = @{ release = 'LTSC 2021'; enterprise = '2027-01-12'; iot = '2032-01-13' }
    '26100' = @{ release = 'LTSC 2024'; enterprise = '2029-10-09'; iot = '2034-10-10' }
}
# Windows 10 22H2 Extended Security Updates (checked 2026-10-01):
# - commercial license: activation ID per year (learn.microsoft.com/windows/whats-new/enable-extended-security-updates) and
#   coverage end per year (learn.microsoft.com/lifecycle/faq/extended-security-updates): 2026-10-13 / 2027-10-12 / 2028-10-10.
# - consumer ESU (Microsoft account, no readable license) ends 2027-10-12 (microsoft.com consumer ESU + end-of-support pages).
# - ESU-only cumulative updates start at build 19045.6575 (KB5068781, 2025-11-11). A non-enrolled 22H2 PC tops out at
#   19045.6456 (KB5066791) / 19045.6466 (KB5071959 out-of-band) -> the build revision (UBR) is the evidence of ESU patching.
#   NOT the install date of 'any' update: KB5072653 (ESU licensing preparation, classified Security Update) installs on
#   every 22H2 PC after 2025-10-14, enrolled or not.
$script:Win10EsuActivationIds = @{ 'f520e45e-7413-4a34-a497-d2765967d094' = 1; '1043add5-23b1-4afb-9a0f-64343c8f3f8d' = 2; '83d49986-add3-41d7-ba33-87c7bfb5c0fb' = 3 }
$script:Win10EsuYearEnd = @{ 1 = '2026-10-13'; 2 = '2027-10-12'; 3 = '2028-10-10' }
$script:Win10ConsumerEsuEnd = '2027-10-12'
$script:Win10FirstEsuUbr = 6575
#   Office (perpetual/LTSC): keyed by version year. Microsoft 365 Apps (subscription) has no fixed end date.
$script:OfficeEol = @{ 2010 = '2020-10-12'; 2013 = '2023-04-10'; 2016 = '2025-10-14'; 2019 = '2025-10-14'; 2021 = '2026-10-13'; 2024 = '2029-10-09' }
# Office internal major version (LicenseFamily 'OfficeNN...' / Name 'Office NN') -> marketing year.
$script:OfficeYearMap = @{ 14 = 2010; 15 = 2013; 16 = 2016; 19 = 2019; 21 = 2021; 24 = 2024 }
#   Other software: installed-program name pattern -> product + last supported day. Only the product/engine entry is matched
#   (not leftovers like 'SQL Server 2008 Setup Support Files').
$script:SoftwareEol = @(
    @{ product = 'SQL Server 2008/2008 R2'; end = '2019-07-09'; match = '^(Microsoft SQL Server 2008( R2)? \((32|64)-bit\)|SQL Server 2008( R2)? Database Engine Services)' }
    @{ product = 'SQL Server 2012'; end = '2022-07-12'; match = '^(Microsoft SQL Server 2012 \((32|64)-bit\)|SQL Server 2012 Database Engine Services)' }
    @{ product = 'SQL Server 2014'; end = '2024-07-09'; match = '^(Microsoft SQL Server 2014 \((32|64)-bit\)|SQL Server 2014 Database Engine Services)' }
    @{ product = 'SQL Server 2016'; end = '2026-07-14'; match = '^(Microsoft SQL Server 2016 \((32|64)-bit\)|SQL Server 2016 Database Engine Services)' }
    @{ product = 'SQL Server 2017'; end = '2027-10-12'; match = '^(Microsoft SQL Server 2017 \((32|64)-bit\)|SQL Server 2017 Database Engine Services)' }
)
$script:OfficeAppId = '0ff1ce15-a989-479d-af46-f275c6370663'   # Office ApplicationID in SPP/OSPP
$script:EolWarningDays = 120   # warn when end of support is closer than this

# Curated lists for the backup module (real backup tools vs mere cloud sync).
$script:BackupTools = 'veeam|acronis|cobian|macrium|aomei|easeus todo|iperius|duplicati|uranium|backup exec|veritas|carbonite|datto|nakivo|arcserve|paragon backup|genie|handy backup|syncback|goodsync|windows server backup|copia de seguridad'
$script:CloudTools  = 'onedrive|google drive|backup and sync|dropbox|megasync|\bmega\b|pcloud|icloud|nextcloud|tresorit'

# ============================ HELPERS ==============================================
# A finding = structured, language-neutral contract + client-facing text (LAW i18n rule):
#   code     : stable English snake_case id (what the report/consolidate key on)
#   severity : high | medium | low | info
#   category : module that raised it (set automatically from the running module)
#   message  : text in the CLIENT's language (Spanish today) - no framework/client references inside
#   compliance_refs.oea : OEA Manual 9 items (RG AFIP 5107/2021) - used ONLY by the report's OEA lens
$script:SeverityRank = @{ high = 0; medium = 1; low = 2; info = 3 }
function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][ValidateSet('high', 'medium', 'low', 'info')][string]$Severity,
        [string[]]$Oea = @(),
        [Parameter(Mandatory)][string]$Message,
        [string]$EvidenceAt = $null   # event-based findings: timestamp of the newest event behind THIS finding (-Compare uses it)
    )
    [void]$script:Findings.Add([ordered]@{
        code            = $Code
        severity        = $Severity
        category        = if ($script:CurrentModule) { $script:CurrentModule } else { 'audit' }
        message         = $Message
        compliance_refs = [ordered]@{ oea = @($Oea) }
        evidence_at     = if ($EvidenceAt) { $EvidenceAt } else { $null }
    })
}

function Write-Section($text) {
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkCyan
}
function Write-Field($label, $value, $color = 'Gray') {
    if ($null -eq $value -or "$value" -eq '') { $value = 'N/D' }
    Write-Host ("  {0,-22}: {1}" -f $label, $value) -ForegroundColor $color
}

# CIM with error handling + per-run cache (modules can query the same class without re-hitting WMI).
# Returns $null if the class/namespace is missing (e.g. Server).
$script:CimCache = @{}
$script:CimTimeoutSec = 30   # per WMI query
function Get-CimSafe {
    param([string]$Class, [string]$Namespace = 'root\cimv2', [string]$Filter = '')
    $cacheKey = "$Namespace|$Class|$Filter"
    if ($script:CimCache.ContainsKey($cacheKey)) { return $script:CimCache[$cacheKey] }
    $result = $null
    try {
        # -OperationTimeoutSec: a WMI provider that hangs (offline network printer, broken driver) must not freeze the audit.
        if ($Filter) { $result = Get-CimInstance -ClassName $Class -Namespace $Namespace -Filter $Filter -OperationTimeoutSec $script:CimTimeoutSec -ErrorAction Stop }
        else         { $result = Get-CimInstance -ClassName $Class -Namespace $Namespace -OperationTimeoutSec $script:CimTimeoutSec -ErrorAction Stop }
    } catch { $result = $null }
    $script:CimCache[$cacheKey] = $result
    return $result
}

# Get-HotFix cached once (oea patching + system hotfix list) - it takes ~1.5 s.
function Get-HotFixCached {
    if ($null -ne $script:HotFixCache) { return ,$script:HotFixCache }
    $hf = @(); try { $hf = @(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending) } catch { $hf = @() }
    $script:HotFixCache = $hf
    return ,$hf
}

# net accounts (password/lockout policy) cached once - used by the accounts and oea modules.
function Get-NetAccountsRaw {
    if ($null -ne $script:NetAccountsRaw) { return $script:NetAccountsRaw }
    $raw = @()
    try { $raw = @(net accounts 2>$null) } catch { }
    $script:NetAccountsRaw = $raw
    return $raw
}

# Decodes the SecurityCenter2 productState bitmask (6 hex digits: PP RR DD).
#   RR '10'/'11' = enabled ; DD '00' = signatures up to date. Community heuristic, not an official contract.
function Get-AvState {
    param([long]$State)
    $hex = '{0:x6}' -f $State
    return [pscustomobject]@{
        Enabled    = ($hex.Substring(2, 2) -in @('10', '11'))
        UpToDate   = ($hex.Substring(4, 2) -eq '00')
        RawHex     = $hex
    }
}

# Installed software inventory (registry Uninstall keys), read once - used by the software and backup modules.
function Get-SoftwareInventory {
    if ($null -ne $script:SoftwareInventory) { return $script:SoftwareInventory }
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    # per-user installs of the AUDITED user (not the elevating account)
    $userUninstall = Get-UserRegPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    if ($userUninstall) { $paths += $userUninstall }
    $items = @()
    foreach ($p in $paths) {
        try {
            Get-ItemProperty $p -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.DisplayName) {
                    # InstallDate in the Uninstall key is usually 'yyyyMMdd' -> ISO date (LAW R13); anything else -> best effort / null
                    $idate = "$($_.InstallDate)"
                    $isoInstall = if ($idate -match '^\d{8}$') { try { [datetime]::ParseExact($idate, 'yyyyMMdd', [Globalization.CultureInfo]::InvariantCulture).ToString('yyyy-MM-dd') } catch { $null } } else { ConvertTo-IsoDate $idate }
                    $items += [pscustomobject]@{ name = $_.DisplayName; version = $_.DisplayVersion; publisher = $_.Publisher; install_date = $isoInstall }
                }
            }
        } catch { }
    }
    $script:SoftwareInventory = @($items | Sort-Object name -Unique)
    return $script:SoftwareInventory
}

# ISO 8601 normalizers (LAW R12 `_at` = timestamp with offset, R13 `_date` = date). Accept [datetime] or a string the
# current culture can parse; return $null when empty/unparseable (never the locale-formatted text).
function ConvertTo-IsoTimestamp($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-ddTHH:mm:sszzz') }
    # "$date" interpolation in PowerShell yields INVARIANT text (MM/dd/yyyy) while the OS may be es-AR (dd/MM/yyyy):
    # try invariant first, then the current culture. Unparseable -> $null (never guess).
    foreach ($ci in @([Globalization.CultureInfo]::InvariantCulture, [Globalization.CultureInfo]::CurrentCulture)) {
        $dt = [datetime]::MinValue
        if ([datetime]::TryParse("$Value", $ci, [Globalization.DateTimeStyles]::None, [ref]$dt)) { return $dt.ToString('yyyy-MM-ddTHH:mm:sszzz') }
    }
    return $null
}
function ConvertTo-IsoDate($Value) {
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd') }
    # "$date" interpolation in PowerShell yields INVARIANT text (MM/dd/yyyy) while the OS may be es-AR (dd/MM/yyyy):
    # try invariant first, then the current culture. Unparseable -> $null (never guess).
    foreach ($ci in @([Globalization.CultureInfo]::InvariantCulture, [Globalization.CultureInfo]::CurrentCulture)) {
        $dt = [datetime]::MinValue
        if ([datetime]::TryParse("$Value", $ci, [Globalization.DateTimeStyles]::None, [ref]$dt)) { return $dt.ToString('yyyy-MM-dd') }
    }
    return $null
}

# Registry value or $null (never throws). Named Get-RegValue on purpose: short names like 'rv' collide with aliases.
function Get-RegValue([string]$Key, [string]$Name) {
    try { return (Get-ItemProperty -Path $Key -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

# Days from today to an ISO date (negative = already past). $null if the date is empty/invalid.
function Get-DaysUntil([string]$IsoDate) {
    if (-not $IsoDate) { return $null }
    try { return [int][math]::Floor(([datetime]::ParseExact($IsoDate, 'yyyy-MM-dd', $null) - (Get-Date).Date).TotalDays) } catch { return $null }
}

# A click inside a classic console window turns on 'Select' mode, which FREEZES the script at its next console write (seen
# 2026-09-29 on a client PC: ~10 min stuck until Esc). Turn QuickEdit off for the run and restore it at the end.
# No console (Scheduled Task) or any failure -> silently skipped.
function Disable-ConsoleQuickEdit {
    try {
        if (-not ('NetLogicSignal.ConsoleMode' -as [type])) {
            Add-Type -Namespace 'NetLogicSignal' -Name 'ConsoleMode' -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetStdHandle(int nStdHandle);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
'@
        }
        $h = [NetLogicSignal.ConsoleMode]::GetStdHandle(-10)   # STD_INPUT_HANDLE
        $mode = [uint32]0
        if ([NetLogicSignal.ConsoleMode]::GetConsoleMode($h, [ref]$mode)) {
            $script:OriginalConsoleMode = $mode
            $new = [uint32]($mode -bor 0x80)                      # ENABLE_EXTENDED_FLAGS (needed for the change to stick)
            if ($new -band 0x40) { $new = [uint32]($new - 0x40) } # ENABLE_QUICK_EDIT_MODE off
            [void][NetLogicSignal.ConsoleMode]::SetConsoleMode($h, $new)
        }
    } catch { }
}
function Restore-ConsoleMode {
    try {
        if ($null -ne $script:OriginalConsoleMode -and ('NetLogicSignal.ConsoleMode' -as [type])) {
            [void][NetLogicSignal.ConsoleMode]::SetConsoleMode([NetLogicSignal.ConsoleMode]::GetStdHandle(-10), [uint32]$script:OriginalConsoleMode)
        }
    } catch { }
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# AUDITED USER vs RUNNER. The audit targets the person who uses the PC (the interactive user), NOT the account
# that elevated it: a standard user + technician typing admin credentials in UAC makes HKCU/$env:USERPROFILE
# point to the TECHNICIAN. So per-user data is read from HKU\<SID of the interactive user>.
#   source 'console'  = Win32_ComputerSystem.UserName (local console session)
#   source 'explorer' = owner of an explorer.exe (covers RDP sessions, where UserName is empty)
#   source 'runner'   = nobody else logged on -> the account running the script
# If the user's hive is not loaded (not logged on), per-user reads return $null - never the runner's HKCU.
function Resolve-AuditedUser {
    if ($null -ne $script:AuditedUser) { return $script:AuditedUser }
    $runnerId  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $runnerSid = $runnerId.User.Value
    $name = $null; $source = $null
    $cs = Get-CimSafe 'Win32_ComputerSystem'
    if ($cs -and $cs.UserName) { $name = "$($cs.UserName)"; $source = 'console' }
    if (-not $name) {
        try {
            $owners = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | ForEach-Object {
                $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
                if ($o -and $o.User) { if ($o.Domain) { "$($o.Domain)\$($o.User)" } else { "$($o.User)" } }
            } | Select-Object -Unique)
            if ($owners.Count -gt 0) { $name = $owners[0]; $source = 'explorer' }
        } catch { }
    }
    $sid = $null
    if ($name) { try { $sid = ([Security.Principal.NTAccount]$name).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid = $null } }
    if (-not $sid) { $name = $runnerId.Name; $sid = $runnerSid; $source = 'runner' }

    $isRunner = ($sid -eq $runnerSid)
    $hiveRoot = $null
    if ($isRunner) { $hiveRoot = 'HKCU:' }
    elseif (Test-Path "Registry::HKEY_USERS\$sid") { $hiveRoot = "Registry::HKEY_USERS\$sid" }

    $profilePath = $null
    $up = Get-CimSafe -Class 'Win32_UserProfile' -Filter "SID='$sid'"
    if ($up) { $profilePath = ($up | Select-Object -First 1).LocalPath }
    elseif ($isRunner) { $profilePath = $env:USERPROFILE }

    # is the audited user a local administrator? (OEA 9.2 - daily user with admin rights)
    $isUserAdmin = $null
    try {
        $adminSids = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { "$($_.SID)" })
        $isUserAdmin = ($adminSids -contains $sid)
    } catch { }

    $script:AuditedUser = [ordered]@{
        name              = $name
        sid               = $sid
        detected_via      = $source
        is_runner         = $isRunner
        is_admin          = $isUserAdmin
        is_hive_available = [bool]$hiveRoot
        profile_path      = $profilePath
        runner_name       = $runnerId.Name
        hive_root         = $hiveRoot   # internal (not serialized): registry root for per-user reads
    }
    return $script:AuditedUser
}

# Per-user registry path of the audited user (e.g. 'Control Panel\Desktop'); $null if the hive is not available.
function Get-UserRegPath([string]$SubPath) {
    $u = Resolve-AuditedUser
    if (-not $u.hive_root) { return $null }
    return (Join-Path $u.hive_root $SubPath)
}

# ============================ MODULE: core ====================================
# identity, operating system, hardware inventory, network adapters

# OEM placeholder strings ("To be filled by O.E.M.", "Default string", all zeros...) mean "not provided" -> $null.
function Get-CleanSmbiosString([string]$Value) {
    $v = "$Value".Trim()
    if (-not $v -or $v -match '^(To be filled by O\.?E\.?M\.?|Default string|System (Product Name|SKU ?Number|Version|Family|Serial Number)|Not Applicable|Not Specified|Not Available|Undefined|System manufacturer|None|N/?A|Unknown|Invalid|0+|0x0+|x+|F+)$') { return $null }
    return $v
}

# Walks the raw SMBIOS table (MSSmBios_RawSMBiosTables.SMBiosData, DMTF DSP0134 3.9.0 §6.1): each structure = formatted
# area (type, length, ...) + string-set (NUL-terminated strings closed by a double NUL). Returns { type; offset; length;
# strings } per structure, stops at type 127 (end-of-table) or at the first malformed length. Pure (unit-tested).
function Get-SmbiosStructures([byte[]]$Data) {
    $list = @()
    if (-not $Data) { return ,$list }
    $i = 0
    while ($i + 4 -le $Data.Length) {
        $type = [int]$Data[$i]; $len = [int]$Data[$i + 1]
        if ($len -lt 4 -or $i + $len -gt $Data.Length) { break }
        $strings = @(); $j = $i + $len; $start = $j
        while ($j + 1 -lt $Data.Length -and -not ($Data[$j] -eq 0 -and $Data[$j + 1] -eq 0)) {
            if ($Data[$j] -eq 0) { $strings += [Text.Encoding]::ASCII.GetString($Data, $start, $j - $start); $start = $j + 1 }
            $j++
        }
        if ($j -gt $start) { $strings += [Text.Encoding]::ASCII.GetString($Data, $start, $j - $start) }
        $list += [pscustomobject]@{ type = $type; offset = $i; length = $len; strings = $strings }
        if ($type -eq 127) { break }
        $i = $j + 2
    }
    return ,$list
}

# String field of a structure: the byte at $Offset is a 1-based index into its string-set (0 = no string). $null when the
# structure is too short for the field, the index is out of range, or the value is an OEM placeholder.
function Get-SmbiosString([byte[]]$Data, $Structure, [int]$Offset) {
    if ($Structure.length -le $Offset) { return $null }
    $n = [int]$Data[$Structure.offset + $Offset]
    if ($n -ge 1 -and $n -le @($Structure.strings).Count) { return Get-CleanSmbiosString @($Structure.strings)[$n - 1] }
    return $null
}

# SMBIOS Type 17 (Memory Device) records. Offsets per DSP0134 3.9.0 §7.18: 0Ch size, 0Eh form factor, 10h/11h locator
# strings, 12h memory type, 15h speed, 17h/1Ah manufacturer/part strings, 1Ch extended size. Empty sockets are listed too
# (size 0): the size is filled at every boot from the module's SPD, so "empty" is reliable (unlike Type 9 slot usage).
function ConvertFrom-SmbiosMemoryDevices([byte[]]$Data) {
    $devices = @()
    foreach ($st in (Get-SmbiosStructures $Data)) {
        if ($st.type -ne 17 -or $st.length -lt 0x15) { continue }
        $i = $st.offset; $len = $st.length
        $size = [BitConverter]::ToUInt16($Data, $i + 0x0C)
        $sizeMb = $null; $installed = $true
        if ($size -eq 0) { $sizeMb = 0; $installed = $false }
        elseif ($size -eq 0xFFFF) { $sizeMb = $null }
        elseif ($size -eq 0x7FFF -and $len -ge 0x20) { $sizeMb = [int64]([BitConverter]::ToUInt32($Data, $i + 0x1C) -band 0x7FFFFFFF) }
        elseif ($size -band 0x8000) { $sizeMb = [math]::Round(($size -band 0x7FFF) / 1024, 3) }
        else { $sizeMb = [int64]$size }
        $speed = if ($len -ge 0x17) { [int][BitConverter]::ToUInt16($Data, $i + 0x15) } else { 0 }
        $devices += [ordered]@{
            array_handle     = [int][BitConverter]::ToUInt16($Data, $i + 0x04)
            is_installed     = $installed
            size_mb          = $sizeMb
            form_factor_code = [int]$Data[$i + 0x0E]
            memory_type_code = [int]$Data[$i + 0x12]
            locator          = Get-SmbiosString $Data $st 0x10
            bank             = Get-SmbiosString $Data $st 0x11
            manufacturer     = if ($installed) { Get-SmbiosString $Data $st 0x17 } else { $null }
            part_number      = if ($installed) { Get-SmbiosString $Data $st 0x1A } else { $null }
            speed_mhz        = if ($installed -and $speed -gt 0 -and $speed -ne 0xFFFF) { $speed } else { $null }
        }
    }
    return ,$devices
}

# SMBIOS Type 16 (Physical Memory Array): 02h handle, 05h use (Table 73: 03h = system memory), 0Dh number of slots or
# sockets for memory devices in this array (DSP0134 3.9.0 §7.17).
function ConvertFrom-SmbiosMemoryArrays([byte[]]$Data) {
    $out = @()
    foreach ($st in (Get-SmbiosStructures $Data)) {
        if ($st.type -ne 16 -or $st.length -lt 0x0F) { continue }
        $out += [ordered]@{
            handle       = [int][BitConverter]::ToUInt16($Data, $st.offset + 0x02)
            use_code     = [int]$Data[$st.offset + 0x05]
            socket_count = [int][BitConverter]::ToUInt16($Data, $st.offset + 0x0D)
        }
    }
    return ,$out
}

# SMBIOS Type 4 (Processor): 04h Socket Designation string, 18h Status (bit 6 = CPU socket populated), 19h Processor
# Upgrade (DSP0134 3.9.0 Table 25), 32h Socket Type string (3.8+, mandatory when 19h = FFh).
function ConvertFrom-SmbiosProcessorSockets([byte[]]$Data) {
    $out = @()
    foreach ($st in (Get-SmbiosStructures $Data)) {
        if ($st.type -ne 4 -or $st.length -lt 0x1A) { continue }
        $code = [int]$Data[$st.offset + 0x19]
        $out += [ordered]@{
            designation  = Get-SmbiosString $Data $st 0x04
            is_populated = [bool]($Data[$st.offset + 0x18] -band 0x40)
            upgrade_code = $code
            upgrade      = $script:CpuUpgradeMap[$code]
            socket_type_text = if ($st.length -gt 0x32) { Get-SmbiosString $Data $st 0x32 } else { $null }
        }
    }
    return ,$out
}

# CPU package from the processor NAME. More reliable than SMBIOS: on 840 desktop + 584 notebook real dumps (linuxhw/DMI,
# 2026-09-30) BIOS templates claim 'Socket LGA1155' for Celeron J1800/J1900/Pentium J2900/J3710/N3010 boards and
# 'Socket rPGA988B'/'Slot 1' for i5-4200U, i7-4510U, i5-3317U, Pentium N3710 notebooks -- all BGA (soldered) parts.
# 'bga' = families that only ship soldered: Intel Core U/Y/H/HQ/HK/HX/HS/G1-G7, Core Ultra U/H/V/HX, Celeron/Pentium
# N/J, Intel N-series (N100, i3-N305), Atom, any 4-5 digit 'U' part; AMD Ryzen/Athlon U/H/HS/HX. $null = name does not decide.
function Get-CpuPackageFromName([string]$Name) {
    $n = "$Name"
    if ($n -match '\bi[3579]-\d{4,5}(U|Y|H|HQ|HK|HX|HS|G\d)\b') { return 'bga' }
    if ($n -match '\bi[3579]-1[2-4]\d{2}P\b') { return 'bga' }                              # 12th-14th gen mobile P (i5-1240P); desktop i5-3350P/6402P untouched
    if ($n -match '\b(i[357]|m[357])-\d{1,2}Y\d{2}\b' -or $n -match '\bi[57]-8[0-9]0[59]G\b') { return 'bga' }   # i5-7Y54, m3-6Y30, Kaby Lake-G
    if ($n -match '\bUltra X?\d+ \d{3}(U|H|V|HX)\b') { return 'bga' }
    if ($n -match '\bCore(\(TM\))? [3579] \d{3}[UH]\b') { return 'bga' }                 # Core 5 120U / Core 7 240H (series 1/2 mobile)
    if ($n -match '\b(Celeron|Pentium)\(R\)( Gold)? [5-7]\d{3}\b') { return 'bga' }       # Celeron 7305, Pentium Gold 7505 (desktop parts carry a G prefix)
    if ($n -match '\b[NJ]\d{4}\b' -or $n -match '(\bi3-|\bIntel\(R\) |\bProcessor )N\d{2,3}\b' -or $n -match '\bAtom\b') { return 'bga' }
    if ($n -match '\b\d{3,5}U\b') { return 'bga' }
    if ($n -match '\b(Ryzen|Athlon)\b.*\b\d{4}(U|H|HS|HX)\b') { return 'bga' }
    # Ryzen AI 9 HX 370 / Ryzen AI 7 PRO 450 / Ryzen 7 260 are mobile; the AM5 DESKTOP Ryzen AI 400 parts carry a G/GE
    # suffix (Ryzen AI 7 PRO 450G, 5 PRO 440GE: amd.com lists CPU socket AM5) -> not BGA
    if (($n -match '\bRyzen AI\b' -or $n -match '\bRyzen [3579] \d{3}\b') -and $n -notmatch '\b\d{3}GE?\b') { return 'bga' }
    if ($n -match 'Snapdragon|Qualcomm|Microsoft SQ\d') { return 'bga' }   # Windows on ARM: SoC on the board
    return $null
}

# CPU socket verdict. Measured (see above + ASUS A320M-C 'P0'/'None'): the Upgrade field is often 'Other' or 'None' on
# socketed desktops and a template on notebooks; the designation is often just 'P0'/'CPU0'. Order:
#   1. the CPU NAME says BGA-only        -> 'soldered' (source 'inferred', from the CPU model), whatever the BIOS claims
#   2. not a laptop + a NAMED socket     -> 'socketed' (source 'reported', by the BIOS); 'None'/'Other'/'Unknown' never decide
#   3. laptop + 'Socket BGA…'            -> 'soldered' (source 'reported'); a laptop is never 'socketed' from the BIOS
#   4. otherwise 'unknown'
# Socket text: the named type ('AM4', 'LGA1700') unless the name veto applies, else the 32h Socket Type string, else the
# designation only if it looks like a socket name ('FP8', 'FT6', 'AM5').
function Get-CpuSocketInfo($Sockets, [string]$ChassisKind, [string]$CpuName) {
    $all = @($Sockets)
    if ($all.Count -eq 0) { return $null }
    $cpu = @($all | Where-Object { $_.is_populated })[0]
    if (-not $cpu) { $cpu = $all[0] }
    $name = if ($cpu.upgrade_code -eq 0xFF) { "$($cpu.socket_type_text)" } else { "$($cpu.upgrade)" }
    $isBgaSocket = $name -match 'BGA|^(Socket )?F[PTL]\d'    # AMD mobile packages FP5-FP8 / FT3-FT6 / FL1 are BGA
    $isNamedSocket = ($name -match '^(Socket (?!BGA)|ZIF Socket|LIF Socket|Slot |370-pin)' -and -not $isBgaSocket) -or ($cpu.upgrade_code -eq 0xFF -and $name -and -not $isBgaSocket)
    $isBgaByName = (Get-CpuPackageFromName $CpuName) -eq 'bga'
    $mounting = 'unknown'; $source = $null
    if ($isBgaByName) { $mounting = 'soldered'; $source = 'inferred' }
    elseif ($ChassisKind -ne 'laptop' -and $isNamedSocket) { $mounting = 'socketed'; $source = 'reported' }
    elseif ($ChassisKind -eq 'laptop' -and $isBgaSocket) { $mounting = 'soldered'; $source = 'reported' }
    $socket = $null
    if (-not $isBgaByName -and $name -match '^Socket (?!BGA)(.+)$') { $socket = $Matches[1] }
    elseif (-not $isBgaByName -and $cpu.upgrade_code -eq 0xFF -and $name) { $socket = ($name -replace '^Socket ', '') }
    elseif ("$($cpu.designation)" -match '^(AM\d|FM\d|FP\d|FT\d|FS\d|FL\d|SP\d|sTRX?\d|sWRX\d|TR\d|LGA ?\d+|BGA ?\d+|rPGA|PGA ?\d+)') { $socket = $cpu.designation }
    return [ordered]@{ socket = $socket; upgrade = if ($cpu.upgrade_code -eq 0xFF) { $cpu.socket_type_text } else { $cpu.upgrade }
                       mounting = $mounting; source = $source; designation = $cpu.designation }
}

# Is a memory device replaceable? Form factor decides when the firmware states it; soldered LPDDR usually reports
# 'Other' (measured on a Lenovo IdeaPad), so the LPDDR family is the fallback. Source (LAW rule 17): 'reported' = the
# firmware states the form factor; 'inferred' = derived by this tool from the memory kind.
function Get-MemoryMounting([int]$FormFactorCode, [int]$MemoryTypeCode) {
    if ($FormFactorCode -in $script:SocketedFormFactors) { return [ordered]@{ mounting = 'socketed'; source = 'reported' } }
    if ($FormFactorCode -in $script:SolderedFormFactors) { return [ordered]@{ mounting = 'soldered'; source = 'reported' } }
    if ($MemoryTypeCode -in $script:LpddrMemoryTypes)    { return [ordered]@{ mounting = 'soldered'; source = 'inferred' } }
    return [ordered]@{ mounting = 'unknown'; source = $null }
}

# How the INSTALLED memory is mounted: soldered | socketed | mixed (soldered + module both installed) | unknown.
# Empty positions never decide it: real dumps show they can be phantoms (next function).
function Get-RamMountingSummary($Modules) {
    $kinds = @(@($Modules) | Where-Object { $_.is_installed } | ForEach-Object { $_.mounting } | Select-Object -Unique)
    if ($kinds.Count -eq 0) { return $null }
    if ($kinds.Count -eq 1) { return $kinds[0] }
    if ($kinds.Count -eq 2 -and $kinds -contains 'soldered' -and $kinds -contains 'socketed') { return 'mixed' }
    return 'unknown'
}

# Whole memory picture from the raw table (pure; the core module adds the Win32 fallback). What the data supports
# (840 desktop + 584 notebook real dumps, board specs checked on gigabyte/asus/msi/asrock.com, 2026-09-30):
# - INSTALLED modules are reliable (size/kind/speed/part come from the module at boot).
# - EMPTY positions are NOT physical slots: Gigabyte H410M H / H310M S2P 2.0 and MSI H61M-P22 have 2 DIMM slots and
#   report 4 positions (consistent tables!), phantoms identical field by field to real empty slots (ASUS PRIME B450M-A).
#   So they are reported as 'empty_position_count' ("what the BIOS lists"), never as free slots; the advice says so.
# - Table consistency (spec 4.8.1: one Type 17 per socket, +1 for soldered memory): Gigabyte H81M/B85M list 4 on 2
#   declared, B85M-D3H declares 2 with 4 physical -> 'is_table_consistent' false = no count can be trusted.
# - Excluded: devices of video/flash/NVRAM/cache arrays (Type 16 use 04h-07h) and ROM/flash memory types (08h-0Ch): HP
#   desktops list their 'SYSTEM ROM' as a Type 17 'Chip' (22 of 120 HP dumps) -> read as "part of the RAM is soldered".
# - Empty positions are counted everywhere EXCEPT the undescribed ones of an all-LPDDR board (LPDDR has no sockets:
#   those are unused channels). An empty 'Unknown' position next to soldered DDR4 may be a real SODIMM slot whose
#   descriptor the BIOS left blank -> counted (hedged), never a confident "cannot be upgraded".
function Get-MemoryLayout([byte[]]$Data, [string]$ChassisKind) {
    # the parsers return ',$list' (one array object): assign first, THEN pipe -- '@(Parser $x | Where …)' would hand the
    # whole array to Where-Object as a single item.
    $arrays     = ConvertFrom-SmbiosMemoryArrays $Data
    $excluded   = @(@($arrays) | Where-Object { $_.use_code -in 4, 5, 6, 7 } | ForEach-Object { $_.handle })
    $counted    = @(@($arrays) | Where-Object { $_.use_code -notin 4, 5, 6, 7 })
    $allDevices = ConvertFrom-SmbiosMemoryDevices $Data
    $devices    = @(@($allDevices) | Where-Object { ($_.memory_type_code -lt 8 -or $_.memory_type_code -gt 12) -and $_.array_handle -notin $excluded })
    if ($devices.Count -eq 0) { return $null }
    $modules = @()
    foreach ($d in $devices) {
        $m = Get-MemoryMounting $d.form_factor_code $d.memory_type_code
        $modules += [ordered]@{
            is_installed = $d.is_installed; size_mb = $d.size_mb
            kind = if ($d.is_installed) { $script:DdrMap[$d.memory_type_code] } else { $null }
            form_factor = $script:MemoryFormFactorMap[$d.form_factor_code]; mounting = $m.mounting; mounting_source = $m.source
            locator = $d.locator; bank = $d.bank; manufacturer = $d.manufacturer; part_number = $d.part_number; speed_mhz = $d.speed_mhz
        }
    }
    $mounting = Get-RamMountingSummary $modules
    $installed = @($modules | Where-Object { $_.is_installed })
    $installedKinds = @($installed | ForEach-Object { "$($_.kind)" })
    $isLpddrBoard = $installedKinds.Count -gt 0 -and -not ($installedKinds | Where-Object { $_ -notmatch '^LPDDR' })
    # an empty position the BIOS itself calls chip/row of chips/die is an unpopulated memory-down footprint, not a slot
    $empty = @($modules | Where-Object { -not $_.is_installed -and $_.mounting -ne 'soldered' -and (-not $isLpddrBoard -or $_.mounting -eq 'socketed') }).Count
    # Is the mounting verdict trustworthy? 'soldered' stated by the form factor: yes. 'socketed': only full-size modules on
    # a DESKTOP chassis -- real notebook dumps show fully soldered models reporting SODIMM with genuine module part numbers
    # (ThinkPad T14s Gen 1 / T490s: Lenovo PSREF "soldered, no slots") and notebook BIOSes reporting 'DIMM' for SODIMM
    # modules (42/584) or even for soldered RAM (Dell XPS L322X). LPDDR inference / unknown: no.
    $fullSize = @('simm', 'dimm', 'rimm', 'fb_dimm', 'cudimm')
    $isConfirmed = $false
    if ($mounting -eq 'soldered') { $isConfirmed = -not ($installed | Where-Object { $_.mounting_source -ne 'reported' }) }
    elseif ($mounting -eq 'socketed') { $isConfirmed = ($ChassisKind -eq 'desktop') -and -not ($installed | Where-Object { $_.form_factor -notin $fullSize }) }
    elseif ($mounting -eq 'mixed') { $isConfirmed = -not ($installed | Where-Object { $_.mounting -eq 'soldered' -and $_.mounting_source -ne 'reported' }) }
    $declared = 0; foreach ($arr in $counted) { $declared += [int]$arr.socket_count }   # Measure-Object -Property can't read [ordered] keys in PS 5.1
    $isConsistent = $null
    if ($declared -gt 0) {
        $hasSoldered = [bool](@($modules | Where-Object { $_.is_installed -and $_.mounting -eq 'soldered' }).Count)
        $isConsistent = ($devices.Count -eq $declared) -or ($hasSoldered -and ($devices.Count - 1) -eq $declared)
    }
    return [ordered]@{ modules = $modules; mounting = $mounting; is_mounting_confirmed = [bool]$isConfirmed; empty_position_count = $empty
                       declared_socket_count = $(if ($declared -gt 0) { [int]$declared } else { $null }); is_table_consistent = $isConsistent }
}

# Spanish advice for RAM findings. Never states a free slot or a socketed module as fact unless the data supports it
# (see Get-MemoryLayout): empty positions are "what the BIOS lists"; SODIMM is "what the BIOS reports"; both point to the
# spec sheet. $null mounting = not measured -> the generic text.
function Get-RamUpgradeAdvice($Mounting, $EmptyPositions = 0, $IsConfirmed = $false, $RamGb = $null, $IsTableConsistent = $null) {
    $sheet = 'confirmar en la ficha del equipo o de la placa'
    $replace = if ($null -ne $RamGb -and $RamGb -le 8) { 'reducir programas o planificar el reemplazo del equipo' } else { 'reducir programas abiertos' }
    switch ($Mounting) {
        'virtual'  { return 'equipo virtual: la RAM se asigna desde el servidor anfitrion' }
        'soldered' {
            if ($IsTableConsistent -eq $false) { return "la RAM instalada esta soldada a la placa y el BIOS informa las ranuras de forma inconsistente: $sheet si existe una ranura libre para ampliar (si no la hay: $replace)" }
            if ($EmptyPositions -gt 0) { return "la RAM instalada esta soldada a la placa y el BIOS informa ademas $EmptyPositions posicion(es) vacia(s): $sheet si existe una ranura libre; si existe, se puede ampliar agregando un modulo (si no: $replace)" }
            if (-not $IsConfirmed) { return "la RAM es de tipo LPDDR, que normalmente va SOLDADA a la placa (no se podria ampliar; $sheet): $replace" }
            return "la RAM esta SOLDADA a la placa (no se puede ampliar): $replace"
        }
        { $_ -in 'socketed', 'mixed' } {
            $pre = if ($Mounting -eq 'mixed') { 'parte de la RAM esta soldada; ' } else { '' }
            if ($Mounting -eq 'socketed' -and -not $IsConfirmed) {
                $pre = 'el BIOS informa la memoria como modulo en ranura, pero en algunas notebooks y equipos compactos lo informa asi aunque este soldada; '
                if ($IsTableConsistent -eq $false) { return "${pre}ademas informa las ranuras de forma inconsistente: $sheet si la memoria se puede ampliar antes de comprar" }
                if ($EmptyPositions -gt 0) { return "${pre}informa $EmptyPositions posicion(es) vacia(s): $sheet si la memoria se puede ampliar y si esas ranuras existen antes de comprar" }
                return "${pre}$sheet si la memoria se puede ampliar (reemplazando modulos por otros de mayor capacidad) antes de comprar"
            }
            if ($IsTableConsistent -eq $false) { return "${pre}el BIOS informa las ranuras de memoria de forma inconsistente: $sheet cuantas ranuras libres tiene antes de comprar memoria" }
            if ($EmptyPositions -gt 0) { return "${pre}el BIOS informa $EmptyPositions posicion(es) de memoria vacia(s): $sheet que sean ranuras libres antes de comprar memoria" }
            return "${pre}las ranuras de memoria informadas estan ocupadas: para ampliar, reemplazar modulos por otros de mayor capacidad ($sheet el maximo admitido)"
        }
        'unknown'  { return "evaluar ampliar RAM o reducir programas ($sheet si la memoria se puede ampliar)" }
        default    { return 'evaluar ampliar RAM o reducir programas' }
    }
}

# Support row for a Windows build + caption. LTSC/LTSB -> fixed-lifecycle table ('iot' column for IoT Enterprise LTSC);
# general channel -> Home/Pro vs Enterprise/Education/IoT Enterprise columns (Microsoft lists IoT Enterprise with
# Enterprise). Unknown build / non-workstation -> $null (nothing asserted).
function Get-WindowsSupportInfo([string]$Caption, [string]$Build, [int]$ProductType) {
    # Enterprise multi-session (Azure Virtual Desktop) reports ProductType 3 like a server but follows Enterprise dates
    if (-not $Build -or ($ProductType -ne 1 -and "$Caption" -notmatch 'multi-session')) { return $null }
    if ("$Caption" -match 'LTSC|LTSB') {
        if (-not $script:WindowsLtscEol.ContainsKey($Build)) { return $null }
        $row = $script:WindowsLtscEol[$Build]
        $col = if ("$Caption" -match 'IoT') { 'iot' } else { 'enterprise' }
        return [ordered]@{ release = $row.release; end_of_support_date = $row[$col]; channel = 'ltsc' }
    }
    if (-not $script:WindowsEol.ContainsKey($Build)) { return $null }
    $row = $script:WindowsEol[$Build]
    $col = if ("$Caption" -match 'Pro Education') { 'home_pro' } elseif ("$Caption" -match 'Enterprise|Education|IoT') { 'enterprise' } else { 'home_pro' }
    return [ordered]@{ release = $row.release; end_of_support_date = $row[$col]; channel = 'general' }
}

# Windows 10 22H2 ESU evidence: active commercial license IDs (+ the coverage end of the highest year) and the build
# revision (UBR) compared with the first ESU-only build. Pure (unit-tested).
function Resolve-Win10Esu([string[]]$ActiveLicenseIds, $Ubr, [datetime]$Today) {
    $years = @(@($ActiveLicenseIds) | ForEach-Object { $script:Win10EsuActivationIds["$_".Trim().ToLower()] } | Where-Object { $_ })
    $year = $null; foreach ($y in $years) { if (-not $year -or [int]$y -gt $year) { $year = [int]$y } }
    $end = if ($year) { $script:Win10EsuYearEnd[$year] } else { $null }
    $isCurrent = [bool]($end -and $Today.Date -le ([datetime]$end).Date)
    $rev = $null; if ($null -ne $Ubr -and "$Ubr" -match '^\d+$') { $rev = [int]"$Ubr" }
    return [ordered]@{ license_year = $year; license_coverage_end_date = $end; is_license_current = $isCurrent
                       build_revision = $rev; has_esu_updates = [bool]($null -ne $rev -and $rev -ge $script:Win10FirstEsuUbr) }
}

# The single OS-support finding (or $null). Pure (unit-tested end to end with Get-WindowsSupportInfo + Resolve-Win10Esu).
function Get-OsSupportFinding([string]$Caption, [string]$Build, $Support, $EolDays, $Esu, [datetime]$Today) {
    # always compare NUMBERS: a string '-352' compared with 0 is a culture string compare that ignores the '-' sign
    if ($null -ne $EolDays -and "$EolDays" -ne '') { $EolDays = [int]$EolDays } else { $EolDays = $null }
    if ("$Caption" -match 'Windows 7|Windows 8|Windows Vista|Windows XP|Server 2008|Server 2012') {
        return [ordered]@{ code = 'os_unsupported'; severity = 'high'; message = "SO SIN SOPORTE de seguridad: $Caption. Sin parches -> riesgo alto." }
    }
    $rel = if ($Support) { $Support.release } else { $null }
    $eol = if ($Support) { $Support.end_of_support_date } else { $null }
    if ($null -ne $EolDays -and $EolDays -lt 0) {
        if ($Esu -and $Esu.is_license_current -and $null -ne $Esu.build_revision -and -not $Esu.has_esu_updates) {
            # licensed but still on a pre-ESU build (< 19045.6575): the PC is NOT getting the patches it pays for
            return [ordered]@{ code = 'os_extended_security_updates_not_applied'; severity = 'high'; message = "Windows 10 22H2 SIN PARCHES: tiene activada la licencia de actualizaciones extendidas (ESU) del periodo $($Esu.license_year) pero no instalo ninguna actualizacion del programa (build 19045.$($Esu.build_revision)): no esta recibiendo los parches de seguridad. Revisar Windows Update." }
        }
        if ($Esu -and $Esu.is_license_current) {
            $check = if ($null -eq $Esu.build_revision) { ' (no se pudo leer el build para confirmar que se instalan)' } else { '' }
            return [ordered]@{ code = 'os_extended_security_updates'; severity = 'medium'; message = "Windows 10 22H2 sin soporte general desde el ${eol}, pero tiene activada la licencia de actualizaciones extendidas (ESU) de empresa del periodo $($Esu.license_year), que cubre hasta el $($Esu.license_coverage_end_date)$check. Planificar la migracion a Windows 11." }
        }
        if ($Esu -and $Esu.license_year) {
            return [ordered]@{ code = 'os_extended_security_updates_expired'; severity = 'high'; message = "Windows 10 22H2 SIN SOPORTE: la licencia de actualizaciones extendidas (ESU) del periodo $($Esu.license_year) vencio el $($Esu.license_coverage_end_date) y no hay una vigente: no recibe parches de seguridad. Renovar el ESU o migrar a Windows 11." }
        }
        if ($Esu -and $Esu.has_esu_updates -and $Today.Date -le ([datetime]$script:Win10ConsumerEsuEnd).Date) {
            return [ordered]@{ code = 'os_extended_security_updates'; severity = 'medium'; message = "Windows 10 22H2 sin soporte general desde el ${eol}, pero instalo actualizaciones del programa de actualizaciones extendidas (ESU) (build 19045.$($Esu.build_revision)), por lo que esta inscripto (el ESU para hogares cubre hasta el $($script:Win10ConsumerEsuEnd); el de empresas y entornos virtuales de Microsoft, segun el periodo contratado). Planificar la migracion a Windows 11." }
        }
        return [ordered]@{ code = 'os_end_of_support'; severity = 'high'; message = "Windows version $rel (build $Build) SIN SOPORTE desde el ${eol}: no recibe parches de seguridad. Actualizar a una version soportada." }
    }
    if ($null -ne $EolDays -and $EolDays -le $script:EolWarningDays) {
        return [ordered]@{ code = 'os_end_of_support_soon'; severity = 'medium'; message = "Windows version $rel (build $Build): el soporte termina el $eol (en $EolDays dias). Planificar la actualizacion." }
    }
    if ("$Caption" -match 'Windows 10' -and "$Caption" -notmatch 'LTSC|LTSB' -and $Build -ne '19045') {
        return [ordered]@{ code = 'os_unsupported_build'; severity = 'high'; message = "Windows 10 build $Build SIN SOPORTE (version anterior a 22H2). Actualizar." }
    }
    return $null
}

# identity + os + hardware + network. Returns an ordered hashtable of top-level keys.
function Get-CoreInfo {
    $os    = Get-CimSafe 'Win32_OperatingSystem'
    $cs    = Get-CimSafe 'Win32_ComputerSystem'
    $bios  = Get-CimSafe 'Win32_BIOS'
    $board = Get-CimSafe 'Win32_BaseBoard'
    $cpu   = Get-CimSafe 'Win32_Processor'

    $osCaption = if ($os) { $os.Caption } else { $null }
    $prodType  = if ($os) { [int]$os.ProductType } else { 1 }
    $osKind    = @{ 1 = 'workstation'; 2 = 'domain_controller'; 3 = 'server' }[$prodType]
    $domain    = if ($cs -and $cs.PartOfDomain) { "$($cs.Domain)" } else { $null }
    $workgroup = if ($cs -and -not $cs.PartOfDomain) { "$($cs.Workgroup)" } else { $null }
    $bootTime  = if ($os) { $os.LastBootUpTime } else { $null }
    $uptime    = if ($bootTime) { $d = (Get-Date) - $bootTime; ('{0}d {1}h' -f $d.Days, $d.Hours) } else { $null }

    # OS end of support (offline tables by build + edition family/channel) + Windows 10 22H2 ESU evidence.
    $osBuild = if ($os) { "$($os.BuildNumber)" } else { $null }
    $osUbr = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'
    $support = Get-WindowsSupportInfo $osCaption $osBuild $prodType
    $osRelease = if ($support) { $support.release } else { $null }
    $osEol = if ($support) { $support.end_of_support_date } else { $null }
    $osEolDays = Get-DaysUntil $osEol
    $esu = $null
    if ($osBuild -eq '19045' -and $support -and $support.channel -eq 'general' -and $null -ne $osEolDays -and $osEolDays -lt 0) {
        $esuIds = "ID='" + ((@($script:Win10EsuActivationIds.Keys)) -join "' OR ID='") + "'"
        $esuLic = Get-CimSafe -Class 'SoftwareLicensingProduct' -Filter "($esuIds) AND LicenseStatus=1"
        $esuLicIds = @(@($esuLic) | Where-Object { $_ } | ForEach-Object { "$($_.ID)" })
        $esu = Resolve-Win10Esu $esuLicIds $osUbr (Get-Date)
    }
    $osFinding = Get-OsSupportFinding $osCaption $osBuild $support $osEolDays $esu (Get-Date)
    if ($osFinding) { Add-Finding -Code $osFinding.code -Severity $osFinding.severity -Oea @('9.7') -Message $osFinding.message }

    # RAM
    $mem = Get-CimSafe 'Win32_PhysicalMemory'
    $ramGb = $null; $ramType = $null; $ramSpeed = $null; $ramSlotsUsed = $null; $ramSlotsTotal = $null
    if ($mem) {
        $ramGb        = [math]::Round((($mem | Measure-Object -Property Capacity -Sum).Sum) / 1GB, 0)
        $ramSlotsUsed = ($mem | Measure-Object).Count
        $ramType      = (($mem | ForEach-Object { $script:DdrMap[[int]$_.SMBIOSMemoryType] }) | Where-Object { $_ } | Select-Object -Unique) -join '/'
        $ramSpeed     = (($mem | ForEach-Object { $_.Speed }) | Where-Object { $_ } | Select-Object -Unique) -join '/'
    } elseif ($cs -and $cs.TotalPhysicalMemory) {
        $ramGb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 0)
    }
    $memArray = Get-CimSafe 'Win32_PhysicalMemoryArray'
    if ($memArray) { $ramSlotsTotal = ($memArray | Measure-Object -Property MemoryDevices -Sum).Sum }

    # Chassis first: the memory and CPU verdicts depend on it (desktop-only inference, BGA = soldered only on laptops).
    $enclosure = Get-CimSafe 'Win32_SystemEnclosure'
    $chassisCodes = @($enclosure | ForEach-Object { $_.ChassisTypes } | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
    $chassisKind = 'other'
    if ($chassisCodes | Where-Object { $_ -in 8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32 }) { $chassisKind = 'laptop' }
    elseif ($chassisCodes | Where-Object { $_ -in 3, 4, 5, 6, 7, 13, 15, 16, 24, 34, 35, 36 }) { $chassisKind = 'desktop' }
    if ($chassisCodes.Count -eq 0) { $chassisKind = $null }

    # Memory + CPU socket from the raw SMBIOS table (Get-MemoryLayout / Get-CpuSocketInfo); Win32 fallback for memory.
    $layout = $null; $cpuSocketInfo = $null
    $smbiosRaw = Get-CimSafe -Class 'MSSmBios_RawSMBiosTables' -Namespace 'root\wmi'
    if ($smbiosRaw) {
        $smbiosBytes = [byte[]](($smbiosRaw | Select-Object -First 1).SMBiosData)
        try { $layout = Get-MemoryLayout $smbiosBytes $chassisKind }
        catch { [void]$script:Errors.Add([ordered]@{ module = 'core'; message = "SMBIOS memory parse: $($_.Exception.Message)" }) }
        $cpuNameForSocket = if ($cpu) { "$(@($cpu)[0].Name)".Trim() } else { $null }
        try { $cpuSocketInfo = Get-CpuSocketInfo (ConvertFrom-SmbiosProcessorSockets $smbiosBytes) $chassisKind $cpuNameForSocket }
        catch { [void]$script:Errors.Add([ordered]@{ module = 'core'; message = "SMBIOS processor parse: $($_.Exception.Message)" }) }
    }
    $memoryModules = @(); $memorySource = $null; $ramEmptyPositions = $null; $declaredSockets = $null; $isTableConsistent = $null
    if ($layout) {
        $memorySource = 'smbios'; $memoryModules = @($layout.modules); $ramMounting = $layout.mounting
        $ramEmptyPositions = $layout.empty_position_count; $declaredSockets = $layout.declared_socket_count; $isTableConsistent = $layout.is_table_consistent
    } elseif ($mem) {
        $memorySource = 'win32'   # no form factor here (CIM enum differs): only the LPDDR inference applies
        foreach ($p in $mem) {
            $m = Get-MemoryMounting 0 ([int]$p.SMBIOSMemoryType)
            $memoryModules += [ordered]@{
                is_installed = $true; size_mb = [int64]($p.Capacity / 1MB); kind = $script:DdrMap[[int]$p.SMBIOSMemoryType]
                form_factor = $null; mounting = $m.mounting; mounting_source = $m.source
                locator = Get-CleanSmbiosString $p.DeviceLocator; bank = Get-CleanSmbiosString $p.BankLabel
                manufacturer = Get-CleanSmbiosString $p.Manufacturer; part_number = Get-CleanSmbiosString $p.PartNumber
                speed_mhz = if ($p.Speed) { [int]$p.Speed } else { $null }
            }
        }
        $ramMounting = Get-RamMountingSummary $memoryModules
    } else { $ramMounting = $null }
    # Virtual machine: the "sockets" are the hypervisor's emulation, not hardware (no upgrade advice by slots).
    $isVirtual = $cs -and ("$($cs.Model)" -match 'Virtual Machine|VMware|VirtualBox|KVM|QEMU|Parallels|HVM domU|Standard PC \(' -or "$($cs.Manufacturer)" -match '^(QEMU|Xen|innotek GmbH|Parallels)')
    if ($isVirtual) { $ramMounting = 'virtual'; $ramEmptyPositions = $null; $isTableConsistent = $null; if ($cpuSocketInfo) { $cpuSocketInfo.mounting = 'virtual'; $cpuSocketInfo.source = $null } }
    $ramMountingConfirmed = if ($layout) { [bool]$layout.is_mounting_confirmed } else { $false }
    if ($isVirtual) { $ramMountingConfirmed = $false }
    $script:RamMounting = $ramMounting; $script:RamEmptyPositions = $ramEmptyPositions   # read by the performance module's RAM finding
    $script:RamMountingConfirmed = $ramMountingConfirmed; $script:RamGb = $ramGb; $script:RamTableConsistent = $isTableConsistent

    # Exact product identity: HP puts its product number in SystemSKUNumber, Lenovo the full MTM + marketing name,
    # Dell's serial IS the service tag. Model alone can be a family ("HP Laptop 15-dy5xxx").
    $csp = Get-CimSafe 'Win32_ComputerSystemProduct' | Select-Object -First 1
    $uuid = if ($csp) { "$($csp.UUID)".Trim() } else { $null }
    if (-not $uuid -or $uuid -match '^[0F-]+$' -or $uuid -eq '03000200-0400-0500-0006-000700080009') { $uuid = $null }   # all-0/all-F + AMI default

    # CPU
    $cpuName    = if ($cpu) { (($cpu | ForEach-Object { $_.Name.Trim() }) -join ' + ') } else { $null }
    $cpuCores   = if ($cpu) { ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum } else { $null }
    $cpuThreads = if ($cpu) { ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum } else { $null }

    # Disks (Win32_DiskDrive enumerates all; media type from Get-PhysicalDisk by index)
    $disks = @()
    $physMap = @{}
    $phys = $null
    try { $phys = Get-PhysicalDisk -ErrorAction Stop } catch { $phys = $null }
    if ($phys) { foreach ($p in $phys) { $physMap["$($p.DeviceId)"] = "$($p.MediaType)" } }
    $dd = Get-CimSafe 'Win32_DiskDrive'
    if ($dd) {
        foreach ($p in ($dd | Sort-Object Index)) {
            $kind = if ($physMap.ContainsKey("$($p.Index)") -and $physMap["$($p.Index)"]) { $physMap["$($p.Index)"].ToLower() } else { 'unknown' }
            $disks += [ordered]@{ model = $p.Model; size_gb = [math]::Round($p.Size / 1GB, 0); kind = $kind }
        }
    }

    # Disk C: free space
    $cDisk = Get-CimSafe -Class 'Win32_LogicalDisk' -Filter "DeviceID='C:'"
    $cFreeGb = $null; $cTotalGb = $null; $cPctFree = $null
    if ($cDisk) {
        $cFreeGb  = [math]::Round($cDisk.FreeSpace / 1GB, 1)
        $cTotalGb = [math]::Round($cDisk.Size / 1GB, 1)
        if ($cDisk.Size -gt 0) { $cPctFree = [math]::Round($cDisk.FreeSpace / $cDisk.Size * 100, 0) }
    }

    # GPU
    $gpu = Get-CimSafe 'Win32_VideoController'
    $gpuName = if ($gpu) { (($gpu | ForEach-Object { $_.Name }) | Where-Object { $_ } | Select-Object -Unique) -join ' + ' } else { $null }

    # Network
    $network = @()
    $nics = Get-CimSafe -Class 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=True'
    if ($nics) {
        foreach ($n in $nics) {
            $ipv4 = ($n.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
            $network += [ordered]@{
                adapter     = $n.Description; ip = $ipv4; mac = $n.MACAddress
                gateway     = (@($n.DefaultIPGateway) | Where-Object { $_ } | Select-Object -First 1)
                dns_servers = @($n.DNSServerSearchOrder | Where-Object { $_ })
                is_dhcp     = [bool]$n.DHCPEnabled
            }
        }
    }

    # BIOS (chassis kind computed above, before the memory verdict; portable = higher theft/loss risk, OEA 9.8)
    $b1 = $bios | Select-Object -First 1
    $biosInfo = if ($b1) { [ordered]@{ version = "$($b1.SMBIOSBIOSVersion)"; release_date = if ($b1.ReleaseDate) { $b1.ReleaseDate.ToUniversalTime().ToString('yyyy-MM-dd') } else { $null } } } else { $null }

    # Hardware findings (Spanish, user-facing)
    if ($null -ne $ramGb -and $ramGb -lt 8) { Add-Finding -Code 'ram_low' -Severity 'low' -Oea @() -Message "RAM baja: $ramGb GB (posible cuello de botella para uso de oficina); $(Get-RamUpgradeAdvice $ramMounting $ramEmptyPositions $ramMountingConfirmed $ramGb $isTableConsistent)." }
    if ($null -ne $cPctFree -and $cPctFree -lt 15) { Add-Finding -Code 'disk_c_low_space' -Severity 'medium' -Oea @('9.12') -Message "Disco C: casi lleno ($cPctFree% libre). Riesgo de lentitud/actualizaciones fallidas." }
    if (($disks | Where-Object { $_.kind -match 'HDD' }) -and -not ($disks | Where-Object { $_.kind -match 'SSD' })) {
        Add-Finding -Code 'hdd_without_ssd' -Severity 'low' -Oea @() -Message 'Disco mecanico (HDD) sin SSD: upgrade a SSD daria la mayor mejora de rendimiento.'
    }

    return [ordered]@{
        identity = [ordered]@{
            computer_name  = $env:COMPUTERNAME
            assigned_user  = $script:AssignedUser
            organization   = $script:Organization
            domain         = $domain
            workgroup      = $workgroup
            logged_on_user = if ($cs) { $cs.UserName } else { $null }
        }
        os = [ordered]@{
            caption      = $osCaption
            version      = if ($os) { $os.Version } else { $null }
            build        = if ($os) { $os.BuildNumber } else { $null }
            architecture = if ($os) { $os.OSArchitecture } else { $null }
            kind         = $osKind
            release      = $osRelease
            end_of_support_date = $osEol
            is_supported = if ($null -ne $osEolDays) { $osEolDays -ge 0 } else { $null }
            servicing_channel = if ($support) { $support.channel } else { $null }
            build_revision = if ($null -ne $osUbr -and "$osUbr" -match '^\d+$') { [int]"$osUbr" } else { $null }
            extended_security_updates = $esu
            installed_at = if ($os) { ConvertTo-IsoTimestamp $os.InstallDate } else { $null }
            uptime_hours = if ($bootTime) { [int][math]::Floor(((Get-Date) - $bootTime).TotalHours) } else { $null }
        }
        hardware = [ordered]@{
            manufacturer  = if ($cs) { $cs.Manufacturer } else { $null }
            model         = if ($cs) { $cs.Model } else { $null }
            family        = if ($cs) { Get-CleanSmbiosString $cs.SystemFamily } else { $null }
            sku           = if ($cs) { Get-CleanSmbiosString $cs.SystemSKUNumber } else { $null }
            product_version = if ($csp) { Get-CleanSmbiosString $csp.Version } else { $null }
            serial        = if ($bios) { ($bios | Select-Object -First 1).SerialNumber } else { $null }
            uuid          = $uuid
            chassis_kind  = $chassisKind
            bios          = $biosInfo
            motherboard   = if ($board) { "$($board.Manufacturer) $($board.Product)" } else { $null }
            cpu           = $cpuName
            cpu_cores     = $cpuCores
            cpu_threads   = $cpuThreads
            cpu_socket    = if ($cpuSocketInfo) { $cpuSocketInfo.socket } else { $null }
            cpu_socket_designation = if ($cpuSocketInfo) { $cpuSocketInfo.designation } elseif ($cpu) { Get-CleanSmbiosString (@($cpu)[0].SocketDesignation) } else { $null }
            cpu_upgrade   = if ($cpuSocketInfo) { $cpuSocketInfo.upgrade } else { $null }
            cpu_mounting  = if ($cpuSocketInfo) { $cpuSocketInfo.mounting } else { $null }
            cpu_mounting_source = if ($cpuSocketInfo) { $cpuSocketInfo.source } else { $null }
            ram_gb        = $ramGb
            ram_slots     = [ordered]@{ used = $ramSlotsUsed; total = $ramSlotsTotal; declared_socket_count = $declaredSockets; empty_position_count = $ramEmptyPositions; is_table_consistent = $isTableConsistent }
            ram_kind      = $ramType
            ram_speed_mhz = $ramSpeed
            ram_mounting  = $ramMounting
            is_ram_mounting_confirmed = $ramMountingConfirmed
            memory_read_via = $memorySource
            memory_modules = $memoryModules
            gpu           = $gpuName
            disks         = $disks
            disk_c        = [ordered]@{ free_gb = $cFreeGb; total_gb = $cTotalGb; free_percent = $cPctFree }
        }
        network_adapters = $network
    }
}

# ============================ MODULE: license =================================
# Windows activation + traces of unofficial activators
function Get-LicenseInfo {
    $appIdWin = '55c92734-d682-4d71-983e-d6ec3f16059f'   # Windows OS ApplicationID
    $lic = Get-CimSafe -Class 'SoftwareLicensingProduct' -Filter "ApplicationID='$appIdWin' AND PartialProductKey <> null"
    $lic = $lic | Select-Object -First 1
    $statusCode = $null; $status = $null; $channel = $null; $partialKey = $null
    if ($lic) {
        $statusCode = [int]$lic.LicenseStatus
        $status     = $script:LicenseStatusMap[$statusCode]
        $channel    = $lic.ProductKeyChannel      # OEM / Retail / Volume:GVLK ... (tecnicismo, se conserva - R18)
        $partialKey = $lic.PartialProductKey       # last 5 chars of the key
    }
    $sls = Get-CimSafe 'SoftwareLicensingService'
    $isOemFirmware = [bool]($sls -and $sls.OA3xOriginalProductKey)
    $osCaption = if ($o = Get-CimSafe 'Win32_OperatingSystem') { $o.Caption } else { '' }

    # findings (Spanish, user-facing)
    if ($null -ne $statusCode -and $statusCode -ne 1) {
        Add-Finding -Code 'windows_not_activated' -Severity 'medium' -Oea @('9.5') -Message "Windows NO activado correctamente (estado: $status)."
    }
    if ($channel -match 'GVLK') {
        if ($osCaption -match 'Home') {
            Add-Finding -Code 'windows_home_volume_activation' -Severity 'high' -Oea @('9.5') -Message 'Windows Home activado con clave de volumen (GVLK/KMS): activacion NO legitima (Home no se licencia por volumen). regularizar licencia.'
        } else {
            Add-Finding -Code 'windows_volume_activation' -Severity 'medium' -Oea @('9.5') -Message 'Activacion por clave de volumen (GVLK/KMS). verificar licenciamiento por volumen legitimo; en una red sin dominio/KMS suele indicar activador no oficial.'
        }
    }

    $winKms = $null
    if ($lic) { $winKms = if ($lic.KeyManagementServiceMachine) { "$($lic.KeyManagementServiceMachine)" } elseif ($lic.DiscoveredKeyManagementServiceMachineName) { "$($lic.DiscoveredKeyManagementServiceMachineName)" } else { $null } }

    return [ordered]@{
        license = [ordered]@{
            status          = $status
            status_code     = $statusCode
            channel         = $channel
            partial_key     = $partialKey
            is_oem_firmware = $isOemFirmware
            kms_host        = $winKms
            activation_tampering = Get-ActivationTampering
        }
    }
}

# Traces of unofficial activators (OEA 9.5 licensing + 9.7 security). Fixed paths/keys/tasks only (fast, read-only).
# Signatures taken from the activators' own source code (verified 2026-09-27):
#   MAS Ohook      : sppc*.dll inside the Office folder (C2R root\vfs\System|SystemX86, MSI Office1x) - Office never ships it
#   MAS Online KMS : task \Activation-Renewal, folder "Program Files\Activation-Renewal", SPP KeyManagementServiceName
#   KMS_VL_ALL     : SppExtComObjHook*.dll / SppExtComObjPatcher.* in System32|SysWOW64, IFEO VerifierDlls/KMS_Emulation on
#                    SppExtComObj.exe|sppsvc.exe|osppsvc.exe, task \Microsoft\Windows\SoftwareProtectionPlatform\SvcTrigger
# NOT detectable locally (documented limit): MAS HWID (license lives on Microsoft servers, nothing stays on the PC).
function Get-ActivationTampering {
    $officeHooks = @()
    $officeDirs = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun', 'HKLM:\SOFTWARE\Microsoft\Office\15.0\ClickToRun') {
        try { $ip = (Get-ItemProperty $k -Name InstallPath -ErrorAction Stop).InstallPath; if ($ip) { $officeDirs += (Join-Path $ip 'root\vfs\System'); $officeDirs += (Join-Path $ip 'root\vfs\SystemX86') } } catch { }
    }
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }) {
        foreach ($v in 'Office14', 'Office15', 'Office16') { $officeDirs += (Join-Path $pf "Microsoft Office\$v") }
    }
    foreach ($d in ($officeDirs | Select-Object -Unique)) {
        if (-not (Test-Path $d)) { continue }
        foreach ($f in @(Get-ChildItem $d -Filter 'sppc*.dll' -File -ErrorAction SilentlyContinue)) {
            $sig = $null; try { $sig = "$((Get-AuthenticodeSignature $f.FullName -ErrorAction Stop).Status)" } catch { }
            $officeHooks += [ordered]@{ path = $f.FullName; size_bytes = [int64]$f.Length; modified_at = ConvertTo-IsoTimestamp $f.LastWriteTime; signature_status = $sig }
        }
    }

    $emulatorFiles = @()
    foreach ($d in @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64")) {
        foreach ($n in 'SppExtComObjHook.dll', 'SppExtComObjHookAvrf.dll', 'SppExtComObjPatcher.dll', 'SppExtComObjPatcher.exe') {
            $fp = Join-Path $d $n; if (Test-Path $fp) { $emulatorFiles += $fp }
        }
    }
    $ifeoHooks = @()
    foreach ($exe in 'SppExtComObj.exe', 'sppsvc.exe', 'osppsvc.exe') {
        $k = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$exe"
        try {
            $v = Get-ItemProperty $k -ErrorAction Stop
            if ($v.VerifierDlls -or $v.Debugger -or ($null -ne $v.KMS_Emulation)) { $ifeoHooks += [ordered]@{ process = $exe; verifier_dlls = "$($v.VerifierDlls)"; debugger = "$($v.Debugger)"; has_kms_emulation = ($null -ne $v.KMS_Emulation) } }
        } catch { }
    }
    $tasks = @()
    foreach ($t in @(@{ path = '\'; name = 'Activation-Renewal' }, @{ path = '\Microsoft\Windows\SoftwareProtectionPlatform\'; name = 'SvcTrigger' })) {
        try { if (Get-ScheduledTask -TaskPath $t.path -TaskName $t.name -ErrorAction Stop) { $tasks += ($t.path + $t.name) } } catch { }
    }
    $renewalFolder = Join-Path $env:ProgramFiles 'Activation-Renewal'
    $sppKms = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform') {
        try { $n = (Get-ItemProperty $k -Name KeyManagementServiceName -ErrorAction Stop).KeyManagementServiceName; if ($n) { $sppKms += "$n" } } catch { }
    }
    $sppKms = @($sppKms | Select-Object -Unique)

    $indicators = @()
    if ($officeHooks.Count -gt 0)   { $indicators += 'office_hook_dll' }
    if ($emulatorFiles.Count -gt 0) { $indicators += 'kms_emulator_files' }
    if ($ifeoHooks.Count -gt 0)     { $indicators += 'ifeo_hook' }
    if ($tasks.Count -gt 0)         { $indicators += 'renewal_task' }
    if (Test-Path $renewalFolder)   { $indicators += 'renewal_folder' }
    $cs = Get-CimSafe 'Win32_ComputerSystem'
    if ($sppKms.Count -gt 0 -and -not ($cs -and $cs.PartOfDomain)) { $indicators += 'kms_host_without_domain' }

    # findings (Spanish, user-facing) - worded as traces, not accusations
    if ($officeHooks.Count -gt 0) { Add-Finding -Code 'office_activation_hook' -Severity 'high' -Oea @('9.5','9.7') -Message ("Rastros de activador no oficial de Office (archivo sppc.dll dentro de la carpeta de Office, firma: " + (($officeHooks | ForEach-Object { $_.signature_status }) -join '/') + "): Office puede figurar activado sin licencia valida. Regularizar la licencia y limpiar el componente.") }
    if ($emulatorFiles.Count -gt 0 -or $ifeoHooks.Count -gt 0) { Add-Finding -Code 'kms_emulator' -Severity 'high' -Oea @('9.5','9.7') -Message 'Rastros de emulador KMS local (componente inyectado en el servicio de licencias de Windows): riesgo de licencia y de seguridad. Regularizar y limpiar.' }
    if ($tasks.Count -gt 0 -or (Test-Path $renewalFolder)) { Add-Finding -Code 'activation_renewal_task' -Severity 'high' -Oea @('9.5','9.7') -Message ("Tarea/carpeta de renovacion automatica de activacion no oficial: $((@($tasks) + @(if (Test-Path $renewalFolder) { $renewalFolder })) -join ', ').") }
    if ('kms_host_without_domain' -in $indicators) { Add-Finding -Code 'kms_host_without_domain' -Severity 'medium' -Oea @('9.5') -Message ("Servidor KMS configurado ($($sppKms -join ', ')) en un equipo sin dominio: tipico de activacion no oficial.") }

    return [ordered]@{
        indicators          = $indicators
        office_hook_dlls    = $officeHooks
        kms_emulator_files  = $emulatorFiles
        ifeo_hooks          = $ifeoHooks
        renewal_tasks       = $tasks
        has_renewal_folder  = [bool](Test-Path $renewalFolder)
        spp_kms_hosts       = $sppKms
    }
}

# ============================ MODULE: office ==================================
# Office licensing (SPP/OSPP/Click-to-Run) + end of support
# Office licensing (OEA 9.5). Sources, all read-only:
#   SoftwareLicensingProduct (SPP)            -> Office 2013+/C2R products with an installed key (channel, status, KMS host)
#   OfficeSoftwareProtectionProduct (OSPP)     -> Office 2010/2013 MSI (class only exists if osppsvc is installed)
#   HKLM ...\Office\ClickToRun\Configuration   -> installed C2R products (e.g. ProPlus2021Volume / O365ProPlusRetail)
#   <user profile>\AppData\Local\Microsoft\Office\Licenses -> Microsoft 365 per-user (vNext) licenses of the AUDITED user
function Get-OfficeYear([string]$Text) {
    if ($Text -match 'Office\s?(\d{2})') { $v = [int]$Matches[1]; if ($script:OfficeYearMap.ContainsKey($v)) { return $script:OfficeYearMap[$v] } }
    return $null
}

# Product year of an Office license row, or $null when the internal 'Office 16' family is NOT a product year: Microsoft 365
# subscriptions and the free companions of current Click-to-Run builds - OneNote, Access Runtime, Skype for Business Basic
# (seen 2026-09-29 on a real client PC:
# 'Office16OneNoteFreeR_Bypass' on build 16.0.20326 was reported as 'Office 2016 without support').
function Get-OfficeProductYear([string]$Family, [string]$Name, [string]$Kind) {
    if ($Kind -eq 'subscription' -or "$Family" -match 'OneNoteFree|AccessRuntime|SkypeforBusinessEntry') { return $null }
    return Get-OfficeYear "$Family $Name"
}

function Get-ActivationKind([string]$Channel, [string]$Family) {
    if ("$Family" -match 'O365|Subscription') { return 'subscription' }
    switch -Regex ("$Channel") {
        'GVLK|KMS' { return 'volume_kms' }
        'MAK'      { return 'volume_mak' }
        '^OEM'     { return 'oem' }
        'Retail'   { return 'retail' }
    }
    return 'unknown'
}

function Get-OfficeLicensing {
    $products = @()
    $sources = @(
        @{ class = 'SoftwareLicensingProduct';        source = 'spp' },
        @{ class = 'OfficeSoftwareProtectionProduct'; source = 'ospp' }
    )
    foreach ($src in $sources) {
        $rows = Get-CimSafe -Class $src.class -Filter "ApplicationID='$($script:OfficeAppId)' AND PartialProductKey <> null"
        foreach ($p in @($rows | Where-Object { $_ })) {
            $family = "$($p.LicenseFamily)"
            $kind = Get-ActivationKind "$($p.ProductKeyChannel) $($p.Description)" $family
            $year = Get-OfficeProductYear $family "$($p.Name)" $kind
            $eol  = if ($kind -ne 'subscription' -and $year -and $script:OfficeEol.ContainsKey($year)) { $script:OfficeEol[$year] } else { $null }
            $kms  = if ($p.KeyManagementServiceMachine) { "$($p.KeyManagementServiceMachine)" } elseif ($p.DiscoveredKeyManagementServiceMachineName) { "$($p.DiscoveredKeyManagementServiceMachineName)" } else { $null }
            $products += [ordered]@{
                name              = "$($p.Name)"
                license_family    = $family
                version_year      = $year
                channel           = "$($p.ProductKeyChannel)"   # raw SPP channel (Retail / OEM:DM / Volume:GVLK / Volume:MAK)
                activation_kind   = $kind
                status            = $script:LicenseStatusMap[[int]$p.LicenseStatus]
                status_code       = [int]$p.LicenseStatus
                partial_key       = "$($p.PartialProductKey)"
                grace_minutes     = if ($null -ne $p.GracePeriodRemaining) { [int]$p.GracePeriodRemaining } else { $null }
                kms_host          = $kms
                end_of_support_date = $eol
                read_via          = $src.source
            }
        }
    }

    # Click-to-Run configuration (what is installed, independent of the license)
    $c2r = $null
    try {
        $cfg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction Stop
        $channelId = $null
        if ("$($cfg.CDNBaseUrl)" -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') { $channelId = $Matches[1].ToLower() }
        $c2r = [ordered]@{
            product_release_ids = @("$($cfg.ProductReleaseIds)".Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            version             = "$($cfg.VersionToReport)"
            platform            = "$($cfg.Platform)"
            provider_update_channel_id = $channelId
        }
    } catch { $c2r = $null }

    # KMS host configured for Office (OSPP registry, used by Office 2010/2013 and some activators)
    $osppKms = $null
    try { $osppKms = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform' -Name KeyManagementServiceName -ErrorAction Stop).KeyManagementServiceName } catch { }

    # Microsoft 365 per-user licenses of the audited user
    $userLicenseCount = $null
    $prof = (Resolve-AuditedUser).profile_path
    if ($prof) {
        $licDir = Join-Path $prof 'AppData\Local\Microsoft\Office\Licenses'
        $userLicenseCount = if (Test-Path $licDir) { @(Get-ChildItem $licDir -Recurse -File -ErrorAction SilentlyContinue).Count } else { 0 }
    }

    $releaseIds = if ($c2r) { @($c2r.product_release_ids) } else { @() }
    $isSubscription = [bool](($releaseIds -match 'O365') -or ($products | Where-Object { $_.activation_kind -eq 'subscription' }))
    $isInstalled = [bool]($c2r -or $products.Count -gt 0)

    # findings (Spanish, user-facing)
    $cs = Get-CimSafe 'Win32_ComputerSystem'
    $inDomain = [bool]($cs -and $cs.PartOfDomain)
    foreach ($p in $products) {
        $label = if ($p.version_year) { "Office $($p.version_year)" } else { $p.name }
        if ($p.status_code -ne 1) { Add-Finding -Code 'office_not_activated' -Severity 'medium' -Oea @('9.5') -Message "$label NO activado (estado: $($p.status)): regularizar la licencia." }
        if ($p.activation_kind -eq 'volume_kms' -and -not $inDomain) {
            $hostTxt = if ($p.kms_host) { " (servidor KMS: $($p.kms_host))" } else { '' }
            Add-Finding -Code 'office_kms_without_domain' -Severity 'high' -Oea @('9.5') -Message "$label activado por clave de volumen (KMS)$hostTxt en un equipo sin dominio: salvo contrato de licencias por volumen de Microsoft, indica un activador no oficial. Verificar y regularizar."
        }
        $d = Get-DaysUntil $p.end_of_support_date
        if ($null -ne $d -and $d -lt 0) { Add-Finding -Code 'office_end_of_support' -Severity 'high' -Oea @('9.7') -Message "$label SIN SOPORTE desde el $($p.end_of_support_date): sin parches de seguridad. Migrar a una version soportada." }
        elseif ($null -ne $d -and $d -le $script:EolWarningDays) { Add-Finding -Code 'office_end_of_support_soon' -Severity 'medium' -Oea @('9.7') -Message "${label}: el soporte termina el $($p.end_of_support_date) (en $d dias). Planificar la migracion." }
    }
    if ($isInstalled -and $products.Count -eq 0 -and -not $isSubscription) {
        Add-Finding -Code 'office_license_undetected' -Severity 'medium' -Oea @('9.5') -Message 'Office instalado sin licencia detectable en el equipo: verificar como esta licenciado.'
    }

    return [ordered]@{
        office = [ordered]@{
            is_installed                = $isInstalled
            is_subscription             = $isSubscription
            products                    = $products
            click_to_run                = $c2r
            configured_kms_host         = $osppKms
            user_subscription_license_count = $userLicenseCount
        }
    }
}

# ============================ MODULE: software ================================
# installed software + end of support of known products
function Get-InstalledSoftware {
    $inventory = Get-SoftwareInventory
    # end of support of known products (offline table)
    $eolItems = @()
    foreach ($rule in $script:SoftwareEol) {
        $hit = @($inventory | Where-Object { "$($_.name)".Trim() -imatch $rule.match })
        if ($hit.Count -gt 0) { $eolItems += [ordered]@{ product = $rule.product; name = "$($hit[0].name)".Trim(); end_of_support_date = $rule.end } }
    }
    foreach ($e in $eolItems) {
        $d = Get-DaysUntil $e.end_of_support_date
        if ($null -ne $d -and $d -lt 0) { Add-Finding -Code 'software_end_of_support' -Severity 'high' -Oea @('9.7') -Message "$($e.product) instalado y SIN SOPORTE desde el $($e.end_of_support_date): sin parches de seguridad. Desinstalar si es un remanente o migrar." }
        elseif ($null -ne $d -and $d -le $script:EolWarningDays) { Add-Finding -Code 'software_end_of_support_soon' -Severity 'medium' -Oea @('9.7') -Message "$($e.product): el soporte termina el $($e.end_of_support_date) (en $d dias). Planificar la migracion." }
    }
    return [ordered]@{
        software = [ordered]@{
            item_count = @($inventory).Count
            items      = $inventory
            end_of_support_items = $eolItems
        }
    }
}

# ============================ MODULE: antivirus ===============================
# Security Center products + Microsoft Defender
# Defender detection history (MSFT_MpThreatDetection) of the last N days joined to the threat names (MSFT_MpThreat), newest
# first. ActionSuccess is the documented "was the action successful" flag ($null when Windows does not say); ThreatStatusID
# and CleaningActionID are kept RAW: real PCs report values the archived doc does not list (status 106, and 104
# 'AllowFailed' with ActionSuccess=True on an inactive threat; CleaningActionID 9 with ActionSuccess=True - ROD-PC
# 2026-10-01), so neither a status rule nor the word 'resolved' is asserted.
function Get-DefenderDetections($Detections, $Threats, [datetime]$Since) {
    $byId = @{}; foreach ($t in @($Threats | Where-Object { $_ })) { $byId["$($t.ThreatID)"] = $t }
    $rows = @()
    foreach ($d in @($Detections | Where-Object { $_ -and $_.InitialDetectionTime })) {
        $first = [datetime]$d.InitialDetectionTime
        $changed = if ($d.LastThreatStatusChangeTime) { [datetime]$d.LastThreatStatusChangeTime } else { $first }
        if ($changed -lt $Since) { continue }
        $rows += [pscustomobject]@{ changed = $changed; first = $first; d = $d; t = $byId["$($d.ThreatID)"] }
    }
    return ,@($rows | Sort-Object changed -Descending | Select-Object -First 20 | ForEach-Object {
        [ordered]@{
            provider_threat_id   = [int64]$_.d.ThreatID
            threat_name          = if ($_.t) { "$($_.t.ThreatName)" } else { $null }
            severity_code        = if ($_.t) { [int]$_.t.SeverityID } else { $null }
            detected_at          = ConvertTo-IsoTimestamp $_.first
            status_changed_at    = ConvertTo-IsoTimestamp $_.changed
            threat_status_code   = [int]$_.d.ThreatStatusID
            cleaning_action_code = if ($null -ne $_.d.CleaningActionID) { [int]$_.d.CleaningActionID } else { $null }
            is_action_successful = if ($null -ne $_.d.ActionSuccess) { [bool]$_.d.ActionSuccess } else { $null }
        }
    })
}

function Get-AntivirusStatus {
    $os = Get-CimSafe 'Win32_OperatingSystem'
    $prodType = if ($os) { [int]$os.ProductType } else { 1 }
    $products = @()
    # SecurityCenter2 exists on workstations (not on Windows Server).
    if ($prodType -eq 1) {
        $avProds = Get-CimSafe -Class 'AntiVirusProduct' -Namespace 'root\SecurityCenter2'
        if ($avProds) {
            foreach ($av in $avProds) {
                $st = Get-AvState ([long]$av.productState)
                $products += [ordered]@{ name = $av.displayName; is_enabled = [bool]$st.Enabled; is_up_to_date = [bool]$st.UpToDate; product_state_hex = $st.RawHex }
                if (-not $st.Enabled) { Add-Finding -Code 'antivirus_disabled' -Severity 'high' -Oea @('9.7') -Message "Antivirus '$($av.displayName)' aparece DESACTIVADO." }
                elseif (-not $st.UpToDate) { Add-Finding -Code 'antivirus_signatures_outdated' -Severity 'high' -Oea @('9.7') -Message "Antivirus '$($av.displayName)' con firmas DESACTUALIZADAS." }
            }
        } else {
            Add-Finding -Code 'antivirus_missing' -Severity 'high' -Oea @('9.7') -Message 'No se detecto ningun antivirus registrado en el Centro de Seguridad.'
        }
    }
    # Windows Defender (authoritative when available).
    $mp = $null
    try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { $mp = $null }
    $defender = $null
    if ($mp) {
        # signatures out of date: Defender's own flag when present (newer platforms), else age > 7 days
        $sigAge = if ($null -ne $mp.AntivirusSignatureAge) { [int]$mp.AntivirusSignatureAge } else { $null }
        $sigOutOfDate = if ($null -ne $mp.DefenderSignaturesOutOfDate) { [bool]$mp.DefenderSignaturesOutOfDate } elseif ($null -ne $sigAge) { $sigAge -gt 7 } else { $null }
        # preferences: exclusions are hidden without admin ("N/A: Must be an administrator...") -> null = not measured
        $pref = $null; try { $pref = Get-MpPreference -ErrorAction Stop } catch { }
        $exclusions = $null
        if ($pref) {
            $all = @(@($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension)) | Where-Object { $_ }
            if (-not ($all | Where-Object { "$_" -match '^N/A' })) { $exclusions = @($all | ForEach-Object { "$_" }) }
        }
        # ASR rules: action 1 = block, 2 = audit, 6 = warn (per Microsoft ASR reference). Data only.
        $asr = $null
        if ($pref -and $null -ne $pref.AttackSurfaceReductionRules_Ids -and -not (@($pref.AttackSurfaceReductionRules_Ids) | Where-Object { "$_" -match '^N/A' })) {
            $acts = @($pref.AttackSurfaceReductionRules_Actions | ForEach-Object { [int]$_ })
            $asr = [ordered]@{ rule_count = @($pref.AttackSurfaceReductionRules_Ids).Count; block_count = @($acts | Where-Object { $_ -eq 1 }).Count; audit_count = @($acts | Where-Object { $_ -eq 2 }).Count; warn_count = @($acts | Where-Object { $_ -eq 6 }).Count }
        } elseif ($pref) { $asr = [ordered]@{ rule_count = 0; block_count = 0; audit_count = 0; warn_count = 0 } }
        # threats Defender has seen on this PC (history) - names only
        $mpThreats = @()
        try { $mpThreats = @(Get-MpThreat -ErrorAction Stop | Where-Object { $_ }) } catch { }
        $threats = @($mpThreats | ForEach-Object { [ordered]@{ name = "$($_.ThreatName)"; severity_code = [int]$_.SeverityID; is_active = [bool]$_.IsActive } })
        # detection history of the last N days: when, and whether Defender's action worked (no file paths / user names kept)
        $detections = $null
        try { $detRaw = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_ }); $detections = Get-DefenderDetections $detRaw $mpThreats ((Get-Date).AddDays(-$script:EventWindowDays)) } catch { }
        $defender = [ordered]@{
            is_enabled                      = [bool]$mp.AntivirusEnabled
            is_real_time_protection_enabled = [bool]$mp.RealTimeProtectionEnabled
            running_mode                    = "$($mp.AMRunningMode)"
            signature_version               = $mp.AntivirusSignatureVersion
            signature_updated_at            = ConvertTo-IsoTimestamp $mp.AntivirusSignatureLastUpdated
            signature_age_days              = $sigAge
            is_signature_out_of_date        = $sigOutOfDate
            is_tamper_protected             = [bool]$mp.IsTamperProtected
            is_pua_protection_enabled       = if ($pref) { ([int]$pref.PUAProtection -eq 1) } else { $null }
            is_cloud_protection_enabled     = if ($pref) { ([int]$pref.MAPSReporting -gt 0) } else { $null }
            exclusions                      = $exclusions
            asr_rules                       = $asr
            threats                         = $threats
            last_quick_scan_at              = if ($null -ne $mp.QuickScanAge -and [uint32]$mp.QuickScanAge -ne [uint32]::MaxValue) { ConvertTo-IsoTimestamp $mp.QuickScanEndTime } else { $null }
            last_full_scan_at               = if ($null -ne $mp.FullScanAge -and [uint32]$mp.FullScanAge -ne [uint32]::MaxValue) { ConvertTo-IsoTimestamp $mp.FullScanEndTime } else { $null }
            detections                      = $detections
            detection_window_days           = $script:EventWindowDays
        }
        # findings (Spanish)
        if ($defender.is_enabled -and $sigOutOfDate) { Add-Finding -Code 'defender_signatures_outdated' -Severity 'high' -Oea @('9.7') -Message "Firmas de Microsoft Defender DESACTUALIZADAS (antiguedad: $sigAge dias): revisar Windows Update." }
        if ($defender.is_enabled -and $pref -and -not $defender.is_pua_protection_enabled) { Add-Finding -Code 'defender_pua_disabled' -Severity 'low' -Oea @('9.7') -Message 'Defender sin bloqueo de aplicaciones potencialmente no deseadas (PUA): activarlo.' }
        if ($exclusions -and $exclusions.Count -gt 0) { Add-Finding -Code 'defender_exclusions' -Severity 'medium' -Oea @('9.7') -Message ("Defender tiene EXCLUSIONES configuradas: $($exclusions -join ' ; '): revisar que cada una este justificada.") }
        $hack = @($threats | Where-Object { $_.name -match 'HackTool|AutoKMS|KMSAuto|Keygen|Crack' } | ForEach-Object { $_.name } | Select-Object -Unique)
        if ($hack.Count -gt 0) { Add-Finding -Code 'defender_hacktool_detected' -Severity 'high' -Oea @('9.5','9.7') -Message ("Defender detecto herramientas de activacion/crackeo en este equipo: $($hack -join ', ').") }
        $active = @($threats | Where-Object { $_.is_active } | ForEach-Object { $_.name } | Select-Object -Unique)
        if ($active.Count -gt 0) { Add-Finding -Code 'defender_active_threats' -Severity 'high' -Oea @('9.7') -Message ("Amenazas ACTIVAS segun Defender: $($active -join ', '): remediar.") }
        # detection history: judged on each threat's LATEST detection (a later successful action supersedes a failed one);
        # active threats and activation tools already have their own finding above. 'Failed' only when Defender is the
        # active antivirus and says so explicitly: in passive mode (another antivirus in charge) it does not remediate.
        $latest = @(@($detections) | Where-Object { $_ } | Group-Object { $_.provider_threat_id } | ForEach-Object { @($_.Group)[0] } | Where-Object { $active -notcontains $_.threat_name })
        # 'EDR Block Mode' is passive but still remediates; platforms without AMRunningMode: enabled = in charge
        $isDefenderActive = if ("$($mp.AMRunningMode)".Trim()) { "$($mp.AMRunningMode)" -in @('Normal', 'EDR Block Mode') } else { [bool]$mp.AntivirusEnabled }
        $failed = @($latest | Where-Object { $isDefenderActive -and $_.is_action_successful -eq $false })
        $threatLabel = { "$(if ($_.threat_name) { $_.threat_name } else { "amenaza $($_.provider_threat_id)" }) ($("$($_.status_changed_at)".Substring(0, 10)))" }
        if ($failed.Count -gt 0) { Add-Finding -Code 'defender_remediation_failed' -Severity 'high' -Oea @('9.7') -EvidenceAt $failed[0].status_changed_at -Message ("Defender NO pudo completar la accion contra: $(@($failed | ForEach-Object $threatLabel) -join ', '): puede seguir presente; correr un analisis completo (o sin conexion) y revisar el historial de proteccion.") }
        $recent = @($latest | Where-Object { $failed -notcontains $_ -and "$($_.threat_name)" -notmatch 'HackTool|AutoKMS|KMSAuto|Keygen|Crack' })
        if ($recent.Count -gt 0) {
            $sev = if (@($recent | Where-Object { $_.severity_code -ge 3 }).Count -gt 0) { 'medium' } else { 'low' }   # 3+ = High/Severe (archived MSFT_MpThreat doc says 3/4, real output uses 4/5: both covered)
            Add-Finding -Code 'defender_recent_detections' -Severity $sev -Oea @('9.7') -EvidenceAt $recent[0].status_changed_at -Message ("Defender registro $($recent.Count) amenaza(s) en los ultimos $($script:EventWindowDays) dias: $(@($recent | Select-Object -First 5 | ForEach-Object $threatLabel) -join ', '): revisar por donde ingresaron (descargas, correo, pendrives) y que no queden rastros.")
        }
    }
    # summary / active / up-to-date
    $summary = $null; $isActive = $false; $isUpToDate = $null   # summary = product names (null = none detected)
    if ($products.Count -gt 0) {
        $summary    = ($products | ForEach-Object { $_.name }) -join ' + '
        $isActive   = [bool]($products | Where-Object { $_.is_enabled })
        $isUpToDate = [bool]($products | Where-Object { $_.is_up_to_date })
    } elseif ($defender) {
        $summary    = if ($defender.is_enabled) { 'Windows Defender' } else { $null }
        $isActive   = [bool]$defender.is_real_time_protection_enabled
        $isUpToDate = if ($null -ne $defender.is_signature_out_of_date) { -not $defender.is_signature_out_of_date } else { $null }   # measured, not inferred from is_enabled
    }
    # third-party AV present = something other than Windows Defender in the summary
    $hasThirdParty = [bool]("$summary" -and (("$summary" -replace 'windows defender', '').Trim(' +/,')))

    return [ordered]@{
        antivirus = [ordered]@{
            summary         = $summary
            is_active       = $isActive
            is_up_to_date   = $isUpToDate
            has_third_party = $hasThirdParty
            products        = $products
            defender        = $defender
        }
    }
}

# ============================ MODULE: security ================================
# disk encryption, firewall, TPM/Secure Boot, session protection
function Get-SessionProtection {
    # 9.8 autologin
    $autologin = $false
    try { $autologin = ("$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction Stop).AutoAdminLogon)" -eq '1') } catch { }

    # 9.2 screen lock by inactivity
    $inactivity = $null
    try { $inactivity = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name InactivityTimeoutSecs -ErrorAction Stop).InactivityTimeoutSecs } catch { }
    $ssSecure = $null
    $desktopKey = Get-UserRegPath 'Control Panel\Desktop'   # audited user's hive (not the elevating account)
    try { $ss = Get-ItemProperty $desktopKey -ErrorAction Stop; if ("$($ss.ScreenSaveActive)" -eq '1') { $ssSecure = ("$($ss.ScreenSaverIsSecure)" -eq '1') } } catch { }

    if ($autologin) { Add-Finding -Code 'autologin_enabled' -Severity 'high' -Oea @('9.8') -Message 'Inicio de sesion automatico (autologin) habilitado: con acceso fisico se entra sin contrasena.' }
    if ((-not $inactivity) -and (-not $ssSecure) -and (Resolve-AuditedUser).is_hive_available) { Add-Finding -Code 'screen_lock_missing' -Severity 'medium' -Oea @('9.2') -Message 'Sin bloqueo de pantalla automatico por inactividad: configurar bloqueo tras N minutos.' }
    return [ordered]@{ is_autologin_enabled = $autologin; screen_lock = [ordered]@{ inactivity_timeout_seconds = $inactivity; is_screensaver_secure = $ssSecure } }
}

function Get-KeyProtectorKinds($Volume) {
    $kinds = @()
    foreach ($p in @($Volume.KeyProtector)) { if ($p) { $kinds += ("$($p.KeyProtectorType)" -creplace '([a-z])([A-Z])', '$1_$2').ToLower() } }
    return ,$kinds
}

# 'awaiting_activation' vs 'suspended' is told apart by the UNLOCK protector (tpm*, password, startup key...): device
# encryption keeps only a clear key until an admin Microsoft/Entra/AD account backs up the recovery key, and on AD/Entra
# the recovery password is created BEFORE the TPM protector - a failed backup leaves Off + 100% + {recovery_password}
# (learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/, "Device encryption").
function Get-BitLockerEncryptionStatus([string]$ProtectionStatus, $EncryptionPercent, [string]$VolumeStatus, $KeyProtectorKinds) {
    if ($VolumeStatus -like 'encryption*') { return 'encrypting' }   # encryption_in_progress | encryption_paused
    if ($VolumeStatus -like 'decryption*') { return 'decrypting' }   # decryption_in_progress | decryption_paused
    if ($ProtectionStatus -eq 'on') { return 'protected' }
    if ($ProtectionStatus -ne 'off') { return 'unknown' }
    if ($EncryptionPercent -eq 100) {
        if (@($KeyProtectorKinds | Where-Object { $_ -and $_ -ne 'recovery_password' }).Count -eq 0) { return 'awaiting_activation' }
        return 'suspended'
    }
    return 'unencrypted'
}

# msinfo32 computes two properties no WMI class exposes (Kernel DMA Protection, Device Encryption support). Labels are
# localized: Spanish verified on a real es-AR PC, English from learn.microsoft.com. Accented letters matched with '.'.
function ConvertFrom-MsinfoSummary([string[]]$Lines) {
    $r = [ordered]@{ kernel_dma_protection = $null; device_encryption_support = $null; device_encryption_support_text = $null }
    foreach ($line in @($Lines)) {
        $parts = "$line".Split("`t")
        if ($parts.Count -lt 2) { continue }
        $label = $parts[0].Trim(); $value = $parts[1].Trim()
        if ($label -match '^(Protecci.n de DMA de kernel|Kernel DMA Protection)$') {
            $r.kernel_dma_protection = if ($value -match '^(Activad|On$)') { 'on' } elseif ($value -match '^(Desactivad|Off$)') { 'off' } else { $null }
        }
        elseif ($label -match 'cifrado de dispositivo|Device Encryption Support') {
            $r.device_encryption_support = if ($value -match 'reason|motivo|raz.n') { 'not_met' }
                                           elseif ($value -match '^(meets prerequisites|cumple)') { 'meets_prerequisites' }
                                           elseif ($value -match 'elevation|elevaci') { 'elevation_required' }
                                           elseif ($value) { 'unknown' } else { $null }
            if ($r.device_encryption_support -in @('not_met', 'unknown')) { $r.device_encryption_support_text = $value }
        }
    }
    return $r
}

# 30-second steps as m:ss (1 -> '0:30', 2 -> '1:00', 9 -> '4:30')
function Format-HalfMinutes([int]$Steps) { return ('{0}:{1:D2}' -f [int][math]::Floor($Steps / 2), (($Steps % 2) * 30)) }

function Get-MsinfoSummary {
    # ~2 min + its own progress window -> admin only, and skipped in unattended runs unless -IncludeMsinfo
    if (-not $script:IsAdmin) { return [ordered]@{ status = 'skipped_no_admin'; data = $null } }
    if ($Silent -and -not $IncludeMsinfo) { return [ordered]@{ status = 'skipped_unattended'; data = $null } }
    $file = Join-Path $env:TEMP ('_ea_msinfo_{0}.txt' -f (Get-Random))
    Write-Host '  Recopilando informacion del sistema con msinfo32 (puede tardar hasta 5 minutos)...' -ForegroundColor DarkGray
    try {
        $proc = Start-Process -FilePath 'msinfo32.exe' -ArgumentList '/report', "`"$file`"" -PassThru
        # 30 s steps with a visible heartbeat: a silent wait looked like a hang on a client PC (2026-09-29)
        $done = $false
        for ($i = 1; $i -le 10; $i++) {
            if ($proc.WaitForExit(30000)) { $done = $true; break }
            if ($i -lt 10) { Write-Host ('   ... msinfo32 sigue trabajando ({0} de 5:00 como maximo)' -f (Format-HalfMinutes $i)) -ForegroundColor DarkGray }
        }
        if (-not $done) { try { $proc.Kill() } catch { }; Write-Host '   ... msinfo32 no termino en 5 minutos: se sigue sin ese dato.' -ForegroundColor DarkGray; return [ordered]@{ status = 'failed'; data = $null } }
        if (-not (Test-Path $file)) { return [ordered]@{ status = 'failed'; data = $null } }
        return [ordered]@{ status = 'collected'; data = ConvertFrom-MsinfoSummary (Get-Content -Path $file -Encoding Unicode -TotalCount 120) }
    }
    catch { return [ordered]@{ status = 'failed'; data = $null } }
    finally { Remove-Item $file -Force -ErrorAction SilentlyContinue }
}

# BitLocker Management log (readable without admin): 4103 = automatic Device Encryption failed (so Windows DID try:
# the PC qualifies), 828/829 = recovery key backed up / failed to back up to a Microsoft account, 770 = decryption started.
function Get-DeviceEncryptionHistory {
    $ev = $null
    try { $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'; Id = 4103, 828, 829, 770 } -MaxEvents 2000 -ErrorAction Stop) }
    catch { if ("$($_.FullyQualifiedErrorId)" -like 'NoMatchingEventsFound*') { $ev = @() } else { return $null } }
    # 770/828/829 are per volume (Properties[2] = mount point, e.g. 'C:'): a decrypted USB stick must not speak for C:
    $ev = @($ev | Where-Object { $_.Id -eq 4103 -or "$(try { $_.Properties[2].Value } catch { })" -eq 'C:' })
    $fail = @($ev | Where-Object { $_.Id -eq 4103 })   # newest first
    $code = $null
    if ($fail.Count -gt 0) { try { $code = '0x{0:X8}' -f [int]$fail[0].Properties[0].Value } catch { } }
    $last = { param($id) $x = @($ev | Where-Object { $_.Id -eq $id } | Select-Object -First 1); if ($x.Count) { ConvertTo-IsoTimestamp $x[0].TimeCreated } else { $null } }
    return [ordered]@{
        auto_enable_failure_count   = $fail.Count
        last_auto_enable_failure_at = & $last 4103
        last_auto_enable_error_code = $code
        key_backup_failure_count    = @($ev | Where-Object { $_.Id -eq 829 }).Count
        last_key_backup_at          = & $last 828
        last_decryption_started_at  = & $last 770
    }
}

# msinfo32 lists the reasons after a colon. 'Disabled by policy' ALONE means a policy blocks Device Encryption, not that the
# hardware lacks support (seen 2026-09-29: 'Razones del error de cifrado automatico de dispositivo: Deshabilitado por directiva').
function Test-DeviceEncryptionBlockedOnlyByPolicy([string]$SupportText) {
    if (-not $SupportText -or $SupportText -notmatch ':\s*(.+)$') { return $false }
    return ($Matches[1].Trim().TrimEnd('.').Trim() -match '^(Deshabilitad[oa] por (la )?directiva|Disabled by policy)$')
}

# Enabled non-built-in local accounts unused for 90+ days. Windows leaves LastLogon EMPTY for accounts that sign in with a
# Microsoft account / PIN (seen 2026-09-29: the very user running the audit was flagged). The audited user and the runner are
# in use by definition; otherwise the MOST RECENT of LastLogon and the profile's last use counts (no date at all = never
# used). Caveat: other software can refresh a profile's LastUseTime -> this is an inventory signal, not forensics.
function Get-InactiveLocalAccounts($LocalUsers, $SidByName, $ProfileLastUseBySid, $ActiveSids) {
    $out = @()
    foreach ($u in @($LocalUsers)) {
        if (-not $u -or -not $u.is_enabled -or $u.rid -lt 1000) { continue }
        $sid = if ($SidByName) { $SidByName[$u.name] } else { $null }
        if ($sid -and @($ActiveSids) -contains $sid) { continue }
        $dates = @(ConvertTo-IsoDate $u.last_logon_at)
        if ($sid -and $ProfileLastUseBySid) { $dates += $ProfileLastUseBySid[$sid] }
        $lastIso = @($dates | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)[0]   # ISO dates sort as text
        $days = Get-DaysUntil $lastIso
        if ($null -eq $days -or $days -lt -90) { $out += $u.name }
    }
    return ,$out
}

# Vendor WMI command consumers seen on real client PCs (2026-09-29). WMI consumers are a classic persistence trick, so a
# consumer is only treated as the vendor's when ALL hold: exact known name, CommandLineEventConsumer, executable inside
# '<ProgramFiles>\<Vendor>\' (normalized path, no '..' tricks) AND a valid Authenticode signature from the vendor. A
# look-alike name, an installed vendor program or '\Dell\' somewhere in the command are NOT enough (fresh-eyes review).
$script:KnownWmiConsumers = @(
    @{ names = @('DellCommandPowerManagerAlertEventConsumer', 'DellCommandPowerManagerPolicyChangeEventConsumer'); folder = 'Dell'; signer = 'Dell' }
)
# First token of a command line: '"C:\path with spaces\x.exe" args' or 'C:\path\x.exe args'.
function Get-CommandExecutable([string]$ExecutablePath, [string]$CommandLine) {
    if ("$ExecutablePath".Trim()) { return "$ExecutablePath".Trim().Trim('"') }
    $c = "$CommandLine".Trim()
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(\S+)') { return $Matches[1] }
    return $null
}
function Test-KnownVendorWmiConsumer([string]$Name, [string]$Kind, [string]$ExecutablePath, [string]$CommandLine) {
    if ($Kind -ne 'CommandLineEventConsumer') { return $false }
    $known = @($script:KnownWmiConsumers | Where-Object { $_.names -contains $Name } | Select-Object -First 1)
    if ($known.Count -eq 0) { return $false }
    $exe = Get-CommandExecutable $ExecutablePath $CommandLine
    if (-not $exe) { return $false }
    try { $exe = [IO.Path]::GetFullPath($exe) } catch { return $false }
    $roots = @(@($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object { (Join-Path $_ $known[0].folder) + '\' })
    if (@($roots | Where-Object { $exe.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 0) { return $false }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $false }
    $sig = $null
    try { $sig = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop } catch { return $false }
    return ([bool]$sig -and "$($sig.Status)" -eq 'Valid' -and "$($sig.SignerCertificate.Subject)" -match ('\b' + [regex]::Escape($known[0].signer) + '\b'))
}

function Get-UnencryptedDiskMessage($IsHome, $HasOsInfo, [int]$OsBuild, $Support, $SupportText, $AutoEnableFailures, $LastErrorCode, $SecureBoot, $FirmwareMode, $DecryptionStartedAt) {
    $msg = 'Disco SIN cifrar: robo/perdida del equipo = datos expuestos.'
    if ($DecryptionStartedAt) { $msg += " El cifrado se desactivo el $("$DecryptionStartedAt".Substring(0, 10))." }
    if (-not $HasOsInfo) { $msg += ' Cifrar con BitLocker (Windows Pro) o con el Cifrado de dispositivo (Windows Home).' }
    elseif (-not $IsHome) { $msg += ' Activar BitLocker.' }
    elseif ($Support -eq 'meets_prerequisites' -or ($Support -ne 'not_met' -and $AutoEnableFailures -gt 0 -and $LastErrorCode -eq '0x80070525')) {
        # 0x80070525 = no such user: Windows was ready to encrypt and only lacked an account to back the key up to
        $msg += ' Este equipo SI admite el Cifrado de dispositivo'
        if ($LastErrorCode -eq '0x80070525') { $msg += ' (no se activo solo porque no hay una cuenta Microsoft con rol de administrador)' }
        $msg += ': activarlo iniciando sesion con una cuenta Microsoft DE LA EMPRESA con rol de administrador.'
    }
    elseif ($Support -eq 'not_met' -and (Test-DeviceEncryptionBlockedOnlyByPolicy $SupportText)) {
        $msg += ' El Cifrado de dispositivo esta BLOQUEADO por una directiva (Windows no da ningun otro motivo): quitar esa directiva (en Windows Home suele ser el valor PreventDeviceEncryption en HKLM\SYSTEM\CurrentControlSet\Control\BitLocker) y volver a relevar para confirmar que el equipo lo admite.'
    }
    elseif ($Support -eq 'not_met') {
        $msg += " Este equipo NO admite el Cifrado de dispositivo (segun Windows: $SupportText): pasar a Pro (BitLocker)"
        if ($OsBuild -gt 0 -and $OsBuild -lt 26100) { $msg += ' o actualizar a Windows 11 24H2, que relaja los requisitos' }
        $msg += '.'
    }
    else {
        $msg += ' En Windows Home se usa el Cifrado de dispositivo, si el equipo lo admite (verificarlo en msinfo32).'
        if ($AutoEnableFailures -gt 0 -and $LastErrorCode) { $msg += " Windows intento activarlo y fallo (codigo $LastErrorCode)." }
        if ($OsBuild -gt 0 -and $OsBuild -lt 26100) { $msg += ' En esta version de Windows exige ademas hardware especifico: si no lo admite, actualizar a Windows 11 24H2 o pasar a Pro (BitLocker).' }
    }
    if (($SecureBoot -eq $false -or $FirmwareMode -eq 'legacy') -and ($IsHome -or -not $HasOsInfo)) {
        if ($FirmwareMode -eq 'legacy') { $msg += ' El equipo arranca en modo Legacy: Secure Boot y el Cifrado de dispositivo requieren UEFI (convertir el disco con mbr2gpt y pasar la BIOS a UEFI, con backup previo).' }
        elseif ($FirmwareMode -eq 'uefi') { $msg += ' Secure Boot desactivado: habilitarlo en la BIOS (requisito del Cifrado de dispositivo; el equipo ya arranca en UEFI).' }
        else { $msg += ' Secure Boot desactivado: habilitarlo primero (requisito del Cifrado de dispositivo; verificar antes que el equipo arranque en modo UEFI).' }
    }
    return $msg
}

function Get-SecurityPosture {
    $bl = $null
    # admin-only: without admin it always fails with "access denied" after ~5 s -> skip (result stays 'Unavailable')
    if ($script:IsAdmin) { try { $bl = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop } catch { $bl = $null } }
    # all fixed volumes (admin) - C: alone misses data partitions / second disks
    $blVolumes = $null
    if ($script:IsAdmin) {
        # Get-BitLockerVolume lists USB sticks as 'Data' too -> tag each letter with its drive kind
        $driveKinds = @{}
        foreach ($ld in @(Get-CimSafe -Class 'Win32_LogicalDisk')) {
            if ($ld) { $driveKinds["$($ld.DeviceID)"] = switch ([int]$ld.DriveType) { 2 { 'removable' } 3 { 'fixed' } 4 { 'network' } 5 { 'optical' } default { $null } } }
        }
        $blVolumes = @()
        try {
            foreach ($v in @(Get-BitLockerVolume -ErrorAction Stop)) {
                $vKinds = Get-KeyProtectorKinds $v
                $vVolumeStatus = ("$($v.VolumeStatus)" -creplace '([a-z])([A-Z])', '$1_$2').ToLower()
                $vProtection = "$($v.ProtectionStatus)".ToLower()
                $vPercent = [int][math]::Floor([double]$v.EncryptionPercentage)
                $blVolumes += [ordered]@{
                    mount_point         = "$($v.MountPoint)"
                    volume_kind         = ("$($v.VolumeType)" -creplace '([a-z])([A-Z])', '$1_$2').ToLower()
                    drive_kind          = $driveKinds["$($v.MountPoint)"]
                    status              = Get-BitLockerEncryptionStatus $vProtection $vPercent $vVolumeStatus $vKinds
                    protection_status   = $vProtection
                    encryption_percent  = $vPercent
                    volume_status       = $vVolumeStatus
                    key_protector_kinds = $vKinds
                }
            }
        } catch { $blVolumes = $null }
    }
    $protectionStatus  = if ($bl) { "$($bl.ProtectionStatus)".ToLower() } else { 'unknown' }   # on | off | unknown
    $encryptionPercent = if ($bl) { [int][math]::Floor([double]$bl.EncryptionPercentage) } else { $null }
    $volumeStatus = $null; $keyProtectorKinds = $null
    if ($bl) {
        $volumeStatus = ("$($bl.VolumeStatus)" -creplace '([a-z])([A-Z])', '$1_$2').ToLower()
        $keyProtectorKinds = Get-KeyProtectorKinds $bl
    }
    $encryptionStatus = Get-BitLockerEncryptionStatus $protectionStatus $encryptionPercent $volumeStatus $keyProtectorKinds
    # 9.8/9.9 recovery key present (needed to recover an encrypted disk)
    $hasRecoveryPassword = $null
    if ($bl) { try { $hasRecoveryPassword = [bool](@($bl.KeyProtector) | Where-Object { "$($_.KeyProtectorType)" -eq 'RecoveryPassword' }) } catch { } }

    # firewall profiles -> { domain, private, public } booleans
    $fw = $null
    try { $fw = Get-NetFirewallProfile -ErrorAction Stop } catch { $fw = $null }
    $firewall = [ordered]@{}
    if ($fw) { foreach ($p in $fw) { $pn = "$($p.Name)".ToLower(); $firewall["is_${pn}_enabled"] = [bool]$p.Enabled } }

    $session = Get-SessionProtection   # autologin + screen lock (moved from the old oea module)

    # TPM / Secure Boot (also feeds Win11 readiness)
    $tpm = $null
    try { $tpm = Get-Tpm -ErrorAction Stop } catch { $tpm = $null }
    $firmwareMode = switch ("$env:firmware_type") { 'UEFI' { 'uefi' } 'Legacy' { 'legacy' } default { $null } }   # OS-computed, not overridable
    $secureBoot = $null
    try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $secureBoot = $null }
    if ($null -eq $secureBoot -and $firmwareMode -eq 'legacy') { $secureBoot = $false }   # BIOS boot: Secure Boot cannot be on (the cmdlet just errors)
    $tpmSpec = $null   # e.g. '2.0' (Win32_Tpm needs admin)
    $wt = if ($script:IsAdmin) { Get-CimSafe -Class 'Win32_Tpm' -Namespace 'root\cimv2\Security\MicrosoftTpm' } else { $null }   # admin-only (~5 s access-denied otherwise)
    if ($wt -and $wt.SpecVersion) { $tpmSpec = ("$($wt.SpecVersion)".Split(',')[0]).Trim() }

    # Home has no BitLocker UI, only Device Encryption, which before Win11 24H2 (build 26100) also needs Modern
    # Standby/HSTI and no DMA-exposed ports (learn.microsoft.com BitLocker overview, "Device encryption").
    $osInfo = Get-CimSafe 'Win32_OperatingSystem'
    $isHome = [bool]($osInfo -and "$($osInfo.Caption)" -match 'Home')
    $osBuild = 0; [void][int]::TryParse("$(if ($osInfo) { $osInfo.BuildNumber })", [ref]$osBuild)
    $msinfo = Get-MsinfoSummary
    $deHistory = Get-DeviceEncryptionHistory
    $deSupport = if ($msinfo.data) { $msinfo.data.device_encryption_support } else { $null }

    # findings (Spanish) - 'unknown' (not measurable, e.g. no admin) asserts nothing
    switch ($encryptionStatus) {
        'unencrypted' {
            $msg = Get-UnencryptedDiskMessage -IsHome $isHome -HasOsInfo ([bool]$osInfo) -OsBuild $osBuild -Support $deSupport `
                -SupportText $(if ($msinfo.data) { $msinfo.data.device_encryption_support_text }) `
                -AutoEnableFailures $(if ($deHistory) { $deHistory.auto_enable_failure_count } else { 0 }) `
                -LastErrorCode $(if ($deHistory) { $deHistory.last_auto_enable_error_code }) -SecureBoot $secureBoot -FirmwareMode $firmwareMode `
                -DecryptionStartedAt $(if ($deHistory) { $deHistory.last_decryption_started_at })
            Add-Finding -Code 'disk_unencrypted' -Severity 'medium' -Oea @('9.8') -Message $msg
        }
        'awaiting_activation' {
            $how = if ($isHome) { 'iniciando sesion con una cuenta Microsoft DE LA EMPRESA con rol de administrador (la clave de recuperacion queda en esa cuenta)' }
                   else { 'iniciando sesion con una cuenta Microsoft DE LA EMPRESA con rol de administrador o activando BitLocker desde su panel (en dominio / Entra ID: habilitar el respaldo de la clave de recuperacion)' }
            Add-Finding -Code 'device_encryption_not_activated' -Severity 'medium' -Oea @('9.8') -Message "Disco cifrado pero SIN proteger: el cifrado nunca se activo y la clave quedo guardada sin proteccion en el mismo disco. Activarlo $how, y guardar una copia de la clave."
        }
        'suspended'  { Add-Finding -Code 'bitlocker_suspended' -Severity 'medium' -Oea @('9.8') -Message 'Disco cifrado pero con la proteccion de BitLocker SUSPENDIDA: reanudarla para que el cifrado sea efectivo.' }
        'decrypting' { Add-Finding -Code 'disk_decryption_in_progress' -Severity 'medium' -Oea @('9.8') -Message 'El disco se esta DESCIFRANDO (BitLocker en proceso de desactivarse): confirmar que sea intencional.' }
        'encrypting' { Add-Finding -Code 'disk_encryption_in_progress' -Severity 'info' -Message "Cifrado del disco EN CURSO ($encryptionPercent%): volver a verificar cuando termine." }
    }
    if ($protectionStatus -eq 'on' -and $hasRecoveryPassword -eq $false) { Add-Finding -Code 'bitlocker_no_recovery_key' -Severity 'medium' -Oea @('9.8','9.9') -Message 'BitLocker activo pero SIN clave de recuperacion: configurar y resguardar la clave de recuperacion.' }
    $unencData = @($blVolumes | Where-Object { $_ -and $_.volume_kind -eq 'data' -and $_.drive_kind -eq 'fixed' -and $_.status -in @('unencrypted', 'awaiting_activation', 'suspended', 'decrypting') } | ForEach-Object { $_.mount_point })
    if ($unencData.Count -gt 0) { Add-Finding -Code 'data_volume_unencrypted' -Severity 'medium' -Oea @('9.8') -Message ("Unidades de datos fijas SIN proteger (sin cifrar, o cifradas sin activar): $($unencData -join ', '). Protegerlas con BitLocker o con el Cifrado de dispositivo.") }
    $hasTbUsb4 = [bool](@(Get-CimSafe 'Win32_PnPEntity') | Where-Object { $_ -and "$($_.Name)" -match 'Thunderbolt|USB4' })
    if ($msinfo.data -and $msinfo.data.kernel_dma_protection -eq 'off' -and $hasTbUsb4) { Add-Finding -Code 'kernel_dma_protection_off' -Severity 'low' -Message 'Proteccion de DMA de kernel DESACTIVADA: si el equipo tiene puertos Thunderbolt/USB4, un dispositivo conectado con el equipo desatendido puede leer la memoria. Se activa habilitando la virtualizacion de E/S (VT-d / AMD-Vi / IOMMU) en la BIOS; si sigue apagada, el equipo no la admite.' }
    if ($fw -and ($fw | Where-Object { -not $_.Enabled })) { Add-Finding -Code 'firewall_profile_disabled' -Severity 'high' -Oea @('9.7') -Message 'Firewall con perfil(es) DESACTIVADO(s).' }

    return [ordered]@{
        security = [ordered]@{
            bitlocker              = [ordered]@{ status = $encryptionStatus; protection_status = $protectionStatus; encryption_percent = $encryptionPercent; volume_status = $volumeStatus; key_protector_kinds = $keyProtectorKinds; has_recovery_password = $hasRecoveryPassword }
            bitlocker_volumes      = $blVolumes
            firewall               = $firewall
            is_autologin_enabled   = $session.is_autologin_enabled
            screen_lock            = $session.screen_lock
            tpm                    = if ($tpm) { [ordered]@{ is_present = [bool]$tpm.TpmPresent; is_ready = [bool]$tpm.TpmReady; spec_version = $tpmSpec } } else { $null }
            is_secure_boot_enabled = $secureBoot
            firmware_mode          = $firmwareMode
            kernel_dma_protection  = if ($msinfo.data) { $msinfo.data.kernel_dma_protection } else { $null }
            has_thunderbolt_usb4_controller = $hasTbUsb4
            device_encryption      = [ordered]@{
                support         = $deSupport
                support_text    = if ($msinfo.data) { $msinfo.data.device_encryption_support_text } else { $null }
                history         = $deHistory
            }
            msinfo32_status        = $msinfo.status
        }
    }
}

# ============================ MODULE: hardening ===============================
# configuration hardening (SMB, UAC, credentials, baseline, firewall rules, features)
function Get-SharedFolders {
    # 9.4/9.8 shared folders (non-administrative)
    $shared = @()
    try { $shared = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '\$$' } | ForEach-Object { "$($_.Name) -> $($_.Path)" }) } catch { }

    if ($shared.Count -gt 0) { Add-Finding -Code 'shared_folders' -Severity 'low' -Oea @('9.4','9.8') -Message ("Carpetas compartidas en red: $($shared -join ' ; '): revisar necesidad y permisos.") }
    return ,@($shared)
}

# Security configuration (OEA 9.7). Registry locations per Microsoft docs unless marked NOT VERIFIED.
function Get-Hardening {
    # SMB (Get-SmbServerConfiguration works without admin per Microsoft docs)
    $smbCfg = $null; try { $smbCfg = Get-SmbServerConfiguration -ErrorAction Stop } catch { }
    $smb1Client = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start'   # 4 = disabled; key absent = not installed
    $smb = [ordered]@{
        is_smb1_server_enabled      = if ($smbCfg) { [bool]$smbCfg.EnableSMB1Protocol } else { $null }
        is_smb1_client_installed    = ($null -ne $smb1Client -and [int]$smb1Client -ne 4)
        is_server_signing_required  = if ($smbCfg) { [bool]$smbCfg.RequireSecuritySignature } else { $null }
    }
    # UAC
    $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua = Get-RegValue $uacKey 'EnableLUA'; $consent = Get-RegValue $uacKey 'ConsentPromptBehaviorAdmin'; $secDesk = Get-RegValue $uacKey 'PromptOnSecureDesktop'
    $uac = [ordered]@{
        is_enabled                    = if ($null -ne $lua) { [int]$lua -eq 1 } else { $null }
        admin_consent_prompt_behavior = if ($null -ne $consent) { [int]$consent } else { $null }   # 0 = elevate without prompting
        is_secure_desktop             = if ($null -ne $secDesk) { [int]$secDesk -eq 1 } else { $null }
    }
    # Credential protection: LSA protection (RunAsPPL 1/2 = on), WDigest plaintext caching, VBS / Credential Guard / HVCI
    $ppl = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    $wdigest = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    $dg = Get-CimSafe -Class 'Win32_DeviceGuard' -Namespace 'root\Microsoft\Windows\DeviceGuard'
    $running = @(); if ($dg) { $running = @($dg.SecurityServicesRunning | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ }) }
    $credential = [ordered]@{
        lsa_protection            = if ($null -ne $ppl) { [int]$ppl } else { $null }   # 1 = with UEFI lock, 2 = without; null = not configured
        is_wdigest_caching_enabled = ($null -ne $wdigest -and [int]$wdigest -eq 1)
        vbs_status                = if ($dg) { [int]$dg.VirtualizationBasedSecurityStatus } else { $null }   # 2 = running
        is_credential_guard_running = if ($dg) { $running -contains 1 } else { $null }
        is_hvci_running           = if ($dg) { $running -contains 2 } else { $null }
    }
    # Name resolution: LLMNR (policy EnableMulticast=0 disables it - verified ADMX_DnsClient) + NetBIOS per adapter (2 = disabled)
    $llmnr = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    $nics = Get-CimSafe -Class 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled=True'
    $netbiosOn = @($nics | Where-Object { [int]$_.TcpipNetbiosOptions -ne 2 }).Count
    # PowerShell logging (NOT VERIFIED path, standard ADMX location) + autorun (NOT VERIFIED)
    $psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $sbl = Get-RegValue "$psKey\ScriptBlockLogging" 'EnableScriptBlockLogging'
    $trn = Get-RegValue "$psKey\Transcription" 'EnableTranscripting'
    $autorun = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    # LAPS (4 official roots; BackupDirectory 0 = disabled)
    $lapsSource = $null
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config', 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd') {
        $bd = Get-RegValue $k 'BackupDirectory'; $en = Get-RegValue $k 'AdmPwdEnabled'
        if (($null -ne $bd -and [int]$bd -gt 0) -or ($null -ne $en -and [int]$en -eq 1)) { $lapsSource = $k; break }
    }
    # Windows Hello PIN policy (GPO "System > PIN Complexity"; registry path NOT VERIFIED). Microsoft docs: PIN expiration/
    # history are NOT enforced on Windows 11 24H2+ when VBS is running -> report whether expiration is enforceable at all.
    $pinKey = 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
    $pinExp = Get-RegValue $pinKey 'Expiration'; $pinMin = Get-RegValue $pinKey 'MinimumPINLength'; $pinHist = Get-RegValue $pinKey 'History'
    $os = Get-CimSafe 'Win32_OperatingSystem'
    $build = if ($os) { [int]$os.BuildNumber } else { 0 }
    $expEnforceable = -not ($build -ge 26100 -and $credential.vbs_status -eq 2)
    $pin = [ordered]@{
        expiration_days             = if ($null -ne $pinExp) { [int]$pinExp } else { $null }
        min_length                  = if ($null -ne $pinMin) { [int]$pinMin } else { $null }
        history_count               = if ($null -ne $pinHist) { [int]$pinHist } else { $null }
        is_expiration_enforceable   = $expEnforceable
    }

    # (1) risky optional features enabled (Win32_OptionalFeature, InstallState 1 = enabled)
    $featWatch = 'MicrosoftWindowsPowerShellV2Root|MicrosoftWindowsPowerShellV2|TelnetClient|TFTP|SMB1Protocol|IIS-WebServerRole|Microsoft-Hyper-V-All|Containers-DisposableClientVM|Microsoft-Windows-Subsystem-Linux|VirtualMachinePlatform'
    $features = @(Get-CimSafe -Class 'Win32_OptionalFeature' -Filter 'InstallState=1' | Where-Object { $_ -and $_.Name -match "^($featWatch)$" } | ForEach-Object { "$($_.Name)" })
    # (2) custom inbound ALLOW firewall rules (no rule group = added by an app/person, not built-in Windows rules)
    $fwCustom = $null
    try {
        $fwCustom = @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop | Where-Object { -not $_.Group } | ForEach-Object { [ordered]@{ name = "$($_.DisplayName)"; profiles = @("$($_.Profile)".ToLower() -split ',\s*') } })
    } catch { }
    $fwPublic = @($fwCustom | Where-Object { $_ -and ($_.profiles -contains 'any' -or $_.profiles -contains 'public') })
    # (5) drivers explicitly NOT signed (IsSigned = $false; $null means unknown and is not flagged)
    $unsigned = @(Get-CimSafe 'Win32_PnPSignedDriver' | Where-Object { $_ -and $_.DeviceName -and $_.IsSigned -eq $false } | ForEach-Object { [ordered]@{ device = "$($_.DeviceName)"; provider = "$($_.DriverProviderName)" } })
    # (6) WMI permanent event consumers (admin). Windows ships 'SCM Event Log Consumer' (NTEventLogEventConsumer);
    # command-line / script consumers are an uncommon persistence mechanism worth reviewing.
    $wmiConsumers = $null; $wmiCommands = @{}   # 'class|name' -> command parts, internal only (not serialized)
    if ($script:IsAdmin) {
        $wmiRaw = @(Get-CimSafe -Class '__EventConsumer' -Namespace 'root\subscription' | Where-Object { $_ })
        $wmiConsumers = @($wmiRaw | ForEach-Object { [ordered]@{ kind = "$($_.CimClass.CimClassName)"; name = "$($_.Name)" } })
        foreach ($c in $wmiRaw) {
            $wmiCommands["$($c.CimClass.CimClassName)|$($c.Name)"] = @{ exe = "$($c.ExecutablePath)"; cmd = "$($c.CommandLineTemplate)"; script = "$($c.ScriptFileName)" }
        }
    }

    $sharedFolders = Get-SharedFolders
    # (P2c) mini-baseline: a curated handful of Microsoft security-baseline controls. Only EXPLICITLY insecure values
    # produce findings; Windows defaults that are merely "not hardened" are kept as data for the report.
    # Verified on learn.microsoft.com (2026-09-27): LmCompatibilityLevel, anonymous enumeration, SMB insecure guest logons,
    # LocalAccountTokenFilterPolicy, PointAndPrint RestrictDriverInstallationToAdministrators (KB5005010), controlled folder
    # access modes. Standard locations NOT VERIFIED: NoLMHash, EveryoneIncludesAnonymous, Remote Assistance, SmartScreen.
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $smbClient = $null; try { $smbClient = Get-SmbClientConfiguration -ErrorAction Stop } catch { }
    function Get-ServiceMode([string]$Name) { $sv = Get-CimSafe -Class 'Win32_Service' | Where-Object { $_.Name -eq $Name } | Select-Object -First 1; if ($sv) { [ordered]@{ start_mode = "$($sv.StartMode)".ToLower(); status = "$($sv.State)".ToLower() } } else { $null } }
    $toInt = { param($v) if ($null -ne $v) { [int]$v } else { $null } }
    $baseline = [ordered]@{
        lm_compatibility_level          = & $toInt (Get-RegValue $lsa 'LmCompatibilityLevel')        # null = not defined (modern default sends NTLMv2)
        restrict_anonymous              = & $toInt (Get-RegValue $lsa 'RestrictAnonymous')
        restrict_anonymous_sam          = & $toInt (Get-RegValue $lsa 'RestrictAnonymousSAM')
        no_lm_hash                      = & $toInt (Get-RegValue $lsa 'NoLMHash')
        everyone_includes_anonymous     = & $toInt (Get-RegValue $lsa 'EveryoneIncludesAnonymous')
        is_smb_client_signing_required  = if ($smbClient) { [bool]$smbClient.RequireSecuritySignature } else { $null }
        is_smb_insecure_guest_allowed   = if ($smbClient) { [bool]$smbClient.EnableInsecureGuestLogons } else { $null }
        local_account_token_filter_policy = & $toInt (Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy')
        printer_driver_install_admin_only = & $toInt (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' 'RestrictDriverInstallationToAdministrators')   # null = default 1 since Aug-2021
        is_remote_assistance_allowed    = ((& $toInt (Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' 'fAllowToGetHelp')) -eq 1)
        smartscreen_policy              = & $toInt (Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen')   # 0 = turned off by policy
        remote_registry                 = Get-ServiceMode 'RemoteRegistry'
        winrm                           = Get-ServiceMode 'WinRM'
        print_spooler                   = Get-ServiceMode 'Spooler'
        controlled_folder_access        = $null   # 0 off, 1 block, 2 audit, 3/4 disk-modification modes
        network_protection              = $null   # 0 off, 1 block, 2 audit
    }
    try { $mpp = Get-MpPreference -ErrorAction Stop; $baseline.controlled_folder_access = [int]$mpp.EnableControlledFolderAccess; $baseline.network_protection = [int]$mpp.EnableNetworkProtection } catch { }

    # Share permissions of non-administrative shares (Get-SmbShareAccess). 'Everyone' is localized (Todos, ...).
    $shareAccess = @()
    try {
        foreach ($sh in @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '\$$' })) {
            foreach ($a in @(Get-SmbShareAccess -Name $sh.Name -ErrorAction SilentlyContinue)) {
                $shareAccess += [ordered]@{ share = "$($sh.Name)"; account = "$($a.AccountName)"; right = "$($a.AccessRight)".ToLower(); control = "$($a.AccessControlType)".ToLower() }
            }
        }
    } catch { }
    $openShares = @($shareAccess | Where-Object { $_.account -imatch '^(Everyone|Todos|Tout le monde|Jeder)$' -and $_.right -in 'full', 'change' -and $_.control -eq 'allow' } | ForEach-Object { "$($_.share) ($($_.right))" } | Select-Object -Unique)

    # findings (Spanish) - mini-baseline: explicitly insecure values only
    if ($null -ne $baseline.lm_compatibility_level -and $baseline.lm_compatibility_level -lt 3) { Add-Finding -Code 'lm_ntlmv1_allowed' -Severity 'high' -Oea @('9.7') -Message "Autenticacion de red permite LM/NTLMv1 (LmCompatibilityLevel=$($baseline.lm_compatibility_level)): configurar 'Enviar solo respuesta NTLMv2' (3) o superior." }
    if ($baseline.restrict_anonymous_sam -eq 0) { Add-Finding -Code 'anonymous_sam_enumeration' -Severity 'medium' -Oea @('9.7') -Message 'Se permite enumerar cuentas del equipo de forma anonima (RestrictAnonymousSAM=0): habilitar la restriccion.' }
    if ($baseline.no_lm_hash -eq 0) { Add-Finding -Code 'lm_hash_stored' -Severity 'high' -Oea @('9.7') -Message 'Windows guarda hashes LM de contrasenas (NoLMHash=0, formato debil): deshabilitarlo.' }
    if ($baseline.everyone_includes_anonymous -eq 1) { Add-Finding -Code 'everyone_includes_anonymous' -Severity 'medium' -Oea @('9.7') -Message "Los permisos de 'Todos' incluyen a usuarios ANONIMOS (EveryoneIncludesAnonymous=1): deshabilitarlo." }
    if ($baseline.is_smb_insecure_guest_allowed) { Add-Finding -Code 'smb_insecure_guest' -Severity 'medium' -Oea @('9.7') -Message 'Conexiones SMB como invitado (sin credenciales) HABILITADAS: expone a servidores falsos, ransomware y ataques de intermediario; deshabilitarlas salvo necesidad puntual.' }
    if ($baseline.local_account_token_filter_policy -eq 1) { Add-Finding -Code 'uac_remote_restrictions_disabled' -Severity 'high' -Oea @('9.7') -Message 'Restricciones remotas de UAC DESACTIVADAS (LocalAccountTokenFilterPolicy=1): una cuenta admin local obtiene control total por red (riesgo de movimiento lateral).' }
    if ($baseline.printer_driver_install_admin_only -eq 0) { Add-Finding -Code 'printer_driver_install_unrestricted' -Severity 'high' -Oea @('9.7') -Message 'Usuarios sin privilegios pueden instalar drivers de impresora (mitigacion PrintNightmare desactivada): volver al valor por defecto (solo administradores).' }
    if ($baseline.smartscreen_policy -eq 0) { Add-Finding -Code 'smartscreen_disabled' -Severity 'medium' -Oea @('9.7') -Message 'SmartScreen DESACTIVADO por politica: reactivarlo.' }
    if ($baseline.remote_registry -and ($baseline.remote_registry.status -eq 'running' -or $baseline.remote_registry.start_mode -eq 'auto')) { Add-Finding -Code 'remote_registry_active' -Severity 'medium' -Oea @('9.7') -Message 'Servicio de Registro remoto activo: deshabilitarlo si no se usa.' }
    if ($features -match 'PowerShellV2') { Add-Finding -Code 'powershell_v2_enabled' -Severity 'medium' -Oea @('9.7','9.10') -Message 'PowerShell 2.0 habilitado (permite eludir el registro de PowerShell): deshabilitar la caracteristica.' }
    if ($features -contains 'TelnetClient' -or $features -contains 'TFTP') { Add-Finding -Code 'cleartext_protocol_clients' -Severity 'low' -Oea @('9.7') -Message ("Clientes de protocolos sin cifrado habilitados: $((@($features | Where-Object { $_ -in 'TelnetClient', 'TFTP' })) -join ', '): deshabilitarlos si no se usan.") }
    if ($fwPublic.Count -gt 0) { Add-Finding -Code 'firewall_public_inbound_rules' -Severity 'medium' -Oea @('9.7') -Message ("$($fwPublic.Count) reglas de firewall personalizadas permiten conexiones ENTRANTES tambien en redes publicas (ej.: $((@($fwPublic | Select-Object -First 3 | ForEach-Object { $_.name })) -join ' | ')): restringirlas al perfil privado/dominio.") }
    if ($unsigned.Count -gt 0) { Add-Finding -Code 'unsigned_drivers' -Severity 'medium' -Oea @('9.7') -Message ("Drivers SIN firma digital: $((@($unsigned | Select-Object -First 5 | ForEach-Object { $_.device })) -join ', '): verificar origen.") }
    $cmdConsumers = @($wmiConsumers | Where-Object { $_ -and ($_.kind -in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) })
    $susp = @($cmdConsumers | Where-Object { $w = $wmiCommands["$($_.kind)|$($_.name)"]; -not ($w -and (Test-KnownVendorWmiConsumer $_.name $_.kind $w.exe $w.cmd)) })
    if ($susp.Count -gt 0) {
        # the command goes in the (free-text) message so the technician can judge it; the JSON contract stays unchanged
        $desc = @($susp | ForEach-Object {
            $w = $wmiCommands["$($_.kind)|$($_.name)"]
            $what = if ($w) { (@($w.exe, $w.cmd, $w.script) | Where-Object { "$_".Trim() } | Select-Object -First 1) } else { $null }
            if ($what) { $what = "$what".Trim(); if ($what.Length -gt 120) { $what = $what.Substring(0, 117) + '...' }; "$($_.name) ($what)" } else { "$($_.name)" }
        })
        Add-Finding -Code 'wmi_command_consumers' -Severity 'high' -Oea @('9.7') -Message ("Consumidores de eventos WMI que ejecutan comandos/scripts: $($desc -join ', '): revisar su origen (mecanismo de persistencia poco habitual).")
    }
    if ($openShares.Count -gt 0) { Add-Finding -Code 'shares_everyone_write' -Severity 'high' -Oea @('9.2','9.4') -Message ("Carpetas compartidas con permiso de escritura para TODOS (Everyone): $($openShares -join ', '): restringir a los usuarios que corresponda.") }
    if ($smb.is_smb1_server_enabled -or $smb.is_smb1_client_installed) { Add-Finding -Code 'smb1_enabled' -Severity 'high' -Oea @('9.7') -Message 'SMBv1 habilitado (protocolo obsoleto, explotado por ransomware tipo WannaCry): deshabilitarlo.' }
    if ($uac.is_enabled -eq $false) { Add-Finding -Code 'uac_disabled' -Severity 'high' -Oea @('9.7') -Message 'Control de cuentas de usuario (UAC) DESACTIVADO: activarlo.' }
    elseif ($uac.admin_consent_prompt_behavior -eq 0) { Add-Finding -Code 'uac_no_prompt' -Severity 'medium' -Oea @('9.7') -Message 'UAC eleva a administrador SIN pedir confirmacion: configurar para que solicite consentimiento.' }
    if ($credential.is_wdigest_caching_enabled) { Add-Finding -Code 'wdigest_enabled' -Severity 'high' -Oea @('9.7') -Message 'WDigest guarda contrasenas en memoria en texto plano: deshabilitar (UseLogonCredential=0).' }
    if ($null -eq $credential.lsa_protection -or $credential.lsa_protection -eq 0) { Add-Finding -Code 'lsa_protection_off' -Severity 'low' -Oea @('9.7') -Message 'Proteccion LSA no configurada (robo de credenciales de memoria): evaluar activarla.' }
    if ($null -eq $llmnr -or [int]$llmnr -ne 0) { Add-Finding -Code 'llmnr_enabled' -Severity 'low' -Oea @('9.7') -Message 'LLMNR habilitado (permite capturar credenciales en la red local): deshabilitarlo por politica.' }
    if ($pin.expiration_days -in @($null, 0)) {
        $extra = if (-not $expEnforceable) { ' Nota: en esta version de Windows con VBS activo, Microsoft NO aplica el vencimiento de PIN; usar otra medida (p. ej. contrasena con caducidad + PIN complejo).' } else { '' }
        Add-Finding -Code 'hello_pin_no_expiration' -Severity 'low' -Oea @('9.7') -Message ("PIN de Windows Hello sin vencimiento configurado.$extra")
    }

    return [ordered]@{
        hardening = [ordered]@{
            smb                 = $smb
            uac                 = $uac
            credential_protection = $credential
            is_llmnr_disabled   = ($null -ne $llmnr -and [int]$llmnr -eq 0)
            netbios_enabled_adapter_count = $netbiosOn
            powershell_logging  = [ordered]@{ is_script_block_logging_enabled = ($null -ne $sbl -and [int]$sbl -eq 1); is_transcription_enabled = ($null -ne $trn -and [int]$trn -eq 1) }
            no_drive_type_autorun = if ($null -ne $autorun) { [int]$autorun } else { $null }   # 255 = autorun off on all drives
            laps_policy_key     = $lapsSource
            shared_folders      = $sharedFolders
            share_access        = $shareAccess
            optional_features_enabled = $features
            firewall_custom_inbound_rules = $fwCustom
            unsigned_drivers    = $unsigned
            wmi_event_consumers = $wmiConsumers
            baseline            = $baseline
            windows_hello_pin   = $pin
        }
    }
}

# ============================ MODULE: accounts ================================
# password policy, lockout, local users and groups
# Controls that used to live in the old "oea" module. They are general security controls, so they belong to their
# natural module; OEA is now only a LENS of the report (compliance_refs on each finding). Code moved verbatim.
function Get-PasswordHardening {
    $raw = Get-NetAccountsRaw

    # 9.7 account lockout + password history/min-age (locale-tolerant, from net accounts)
    $lockoutThreshold = $null; $lockoutDuration = $null; $lockoutWindow = $null; $pwdHistory = $null; $pwdMinAge = $null
    $lt = $raw | Where-Object { $_ -imatch 'lockout threshold|umbral de bloqueo' } | Select-Object -First 1
    if ($lt) { if ($lt -imatch 'never|nunca|none|ningun') { $lockoutThreshold = 0 } elseif ($lt -match '(\d+)') { $lockoutThreshold = [int]$Matches[1] } }
    $ld = $raw | Where-Object { $_ -imatch 'lockout duration|duraci.n de bloqueo' } | Select-Object -First 1
    if ($ld -and $ld -match '(\d+)') { $lockoutDuration = [int]$Matches[1] }
    $lw = $raw | Where-Object { $_ -imatch 'lockout observation|ventana de obs' } | Select-Object -First 1
    if ($lw -and $lw -match '(\d+)') { $lockoutWindow = [int]$Matches[1] }
    $ph = $raw | Where-Object { $_ -imatch 'password history|historial de contrase' } | Select-Object -First 1
    if ($ph) { if ($ph -imatch 'none|ningun') { $pwdHistory = 0 } elseif ($ph -match '(\d+)') { $pwdHistory = [int]$Matches[1] } }
    $pma = $raw | Where-Object { $_ -imatch 'minimum password age|duraci.n m.n.*contrase' } | Select-Object -First 1
    if ($pma -and $pma -match '(\d+)') { $pwdMinAge = [int]$Matches[1] }

    # 9.7 password complexity (secedit; admin)
    $complexity = $null
    if ($script:IsAdmin) {
        try {
            $secInf = Join-Path $env:TEMP ('_ea_sec_{0}.inf' -f (Get-Random))
            secedit /export /areas SECURITYPOLICY /cfg $secInf 2>$null | Out-Null
            $pc = Get-Content $secInf -ErrorAction Stop | Where-Object { $_ -match 'PasswordComplexity' } | Select-Object -First 1
            if ($pc -and $pc -match '=\s*(\d+)') { $complexity = ([int]$Matches[1] -eq 1) }
            Remove-Item $secInf -ErrorAction SilentlyContinue
        } catch { }
    }

    if ($lockoutThreshold -eq 0) { Add-Finding -Code 'account_lockout_disabled' -Severity 'medium' -Oea @('9.7') -Message 'Sin bloqueo de cuenta por intentos fallidos: habilitar umbral (ej. 5-10 intentos).' }
    if ($complexity -eq $false) { Add-Finding -Code 'password_complexity_off' -Severity 'medium' -Oea @('9.7') -Message 'Complejidad de contrasena NO exigida: activar el requisito de complejidad.' }
    return [ordered]@{
        account_lockout = [ordered]@{ threshold = $lockoutThreshold; duration_minutes = $lockoutDuration; observation_window_minutes = $lockoutWindow }
        history_count = $pwdHistory; min_age_days = $pwdMinAge; is_complexity_required = $complexity
    }
}

function Get-LocalAccountFlags {
    # 9.2/9.7 local accounts: guest enabled + accounts that do NOT require a password
    $guestEnabled = $null; $passwordless = @()
    $localAccts = Get-CimSafe -Class 'Win32_UserAccount' -Filter 'LocalAccount=True'
    if ($localAccts) {
        $guestEnabled = $false
        foreach ($u in $localAccts) {
            if (("$($u.SID)" -like '*-501') -and (-not $u.Disabled)) { $guestEnabled = $true }
            if ((-not $u.Disabled) -and (-not $u.PasswordRequired)) { $passwordless += $u.Name }
        }
    }

    if ($guestEnabled) { Add-Finding -Code 'guest_enabled' -Severity 'medium' -Oea @('9.2') -Message 'Cuenta Invitado (Guest) habilitada: deshabilitarla.' }
    if (@($passwordless).Count -gt 0) { Add-Finding -Code 'passwordless_accounts' -Severity 'high' -Oea @('9.2','9.7') -Message ("Cuentas locales que NO requieren contrasena: $($passwordless -join ', '): exigir contrasena.") }
    return [ordered]@{ is_guest_enabled = $guestEnabled; passwordless_accounts = $passwordless }
}

# Enabled local accounts whose name ends in '$': 'net user' does not list them (a known way to hide an account).
# HomeGroupUser$ is the account Windows created for HomeGroup (removed in 1803, it survives on upgraded PCs).
function Get-HiddenLocalAccounts($LocalUsers) {
    return ,@(@($LocalUsers) | Where-Object { $_ -and $_.is_enabled -and "$($_.name)" -like '*$' -and "$($_.name)" -ne 'HomeGroupUser$' } | ForEach-Object { "$($_.name)" })
}

function Get-AccountPolicy {
    $raw = Get-NetAccountsRaw

    # max password age (locale-tolerant: EN "Maximum password age", ES "Duracion max...")
    $maxAgeDays = $null; $neverExpires = $false
    $maxLine = $raw | Where-Object { $_ -imatch 'maximum password age|duraci.n\s+m.x.*contrase' } | Select-Object -First 1
    if ($maxLine) {
        if ($maxLine -imatch 'unlimited|ilimitad|never|nunca') { $neverExpires = $true }
        elseif ($maxLine -match '(\d+)') { $maxAgeDays = [int]$Matches[1] }
    }
    # minimum password length
    $minLength = $null
    $minLine = $raw | Where-Object { $_ -imatch 'minimum password length|longitud m.nima' } | Select-Object -First 1
    if ($minLine -and $minLine -match '(\d+)') { $minLength = [int]$Matches[1] }

    # local users (SIDs kept internal, not serialized: needed to tell the account in use apart)
    $localUsers = @(); $sidByName = @{}; $isLocalUserListRead = $false
    try {
        $localUsers = @(Get-LocalUser -ErrorAction Stop | ForEach-Object {
            $sidByName[$_.Name] = "$($_.SID.Value)"
            [ordered]@{ name = $_.Name; is_enabled = [bool]$_.Enabled; password_expires_at = ConvertTo-IsoTimestamp $_.PasswordExpires; password_set_at = ConvertTo-IsoTimestamp $_.PasswordLastSet
                        last_logon_at = ConvertTo-IsoTimestamp $_.LastLogon; rid = [int]("$($_.SID.Value)".Split('-')[-1]) }
        })
        $isLocalUserListRead = $true
    } catch { }
    # local administrators (SID S-1-5-32-544, language-agnostic)
    $admins = @()
    try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name }) } catch { }

    # built-in Administrator (RID 500) and inactive enabled accounts (> 90 days or never used). RIDs < 1000 = built-in.
    $builtinAdminEnabled = $null; $inactive = @()
    if ($localUsers.Count -gt 0) {
        $builtinAdminEnabled = [bool]($localUsers | Where-Object { $_.rid -eq 500 -and $_.is_enabled })
        $profileUse = @{}
        foreach ($pr in @(Get-CimSafe -Class 'Win32_UserProfile' | Where-Object { $_ -and $_.SID })) { $profileUse["$($pr.SID)"] = ConvertTo-IsoDate $pr.LastUseTime }
        $activeSids = @(@((Resolve-AuditedUser).sid, [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) | Where-Object { $_ })
        $inactive = Get-InactiveLocalAccounts $localUsers $sidByName $profileUse $activeSids
    }
    # other privileged local groups (well-known SIDs; several do not exist on Windows Home -> skipped silently)
    $privGroups = @()
    foreach ($g in @(@{ sid = 'S-1-5-32-555'; key = 'remote_desktop_users' }, @{ sid = 'S-1-5-32-551'; key = 'backup_operators' }, @{ sid = 'S-1-5-32-580'; key = 'remote_management_users' }, @{ sid = 'S-1-5-32-578'; key = 'hyperv_administrators' }, @{ sid = 'S-1-5-32-547'; key = 'power_users' })) {
        try { $mem = @(Get-LocalGroupMember -SID $g.sid -ErrorAction Stop | ForEach-Object { "$($_.Name)" }); if ($mem.Count -gt 0) { $privGroups += [ordered]@{ group = $g.key; members = $mem } } } catch { }
    }
    foreach ($pg in $privGroups) { Add-Finding -Code 'privileged_group_members' -Severity 'medium' -Oea @('9.2') -Message ("Grupo privilegiado '$($pg.group)' con miembros: $($pg.members -join ', '): verificar que cada acceso este autorizado.") }
    if ($builtinAdminEnabled) { Add-Finding -Code 'builtin_admin_enabled' -Severity 'medium' -Oea @('9.2') -Message 'Cuenta Administrador integrada HABILITADA: deshabilitarla y usar una cuenta admin nominal.' }
    $hidden = $null   # null = the local user list could not be read (not measured), [] = measured, none
    if ($isLocalUserListRead) { $hidden = Get-HiddenLocalAccounts $localUsers }
    if ($hidden -and $hidden.Count -gt 0) { Add-Finding -Code 'hidden_local_account' -Severity 'high' -Oea @('9.2') -Message ("Cuenta local habilitada con nombre terminado en `$ (no aparece en 'net user'): $($hidden -join ', '): verificar quien la creo y para que; si no es conocida, deshabilitarla.") }
    if ($inactive.Count -gt 0) { Add-Finding -Code 'inactive_accounts' -Severity 'medium' -Oea @('9.2','9.3') -Message ("Cuentas locales habilitadas sin uso en 90+ dias: $($inactive -join ', '): deshabilitar las que no correspondan.") }

    $pwdHard = Get-PasswordHardening        # lockout + history + min age + complexity (moved from the old oea module)
    $acctFlags = Get-LocalAccountFlags      # guest + accounts without password
    $au = Resolve-AuditedUser
    if ($au.is_admin) { Add-Finding -Code 'daily_user_is_admin' -Severity 'high' -Oea @('9.2') -Message ("El usuario de uso diario ($($au.name)) es ADMINISTRADOR local: usar una cuenta estandar para el trabajo diario.") }

    # findings (Spanish)
    if ($neverExpires) { Add-Finding -Code 'password_never_expires' -Severity 'medium' -Oea @('9.7') -Message 'Contrasenas locales NUNCA expiran: implementar caducidad a 90 dias.' }
    if ($null -ne $minLength -and $minLength -lt 8) { Add-Finding -Code 'password_min_length_weak' -Severity 'medium' -Oea @('9.7') -Message "Longitud minima de contrasena = $minLength (debil): exigir 8+ caracteres." }

    return [ordered]@{
        accounts = [ordered]@{
            password_policy = [ordered]@{
                max_age_days      = $maxAgeDays
                is_never_expiring = $neverExpires
                min_length        = $minLength
                history_count     = $pwdHard.history_count
                min_age_days      = $pwdHard.min_age_days
                is_complexity_required = $pwdHard.is_complexity_required
                raw_output        = $raw
            }
            account_lockout = $pwdHard.account_lockout
            is_guest_enabled = $acctFlags.is_guest_enabled
            passwordless_accounts = $acctFlags.passwordless_accounts
            local_users    = $localUsers
            administrators = $admins
            is_builtin_admin_enabled = $builtinAdminEnabled
            privileged_groups = $privGroups
            inactive_accounts = $inactive
            hidden_accounts = $hidden
        }
    }
}

# ============================ MODULE: remote_access ===========================
# remote access tools + RDP
# Remote access tools + RDP exposure (OEA 9.2 access control / 9.4 leakage / 9.3 third parties).
# Leading \b on purpose: without it 'todesk' matched 'Autodesk' (false positive found on real client data, 2026-09-27).
# 3.4.0 adds the tools of the 2026-09 remote-access inspection script (ultraviewer ... gotoassist): UltraViewer was missing.
$script:RemoteTools = '\b(?:anydesk|teamviewer|rustdesk|screenconnect|connectwise control|splashtop|ultravnc|tightvnc|realvnc|vnc server|tigervnc|logmein|goto resolve|chrome remote desktop|supremo|radmin|zoho assist|ninjarmm|ninjaone|atera|centrastage|datto rmm|n-able|kaseya|action1|meshagent|meshcentral|dwservice|parsec|awesun|aweray|todesk|remote utilities|nomachine|bomgar|beyondtrust|dameware|remotepc|getscreen|hoptodesk|ultraviewer|ammyy|aeroadmin|anyviewer|helpwire|netsupport|litemanager|iperius remote|gotomypc|gotoassist)'
# Process image names that do not contain the product name (LOLRMM process lists; same set as the 2026-09 script).
# quickassist / msra are Windows' own remote assistance: only meaningful while RUNNING (a session in progress).
$script:RemoteToolProcesses = @{
    aa_v3 = 'Ammyy Admin'; rutserv = 'Remote Utilities'; rfusclient = 'Remote Utilities'; client32 = 'NetSupport Manager'; pcictlui = 'NetSupport Manager'
    srserver = 'Splashtop'; srmanager = 'Splashtop'; srservice = 'Splashtop'; remoting_host = 'Chrome Remote Desktop'; winvnc = 'VNC'; tvnserver = 'TightVNC'
    vncserver = 'VNC'; rserver3 = 'Radmin'; dwagsvc = 'DWService'; dwagent = 'DWService'; nxservice = 'NoMachine'; nxnode = 'NoMachine'
    lmiguardiansvc = 'LogMeIn'; g2comm = 'GoTo'; g2svc = 'GoTo'; parsecd = 'Parsec'; quickassist = 'Quick Assist'; msra = 'Windows Remote Assistance'
}
$script:BuiltinRemoteAssistance = @('quickassist', 'msra')
# Remote-support agents that install their PROGRAM inside ProgramData (vendor docs): BeyondTrust/Bomgar Jump Client, Datto RMM
# (CentraStage), NinjaOne. Any other ProgramData folder is a staging place (scam AnyDesk / ScreenConnect copies, ransomware).
$script:RemoteToolVendorFolders = '(?i)^(?:bomgar-scc-[^\\]*|centrastage|ninjarmmagent)\\'

# Remote-tool processes from Win32_Process rows ({Name, ExecutablePath}). is_portable = runs outside the program folders
# (Program Files, Windows, a vendor's own folder inside ProgramData - BeyondTrust and Datto RMM install there) or from a
# folder any user can write inside them (Windows\Temp, Tasks, Tracing, spool\drivers\color) or from the ROOT of
# ProgramData: AnyDesk / TeamViewer QuickSupport started from Downloads or %TEMP%, or a copy dropped where ransomware
# stages it. A path hidden by permissions (other users' processes without admin) leaves is_portable $null: not measured.
function Get-RemoteToolProcessMatches($Processes, [string[]]$InstallRoots, [string[]]$WritableRoots = @(), [string[]]$VendorFolderRoots = @()) {
    $roots = @($InstallRoots | Where-Object { "$_".Trim() } | ForEach-Object { "$_".TrimEnd('\') + '\' })
    $writable = @($WritableRoots | Where-Object { "$_".Trim() } | ForEach-Object { "$_".TrimEnd('\') + '\' })
    $vendor = @($VendorFolderRoots | Where-Object { "$_".Trim() } | ForEach-Object { "$_".TrimEnd('\') + '\' })
    $out = @(); $seen = @{}
    foreach ($p in @($Processes | Where-Object { $_ -and $_.Name })) {
        $base = ("$($p.Name)" -replace '(?i)\.exe$', '').ToLower()
        # the image name, or its path BELOW the user's profile (a user named 'radmin' must not make excel.exe a remote tool)
        if (-not ($script:RemoteToolProcesses.ContainsKey($base) -or "$($p.Name) $("$($p.ExecutablePath)" -replace '(?i)^[a-z]:\\users\\[^\\]+\\', '')" -imatch $script:RemoteTools)) { continue }
        $path = if ("$($p.ExecutablePath)".Trim()) { "$($p.ExecutablePath)".Trim() } else { $null }
        $key = "$base|$path"; if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
        $portable = $null
        if ($path -and $script:BuiltinRemoteAssistance -notcontains $base) {
            $inRoot = [bool](@($roots | Where-Object { $path.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count) -or
                      [bool](@($vendor | Where-Object { $path.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) -and $path.Substring($_.Length) -match $script:RemoteToolVendorFolders }).Count)
            $inWritable = [bool](@($writable | Where-Object { $path.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count)
            $portable = (-not $inRoot) -or $inWritable
        }
        $out += [ordered]@{ name = "$($p.Name)"; kind = 'process'; status = 'running'; path = $path; is_portable = $portable }
    }
    # the same image seen with and without a readable path (another session, no admin) -> keep the one with the path
    $withPath = @($out | Where-Object { $_.path } | ForEach-Object { "$($_.name)".ToLower() })
    $out = @($out | Where-Object { $_.path -or $withPath -notcontains "$($_.name)".ToLower() })
    return ,$out
}
# Where a program runs from, for a message: its folder name, or the whole folder when that is a drive or share root.
function Get-FolderLabel([string]$Path) {
    try { return (Get-FolderLabelCore $Path) } catch { return "$Path" }   # odd characters make the .NET path methods throw
}
function Get-FolderLabelCore([string]$Path) {
    $dir = Split-Path -Parent $Path
    if (-not $dir) { return $Path }
    if ($dir -match '^[A-Za-z]:\\?$' -or $dir -match '^\\\\[^\\]+\\[^\\]+\\?$') { return $dir }
    $leaf = Split-Path -Leaf $dir
    if (-not $leaf) { return $dir }
    $exeBase = [IO.Path]::GetFileNameWithoutExtension($Path)
    if ($leaf -ieq $exeBase) { $up = Split-Path -Leaf (Split-Path -Parent $dir); if ($up) { return "$up\$leaf" } }   # Temp\TeamViewer\TeamViewer.exe
    return $leaf
}

# qwinsta lines -> CONNECTED, LOGGED-ON RDP sessions other than the one running this audit ('>' marks the current
# session). Session names ('rdp-tcp#N') are not localized (state words are). A disconnected session loses its name; a
# session still authenticating ('Conn', e.g. a scanner hitting an exposed port) has no user yet -> neither is counted.
# $null = qwinsta not available (Windows Home has no RDP host and no qwinsta.exe: measured on ROD-PC 2026-10-01).
function Get-RdpSessionCount([AllowNull()][string[]]$Lines) {
    if ($null -eq $Lines) { return $null }
    return @($Lines | Where-Object {
        $l = "$_"
        if ($l -notmatch '(?i)\brdp-tcp#\d+' -or $l -match '^\s*>') { return $false }
        $parts = @($l.Trim() -split '\s+')
        return ($parts.Count -ge 4)   # name, USER, id, state (a user name may itself be all digits); pre-auth rows have 3
    }).Count
}
function Get-QwinstaOutput {
    $exe = Join-Path $env:SystemRoot 'System32\qwinsta.exe'
    if (-not (Test-Path -LiteralPath $exe)) { return $null }
    try { return ,@(& $exe 2>$null | ForEach-Object { "$_" }) } catch { return $null }
}

# Networks of this PC (address + prefix length), to tell a LAN peer from an internet one.
function Get-LocalNetworks {
    try { return ,@(Get-NetIPAddress -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ address = ("$($_.IPAddress)" -replace '%.*$', ''); prefix_length = [int]$_.PrefixLength } }) } catch { return ,@() }
}
# Same network? IPv4: the PC's own subnet. IPv6: the same /56 as one of the PC's global addresses (a site gets a /48-/56
# from the ISP and every LAN /64 inside it is its own: a colleague's RDP over IPv6 is NOT an internet logon).
function Test-AddressInNetwork([System.Net.IPAddress]$Ip, $Network) {
    $n = $null
    if (-not [System.Net.IPAddress]::TryParse("$($Network.address)", [ref]$n)) { return $false }
    if ($n.IsIPv4MappedToIPv6) { $n = $n.MapToIPv4() }
    if ($n.AddressFamily -ne $Ip.AddressFamily) { return $false }
    $bits = [int]$Network.prefix_length
    if ($Ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { if ($n.IsIPv6LinkLocal) { return $false }; $bits = [math]::Min($bits, 56) }
    $a = $Ip.GetAddressBytes(); $c = $n.GetAddressBytes()
    for ($i = 0; $i -lt $a.Length -and $bits -gt 0; $i++) {
        $mask = if ($bits -ge 8) { 0xFF } else { (0xFF -shl (8 - $bits)) -band 0xFF }
        if (($a[$i] -band $mask) -ne ($c[$i] -band $mask)) { return $false }
        $bits -= 8
    }
    return $true
}
# Internet address? Not: private, loopback, link-local, multicast, IPv6 unique-local, carrier-grade NAT 100.64/10
# (Tailscale) and the 25/8 / 26/8 blocks Hamachi and Radmin VPN hand out (a VPN overlay is the recommended way to reach
# RDP), nor anything inside the PC's own networks. Unparseable text (a host name, '-') is not asserted as internet.
function Test-InternetAddress([string]$Address, $LocalNetworks = @()) {
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse(("$Address".Trim() -replace '%.*$', ''), [ref]$ip)) { return $false }
    if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    $b = $ip.GetAddressBytes()
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        if ($b[0] -in 0, 10, 25, 26, 127 -or $b[0] -ge 224) { return $false }
        if (($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 169 -and $b[1] -eq 254)) { return $false }
        if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
    } else {
        if ([System.Net.IPAddress]::IsLoopback($ip) -or $ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or $ip.IsIPv6Multicast -or $ip.Equals([System.Net.IPAddress]::IPv6Any)) { return $false }
        if (($b[0] -band 0xFE) -eq 0xFC) { return $false }
    }
    foreach ($n in @($LocalNetworks | Where-Object { $_ })) { if (Test-AddressInNetwork $ip $n) { return $false } }
    return $true
}

# RDP logons = event 1149 of TerminalServices-RemoteConnectionManager/Operational ("User authentication succeeded"); the
# source address is the 3rd UserData field (Param3). Kept: counts + the INTERNET sources only (the evidence of exposure);
# account names and LAN addresses are not stored (asset audit, not a log of who worked from where).
function Get-RdpLogonEvents {
    $f = @{ LogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id = 1149; StartTime = (Get-Date).AddDays(-$script:EventWindowDays) }
    try {
        return ,@(Get-WinEvent -FilterHashtable $f -MaxEvents $script:EventMax -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ at = $_.TimeCreated; address = if ($_.Properties.Count -ge 3) { "$($_.Properties[2].Value)".Trim() } else { $null } }
        })
    } catch { if ("$($_.FullyQualifiedErrorId)" -like 'NoMatchingEventsFound*') { return ,@() } else { return $null } }
}
function Get-RdpLogonSummary($Events, $CoveredDays, $LocalNetworks = @(), [int]$MaxEvents = 0) {
    if ($null -eq $Events) { return $null }
    $all = @($Events | Where-Object { $_ })
    # the query returns the NEWEST events up to the cap: at the cap, the evidence only reaches back to the oldest one returned
    $isCapReached = ($MaxEvents -gt 0 -and $all.Count -ge $MaxEvents)
    if ($isCapReached) {
        $oldest = @($all | Where-Object { $_.at } | Sort-Object { $_.at })[0].at
        if ($oldest) { $CoveredDays = [int][math]::Max(1, [math]::Floor(((Get-Date) - $oldest).TotalDays)) }   # same rounding as Get-LogCoverageDays
    }
    $internet = @($all | Where-Object { Test-InternetAddress $_.address $LocalNetworks })
    # newest first: an address that just appeared must not fall out behind old busy ones (second review, 2026-10-01)
    $sources = @($internet | Group-Object { "$($_.address)" } | ForEach-Object {
        $last = @($_.Group | Sort-Object { $_.at } -Descending)[0].at
        [pscustomobject]@{ at = $last; row = [ordered]@{ address = $_.Name; logon_count = $_.Count; last_logon_at = ConvertTo-IsoTimestamp $last } }
    } | Sort-Object at -Descending | ForEach-Object { $_.row })
    $lastAll = if ($all.Count -gt 0) { ConvertTo-IsoTimestamp (@($all | Sort-Object { $_.at } -Descending)[0].at) } else { $null }
    $lastInternet = if ($internet.Count -gt 0) { ConvertTo-IsoTimestamp (@($internet | Sort-Object { $_.at } -Descending)[0].at) } else { $null }
    return [ordered]@{ covered_days = $CoveredDays; is_event_cap_reached = $isCapReached; logon_count = $all.Count; internet_logon_count = $internet.Count
                       last_logon_at = $lastAll; last_internet_logon_at = $lastInternet; internet_sources = @($sources | Select-Object -First 10) }
}

# UltraViewer per-user incoming log %APPDATA%\UltraViewer\Connection_IN_Log.txt, one line per incoming session:
#   '<date time>|<partner id>|<partner computer>|RandomPass|FixedPass|<partner public address>'  (UltraViewer 6.6, real
# capture 2026-09). FixedPass = the session was authenticated with the FIXED (unattended) password: evidence the vendor's
# documented unattended mode is in use. The date is written with the culture of the account that wrote the log.
$script:UltraViewerMaxLines = 20000   # newest lines read per log: it is never rotated (one line per session, years of history)
function ConvertFrom-UltraViewerInLog([string[]]$Lines, [Globalization.CultureInfo]$Culture = [Globalization.CultureInfo]::CurrentCulture) {
    $latest = (Get-Date).AddDays(1); $inv = [Globalization.CultureInfo]::InvariantCulture
    # the SAME formats in both orders: with an asymmetric pair an AMBIGUOUS line ('9/5/2026 10:00') parsed in one order only
    # and voted for it (third review, 2026-10-02)
    $dayFirst = @(); $monthFirst = @()
    foreach ($sep in '/', '-', '.') { foreach ($tf in 'H:mm:ss', 'h:mm:ss tt', 'H:mm', 'h:mm tt') { $dayFirst += "d${sep}M${sep}yyyy $tf"; $monthFirst += "M${sep}d${sep}yyyy $tf" } }
    $dayFirst = [string[]]$dayFirst; $monthFirst = [string[]]$monthFirst
    $rows = New-Object System.Collections.Generic.List[object]; $votes = @{ day = 0; month = 0 }   # lists: '+=' copies (quadratic on a long log)
    foreach ($l in @($Lines)) {
        $p = "$l".Split('|')
        if ($p.Count -lt 4 -or -not $p[1].Trim()) { continue }
        $text = $p[0].Trim(); $byDay = $null; $byMonth = $null; $tmp = [datetime]::MinValue
        if ([datetime]::TryParseExact($text, $dayFirst, $inv, [Globalization.DateTimeStyles]::None, [ref]$tmp) -and $tmp -le $latest) { $byDay = $tmp }
        if ([datetime]::TryParseExact($text, $monthFirst, $inv, [Globalization.DateTimeStyles]::None, [ref]$tmp) -and $tmp -le $latest) { $byMonth = $tmp }
        if ($byDay -and -not $byMonth) { $votes.day++ } elseif ($byMonth -and -not $byDay) { $votes.month++ }   # unambiguous lines (a day > 12) tell the log's order
        $auth = switch -Regex ($p[3].Trim()) { '^(?i)fixedpass$' { 'fixed_password' } '^(?i)randompass$' { 'random_password' } default { 'unknown' } }
        $rows.Add([pscustomobject]@{ text = $text; by_day = $byDay; by_month = $byMonth; partner_id = $p[1].Trim(); partner_name = $p[2].Trim(); auth = $auth })
    }
    # the log is written in ONE order (its owner's locale). Prefer what its own unambiguous lines show, then the culture
    # of the account that wrote it: a mixed-up culture would read 5/9 as May 9 instead of September 5 without failing.
    $isMonthFirst = if ($votes.day -ne $votes.month) { $votes.month -gt $votes.day } else { "$($Culture.DateTimeFormat.ShortDatePattern)".TrimStart() -match '^M' }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $at = if ($isMonthFirst) { $r.by_month } else { $r.by_day }
        if (-not $at) { $dt = [datetime]::MinValue; if ([datetime]::TryParse($r.text, $Culture, [Globalization.DateTimeStyles]::None, [ref]$dt) -and $dt -le $latest) { $at = $dt } }
        $out.Add([pscustomobject]@{ at = $at; partner_id = $r.partner_id; partner_name = $r.partner_name; auth = $r.auth })
    }
    return ,$out.ToArray()
}
# Counts over the last N days (the log is never rotated: an old fixed-password session must not raise the finding forever,
# and a later capture can show it resolved); the lines read (each log's newest 20,000) stay summarized by
# log_connection_count / first / last dates.
function Get-UltraViewerSummary($Connections, $IsServiceAutoStart, [int]$WindowDays = 90, [bool]$IsLineCapReached = $false) {
    $all = @($Connections | Where-Object { $_ })
    if ($all.Count -eq 0 -and $null -eq $IsServiceAutoStart) { return $null }
    $since = (Get-Date).AddDays(-$WindowDays)
    $recent = @($all | Where-Object { $_.at -and $_.at -ge $since })
    $dated = @($all | Where-Object { $_.at } | Sort-Object { $_.at })
    $fixedDated = @($dated | Where-Object { $_.auth -eq 'fixed_password' })
    $partners = @($recent | Group-Object { $_.partner_id } | ForEach-Object {
        $g = @($_.Group | Sort-Object { $_.at })
        [ordered]@{ provider_partner_id = $_.Name; partner_name = @($g | ForEach-Object { $_.partner_name } | Where-Object { $_ } | Select-Object -Last 1)[0]
                    connection_count = $g.Count; fixed_password_connection_count = @($g | Where-Object { $_.auth -eq 'fixed_password' }).Count
                    last_connection_at = ConvertTo-IsoTimestamp $g[-1].at }
    } | Sort-Object { "$($_.last_connection_at)" } -Descending)
    return [ordered]@{
        is_service_auto_start           = $IsServiceAutoStart
        window_days                     = $WindowDays
        connection_count                = $recent.Count
        fixed_password_connection_count = @($recent | Where-Object { $_.auth -eq 'fixed_password' }).Count
        log_connection_count            = $all.Count
        is_line_cap_reached             = $IsLineCapReached   # a log over the line cap: only its newest lines were read
        undated_connection_count        = @($all | Where-Object { -not $_.at }).Count
        undated_fixed_password_connection_count = @($all | Where-Object { -not $_.at -and $_.auth -eq 'fixed_password' }).Count
        first_connection_at             = if ($dated.Count -gt 0) { ConvertTo-IsoTimestamp $dated[0].at } else { $null }
        last_connection_at              = if ($dated.Count -gt 0) { ConvertTo-IsoTimestamp $dated[-1].at } else { $null }
        last_fixed_password_at          = if ($fixedDated.Count -gt 0) { ConvertTo-IsoTimestamp $fixedDated[-1].at } else { $null }
        partners                        = @($partners | Select-Object -First 10)
    }
}
# Culture an account writes dates with: its Control Panel\International (locale + the short-date / time patterns the user
# may have customized). A user who is not logged on has no hive loaded -> the machine default (.DEFAULT).
function Get-ProfileCulture([string]$Sid) {
    foreach ($root in @("Registry::HKEY_USERS\$Sid", 'Registry::HKEY_USERS\.DEFAULT')) {
        $k = "$root\Control Panel\International"
        $name = Get-RegValue $k 'LocaleName'
        if (-not $name) { continue }
        try { $ci = ([Globalization.CultureInfo]::GetCultureInfo("$name")).Clone() } catch { continue }
        $sd = Get-RegValue $k 'sShortDate'; $tf = Get-RegValue $k 'sTimeFormat'
        try { if ($sd) { $ci.DateTimeFormat.ShortDatePattern = "$sd" }; if ($tf) { $ci.DateTimeFormat.LongTimePattern = "$tf" } } catch { }
        return $ci
    }
    return [Globalization.CultureInfo]::CurrentCulture
}
# Every profile's log (other profiles need admin) + the SYSTEM profile seen by the 32-bit service (SysWOW64 redirection),
# each read with the culture of the account that wrote it (the audit may run as another admin, or as SYSTEM).
function Get-UltraViewerLogSets {
    $targets = @()
    foreach ($p in @(Get-CimSafe 'Win32_UserProfile' | Where-Object { $_ -and $_.LocalPath })) { $targets += @{ file = (Join-Path "$($p.LocalPath)" 'AppData\Roaming\UltraViewer\Connection_IN_Log.txt'); sid = "$($p.SID)" } }
    $targets += @{ file = (Join-Path $env:SystemRoot 'SysWOW64\config\systemprofile\AppData\Roaming\UltraViewer\Connection_IN_Log.txt'); sid = 'S-1-5-18' }
    $sets = @(); $done = @{}
    foreach ($t in $targets) {
        if ($done.ContainsKey($t.file)) { continue }; $done[$t.file] = $true
        # Test-Path WRITES an 'access denied' error (it does not just return false) on another profile without admin
        if (-not (Test-Path -LiteralPath $t.file -PathType Leaf -ErrorAction SilentlyContinue)) { continue }
        try { $raw = @(Get-Content -LiteralPath $t.file -Tail $script:UltraViewerMaxLines -ErrorAction Stop) } catch { continue }
        $sets += [pscustomobject]@{ lines = @($raw | Where-Object { "$_".Trim() }); culture = (Get-ProfileCulture $t.sid); is_line_cap_reached = ($raw.Count -ge $script:UltraViewerMaxLines) }
    }
    return ,$sets
}

function Get-RemoteAccess {
    $tools = @()
    foreach ($i in (Get-SoftwareInventory | Where-Object { $_.name -imatch $script:RemoteTools })) {
        $tools += [ordered]@{ name = $i.name; kind = 'software'; status = $null; path = $null; is_portable = $null }
    }
    $svcs = Get-CimSafe 'Win32_Service'
    foreach ($sv in @($svcs | Where-Object { "$($_.Name) $($_.DisplayName)" -imatch $script:RemoteTools })) {
        $tools += [ordered]@{ name = "$($sv.DisplayName)"; kind = 'service'; status = "$($sv.State)".ToLower(); path = (Get-LaunchedExecutable "$($sv.PathName)"); is_portable = $null }
    }
    $winWritable = @('Temp', 'Tasks', 'Tracing', 'System32\spool\drivers\color') | ForEach-Object { Join-Path $env:SystemRoot $_ }
    $procs = Get-RemoteToolProcessMatches (Get-CimSafe 'Win32_Process') @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432, $env:SystemRoot) $winWritable @($env:ProgramData)
    $tools += @($procs)
    # RDP: enabled / NLA required / port (HKLM ...\WinStations\RDP-Tcp, per Microsoft docs) + sessions now + logon history
    $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    $deny = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    $nla  = Get-RegValue $rdpKey 'UserAuthentication'
    $port = Get-RegValue $rdpKey 'PortNumber'
    $rdpLog = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    $networks = Get-LocalNetworks
    $rdp = [ordered]@{
        is_enabled      = ($null -ne $deny -and [int]$deny -eq 0)
        is_listening    = [bool](Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction SilentlyContinue)
        is_nla_required = if ($null -ne $nla) { [int]$nla -eq 1 } else { $null }
        port            = if ($null -ne $port) { [int]$port } else { $null }
        session_count   = Get-RdpSessionCount (Get-QwinstaOutput)
        logons          = Get-RdpLogonSummary (Get-RdpLogonEvents) (Get-EffectiveWindowDays $rdpLog) $networks $script:EventMax
    }
    $uvService = @($svcs | Where-Object { "$($_.Name)" -eq 'UltraViewService' })[0]
    $uvAuto = if ($uvService) { "$($uvService.StartMode)" -eq 'Auto' } else { $null }
    $uvConnections = @()
    $uvSets = Get-UltraViewerLogSets   # assign first: '@(f)' of a ',$x' return = ONE element
    foreach ($set in $uvSets) { $c = ConvertFrom-UltraViewerInLog $set.lines $set.culture; $uvConnections += $c }
    $uvCap = [bool](@($uvSets | Where-Object { $_.is_line_cap_reached }).Count)
    $ultraviewer = Get-UltraViewerSummary $uvConnections $uvAuto $script:EventWindowDays $uvCap
    $os = Get-CimSafe 'Win32_OperatingSystem'
    $isServer = [bool]($os -and [int]$os.ProductType -ne 1)   # a terminal server has RDP sessions by design

    # findings (Spanish)
    $names = @($tools | Where-Object { $_.kind -ne 'process' } | ForEach-Object { $_.name } | Select-Object -Unique)
    if ($names.Count -gt 0) { Add-Finding -Code 'remote_access_tools' -Severity 'medium' -Oea @('9.2','9.4') -Message ("Herramientas de acceso remoto instaladas: $($names -join ', '): verificar que esten autorizadas, con contrasena fuerte/2FA y con registro de accesos.") }
    $portable = @($procs | Where-Object { $_.is_portable } | ForEach-Object { $b = ("$($_.name)" -replace '(?i)\.exe$', '').ToLower(); $label = if ($script:RemoteToolProcesses.ContainsKey($b)) { "$($script:RemoteToolProcesses[$b]) ($($_.name))" } else { $_.name }; "$label en $(Get-FolderLabel $_.path)" } | Select-Object -Unique)
    if ($portable.Count -gt 0) { Add-Finding -Code 'remote_tool_portable' -Severity 'medium' -Oea @('9.2','9.7') -Message ("Herramienta de acceso remoto EN EJECUCION fuera de las carpetas de programas (portable, sin instalar): $($portable -join ', '). Es la forma habitual de las estafas de soporte tecnico: confirmar que sea una sesion de soporte autorizada; si no, cerrarla y revisar el equipo.") }
    $assist = @($procs | Where-Object { $script:BuiltinRemoteAssistance -contains (("$($_.name)" -replace '(?i)\.exe$', '').ToLower()) } | ForEach-Object { $script:RemoteToolProcesses[(("$($_.name)" -replace '(?i)\.exe$', '').ToLower())] } | Select-Object -Unique)
    if ($assist.Count -gt 0) { Add-Finding -Code 'remote_assistance_running' -Severity 'medium' -Oea @('9.2') -Message ("Asistencia remota de Windows EN USO en este momento ($($assist -join ', ')): si no es una sesion de soporte autorizada, cerrarla.") }
    if ($rdp.session_count -gt 0 -and -not $isServer) { Add-Finding -Code 'rdp_session_active' -Severity 'medium' -Oea @('9.2') -Message "$($rdp.session_count) sesion(es) de Escritorio remoto CONECTADA(S) en este momento (sin contar la de este relevamiento): confirmar que sean accesos autorizados." }
    if ($rdp.logons -and $rdp.logons.internet_logon_count -gt 0) {
        $from = @($rdp.logons.internet_sources | Select-Object -First 3 | ForEach-Object { $_.address })
        $atLeast = if ($rdp.logons.is_event_cap_reached) { 'Al menos ' } else { '' }
        Add-Finding -Code 'rdp_logons_from_internet' -Severity 'high' -Oea @('9.2','9.7') -EvidenceAt $rdp.logons.last_internet_logon_at -Message ("$($atLeast)$($rdp.logons.internet_logon_count) inicio(s) de sesion por Escritorio remoto desde direcciones de INTERNET en $($rdp.logons.covered_days) dias (origen: $($from -join ', ')): el equipo acepta RDP desde fuera de la red; restringirlo (VPN o firewall) y verificar que los accesos sean legitimos.")
    }
    if ($ultraviewer -and ($ultraviewer.fixed_password_connection_count -gt 0 -or $ultraviewer.undated_fixed_password_connection_count -gt 0)) {
        $who = @($ultraviewer.partners | Where-Object { $_.fixed_password_connection_count -gt 0 } | Select-Object -First 3 | ForEach-Object { if ($_.partner_name) { $_.partner_name } else { $_.provider_partner_id } })
        $parts = @()
        if ($ultraviewer.fixed_password_connection_count -gt 0) {
            $last = if ($ultraviewer.last_fixed_password_at) { "ultima: $("$($ultraviewer.last_fixed_password_at)".Substring(0, 10)), " } else { '' }   # ISO timestamp -> its date part
            $parts += "$($ultraviewer.fixed_password_connection_count) en los ultimos $($ultraviewer.window_days) dias ($($last)desde: $($who -join ', '))"
        }
        if ($ultraviewer.undated_fixed_password_connection_count -gt 0) { $parts += "$($ultraviewer.undated_fixed_password_connection_count) con fecha ilegible en el registro" }
        $evidenceAt = if ($ultraviewer.fixed_password_connection_count -gt 0) { $ultraviewer.last_fixed_password_at } else { $null }
        Add-Finding -Code 'remote_tool_fixed_password' -Severity 'medium' -Oea @('9.2','9.3') -EvidenceAt $evidenceAt -Message ("UltraViewer registra conexiones entrantes con CLAVE FIJA: $($parts -join '; '). Con clave fija se puede entrar sin que alguien en la PC entregue una clave nueva. Confirmar que cada equipo sea de soporte autorizado; si no se usa acceso desatendido, volver a clave aleatoria.")
    }
    if ($rdp.is_enabled -and $rdp.is_nla_required -eq $false) { Add-Finding -Code 'rdp_without_nla' -Severity 'high' -Oea @('9.7') -Message 'Escritorio remoto habilitado SIN autenticacion a nivel de red (NLA): exigir NLA.' }
    if ($rdp.is_enabled) { Add-Finding -Code 'rdp_enabled' -Severity 'low' -Oea @('9.7') -Message 'RDP (Escritorio remoto) habilitado: revisar si es necesario y si esta expuesto.' }
    return [ordered]@{ remote_access = [ordered]@{ tools = $tools; rdp = $rdp; ultraviewer = $ultraviewer } }
}

# ============================ MODULE: persistence =============================
# what starts by itself (Run keys, Startup folders, scheduled tasks, services, Winlogon) checked for malware patterns
# Ported from the 2026-09 remote-access inspection script. Real case behind it (hostel reception PC): a loader persisted
# as 8 Run keys 'cmd /c start /min "" powershell -WindowStyle Hidden -ExecutionPolicy Bypass -command ". '...\AppData\
# LocalLow\...\Program Rules NVIDEO\xxxxx.ps1'"' under fake names ('Update Drivers NVIDEO'); the antivirus removed the RAT,
# not the Run keys. Three tiers (fresh-eyes review 2026-10-01 measured the first design's false positives/negatives):
#   STRONG -> 'suspicious' (high): patterns that ordinary software does not use at startup (encoded PowerShell, download
#     and run, code built at run time, Windows binaries used as launchers, AppData\LocalLow, a script in a per-user or
#     temp folder, a program in a folder any user can write).
#   REVIEW -> low: a script in a folder SHARED by all users (ProgramData, Users\Public). Both IT automation (WinGet
#     auto-update, GPO/RMM inventory scripts, drive mapping) and malware live there: only a person can tell them apart.
#   WEAK -> context only: hidden window, execution-policy bypass, a plain web request (DynDNS updaters, health pings).
#     Windows and OEM tasks run hidden PowerShell from protected folders every day.
# Measured with these functions (2026-10-01): the hostel's 14 Run keys -> 8 loaders flagged, 6 benign not; ROD-PC (13 Run
# values in 4 hives, 92 task actions - 37 with arguments -, 285 services) and 6 real client captures carrying the system
# module (92 Run values, 3 Startup items, 142 task executables without arguments, 135 services) -> 0 flagged.
$script:ParamDash = '[-/\u2013\u2014\u2015]'   # PowerShell also accepts en/em dashes before a parameter (an en dash + 'enc' dodges '-enc' filters)
$script:ScriptExtensions = 'ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd'
$script:ProgramExtensions = 'exe|com|scr|pif'
# LINE-level patterns (a command line, or ONE line of a Startup script): nothing here may span lines - the second review
# found unrelated lines of a printer-mapping .bat joining into 'malware'. Compiled once, with a match timeout.
$script:CommandIndicatorPatterns = [ordered]@{
    # strong
    download_execute     = 'downloadstring|downloadfile|downloaddata|start-bitstransfer|bitsadmin(?:\.exe)?\s+/transfer|certutil(?:\.exe)?\s.*?' + $script:ParamDash + '(?:urlcache|decode)\b|adodb\.stream|savetofile|\bmsiexec(?:\.exe)?\s.*?https?://'
    dynamic_execution    = '(?<![\w\\/.-])iex(?![\w\\.])|invoke-expression|frombase64string|\[scriptblock\]::create|\beval\s*\(|\bexecute(?:global)?\s*\('
    lolbin_proxy         = '\bmshta(?:\.exe)?\b|\brundll32(?:\.exe)?\b.*?(?:javascript:|vbscript:)|\bregsvr32(?:\.exe)?\b.*?(?:\s/i:\s*["'']?(?:https?:|ftp:|\\\\)|\.sct\b|\bscrobj\b)|\b(?:wscript|cscript)(?:\.exe)?\b.*?//e:|\bconhost(?:\.exe)?\b.*?--headless'
    # weak (context)
    hidden_window        = $script:ParamDash + 'w[a-z]*\s+(?:hidden|1)\b|\bstart\s+(?:"[^"]*"\s+)?/min\b|\.run\b.*?,\s*0\b'
    policy_bypass        = $script:ParamDash + 'ex[a-z]*\s+(?:bypass|unrestricted)\b|' + $script:ParamDash + 'ep\s+(?:bypass|unrestricted)\b'
    web_request          = 'invoke-webrequest|(?<![\w\\/.-])iwr(?![\w\\.])|invoke-restmethod|(?<![\w\\/.-])irm\s|\b(?:curl|wget)(?:\.exe)?\s.*?https?://|msxml2\.(?:server)?xmlhttp|winhttp\.winhttprequest|net\.webclient'
}
# -EncodedCommand and the prefixes PowerShell accepts for it (-e, -ec, -en, -enc ... -encodedcommand) + its base64 value
$script:EncodedCommandPattern = $script:ParamDash + '(?:ec|e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)\s+["'']?([A-Za-z0-9+/]{16,}={0,2})'
$script:StrongIndicators = @('encoded_command', 'download_execute', 'dynamic_execution', 'lolbin_proxy', 'reverse_tunnel', 'locallow_path', 'user_writable_script', 'risky_startup_file', 'user_writable_binary', 'masquerading_binary')
# REVIEW tier: IT automation and malware both live here - a person decides (finding 'autorun_needs_review', low)
$script:ReviewIndicators = @('shared_folder_script', 'shared_folder_binary', 'hidden_user_script', 'startup_program_file', 'unread_startup_script', 'unanalyzed_command',
                             'shared_folder_library', 'user_library_registration')
# Startup-folder file kinds with no ordinary business use (encoded scripts, screensaver/PIF executables, HTA/WSF/JS).
# .bat/.cmd/.vbs are judged by their CONTENT, line by line: offices map network drives and printers with them.
$script:RiskyStartupExtensions = @('.scr', '.pif', '.vbe', '.jse', '.js', '.wsf', '.hta')
$script:StartupProgramExtensions = @('.exe', '.com', '.url')   # a program dropped straight into Startup: review
$script:StartupScriptExtensions = @('.bat', '.cmd', '.vbs', '.ps1', '.js', '.wsf', '.hta')   # Startup files whose CONTENT is read (<= 64 KB)
# Windows components no software ships under another folder: one of these names outside C:\Windows = masquerading
$script:SystemBinaryNames = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'wininit.exe', 'spoolsv.exe', 'taskhostw.exe',
                              'taskhost.exe', 'dllhost.exe', 'conhost.exe', 'rundll32.exe', 'regsvr32.exe', 'explorer.exe', 'dwm.exe', 'sihost.exe', 'ctfmon.exe',
                              'wuauclt.exe', 'lsm.exe', 'userinit.exe', 'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
# Verbs that only MENTION a path (delete, copy, archive, change permissions, read, print): a script or program named as
# their argument does not run there ('cmd /c del %TEMP%\x.bat', 'icacls C:\Windows\Temp\x.cmd', 'rar a D:\b.rar ...').
# reg / schtasks / sc are NOT here: they CONFIGURE something to run later.
$script:MentionVerbs = @('del', 'erase', 'rd', 'rmdir', 'copy', 'xcopy', 'robocopy', 'move', 'ren', 'rename', 'attrib', 'icacls', 'cacls', 'xcacls', 'takeown',
                         'type', 'more', 'find', 'findstr', 'echo', 'mkdir', 'md', 'compact', 'rar', 'winrar', '7z', '7za', '7zg', 'zip', 'unzip', 'tar', 'wzzip',
                         'makecab', 'remove-item', 'rm', 'ri', 'copy-item', 'cp', 'cpi', 'move-item', 'mv', 'mi', 'rename-item', 'rni', 'get-content', 'gc', 'cat',
                         'set-content', 'add-content', 'ac', 'out-file', 'test-path', 'get-item', 'gi', 'get-childitem', 'gci', 'dir', 'ls', 'new-item', 'ni',
                         'get-acl', 'set-acl', 'compress-archive', 'expand-archive', 'get-filehash', 'select-string', 'sls', 'write-host', 'write-output')
$script:AccessibilityBinaries = @('sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe', 'displayswitch.exe', 'atbroker.exe')
$script:IndicatorLabels = @{   # client-facing (Spanish) wording of each indicator
    encoded_command = 'comando codificado'; download_execute = 'descarga y ejecuta desde internet'; dynamic_execution = 'codigo armado al ejecutarse'
    lolbin_proxy = 'usa un componente de Windows para lanzar otro programa'; reverse_tunnel = 'tunel inverso hacia afuera'
    locallow_path = 'ruta AppData\LocalLow'; user_writable_script = 'script en carpeta de usuario o temporal'
    risky_startup_file = 'tipo de archivo riesgoso en Inicio'; user_writable_binary = 'programa en una carpeta donde cualquier usuario puede escribir'
    shared_folder_script = 'script en carpeta compartida por todos los usuarios'; shared_folder_binary = 'programa en carpeta temporal compartida'
    hidden_user_script = 'script del perfil del usuario lanzado oculto o salteando la politica'; startup_program_file = 'programa copiado directo en Inicio'
    unread_startup_script = 'script de Inicio que no se pudo analizar (muy grande o ilegible)'; unanalyzed_command = 'comando que no se pudo analizar'
    masquerading_binary = 'programa con el nombre de un componente de Windows fuera de la carpeta de Windows'
    shared_folder_library = 'biblioteca (DLL) de una carpeta compartida cargada con un componente de Windows'
    user_library_registration = 'biblioteca registrada para el usuario desde su AppData (regsvr32 /i:user, p. ej. el complemento de Teams)'
    hidden_window = 'ventana oculta'; policy_bypass = 'saltea la politica de ejecucion'; web_request = 'consulta a internet'; user_profile_script = 'script del perfil del usuario'
}
$script:RegexTimeout = [TimeSpan]::FromMilliseconds(250)
# bound for hostile registry values only: longer than any Startup script read (64 KB) and than any command Windows can
# start (32767 characters), so nothing that can run is ever cut
$script:MaxLineLength = 65536

# Pattern -> compiled regex with a match timeout; a timeout counts as "no match" (a hostile line cannot stall the audit).
function Get-IndicatorRegex([string]$Pattern) {
    if (-not $script:IndicatorRegexCache) { $script:IndicatorRegexCache = @{} }
    if (-not $script:IndicatorRegexCache.ContainsKey($Pattern)) {
        $script:IndicatorRegexCache[$Pattern] = New-Object System.Text.RegularExpressions.Regex($Pattern, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant', $script:RegexTimeout)
    }
    return $script:IndicatorRegexCache[$Pattern]
}
function Test-IndicatorPattern([string]$Pattern, [string]$Text) {
    try { return (Get-IndicatorRegex $Pattern).IsMatch($Text) } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { return $false }
}

# Base64 that decodes to UTF-16LE text = a real PowerShell -EncodedCommand payload (a hash or a key does not).
function Test-Utf16Base64([string]$Text) {
    try { $b = [Convert]::FromBase64String($Text) } catch { return $false }
    if ($b.Length -lt 8 -or ($b.Length % 2) -ne 0) { return $false }
    $zeros = 0; for ($i = 1; $i -lt $b.Length; $i += 2) { if ($b[$i] -eq 0) { $zeros++ } }
    return ($zeros -ge 0.8 * ($b.Length / 2))
}

# Absolute paths mentioned in one line, environment variables expanded (%VAR% and PowerShell's $env:VAR). A path with
# spaces only works QUOTED, so quotes delimit it (also nested: ". 'C:\x\y z.ps1'"); an unquoted path ends at whitespace
# or a shell separator. Wildcards (archive / copy arguments) are not paths that run.
function Get-PathCandidates([string]$Line) {
    $t = [Environment]::ExpandEnvironmentVariables(($Line -replace '(?i)\$env:(\w+)', '%$1%'))
    $raw = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($t, '"([^"]*)"')) {
        $inner = $m.Groups[1].Value; $raw.Add($inner)
        foreach ($s in [regex]::Matches($inner, "'([^']*)'")) { $raw.Add($s.Groups[1].Value) }
        foreach ($tok in ([regex]::Replace($inner, "'[^']*'", ' ') -split '[\s;&|<>,()=]+')) { if ($tok) { $raw.Add($tok) } }
    }
    $rest = [regex]::Replace($t, '"[^"]*"', ' ')
    foreach ($s in [regex]::Matches($rest, "'([^']*)'")) { $raw.Add($s.Groups[1].Value) }
    foreach ($tok in ([regex]::Replace($rest, "'[^']*'", ' ') -split '[\s;&|<>,()=]+')) { if ($tok) { $raw.Add($tok) } }
    # a path cannot hold control characters or " < > | (a quoted 'x.bat > log 2>&1' was split into its parts above) - .NET
    # path methods THROW on them; de-duplicated in linear time (a hostile line can carry thousands of paths)
    $out = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $raw) {
        $c = $r.Trim().TrimStart('.', '&', ' ').Trim()
        if ($c -match '^(?:[a-zA-Z]:\\|\\\\)' -and $c -notmatch '[*?\x00-\x1f"<>|]' -and $seen.Add($c)) { $out.Add($c) }
    }
    return ,$out.ToArray()
}

# Where a path lives, by who can write there (no ACL reads: the classes below are writable by any standard user on a
# default Windows install). $null = a protected location (Program Files, Windows, ProgramData vendor folders...).
function Get-PathClass([string]$Path) {
    $p = "$Path".ToLower()
    if ($p -match '^[a-z]:\\\$recycle\.bin\\') { return 'recycle_bin' }   # user-writable, nothing legitimate runs from it
    if ($p -match '\\appdata\\locallow\\') { return 'locallow' }
    if ($p -match '\\appdata\\local\\temp\\|\\windows\\temp\\') { return 'temp' }
    if ($p -match '\\appdata\\(?:roaming|local)\\[^\\]+$') { return 'appdata_root' }
    if ($p -match '\\appdata\\') { return 'appdata' }
    if ($p -match '\\users\\[^\\]+\\downloads\\') { return 'downloads' }
    if ($p -match '\\windows\\(?:tasks|tracing)\\|\\windows\\system32\\spool\\drivers\\color\\') { return 'windows_writable' }
    if ($p -match '\\users\\public\\') { return 'public' }
    if ($p -match '^[a-z]:\\programdata\\[^\\]+$') { return 'programdata_root' }
    if ($p -match '^[a-z]:\\programdata\\') { return 'programdata' }
    if ($p -match '^[a-z]:\\temp\\') { return 'root_temp' }
    if ($p -match '\\users\\[^\\]+\\') { return 'user_profile' }
    return $null
}

# The command a statement runs, past the wrappers that only start it (cmd /c, start, call, powershell -Command, & and .).
# Only the first 512 characters are looked at (the verb is at the start).
function Get-StatementVerb([string]$Statement) {
    $s = "$Statement".Trim(); if ($s.Length -gt 512) { $s = $s.Substring(0, 512) }
    for ($i = 0; $i -lt 8; $i++) {
        $before = $s
        $s = $s -replace '^[@\s{(]+', ''
        $s = $s -replace '^[&.]\s+', ''
        $s = $s -replace '(?i)^"?(?:[^\s"]*\\)?cmd(?:\.exe)?"?\s+(?:/[a-z](?::\S*)?\s+)*?/[ck]\s*', ''
        $s = $s -replace '(?i)^start\s+(?:"[^"]*"\s+)?(?:/\S+\s+)*', ''
        $s = $s -replace '(?i)^call\s+', ''
        $s = $s -replace '(?i)^"?(?:[^\s"]*\\)?(?:powershell|pwsh)(?:\.exe)?"?(?:\s+-(?!c\b|command\b)\w+(?:\s+(?![-"])\S+)?)*?\s+-(?:c|command)\s+', ''
        if ($s -eq $before) { break }
    }
    $first = if ($s -match '^"([^"]*)"') { $Matches[1] } elseif ($s -match "^'([^']*)'") { $Matches[1] } elseif ($s -match '^["'']?([^\s"'']+)') { $Matches[1] } else { '' }
    if ($first -notmatch '^(?:[a-zA-Z]:\\|\\\\|%|\.\\)' -and $first -match '^(\S+)\s') { $first = $Matches[1] }   # a quoted COMMAND -> its first word; a quoted PATH stays whole
    return (($first -replace '^.*[\\/]', '') -replace '(?i)\.(?:exe|com)$', '').ToLower()
}
# ssh / plink remote forward: '-R' alone or inside a cluster of one-letter options ('-NR', '-fNR9000:...'), or
# RemoteForward. A letter that takes an argument ends the cluster: '-oRemoteCommand=none' is -o with an argument.
function Test-SshRemoteForward([string]$Line) {
    foreach ($tok in ("$Line" -split '\s+')) {
        if ($tok -match '(?i)remoteforward') { return $true }
        if ($tok -cmatch '^-[A-Za-z]') {
            foreach ($ch in $tok.Substring(1).ToCharArray()) {
                if ($ch -ceq 'R') { return $true }
                if ('BbcDEeFIiJLlmOoPpQSWw'.IndexOf([string]$ch) -ge 0) { break }
            }
        }
    }
    return $false
}

# Indicator codes of ONE line (a command line, or one line of a Startup script).
function Get-LineIndicators([string]$Line, [string]$Kind = '', [string]$Location = '') {
    if ([string]::IsNullOrWhiteSpace($Line)) { return ,@() }
    $t = if ($Line.Length -gt $script:MaxLineLength) { $Line.Substring(0, $script:MaxLineLength) } else { $Line }
    $codes = @()
    foreach ($k in $script:CommandIndicatorPatterns.Keys) { if (Test-IndicatorPattern $script:CommandIndicatorPatterns[$k] $t) { $codes += $k } }
    # every -EncodedCommand value must decode as UTF-16LE text (a decoy '-e <key>' before the real one is skipped); no
    # 'powershell' word required: a renamed powershell.exe still takes the switch
    try { foreach ($m in (Get-IndicatorRegex $script:EncodedCommandPattern).Matches($t)) { if (Test-Utf16Base64 $m.Groups[1].Value) { $codes += 'encoded_command'; break } } } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { }
    # reverse tunnel: ssh/plink itself, with a -R remote forward (also clustered -NR / attached -R9000:...) or RemoteForward
    if ((Test-IndicatorPattern '(?:^|[\s"\\/])(?:ssh|plink)(?:\.exe)?"?\s' $t) -and (Test-SshRemoteForward $t)) { $codes += 'reverse_tunnel' }
    $isRunOnce = ($Kind -eq 'run_key' -and "$Location" -match '(?i)\\RunOnce$')
    $isLoader = Test-IndicatorPattern '\b(?:rundll32|regsvr32)(?:\.exe)?\b' $t
    $isUrlHandler = Test-IndicatorPattern 'url\.dll\s*,\s*(?:fileprotocolhandler|openurl)' $t
    $isUserRegistration = Test-IndicatorPattern '\bregsvr32(?:\.exe)?\b.*?\s/i:\s*"?user\b' $t   # per-user DllInstall: the Teams add-in repair
    # + the program the line starts: Windows runs an unquoted path with spaces ('C:\Users\Juan Perez\AppData\x.exe -k') as
    #   one path, the tokens only see 'C:\Users\Juan'
    $paths = Get-PathCandidates $t   # assign first: '@(f)' of a ',$x' return = ONE element
    $launched = [Environment]::ExpandEnvironmentVariables(("$(Get-LaunchedExecutable $t)" -replace '(?i)\$env:(\w+)', '%$1%')).Trim()
    if ($launched -match '^(?:[a-zA-Z]:\\|\\\\)' -and $launched -notmatch '[*?\x00-\x1f"<>|]' -and $paths -notcontains $launched) { $paths = @($paths) + $launched }
    # where each path appears (statements: cmd & && || |, PowerShell ;): only as an argument of a verb that does not run it
    # ('del', 'icacls', 'rar a'...) -> not judged; next to a web request in the SAME statement -> may be what was fetched
    # (a health ping beside a backup script is not "download and run")
    $mentionOnly = @{}; $fetched = @{}
    if (@($paths).Count -gt 0) {
        $statements = if ($t -match '[&|;]') { @($t -split '&&|\|\||[&|;]' | Where-Object { "$_".Trim() }) } else { @($t) }
        foreach ($st in $statements) {
            $sp = if ($statements.Count -eq 1) { $paths } else { Get-PathCandidates $st }
            $isMention = $script:MentionVerbs -contains (Get-StatementVerb $st)
            $isFetch = ($codes -contains 'web_request') -and ($statements.Count -eq 1 -or (Test-IndicatorPattern $script:CommandIndicatorPatterns['web_request'] $st))
            foreach ($sPath in $sp) {
                if ($isMention) { if (-not $mentionOnly.ContainsKey($sPath)) { $mentionOnly[$sPath] = $true } } else { $mentionOnly[$sPath] = $false }
                if ($isFetch) { $fetched[$sPath] = $true }
            }
        }
    }
    foreach ($path in $paths) {
        if ($mentionOnly[$path]) { continue }
        $class = Get-PathClass $path
        $ext = if ($path -match '\.([^.\\/:]+)$') { $Matches[1].ToLower() } else { '' }   # no [IO.Path]: it throws on odd characters
        $isScript = $ext -match "^(?:$($script:ScriptExtensions))$"; $isProgram = $ext -match "^(?:$($script:ProgramExtensions))$"
        if ($class -eq 'locallow' -and ($isScript -or $isProgram -or $ext -match '^(?:dll|ocx|cpl)$')) { $codes += 'locallow_path' }   # a log / cache path there (Java, games) is not
        if ($isScript) {
            if ($class -in 'locallow', 'temp', 'appdata_root', 'appdata', 'downloads', 'windows_writable', 'recycle_bin') { $codes += 'user_writable_script' }
            elseif ($class -in 'public', 'programdata', 'programdata_root', 'root_temp') { $codes += 'shared_folder_script' }
            elseif ($class -eq 'user_profile') { $codes += 'user_profile_script' }
        }
        if ($isProgram) {
            $writable = $class -in 'public', 'downloads', 'appdata_root', 'programdata_root', 'temp', 'windows_writable', 'recycle_bin'
            if ($Kind -eq 'service' -and $class -in 'appdata', 'locallow', 'user_profile') { $writable = $true }   # services never run from a user's folders
            if ($isRunOnce -and $class -in 'temp', 'downloads') { $writable = $false }               # installers resume from there after a reboot
            if ($writable) { $codes += 'user_writable_binary' } elseif ($class -eq 'root_temp') { $codes += 'shared_folder_binary' }
            if ($script:SystemBinaryNames -contains ($path -replace '^.*\\', '').ToLower() -and $path -notmatch '(?i)^[a-z]:\\windows\\') { $codes += 'masquerading_binary' }
        }
        # rundll32/regsvr32 on a library from a writable folder; a vendor's ProgramData folder (legacy OCX/DLL registration) and a
        # per-user registration under the user's AppData ('regsvr32 /n /i:user', the Teams add-in repair) are left for review
        if ($isLoader -and $ext -match '^(?:dll|ocx|cpl|dat|tmp|bin)$' -and $class) {
            if ($class -eq 'programdata') { $codes += 'shared_folder_library' }
            elseif ($isUserRegistration -and $class -eq 'appdata') { $codes += 'user_library_registration' }
            else { $codes += 'lolbin_proxy' }
        }
        if ($isUrlHandler -and ($isScript -or $isProgram)) { $codes += 'lolbin_proxy' }                          # url.dll handler launching a program
        if ($fetched.ContainsKey($path) -and ($isScript -or $isProgram) -and $class -and $class -ne 'programdata') { $codes += 'download_execute' }   # fetched as a program/script into a writable folder (a vendor's own ProgramData folder is not)
    }
    # a script of the user's own profile is ordinary; launched hidden or bypassing the policy it deserves a look (REVIEW:
    # admins schedule their own scripts like that every day; the hostel loader in AppData\LocalLow stays strong)
    if ($codes -contains 'user_profile_script' -and ($codes -contains 'hidden_window' -or $codes -contains 'policy_bypass')) { $codes += 'hidden_user_script' }
    return ,@($codes | Select-Object -Unique)
}
# Indicator codes of a command line or of a script's text (each line on its own).
function Get-CommandIndicators([string]$Text, [string]$Kind = '', [string]$Location = '') {
    if ([string]::IsNullOrWhiteSpace($Text)) { return ,@() }
    $codes = @()
    foreach ($line in ($Text -split "\r?\n")) { $found = Get-LineIndicators $line $Kind $Location; $codes += $found }
    return ,@($codes | Select-Object -Unique)
}
function Test-HasStrongIndicator($Codes) { return [bool](@($Codes | Where-Object { $script:StrongIndicators -contains $_ }).Count) }
# 'suspicious' (strong) | 'review' (shared folder / hidden profile script / program dropped in Startup) | $null
function Get-AutorunVerdict($Codes) {
    if (Test-HasStrongIndicator $Codes) { return 'suspicious' }
    if (@($Codes | Where-Object { $script:ReviewIndicators -contains $_ }).Count -gt 0) { return 'review' }
    return $null
}

# Program a command line / service ImagePath starts: the quoted part, else up to the first executable extension (unquoted
# paths with spaces exist, e.g. 'C:\Users\Juan Perez\AppData\x.exe -k'), else the first token.
function Get-LaunchedExecutable([string]$CommandLine) {
    $c = "$CommandLine".Trim()
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.*?\.(?:exe|com|scr|pif|bat|cmd))(?:\s|$)') { return $Matches[1] }
    return (Get-CommandExecutable $null $c)
}

# Indicators of one autorun entry { kind, location, command, target, extension, content }. Startup-folder files live under
# AppData / ProgramData by definition, so their own PATH is never judged: a shortcut by its RESOLVED target + arguments
# (an unresolved one is not judged), a script by its content line by line (<= 64 KB; one that cannot be read is left for
# review), program files by their kind.
function Get-AutorunIndicators($Entry) {
    $codes = @()
    if ($Entry.kind -eq 'startup_folder') {
        $ext = "$($Entry.extension)".ToLower()
        if ($script:RiskyStartupExtensions -contains $ext) { $codes += 'risky_startup_file' }
        if ($script:StartupProgramExtensions -contains $ext) { $codes += 'startup_program_file' }
        # a script that could not be read (> 64 KB: padding hides a payload from a line-level check; or unreadable) cannot be cleared
        if ($script:StartupScriptExtensions -contains $ext -and $null -eq $Entry.content) { $codes += 'unread_startup_script' }
        $text = if ($null -ne $Entry.content) { $Entry.content } elseif ($Entry.target) { $Entry.target } else { $null }
        if ($text) { $found = Get-CommandIndicators $text 'startup_folder' $Entry.location; $codes += $found }   # assign first: '@(f)' of a ',$x' return = ONE element
    } else {
        $found = Get-CommandIndicators $Entry.command $Entry.kind $Entry.location; $codes += $found
    }
    return ,@($codes | Select-Object -Unique)
}

# Secrets inside a command kept as evidence (task arguments can carry tokens/passwords) are masked as '***': values of
# token=/password=/client_secret=-style pairs, of --password/--token/-pw/-clave style switches, '/p:' / '/clave:', curl -u
# user:password, Authorization Bearer/Basic values and URL credentials. Values that are paths or URLs stay (a payload
# path or a C2 address is the evidence the technician needs). Best effort: an unknown switch name is not recognized.
function Protect-CommandSecrets([string]$Text) {
    $t = "$Text"
    $keep = '(?![a-zA-Z]:\\|\\\\|https?://|ftp://|HK(?:LM|CU|CR|CC|U|EY_)\b)'
    $t = [regex]::Replace($t, '(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}', '$1 ***')
    $t = [regex]::Replace($t, '(?i)((?:^|\s)(?:-u|--user)\s+[^\s:]+:)\S+', '$1***')
    $t = [regex]::Replace($t, "(?i)(?<![a-z0-9])((?:[a-z]+_)?(?:token|secret|password|passwd|pwd|pass|apikey|api_key|key|sig|signature|clave|contrasena))(\s*[=:]\s*)$keep[^\s&`"';,]+", '$1$2***')
    $t = [regex]::Replace($t, "(?i)((?:^|\s)$($script:ParamDash){1,2}(?:pw|pwd|pass|password|passwd|token|secret|apikey|api-key|api_key|key|clave|contrasena)[\s=:]+)$keep(`"[^`"]*`"|'[^']*'|\S+)", '$1***')
    $t = [regex]::Replace($t, "(?i)((?:^|\s)$($script:ParamDash)p\s+)$keep(?!\d+(?:\s|$))(`"[^`"]*`"|'[^']*'|\S+)", '$1***')   # PsExec / mysql '-p <password>' (a port number stays)
    $t = [regex]::Replace($t, '(?i)(\bnet(?:\.exe)?\s+use\s+(?:(?:[a-z]:|\*)\s+)?\\\\\S+\s+)(?!/)("[^"]*"|\S+)', '$1***')   # net use Z: \\srv\share <password>
    $t = [regex]::Replace($t, '(?i)(\bnet(?:\.exe)?\s+use\b.*?\s/user:\S+\s+)(?![/"])(\S+)', '$1***')                       # ... /user:x <password>
    $t = [regex]::Replace($t, "(?i)(\s/rp\s+)$keep(`"[^`"]*`"|\S+)", '$1***')                                                     # schtasks /rp <password>
    $t = [regex]::Replace($t, "(?i)(\s/(?:p|pass|password|pwd|clave|contrasena):)$keep\S+", '$1***')
    $t = [regex]::Replace($t, '(?i)(\w+://)[^/\s:@]+:[^/\s@]+@', '$1***@')
    return $t
}

# Winlogon defaults: Userinit '<windir>\system32\userinit.exe,' and Shell 'explorer.exe'. Anything appended runs at
# every logon (classic RAT persistence). Kiosk / shell-replacement setups change Shell on purpose -> wording says verify.
function Test-DefaultUserinit([string]$Value) { return ("$Value".Trim() -match '^(?i)(?:[a-z]:\\windows\\system32\\)?userinit(?:\.exe)?\s*,?$') }
function Test-DefaultShell([string]$Value) { return ("$Value".Trim() -match '^(?i)(?:[a-z]:\\windows\\)?explorer\.exe$') }

# ---- raw readers (thin wrappers: the integration test replaces them) ----
function Get-RegistryValues([string]$Key) {   # value name -> text; empty when the key is missing / unreadable
    $out = [ordered]@{}
    try { $k = Get-Item -LiteralPath $Key -ErrorAction Stop; foreach ($n in $k.GetValueNames()) { if ($n) { $out[$n] = "$($k.GetValue($n))" } } } catch { }
    return $out
}
# HKU\.DEFAULT is LocalSystem's hive, the same one as HKU\S-1-5-18 (Win32_StartupCommand lists its Run values twice).
# .NET lists every loaded hive; Get-ChildItem drops the ones it cannot open (S-1-5-19/20 without admin, measured on ROD-PC).
function Get-UserHiveNames {
    $names = @(); try { $names = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -notlike '*_Classes' }) } catch { }
    if ($names -contains 'S-1-5-18') { $names = @($names | Where-Object { $_ -ne '.DEFAULT' }) }
    return ,$names
}
function Get-StartupFolderFiles([string]$Dir) { return ,@(Get-ChildItem -LiteralPath $Dir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' }) }
function Get-ShortcutCommand([string]$Path) {   # target + arguments of a .lnk (WScript.Shell only READS it; nothing is saved)
    try { $sh = New-Object -ComObject WScript.Shell; $l = $sh.CreateShortcut($Path); $c = ("$($l.TargetPath) $($l.Arguments)").Trim(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($sh); return $c } catch { return $null }
}
# $null = not read (> 64 KB or unreadable); an empty file is read as '' ('Get-Content -Raw' returns $null for it)
function Get-SmallTextFile([string]$Path) { try { if ((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 65536) { return $null }; return "$(Get-Content -LiteralPath $Path -Raw -ErrorAction Stop)" } catch { return $null } }

# Run / RunOnce / policy Run of HKLM (64- and 32-bit views) and of every LOADED user hive (logged-on users, service
# accounts, .DEFAULT). A user who is not logged on has no hive loaded: their Run keys are not visible (loaded_hive_count).
function Get-RunKeyEntries {
    $subs = @('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run')
    $roots = @(@{ path = 'HKLM:'; label = 'HKLM'; subs = @($subs) + @('SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce') })
    $hiveNames = Get-UserHiveNames
    foreach ($h in $hiveNames) { $roots += @{ path = "Registry::HKEY_USERS\$h"; label = "HKU\$h"; subs = $subs } }
    $entries = @()
    foreach ($r in $roots) {
        foreach ($sp in $r.subs) {
            $vals = Get-RegistryValues (Join-Path $r.path $sp)
            foreach ($n in $vals.Keys) { $entries += [ordered]@{ kind = 'run_key'; location = "$($r.label)\$sp"; name = "$n"; command = $vals[$n] } }
        }
    }
    return ,$entries
}
# A registry value as stored: REG_EXPAND_SZ NOT expanded (another user's %USERPROFILE% is not the auditor's).
function Get-RegRawValue([string]$Key, [string]$Name) {
    try { return (Get-Item -LiteralPath $Key -ErrorAction Stop).GetValue($Name, $null, 'DoNotExpandEnvironmentNames') } catch { return $null }
}
function Get-StartupFolderEntries {
    $dirs = @()
    if ($env:ProgramData) { $dirs += (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup') }
    # the folders can be redirected (GPO) or MOVED (a persistence trick): read where User Shell Folders points too
    $common = Get-RegRawValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' 'Common Startup'
    if ("$common".Trim()) { $dirs += [Environment]::ExpandEnvironmentVariables("$common") }   # machine-wide variables: ours are right
    foreach ($p in @(Get-CimSafe 'Win32_UserProfile' | Where-Object { $_ -and -not $_.Special -and $_.LocalPath })) {
        $dirs += (Join-Path "$($p.LocalPath)" 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
        $u = Get-RegRawValue "Registry::HKEY_USERS\$($p.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" 'Startup'   # loaded hives only
        if ("$u".Trim()) { $dirs += [Environment]::ExpandEnvironmentVariables((("$u" -replace '(?i)%USERPROFILE%', "$($p.LocalPath)") -replace '(?i)%APPDATA%', (Join-Path "$($p.LocalPath)" 'AppData\Roaming'))) }
    }
    $entries = @()
    foreach ($d in @($dirs | ForEach-Object { "$_".TrimEnd('\') } | Sort-Object -Unique)) {   # case-insensitive: one folder read once
        $files = Get-StartupFolderFiles $d
        foreach ($f in $files) {
            $ext = "$($f.Extension)".ToLower(); $target = $null; $content = $null
            if ($ext -eq '.lnk') { $target = Get-ShortcutCommand $f.FullName }
            elseif ($script:StartupScriptExtensions -contains $ext) { $content = Get-SmallTextFile $f.FullName }
            $entries += [ordered]@{ kind = 'startup_folder'; location = $d; name = "$($f.Name)"; command = $(if ($target) { $target } else { "$($f.FullName)" }); target = $target; extension = $ext; content = $content }
        }
    }
    return ,$entries
}
function Get-ScheduledTaskEntries {   # every task (malware hides under \Microsoft\ too); COM-handler actions have no command line
    $entries = @()
    try { $all = @(Get-ScheduledTask -ErrorAction Stop) } catch { return $null }
    foreach ($t in $all) {
        foreach ($a in @($t.Actions | Where-Object { $_ -and $_.PSObject.Properties['Execute'] -and "$($_.Execute)".Trim() })) {
            $entries += [ordered]@{ kind = 'scheduled_task'; location = "$($t.TaskPath)"; name = "$($t.TaskName)"; command = ("$($a.Execute) $($a.Arguments)").Trim() }
        }
    }
    return ,$entries
}
function Get-ServiceEntries {
    $svcs = Get-CimSafe 'Win32_Service'
    if ($null -eq $svcs) { return $null }
    return ,@(@($svcs | Where-Object { $_ -and $_.PathName }) | ForEach-Object { [ordered]@{ kind = 'service'; location = "HKLM\SYSTEM\CurrentControlSet\Services\$($_.Name)"; name = "$($_.Name)"; command = "$($_.PathName)" } })
}

function Get-PersistenceState {
    $hives = Get-UserHiveNames
    $run = Get-RunKeyEntries; $startup = Get-StartupFolderEntries; $tasks = Get-ScheduledTaskEntries; $services = Get-ServiceEntries
    $suspicious = @(); $toReview = @(); $seen = @{}
    foreach ($e in @(@($run) + @($startup) + @($tasks) + @($services) | Where-Object { $_ })) {
        # one odd entry must not take the whole module down (a 2026-10-01 bug did: '> log' inside quotes): it goes to review
        try { $codes = Get-AutorunIndicators $e }
        catch { $codes = @('unanalyzed_command'); [void]$script:Errors.Add([ordered]@{ module = 'persistence'; message = "autorun entry not analyzed ($($e.kind) '$($e.name)'): $($_.Exception.Message)" }) }
        $verdict = Get-AutorunVerdict $codes
        $key = "$($e.kind)|$($e.name)|$($e.command)"
        if (-not $verdict -or $seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $cmd = Protect-CommandSecrets "$($e.command)"; if ($cmd.Length -gt 300) { $cmd = $cmd.Substring(0, 297) + '...' }
        $row = [ordered]@{ kind = $e.kind; location = $e.location; name = $e.name; command = $cmd; indicators = @($codes) }
        if ($verdict -eq 'suspicious') { $suspicious += $row } else { $toReview += $row }
    }
    # Winlogon (HKLM) + per-user Shell overrides (HKU\<sid>\...\Winlogon\Shell should not exist)
    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $userinit = Get-RegValue $wl 'Userinit'; $shell = Get-RegValue $wl 'Shell'
    $userShells = @()
    foreach ($h in $hives) {
        $s = Get-RegValue "Registry::HKEY_USERS\$h\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'Shell'
        if ("$s".Trim() -and -not (Test-DefaultShell $s)) { $userShells += [ordered]@{ hive = "HKU\$h"; shell = "$s" } }   # 'explorer.exe' left behind is the default
    }
    $winlogon = [ordered]@{
        userinit            = $userinit
        shell               = $shell
        is_userinit_default = if ($null -ne $userinit) { Test-DefaultUserinit $userinit } else { $null }
        is_shell_default    = if ($null -ne $shell) { Test-DefaultShell $shell } else { $null }
        user_shells         = $userShells
    }
    # Accessibility tools reachable from the logon screen (sticky keys, utility manager...) with a 'Debugger' redirect =
    # a SYSTEM shell before logging on, typically used over RDP. No ordinary software sets these values.
    $debuggers = @()
    foreach ($b in $script:AccessibilityBinaries) {
        $d = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$b" 'Debugger'
        if ("$d".Trim()) { $debuggers += [ordered]@{ binary = $b; debugger = "$d" } }
    }

    # findings (Spanish)
    if ($suspicious.Count -gt 0) {
        $kindLabel = @{ run_key = 'clave Run'; startup_folder = 'carpeta Inicio'; scheduled_task = 'tarea programada'; service = 'servicio' }
        $desc = @($suspicious | Select-Object -First 3 | ForEach-Object {
            $why = @($_.indicators | Where-Object { $script:StrongIndicators -contains $_ } | ForEach-Object { $script:IndicatorLabels[$_] })
            "'$($_.name)' [$($kindLabel[$_.kind])] ($($why -join ', '))"
        })
        $more = if ($suspicious.Count -gt 3) { " (+$($suspicious.Count - 3) mas)" } else { '' }
        Add-Finding -Code 'suspicious_autorun' -Severity 'high' -Oea @('9.7') -Message ("Arranque automatico con patron tipico de malware: $($desc -join '; ')$($more). Revisar cada uno; si no es legitimo, eliminarlo y analizar el equipo con un antivirus actualizado.")
    }
    if ($toReview.Count -gt 0) {
        $kindLabel = @{ run_key = 'clave Run'; startup_folder = 'carpeta Inicio'; scheduled_task = 'tarea programada'; service = 'servicio' }
        $desc = @($toReview | Select-Object -First 3 | ForEach-Object {
            $why = @($_.indicators | Where-Object { $script:ReviewIndicators -contains $_ } | ForEach-Object { $script:IndicatorLabels[$_] })
            "'$($_.name)' [$($kindLabel[$_.kind])] ($($why -join ', '))"
        })
        $more = if ($toReview.Count -gt 3) { " (+$($toReview.Count - 3) mas)" } else { '' }
        Add-Finding -Code 'autorun_needs_review' -Severity 'low' -Oea @('9.7') -Message ("Arranque automatico para verificar: $($desc -join '; ')$($more). Lo usan tanto automatizaciones de sistemas como programas maliciosos: confirmar que sean de la empresa y que un usuario comun no pueda modificarlos (si corren con privilegios, seria una via para obtener permisos de administrador).")
    }
    $wlBad = @()
    if ($winlogon.is_userinit_default -eq $false) { $wlBad += "Userinit = $userinit" }
    if ($winlogon.is_shell_default -eq $false) { $wlBad += "Shell = $shell" }
    foreach ($u in $userShells) { $wlBad += "Shell de usuario ($($u.hive)) = $($u.shell)" }
    if ($wlBad.Count -gt 0) { Add-Finding -Code 'winlogon_modified' -Severity 'high' -Oea @('9.7') -Message ("Inicio de sesion de Windows (Winlogon) modificado: $($wlBad -join ' ; '). Lo que se agrega ahi se ejecuta en cada inicio de sesion: verificar (puede ser un modo kiosco); si no es intencional, restaurar el valor de Windows.") }
    if ($debuggers.Count -gt 0) { Add-Finding -Code 'accessibility_debugger_hijack' -Severity 'high' -Oea @('9.7') -Message ("Herramientas de accesibilidad de la pantalla de inicio redirigidas a otro programa: $(@($debuggers | ForEach-Object { "$($_.binary) -> $($_.debugger)" }) -join ' ; '). Da una consola con maximos privilegios SIN iniciar sesion (puerta trasera conocida): eliminar la redireccion y revisar el equipo.") }

    return [ordered]@{
        persistence = [ordered]@{
            run_key_count           = @($run).Count
            startup_file_count      = @($startup).Count
            scheduled_task_action_count = if ($null -ne $tasks) { @($tasks).Count } else { $null }
            service_count           = if ($null -ne $services) { @($services).Count } else { $null }
            loaded_hive_count       = $hives.Count   # logged-on users + service accounts; users not logged on are not visible
            suspicious_autoruns     = $suspicious
            reviewable_autoruns     = $toReview
            winlogon                = $winlogon
            accessibility_debuggers = $debuggers
        }
    }
}

# ============================ MODULE: network =================================
# proxy, Wi-Fi, hosts, VPN, listening ports
# Proxy, saved Wi-Fi profiles (auth type only - the key is NEVER read), hosts file, VPN, listening ports (OEA 9.7).
$script:RiskyPorts = @{ 5985 = 'WinRM (HTTP)'; 21 = 'FTP'; 23 = 'Telnet'; 1433 = 'SQL Server'; 3306 = 'MySQL'; 5432 = 'PostgreSQL'; 5900 = 'VNC'; 5901 = 'VNC'; 5938 = 'TeamViewer'; 7070 = 'AnyDesk' }
function Get-NetworkExposure {
    # proxy of the audited user (not the technician)
    $inet = Get-UserRegPath 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $proxy = $null
    if ($inet) {
        $pe = Get-RegValue $inet 'ProxyEnable'
        $proxy = [ordered]@{ is_enabled = ($null -ne $pe -and [int]$pe -eq 1); server = Get-RegValue $inet 'ProxyServer'; auto_config_url = Get-RegValue $inet 'AutoConfigURL' }
    }
    # Wi-Fi profiles from the WLAN service XMLs: name / authentication / connection mode. keyMaterial is never read.
    $wifi = @(); $seen = @{}
    foreach ($x in @(Get-ChildItem "$env:ProgramData\Microsoft\Wlansvc\Profiles\Interfaces" -Recurse -Filter '*.xml' -File -ErrorAction SilentlyContinue)) {
        try {
            [xml]$d = Get-Content $x.FullName -Raw -ErrorAction Stop
            $n = "$($d.WLANProfile.name)"; if (-not $n -or $seen.ContainsKey($n)) { continue }; $seen[$n] = $true
            $wifi += [ordered]@{ name = $n; authentication = "$($d.WLANProfile.MSM.security.authEncryption.authentication)"; connection_mode = "$($d.WLANProfile.connectionMode)" }
        } catch { }
    }
    # hosts file: active (non-comment) lines
    $hosts = @()
    try { $hosts = @(Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' }) } catch { }
    # VPN: machine-wide + current-account phonebook (per-user entries of another account are not visible)
    $vpn = @()
    foreach ($spec in @(@{ all = $true }, @{ all = $false })) {
        try {
            $list = if ($spec.all) { Get-VpnConnection -AllUserConnection -ErrorAction Stop } else { Get-VpnConnection -ErrorAction Stop }
            foreach ($v in @($list)) { if ($v) { $vpn += [ordered]@{ name = "$($v.Name)"; server = "$($v.ServerAddress)"; tunnel_kind = "$($v.TunnelType)".ToLower(); authentication = (@($v.AuthenticationMethod) -join ','); scope = if ($spec.all) { 'all_users' } else { 'runner' } } } }
        } catch { }
    }
    # listening TCP ports reachable from the network (loopback excluded) + owning process
    $ports = @()
    try {
        $names = @{}; foreach ($pr in @(Get-Process -ErrorAction SilentlyContinue)) { $names[[int]$pr.Id] = $pr.ProcessName }
        $seenP = @{}
        foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' })) {
            $k = "$($c.LocalPort)|$($c.OwningProcess)"; if ($seenP.ContainsKey($k)) { continue }; $seenP[$k] = $true
            $ports += [ordered]@{ port = [int]$c.LocalPort; address = "$($c.LocalAddress)"; process = $names[[int]$c.OwningProcess] }
        }
        $ports = @($ports | Sort-Object { $_.port })
    } catch { $ports = $null }

    # findings (Spanish)
    $openAuto = @($wifi | Where-Object { $_.authentication -eq 'open' -and $_.connection_mode -eq 'auto' } | ForEach-Object { $_.name })
    if ($openAuto.Count -gt 0) { Add-Finding -Code 'wifi_open_autoconnect' -Severity 'medium' -Oea @('9.7') -Message ("Redes Wi-Fi ABIERTAS guardadas con conexion automatica: $(@($openAuto | Select-Object -First 5) -join ', ')$(if ($openAuto.Count -gt 5) { " (+$($openAuto.Count - 5))" }): eliminarlas.") }
    if ($hosts.Count -gt 0) { Add-Finding -Code 'hosts_entries' -Severity 'medium' -Oea @('9.7') -Message ("Archivo hosts con entradas activas: $(@($hosts | Select-Object -First 3) -join ' | '): verificar que sean legitimas (lo usan malware y activadores).") }
    foreach ($pt in @($ports | Where-Object { $_ -and $script:RiskyPorts.ContainsKey($_.port) })) { Add-Finding -Code 'risky_port_open' -Severity 'medium' -Oea @('9.7') -Message "Puerto $($pt.port) ($($script:RiskyPorts[$pt.port])) abierto a la red, proceso '$($pt.process)': cerrarlo o restringirlo por firewall si no es necesario." }

    return [ordered]@{ network = [ordered]@{ proxy = $proxy; wifi_profiles = $wifi; hosts_entries = $hosts; vpn_connections = $vpn; listening_ports = $ports } }
}

# ============================ MODULE: data ====================================
# where company data lives and how it can leave the endpoint
function Get-UsbStorageControl {
    # 9.4 USB storage control
    $usbStart = $null
    try { $usbStart = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name Start -ErrorAction Stop).Start } catch { }
    $usbReadOnly = $false
    try { $usbReadOnly = ([int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies' -Name WriteProtect -ErrorAction Stop).WriteProtect -eq 1) } catch { }
    $usbState = if ($usbStart -eq 4) { 'disabled' } elseif ($usbReadOnly) { 'read_only' } else { 'enabled' }
    $usbHistory = @()
    try { $usbHistory = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction Stop | ForEach-Object { $_.PSChildName }) } catch { }

    if ($usbState -eq 'enabled') { Add-Finding -Code 'usb_storage_unrestricted' -Severity 'medium' -Oea @('9.4') -Message 'Dispositivos USB de almacenamiento sin restriccion: definir politica de uso/bloqueo.' }
    return [ordered]@{ status = $usbState; device_history = $usbHistory }
}

# Where company data lives on the endpoint and how it can leave it (OEA 9.4 leakage, 9.9 backup): removable-storage
# policy, Outlook data files, File History, machine certificates, browsers + extensions and cloud accounts of the
# AUDITED user. Removable-storage policy path = standard ADMX location (NOT VERIFIED against docs).
function Get-ExtensionName([string]$Dir, $Manifest) {
    $n = "$($Manifest.name)"
    if ($n -match '^__MSG_(.+)__$') {
        $key = $Matches[1]; $loc = if ($Manifest.default_locale) { "$($Manifest.default_locale)" } else { 'en' }
        $mf = Join-Path $Dir "_locales\$loc\messages.json"
        if (Test-Path $mf) {
            try { $msgs = Get-Content $mf -Raw -Encoding UTF8 | ConvertFrom-Json; $prop = $msgs.PSObject.Properties | Where-Object { $_.Name -ieq $key } | Select-Object -First 1; if ($prop) { $n = "$($prop.Value.message)" } } catch { }
        }
    }
    return $n
}

function Get-DataProtection {
    $u = Resolve-AuditedUser; $prof = $u.profile_path
    # removable storage policies
    $rsKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices'
    $denyAll = Get-RegValue $rsKey 'Deny_All'
    $classDeny = @()
    foreach ($k in @(Get-ChildItem $rsKey -ErrorAction SilentlyContinue)) {
        $w = Get-RegValue $k.PSPath 'Deny_Write'; $r = Get-RegValue $k.PSPath 'Deny_Read'
        if (($null -ne $w -and [int]$w -eq 1) -or ($null -ne $r -and [int]$r -eq 1)) { $classDeny += "$($k.PSChildName)" }
    }
    $rdv = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'RDVDenyWriteAccess'
    $removable = [ordered]@{ is_policy_configured = [bool](Test-Path $rsKey); is_all_denied = ($null -ne $denyAll -and [int]$denyAll -eq 1); denied_class_count = $classDeny.Count; is_unencrypted_write_denied = ($null -ne $rdv -and [int]$rdv -eq 1) }

    $outlook = @(); $fileHistory = $null; $extensions = @(); $cloud = @()
    if ($prof) {
        foreach ($d in @("$prof\AppData\Local\Microsoft\Outlook", "$prof\Documents\Outlook Files")) {
            foreach ($f in @(Get-ChildItem $d -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.pst', '.ost' })) { $outlook += [ordered]@{ file = $f.Name; size_gb = [math]::Round($f.Length / 1GB, 2) } }
        }
        $fileHistory = [bool](Test-Path "$prof\AppData\Local\Microsoft\Windows\FileHistory\Configuration")
        foreach ($b in @(@{ n = 'chrome'; p = "$prof\AppData\Local\Google\Chrome\User Data" }, @{ n = 'edge'; p = "$prof\AppData\Local\Microsoft\Edge\User Data" }, @{ n = 'brave'; p = "$prof\AppData\Local\BraveSoftware\Brave-Browser\User Data" })) {
            foreach ($pp in @(Get-ChildItem $b.p -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' })) {
                foreach ($e in @(Get-ChildItem (Join-Path $pp.FullName 'Extensions') -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^[a-p]{32}$' })) {
                    $ver = Get-ChildItem $e.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -Last 1
                    if (-not $ver) { continue }
                    $mfile = Join-Path $ver.FullName 'manifest.json'
                    try { $m = Get-Content $mfile -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json } catch { continue }
                    $extensions += [ordered]@{ browser = $b.n; profile = $pp.Name; provider_extension_id = $e.Name; name = Get-ExtensionName $ver.FullName $m; version = "$($m.version)" }
                }
            }
        }
    }
    $odKey = Get-UserRegPath 'Software\Microsoft\OneDrive\Accounts'
    if ($odKey) {
        foreach ($a in @(Get-ChildItem $odKey -ErrorAction SilentlyContinue)) {
            $em = Get-RegValue $a.PSPath 'UserEmail'
            if ($em) { $cloud += [ordered]@{ service = 'onedrive'; account = "$($a.PSChildName)"; email = "$em"; folder = Get-RegValue $a.PSPath 'UserFolder' } }
        }
    }
    if ($prof -and (Test-Path "$prof\AppData\Local\Google\DriveFS")) { $cloud += [ordered]@{ service = 'google_drive'; account = $null; email = $null; folder = $null } }
    # (7) Firefox add-ons of the audited user (extensions.json per profile)
    if ($prof) {
        foreach ($fp in @(Get-ChildItem "$prof\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory -ErrorAction SilentlyContinue)) {
            $ej = Join-Path $fp.FullName 'extensions.json'
            if (-not (Test-Path $ej)) { continue }
            try {
                $j = Get-Content $ej -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
                foreach ($a in @($j.addons | Where-Object { $_.type -eq 'extension' -and $_.location -eq 'app-profile' })) {
                    $extensions += [ordered]@{ browser = 'firefox'; profile = $fp.Name; provider_extension_id = "$($a.id)"; name = "$($a.defaultLocale.name)"; version = "$($a.version)" }
                }
            } catch { }
        }
    }
    # (4) trusted root certificates of the machine that are not Microsoft's (a local root CA can intercept HTTPS: used by
    # corporate proxies/antivirus and also by malware) -> inventory; judged by the technician.
    $roots = @(Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -notmatch 'Microsoft' } | ForEach-Object { [ordered]@{ subject = "$($_.Subject)"; expires_at = ConvertTo-IsoTimestamp $_.NotAfter } })
    $browsers = @(Get-SoftwareInventory | Where-Object { $_.name -match '^(Google Chrome|Microsoft Edge|Mozilla Firefox|Brave|Opera)( |$)' -and $_.name -notmatch 'Update|WebView' } | ForEach-Object { [ordered]@{ name = $_.name; version = $_.version } })
    # machine certificates expiring within 60 days / already expired (per-user stores of another account are not readable)
    $certs = @()
    foreach ($c in @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue)) {
        $d = [int][math]::Floor(($c.NotAfter - (Get-Date)).TotalDays)
        if ($d -le 60) { $certs += [ordered]@{ subject = "$($c.Subject)"; expires_at = ConvertTo-IsoTimestamp $c.NotAfter; days_left = $d } }
    }

    # findings (Spanish)
    foreach ($o in @($outlook | Where-Object { $_.size_gb -ge 40 })) { Add-Finding -Code 'outlook_data_file_large' -Severity 'medium' -Oea @('9.9') -Message "Archivo de Outlook '$($o.file)' de $($o.size_gb) GB (limite por defecto 50 GB): archivar antes de que deje de funcionar." }
    foreach ($c in $certs) { if ($c.days_left -lt 0) { Add-Finding -Code 'certificate_expired' -Severity 'medium' -Oea @() -Message "Certificado del equipo VENCIDO ($($c.subject), $(ConvertTo-IsoDate $c.expires_at))." } else { Add-Finding -Code 'certificate_expiring' -Severity 'low' -Oea @() -Message "Certificado del equipo vence en $($c.days_left) dias ($($c.subject), $(ConvertTo-IsoDate $c.expires_at))." } }

    $usbStorage = Get-UsbStorageControl
    return [ordered]@{ data = [ordered]@{ usb_storage = $usbStorage; removable_storage_policy = $removable; outlook_data_files = $outlook; is_file_history_configured = $fileHistory; browsers = $browsers; browser_extensions = $extensions; cloud_accounts = $cloud; expiring_certificates = $certs; non_microsoft_root_certificates = $roots } }
}

# ============================ MODULE: backup ==================================
# backup software/tasks, cloud sync, restore points
function Get-RestorePointCount {
    # 9.9/9.12 restore points
    $restoreCount = $null
    try { $restoreCount = @(Get-ComputerRestorePoint -ErrorAction Stop).Count } catch { }

    return $restoreCount
}

function Get-BackupStatus {
    $inventory = Get-SoftwareInventory
    $backupSoftware = @($inventory | Where-Object { $_.name -imatch $script:BackupTools } | ForEach-Object { $_.name } | Select-Object -Unique)
    $cloudSync = @($inventory | Where-Object { $_.name -imatch $script:CloudTools -and $_.name -notmatch 'plugin' } | ForEach-Object { $_.name } | Select-Object -Unique)
    $userProfilePath = (Resolve-AuditedUser).profile_path
    if ($userProfilePath -and (Test-Path (Join-Path $userProfilePath 'OneDrive')) -and -not ($cloudSync -match 'onedrive')) { $cloudSync += 'OneDrive (carpeta presente)' }

    # scheduled tasks of real backup products (Windows' own \Microsoft\Windows\* tasks are excluded: false positives).
    $tasks = @()
    try {
        Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\Windows\*' } | ForEach-Object {
            $t = $_
            $txt = "$($t.TaskName) " + (($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ')
            if ($txt -imatch $script:BackupTools) { $tasks += $t.TaskName }
        }
    } catch { }
    $tasks = @($tasks | Select-Object -Unique)

    $logical = Get-CimSafe 'Win32_LogicalDisk'
    $networkDrives   = @($logical | Where-Object { $_.DriveType -eq 4 } | ForEach-Object { ("{0} {1}" -f $_.DeviceID, $_.ProviderName).Trim() })
    $removableDrives = @($logical | Where-Object { $_.DriveType -eq 2 } | ForEach-Object { $_.DeviceID })
    $diskUsage = @($logical | Where-Object { $_.DriveType -eq 3 -and $_.Size -gt 0 } | ForEach-Object {
        [ordered]@{ drive = $_.DeviceID; used_gb = [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 1); total_gb = [math]::Round($_.Size / 1GB, 1) }
    })

    # optional (slow): size per user profile
    $userProfiles = @()
    if ($script:MeasureUserProfiles) {
        try {
            Get-ChildItem 'C:\Users' -Directory -ErrorAction Stop | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') } | ForEach-Object {
                $sz = 0
                try { $sz = (Get-ChildItem $_.FullName -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum } catch { }
                $userProfiles += [ordered]@{ profile = $_.Name; size_gb = [math]::Round(($sz / 1GB), 1) }
            }
        } catch { }
    }

    $hasRealBackup = ($backupSoftware.Count -gt 0 -or $tasks.Count -gt 0)
    $summary = if ($backupSoftware.Count -gt 0) { $backupSoftware -join ' + ' } else { $null }   # real backup products only; sync lives in cloud_sync

    if (-not $hasRealBackup) {
        if ($cloudSync.Count -gt 0) { Add-Finding -Code 'backup_sync_only' -Severity 'high' -Oea @('9.9') -Message 'Sin backup real: solo hay sincronizacion a la nube (OneDrive/similar), que NO es un backup.' }
        else { Add-Finding -Code 'backup_missing' -Severity 'high' -Oea @('9.9') -Message 'No se detecto software ni tareas de backup ni sync a la nube: sin respaldo visible.' }
    }

    return [ordered]@{
        backup = [ordered]@{
            summary          = $summary
            has_real_backup  = $hasRealBackup
            restore_point_count = Get-RestorePointCount
            software         = $backupSoftware
            cloud_sync       = $cloudSync
            tasks            = $tasks
            network_drives   = $networkDrives
            removable_drives = $removableDrives
            disk_usage       = $diskUsage
            user_profiles    = $userProfiles
        }
    }
}

# ============================ MODULE: system ==================================
# reboot pending, Windows Update, patching, startup, tasks, services
function Get-PatchingState {
    # 9.7 patching / Windows Update
    $lastPatch = $null; $lastPatchAt = $null; $patchCount = $null
    try {
        $hf = Get-HotFixCached
        $patchCount = @($hf).Count
        $u = $hf | Select-Object -First 1
        if ($u) { $lastPatch = $u.HotFixID; $lastPatchAt = $u.InstalledOn }   # keep [datetime] (no locale round-trip)
    } catch { }
    $wu = $null
    try { $wu = (Get-Service wuauserv -ErrorAction Stop).StartType.ToString() } catch { }

    if ($lastPatchAt) { try { if (((Get-Date) - [datetime]$lastPatchAt).Days -gt 60) { Add-Finding -Code 'patches_outdated' -Severity 'high' -Oea @('9.7') -Message ("Ultimo parche de Windows hace mas de 60 dias ($(ConvertTo-IsoDate $lastPatchAt)): revisar Windows Update.") } } catch { } }
    return [ordered]@{ last_provider_hotfix_id = $lastPatch; last_hotfix_date = ConvertTo-IsoDate $lastPatchAt; hotfix_count = $patchCount; windows_update_start_mode = if ($wu) { "$wu".ToLower() } else { $null } }
}

# Reboot pending, Windows Update policy, and what starts automatically (startup items, non-Microsoft scheduled tasks,
# non-Windows services). OEA 9.7 (patching) + persistence inventory.
function Get-SystemState {
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons += 'component_servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons += 'windows_update' }
    $pfro = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'
    $reboot = [ordered]@{ is_pending = ($reasons.Count -gt 0); reasons = $reasons; pending_file_rename_count = @($pfro | Where-Object { $_ }).Count }   # file renames alone are common -> informative only

    $wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $noAuto = Get-RegValue "$wuPol\AU" 'NoAutoUpdate'
    $pause = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesExpiryTime'
    $pauseUntil = ConvertTo-IsoDate $pause
    $wu = [ordered]@{
        wsus_server             = Get-RegValue $wuPol 'WUServer'
        is_auto_update_disabled = ($null -ne $noAuto -and [int]$noAuto -eq 1)
        au_options              = Get-RegValue "$wuPol\AU" 'AUOptions'
        pause_expires_at        = ConvertTo-IsoTimestamp $pause
    }

    $startup = @()
    foreach ($st in @(Get-CimSafe 'Win32_StartupCommand' | Where-Object { $_ })) {
        $cmd = "$($st.Command)"; if ($cmd.Length -gt 200) { $cmd = $cmd.Substring(0, 200) }
        $startup += [ordered]@{ name = "$($st.Name)"; command = $cmd; location = "$($st.Location)"; user = "$($st.User)" }
    }
    $tasks = @()
    try {
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
            $tasks += [ordered]@{ task = "$($t.TaskPath)$($t.TaskName)"; status = "$($t.State)".ToLower(); author = "$($t.Author)"; action = (@($t.Actions | ForEach-Object { "$($_.Execute)" }) -join '; ') }
        }
    } catch { $tasks = $null }
    $services = @()
    foreach ($sv in @(Get-CimSafe 'Win32_Service' | Where-Object { $_ -and $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\(system32|SysWOW64|servicing|Microsoft\.NET)\\|svchost\.exe' })) {
        $services += [ordered]@{ name = "$($sv.Name)"; display_name = "$($sv.DisplayName)"; start_mode = "$($sv.StartMode)".ToLower(); status = "$($sv.State)".ToLower(); path = "$($sv.PathName)" }
    }

    # findings (Spanish)
    if ($reboot.is_pending) { Add-Finding -Code 'reboot_pending' -Severity 'medium' -Oea @('9.7') -Message 'Reinicio PENDIENTE para completar actualizaciones: hasta reiniciar, los parches no quedan aplicados.' }
    if ($wu.is_auto_update_disabled) { Add-Finding -Code 'windows_update_disabled' -Severity 'high' -Oea @('9.7') -Message 'Actualizaciones automaticas de Windows DESACTIVADAS por politica: reactivarlas.' }
    if ($pauseUntil -and ($d = Get-DaysUntil $pauseUntil) -ne $null -and $d -ge 0) { Add-Finding -Code 'windows_update_paused' -Severity 'medium' -Oea @('9.7') -Message "Actualizaciones de Windows PAUSADAS hasta el $pauseUntil." }

    $hfList = Get-HotFixCached   # assign first: piping the ,@() result directly would pass the whole array as ONE object
    $hotfixes = @($hfList | ForEach-Object { [ordered]@{ provider_hotfix_id = "$($_.HotFixID)"; installed_date = ConvertTo-IsoDate $_.InstalledOn } })
    $patching = Get-PatchingState
    return [ordered]@{ system = [ordered]@{ reboot = $reboot; windows_update = $wu; patching = $patching; hotfixes = $hotfixes; startup_items = $startup; scheduled_tasks = $tasks; services = $services } }
}

# ============================ MODULE: events ==================================
# event history (last N days), audit policy, security log
# Last N days of relevant Windows events (OEA 9.10 incidents, 9.11 hardware, 9.12 continuity). Every query uses
# FilterHashtable + StartTime + MaxEvents (never a full log scan). Security-log queries need admin -> null without it.
$script:EventWindowDays = 90
$script:EventMax = 500
function Get-EventCount([hashtable]$Filter) {
    $f = $Filter.Clone(); $f['StartTime'] = (Get-Date).AddDays(-$script:EventWindowDays)
    # NOTE: 'return ,@(...)' (unary comma) - a function returning an EMPTY array hands $null to the caller in PowerShell,
    # which would turn "0 events" into "not measured". 'No events' is detected by the language-independent error id.
    try { return ,@(Get-WinEvent -FilterHashtable $f -MaxEvents $script:EventMax -ErrorAction Stop) }
    catch { if ("$($_.FullyQualifiedErrorId)" -like 'NoMatchingEventsFound*') { return ,@() } else { return $null } }
}

function Get-AuditPolicyState {
    # 9.4/9.10 audit policy (auditpol; admin) - logon + object access + removable storage
    $auditPolicy = $null
    if ($script:IsAdmin) {
        try {
            $ap = auditpol /get /category:* 2>$null
            $active = @($ap | Where-Object { $_ -imatch 'correcto|success|err.neo|failure' -and $_ -notmatch 'sin auditor|no auditing' })
            $logonAudited     = [bool]($ap | Where-Object { ($_ -imatch 'logon|inicio de sesi') -and ($_ -imatch 'correcto|success') })
            $objectAccess     = [bool]($ap | Where-Object { ($_ -imatch 'file system|sistema de archivos|handle manip|manipulaci.n de') -and ($_ -imatch 'correcto|success') })
            $removableAudited = [bool]($ap | Where-Object { ($_ -imatch 'removable storage|almacenamiento extra') -and ($_ -imatch 'correcto|success') })
            $auditPolicy = [ordered]@{ audited_subcategory_count = $active.Count; is_logon_audited = $logonAudited; is_object_access_audited = $objectAccess; is_removable_storage_audited = $removableAudited }
        } catch { }
    }

    if ($script:IsAdmin -and $auditPolicy -and (-not $auditPolicy.is_logon_audited)) { Add-Finding -Code 'logon_audit_disabled' -Severity 'medium' -Oea @('9.10') -Message 'Auditoria de inicios de sesion no habilitada: activar el registro de logon para trazabilidad.' }
    if ($script:IsAdmin -and $auditPolicy -and (-not $auditPolicy.is_object_access_audited) -and (-not $auditPolicy.is_removable_storage_audited)) { Add-Finding -Code 'object_access_audit_disabled' -Severity 'low' -Oea @('9.4','9.10') -Message 'Sin auditoria de acceso a archivos ni a dispositivos extraibles: habilitar la auditoria de "Object Access" para registrar accesos y movimientos.' }
    return $auditPolicy
}

function Get-SecurityLogState {
    # 9.10 security event log retention (a small circular log rotates -> incidents are lost)
    $securityLog = $null
    try {
        $sl = Get-WinEvent -ListLog Security -ErrorAction Stop
        $securityLog = [ordered]@{ max_size_mb = [math]::Round($sl.MaximumSizeInBytes / 1MB, 0); mode = "$($sl.LogMode)"; record_count = [int64]$sl.RecordCount }
    } catch { }

    if ($securityLog -and $securityLog.mode -eq 'Circular' -and $securityLog.max_size_mb -lt 128) { Add-Finding -Code 'security_log_small' -Severity 'low' -Oea @('9.10') -Message ("Registro de Seguridad chico y circular ($($securityLog.max_size_mb) MB): puede rotar y perder incidentes: aumentar el tamano o archivarlo.") }
    return $securityLog
}

# Days the log really reaches back (a 20 MB circular log can hold far less than the query window)
function Get-LogCoverageDays([string]$LogName) {
    try { $o = Get-WinEvent -LogName $LogName -MaxEvents 1 -Oldest -ErrorAction Stop; return [int][math]::Max(1, [math]::Floor(((Get-Date) - $o.TimeCreated).TotalDays)) } catch { return $null }
}
function Get-EffectiveWindowDays([string]$LogName) {
    $d = Get-LogCoverageDays $LogName
    if ($null -ne $d -and $d -lt $script:EventWindowDays) { return $d } else { return $script:EventWindowDays }
}

function Get-EventsSummary {
    $kp  = Get-EventCount @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41 }
    $bug = Get-EventCount @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001 }
    $dsk = Get-EventCount @{ LogName = 'System'; ProviderName = 'disk'; Id = 7, 51, 153 }
    $nt  = Get-EventCount @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Ntfs'; Id = 55 }
    $msi = Get-EventCount @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Id = 1033 }
    $sec = $null; $lock = $null; $clr = $null
    if ($script:IsAdmin) {
        $sec  = Get-EventCount @{ LogName = 'Security'; Id = 4625 }
        $lock = Get-EventCount @{ LogName = 'Security'; Id = 4740 }
        $clr  = Get-EventCount @{ LogName = 'Security'; Id = 1102 }
    }
    function Get-Cnt($x) { if ($null -eq $x) { $null } else { @($x).Count } }
    $w = $script:EventWindowDays
    $sysDays = Get-LogCoverageDays 'System'
    $secDays = if ($script:IsAdmin) { Get-LogCoverageDays 'Security' } else { $null }
    $ws = if ($null -ne $sysDays -and $sysDays -lt $w) { $sysDays } else { $w }       # effective System-log window
    $wsec = if ($null -ne $secDays -and $secDays -lt $w) { $secDays } else { $w }
    # BSODs: minidumps survive the event log rotation (a crash can outlive its 1001 event)
    $dumpDir = Join-Path $env:SystemRoot 'Minidump'
    $dumpDates = $null
    if (-not (Test-Path $dumpDir)) { $dumpDates = @() }
    else { try { $dumpDates = @(Get-ChildItem -Path $dumpDir -Filter '*.dmp' -ErrorAction Stop | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$w) } | ForEach-Object { $_.LastWriteTime.ToString('yyyy-MM-dd') } | Sort-Object) } catch { $dumpDates = $null } }
    $bugDates = @($bug | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd') })
    $crashDates = @(@($bugDates) + @($dumpDates) | Where-Object { $_ } | Sort-Object -Unique)
    # which physical disks logged errors (message text is localized; the device path is not)
    $diskIds = @($dsk | ForEach-Object { if ("$($_.Message)" -match 'Harddisk(\d+)') { [int]$Matches[1] } elseif ("$($_.Message)" -match '(?:disco|disk) (\d+)') { [int]$Matches[1] } } | Select-Object -Unique)
    # recent MSI installs with the account that ran them
    $installs = @()
    foreach ($e in @($msi | Select-Object -First 20)) {
        $who = $null; if ($e.UserId) { try { $who = $e.UserId.Translate([Security.Principal.NTAccount]).Value } catch { $who = "$($e.UserId)" } }
        $installs += [ordered]@{ installed_at = ConvertTo-IsoTimestamp $e.TimeCreated; product = "$($e.Properties[0].Value)"; version = "$($e.Properties[1].Value)"; user = $who }
    }
    # time sync (OEA 9.10: timestamps must be trustworthy)
    $tp = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    $timeSync = [ordered]@{ kind = Get-RegValue $tp 'Type'; ntp_server = Get-RegValue $tp 'NtpServer' }   # W32Time 'Type' (NTP/NT5DS/NoSync) - LAW R16: kind

    $r = [ordered]@{
        window_days               = $script:EventWindowDays
        unexpected_shutdown_count = Get-Cnt $kp
        unexpected_shutdown_dates = @($kp | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd') } | Select-Object -Unique)
        bugcheck_count            = Get-Cnt $bug
        minidump_count            = Get-Cnt $dumpDates
        crash_dates               = $crashDates
        system_log_covered_days   = $sysDays
        application_log_covered_days = Get-LogCoverageDays 'Application'
        security_log_covered_days = $secDays
        disk_error_count          = Get-Cnt $dsk
        error_disks               = $diskIds
        ntfs_error_count          = Get-Cnt $nt
        failed_logon_count        = Get-Cnt $sec
        account_lockout_count     = Get-Cnt $lock
        security_log_cleared_count = Get-Cnt $clr
        recent_installs           = $installs
        time_sync                 = $timeSync
        max_query_events          = $script:EventMax
        audit_policy              = Get-AuditPolicyState
        security_log              = Get-SecurityLogState
    }
    # findings (Spanish) - each count is stated over the days its log REALLY covers
    if ($r.unexpected_shutdown_count -ge 3) { Add-Finding -Code 'unexpected_shutdowns' -Severity 'medium' -Oea @('9.12') -Message "$($r.unexpected_shutdown_count) apagados/reinicios inesperados en $ws dias: revisar energia (UPS), temperatura o fallas de hardware." }
    $crashCount = [math]::Max([math]::Max([int]$r.bugcheck_count, [int]$r.minidump_count), $crashDates.Count)
    $wc = if ($null -ne $dumpDates) { $w } else { $ws }   # minidumps outlive the log; without them only the log's days count
    if ($crashCount -gt 0) { Add-Finding -Code 'bugchecks' -Severity 'medium' -Oea @('9.12') -Message "$crashCount pantallazo(s) azul(es) en $wc dias (fechas: $($crashDates -join ', ')): revisar drivers/hardware." }
    if ($r.disk_error_count -gt 0) { Add-Finding -Code 'disk_errors' -Severity 'high' -Oea @('9.11') -Message ("$($r.disk_error_count) errores de disco en $ws dias (discos: $($diskIds -join ', ')): riesgo de perdida de datos; verificar si es el disco interno o un extraible.") }
    if ($r.ntfs_error_count -gt 0) { Add-Finding -Code 'ntfs_errors' -Severity 'medium' -Oea @('9.11') -Message "$($r.ntfs_error_count) errores de sistema de archivos (NTFS) en $ws dias: correr chequeo de disco." }
    if ($r.failed_logon_count -ge 10) { Add-Finding -Code 'failed_logons' -Severity 'medium' -Oea @('9.10') -Message "$($r.failed_logon_count) inicios de sesion FALLIDOS en $wsec dias: revisar si hubo intentos de acceso indebido." }
    if ($r.security_log_cleared_count -gt 0) { Add-Finding -Code 'security_log_cleared' -Severity 'high' -Oea @('9.10') -Message "El registro de Seguridad fue BORRADO $($r.security_log_cleared_count) vez/veces en $wsec dias: evento critico, investigar quien y por que." }
    if ($null -ne $sysDays -and $sysDays -lt $w) {
        $sysLog = $null; try { $sysLog = Get-WinEvent -ListLog System -ErrorAction Stop } catch { }
        $isFull = $sysLog -and $sysLog.MaximumSizeInBytes -and $sysLog.FileSize -ge (0.9 * $sysLog.MaximumSizeInBytes)
        $why = if ($isFull) { " porque se llena ($([math]::Round($sysLog.MaximumSizeInBytes / 1MB)) MB) y pisa lo viejo: para conservar mas historia, aumentar su tamano" } else { ' y no por falta de espacio: el equipo se instalo/reseteo hace poco o el registro fue borrado' }
        Add-Finding -Code 'event_log_short_coverage' -Severity 'info' -Message "El registro de Sistema solo tiene $sysDays dias de historia$why. Los conteos de eventos de este equipo cubren ese periodo, no $w dias."
    }
    if ("$($timeSync.kind)" -eq 'NoSync') { Add-Finding -Code 'time_sync_disabled' -Severity 'medium' -Oea @('9.10') -Message 'Sincronizacion horaria DESACTIVADA: la hora de los registros no es confiable.' }
    return [ordered]@{ events = $r }
}

# ============================ MODULE: health ==================================
# hardware health (disks, battery, monitors, printers)
function Get-DiskHealthStatus {
    # 9.11 disk health (SMART)
    $diskHealth = @()
    try { $diskHealth = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object { [ordered]@{ disk = $_.FriendlyName; health_status = "$($_.HealthStatus)"; operational_status = "$($_.OperationalStatus)" } }) } catch { }

    foreach ($dh in $diskHealth) { if ($dh.health_status -and ("$($dh.health_status)" -notmatch 'Healthy|Correcto')) { Add-Finding -Code 'disk_health_degraded' -Severity 'high' -Oea @('9.11') -Message ("Disco '$($dh.disk)' con salud '$($dh.health_status)': planificar reemplazo.") } }
    return ,@($diskHealth)
}

# Hardware health + peripherals inventory (OEA 9.11 maintenance, 9.8 equipment). Admin-only parts degrade to null
# and are SKIPPED without admin (they only return access-denied after seconds).
function ConvertFrom-WmiCharArray($a) { if ($null -eq $a) { return $null }; $t = (($a | Where-Object { $_ -ne 0 }) | ForEach-Object { [char]$_ }) -join ''; if ($t) { $t.Trim() } else { $null } }
# Device Manager problem codes (learn.microsoft.com windows-hardware/drivers/install/device-manager-error-messages)
function Get-DeviceErrorMeaning([int]$Code) {
    switch ($Code) {
        { $_ -in 1, 18, 28, 31, 37, 39, 40 } { return 'driver faltante o danado: reinstalar el driver' }
        { $_ -in 10, 43 } { return 'el dispositivo no puede iniciar o Windows lo detuvo por fallas' }
        { $_ -in 12, 16, 33, 34, 35, 36 } { return 'conflicto de recursos' }
        14 { return 'requiere reiniciar el equipo' }
        19 { return 'configuracion danada en el registro' }
        24 { return 'no esta presente o no funciona correctamente' }
        29 { return 'deshabilitado por el firmware (BIOS)' }
        44 { return 'detenido por una aplicacion o servicio' }
        48 { return 'driver bloqueado por incompatibilidad' }
        52 { return 'driver sin firma digital valida' }
        default { return 'error de dispositivo' }
    }
}

function Get-HardwareHealth {
    # devices with a Device Manager error (yellow bang); 22 = disabled on purpose and 45 = not connected are not faults
    # 21/47 = being removed / prepared for safe removal (transient) -> not faults either
    $problemDevices = $null; $disabledDevices = $null
    $pnp = Get-CimSafe 'Win32_PnPEntity'
    if ($null -ne $pnp) {
        $problemDevices = @(); $disabledDevices = @()
        foreach ($pd in @($pnp | Where-Object { $_ -and $_.ConfigManagerErrorCode })) {
            $code = [int]$pd.ConfigManagerErrorCode
            if ($code -in @(21, 45, 47)) { continue }
            $item = [ordered]@{ name = $(if ($pd.Name) { "$($pd.Name)" } else { "$($pd.PNPDeviceID)" }); pnp_class = "$($pd.PNPClass)"; error_code = $code }
            if ($code -eq 22) { $disabledDevices += $item } else { $problemDevices += $item }
        }
    }
    # disks: SMART-like reliability counters (admin)
    $disks = $null
    if ($script:IsAdmin) {
        $disks = @()
        try {
            foreach ($pd in @(Get-PhysicalDisk -ErrorAction Stop)) {
                $rc = $null; try { $rc = $pd | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
                $disks += [ordered]@{
                    disk = "$($pd.FriendlyName)"; media_kind = "$($pd.MediaType)".ToLower(); bus_kind = "$($pd.BusType)".ToLower()
                    wear_percent = if ($rc -and $null -ne $rc.Wear) { [int]$rc.Wear } else { $null }
                    temperature_c = if ($rc -and $rc.Temperature) { [int]$rc.Temperature } else { $null }
                    read_errors_uncorrected = if ($rc -and $null -ne $rc.ReadErrorsUncorrected) { [int64]$rc.ReadErrorsUncorrected } else { $null }
                    write_errors_uncorrected = if ($rc -and $null -ne $rc.WriteErrorsUncorrected) { [int64]$rc.WriteErrorsUncorrected } else { $null }
                    power_on_hours = if ($rc -and $null -ne $rc.PowerOnHours) { [int64]$rc.PowerOnHours } else { $null }
                }
            }
        } catch { }
    }
    # battery (laptops): full-charge vs design capacity (design needs admin)
    $battery = $null
    $wb = Get-CimSafe 'Win32_Battery'
    if ($wb) {
        $full = Get-CimSafe -Class 'BatteryFullChargedCapacity' -Namespace 'root\wmi'
        $stat = if ($script:IsAdmin) { Get-CimSafe -Class 'BatteryStaticData' -Namespace 'root\wmi' } else { $null }
        $fullC = if ($full) { [int64](@($full)[0].FullChargedCapacity) } else { $null }
        $desC  = if ($stat) { [int64](@($stat)[0].DesignedCapacity) } else { $null }
        # Fallback: WMI BatteryStaticData fails on many laptops (e.g. Lenovo) even as admin -> 'powercfg /batteryreport /xml'
        # into a %TEMP% file that is deleted right away (same documented exception as secedit's temp .inf). Works w/o admin.
        $cycles = $null
        if (-not $desC) {
            $bxml = Join-Path $env:TEMP ('_ea_bat_{0}.xml' -f (Get-Random))
            try {
                powercfg /batteryreport /xml /output $bxml 2>&1 | Out-Null
                if (Test-Path $bxml) {
                    [xml]$bx = Get-Content $bxml -Raw -ErrorAction Stop
                    $b0 = @($bx.BatteryReport.Batteries.Battery)[0]
                    if ($b0) { if ($b0.DesignCapacity) { $desC = [int64]$b0.DesignCapacity }; if (-not $fullC -and $b0.FullChargeCapacity) { $fullC = [int64]$b0.FullChargeCapacity }; if ($b0.CycleCount) { $cycles = [int]$b0.CycleCount } }
                }
            } catch { } finally { Remove-Item $bxml -Force -ErrorAction SilentlyContinue }
        }
        $battery = [ordered]@{
            cycle_count = $cycles
            charge_percent = [int](@($wb)[0].EstimatedChargeRemaining)
            full_charge_capacity_mwh = $fullC
            design_capacity_mwh = $desC
            health_percent = if ($fullC -and $desC) { [int][math]::Round($fullC / $desC * 100) } else { $null }
        }
    }
    # monitors
    $monitors = @()
    foreach ($m in @(Get-CimSafe -Class 'WmiMonitorID' -Namespace 'root\wmi' | Where-Object { $_ })) {
        $monitors += [ordered]@{ manufacturer = ConvertFrom-WmiCharArray $m.ManufacturerName; model = ConvertFrom-WmiCharArray $m.UserFriendlyName; serial = ConvertFrom-WmiCharArray $m.SerialNumberID; year = [int]$m.YearOfManufacture }
    }
    # printers: network = port says so (IP_x / WSD / \\server), Win32_Printer.Network alone misses TCP/IP ports
    $printers = @()
    foreach ($pr in @(Get-CimSafe 'Win32_Printer' | Where-Object { $_ })) {
        $port = "$($pr.PortName)"
        $printers += [ordered]@{
            name = "$($pr.Name)"; port = $port
            is_network = [bool]($pr.Network -or $port -match '^(IP_|WSD|\\\\|http)' -or $port -match '^\d{1,3}(\.\d{1,3}){3}')
            is_virtual = [bool]($port -match '^(nul:|PORTPROMPT:|FILE:|XPSPort:|SHRFAX:)' -or $pr.Name -match 'PDF|OneNote|XPS|Fax')
            is_shared = [bool]$pr.Shared; is_default = [bool]$pr.Default
        }
    }
    # findings (Spanish)
    foreach ($d in @($disks)) {
        if ($d.wear_percent -ge 80) { Add-Finding -Code 'disk_wear_high' -Severity 'medium' -Oea @('9.11') -Message "Disco '$($d.disk)' con desgaste del $($d.wear_percent)%: planificar reemplazo." }
        if ($d.read_errors_uncorrected -gt 0) { Add-Finding -Code 'disk_uncorrected_errors' -Severity 'high' -Oea @('9.11') -Message "Disco '$($d.disk)' con $($d.read_errors_uncorrected) errores de lectura NO corregidos: riesgo de perdida de datos, respaldar y reemplazar." }
    }
    if ($battery -and $battery.health_percent -and $battery.health_percent -lt 60) { Add-Finding -Code 'battery_degraded' -Severity 'low' -Oea @('9.12') -Message "Bateria degradada: $($battery.health_percent)% de su capacidad original: poca autonomia ante un corte de luz." }
    $shared = @($printers | Where-Object { $_.is_shared } | ForEach-Object { $_.name })
    if ($shared.Count -gt 0) { Add-Finding -Code 'printer_shared' -Severity 'low' -Oea @('9.4') -Message ("Impresoras compartidas desde este equipo: $($shared -join ', '): revisar si es necesario.") }
    if (@($problemDevices).Count -gt 0) {
        $list = (@($problemDevices | Select-Object -First 5 | ForEach-Object { "$($_.name) (codigo $($_.error_code): $(Get-DeviceErrorMeaning $_.error_code))" }) -join '; ')
        if ($problemDevices.Count -gt 5) { $list += " y $($problemDevices.Count - 5) mas" }
        Add-Finding -Code 'devices_with_errors' -Severity 'low' -Message "Dispositivos con error en el Administrador de dispositivos: $list."
    }
    $diskStatus = Get-DiskHealthStatus
    return [ordered]@{ health = [ordered]@{ disk_health = $diskStatus; disks = $disks; battery = $battery; monitors = $monitors; printers = $printers; problem_devices = $problemDevices; disabled_devices = $disabledDevices } }
}

# ============================ MODULE: performance =============================
# resource usage snapshot + stability/crash/boot history
# "Why is this PC slow / what fills up": a snapshot (RAM, commit, pagefile, top processes, disk activity, free space on
# every fixed volume) + the history Windows already keeps (stability index, app crashes/hangs, low-memory and disk-full
# warnings, boot times). The snapshot depends on what is open at audit time; the history does not.
function Get-EventDataValue($Event, [string]$Name) {
    try { $x = [xml]$Event.ToXml(); $n = $x.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1; if ($n) { return "$($n.'#text')" } } catch { }
    return $null
}

function Get-TopByName($Events, [int]$Top = 5) {
    @($Events | ForEach-Object { "$($_.Properties[0].Value)" } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object { [ordered]@{ name = $_.Name; count = $_.Count } })
}

function Get-PerformanceState {
    $os = Get-CimSafe 'Win32_OperatingSystem'
    $ramUsed = $null; $commitUsed = $null
    if ($os -and $os.TotalVisibleMemorySize) {
        $ramUsed = [int][math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100)
        if ($os.TotalVirtualMemorySize) { $commitUsed = [int][math]::Round((1 - $os.FreeVirtualMemory / $os.TotalVirtualMemorySize) * 100) }
    }
    $pagefile = @(Get-CimSafe 'Win32_PageFileUsage' | Where-Object { $_ } | ForEach-Object { [ordered]@{ path = "$($_.Name)"; allocated_mb = [int]$_.AllocatedBaseSize; current_mb = [int]$_.CurrentUsage; peak_mb = [int]$_.PeakUsage } })
    $topMem = @(Get-Process -ErrorAction SilentlyContinue | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 | ForEach-Object { [ordered]@{ name = $_.ProcessName; memory_mb = [int][math]::Round($_.WorkingSet64 / 1MB) } })
    # CPU per process from the formatted perf class (language independent, unlike Get-Counter paths)
    $topCpu = @(Get-CimSafe 'Win32_PerfFormattedData_PerfProc_Process' | Where-Object { $_ -and $_.Name -notin '_Total', 'Idle' -and $_.PercentProcessorTime -gt 0 } | Sort-Object PercentProcessorTime -Descending | Select-Object -First 5 | ForEach-Object { [ordered]@{ name = "$($_.Name)"; cpu_percent = [int]$_.PercentProcessorTime } })
    $diskActivity = @(Get-CimSafe 'Win32_PerfFormattedData_PerfDisk_PhysicalDisk' | Where-Object { $_ -and $_.Name -ne '_Total' } | ForEach-Object { [ordered]@{ disk = "$($_.Name)"; busy_percent = [int]$_.PercentDiskTime; queue_length = [int]$_.CurrentDiskQueueLength } })
    $volumes = @(Get-CimSafe -Class 'Win32_LogicalDisk' -Filter 'DriveType=3' | Where-Object { $_ -and $_.Size -gt 0 } | ForEach-Object { [ordered]@{ drive = "$($_.DeviceID)"; free_gb = [math]::Round($_.FreeSpace / 1GB, 1); free_percent = [int][math]::Round($_.FreeSpace / $_.Size * 100) } })

    # history
    $stab = @(Get-CimSafe 'Win32_ReliabilityStabilityMetrics' | Where-Object { $_ } | Sort-Object TimeGenerated -Descending | Select-Object -First 30)
    $stability = if ($stab.Count -gt 0) { [ordered]@{ current = [math]::Round([double]$stab[0].SystemStabilityIndex, 1); recent_minimum = [math]::Round((($stab | Measure-Object SystemStabilityIndex -Minimum).Minimum), 1); sample_count = $stab.Count } } else { $null }
    $crashes = Get-EventCount @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000 }
    $hangs   = Get-EventCount @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002 }
    $lowMem  = Get-EventCount @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Id = 2004 }
    $diskFull = Get-EventCount @{ LogName = 'System'; ProviderName = 'srv'; Id = 2013 }
    $boots   = Get-EventCount @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100 }
    $bootSec = @($boots | ForEach-Object { $v = Get-EventDataValue $_ 'BootTime'; if ($v -match '^\d+$') { [math]::Round([int64]$v / 1000) } } | Where-Object { $null -ne $_ })
    $bootTimes = if ($bootSec.Count -gt 0) { [ordered]@{ sample_count = $bootSec.Count; average_seconds = [int][math]::Round(($bootSec | Measure-Object -Average).Average); max_seconds = [int](($bootSec | Measure-Object -Maximum).Maximum) } } else { $null }

    $r = [ordered]@{
        ram_used_percent    = $ramUsed
        commit_used_percent = $commitUsed
        pagefiles           = $pagefile
        top_memory_processes = $topMem
        top_cpu_processes   = $topCpu
        disk_activities     = $diskActivity
        volumes             = $volumes
        stability_index     = $stability
        app_crashes         = [ordered]@{ count = if ($null -ne $crashes) { @($crashes).Count } else { $null }; top = Get-TopByName $crashes }
        app_hangs           = [ordered]@{ count = if ($null -ne $hangs) { @($hangs).Count } else { $null }; top = Get-TopByName $hangs }
        low_memory_warning_count = if ($null -ne $lowMem) { @($lowMem).Count } else { $null }
        disk_full_warning_count  = if ($null -ne $diskFull) { @($diskFull).Count } else { $null }
        boot_times          = $bootTimes
    }

    # findings (Spanish)
    if ($ramUsed -ge 85) { Add-Finding -Code 'ram_usage_high' -Severity 'low' -Oea @() -Message ("Memoria RAM al $ramUsed% al momento de la auditoria (mayor consumo: $((@($topMem | Select-Object -First 3 | ForEach-Object { "$($_.name) $($_.memory_mb) MB" })) -join ', ')): posible lentitud; $(Get-RamUpgradeAdvice $script:RamMounting $script:RamEmptyPositions $script:RamMountingConfirmed $script:RamGb $script:RamTableConsistent).") }
    $wSys = Get-EffectiveWindowDays 'System'; $wApp = Get-EffectiveWindowDays 'Application'
    if ($r.low_memory_warning_count -gt 0) { Add-Finding -Code 'low_memory_warnings' -Severity 'medium' -Oea @() -Message "Windows aviso $($r.low_memory_warning_count) vez/veces que se quedo SIN MEMORIA en $wSys dias: la RAM no alcanza para el uso real." }
    if ($r.disk_full_warning_count -gt 0) { Add-Finding -Code 'disk_full_warnings' -Severity 'medium' -Oea @('9.12') -Message "Windows aviso $($r.disk_full_warning_count) vez/veces DISCO LLENO en $wSys dias." }
    foreach ($v in @($volumes | Where-Object { $_.free_percent -lt 15 -and $_.drive -ne 'C:' })) { Add-Finding -Code 'volume_low_space' -Severity 'medium' -Oea @('9.12') -Message "Unidad $($v.drive) casi llena ($($v.free_percent)% libre, $($v.free_gb) GB)." }   # C: already covered by core
    if ($stability -and $stability.current -lt 5) { Add-Finding -Code 'stability_low' -Severity 'low' -Oea @('9.12') -Message "Indice de estabilidad de Windows bajo: $($stability.current) de 10 (muchas fallas recientes de programas o del sistema)." }
    foreach ($a in @($r.app_crashes.top | Where-Object { $_.count -ge 3 })) { Add-Finding -Code 'app_crashes_frequent' -Severity 'low' -Oea @() -Message "El programa '$($a.name)' se cerro inesperadamente $($a.count) veces en $wApp dias: revisar/actualizar/reinstalar." }
    foreach ($a in @($r.app_hangs.top | Where-Object { $_.count -ge 3 })) { Add-Finding -Code 'app_hangs_frequent' -Severity 'low' -Oea @() -Message "El programa '$($a.name)' se colgo $($a.count) veces en $wApp dias: revisar (complementos, tamano de datos, actualizacion)." }
    if ($bootTimes -and $bootTimes.average_seconds -gt 120) { Add-Finding -Code 'boot_slow' -Severity 'low' -Oea @() -Message "Arranque lento: promedio $($bootTimes.average_seconds) s (maximo $($bootTimes.max_seconds) s): revisar programas de inicio y disco." }
    return [ordered]@{ performance = $r }
}

# ============================ MODULE CATALOG / PROFILES ===========================
# Console-only progress labels (Spanish: the person at the PC reads them)
$script:ModuleLabels = @{
    core = 'Equipo y sistema'; license = 'Licencia de Windows'; office = 'Office'; software = 'Programas instalados'
    antivirus = 'Antivirus'; security = 'Seguridad y cifrado (incluye msinfo32)'; hardening = 'Configuracion de seguridad'
    accounts = 'Cuentas y contrasenas'; remote_access = 'Acceso remoto'; persistence = 'Arranque automatico (malware)'; network = 'Red'; data = 'Datos y pendrives'
    backup = 'Backup'; system = 'Actualizaciones e inicio'; events = 'Registro de eventos'; health = 'Salud del hardware'
    performance = 'Rendimiento'
}
$script:ModuleCatalog = [ordered]@{   # order = file order = JSON key order
    core          = 'Get-CoreInfo'
    license       = 'Get-LicenseInfo'
    office        = 'Get-OfficeLicensing'
    software      = 'Get-InstalledSoftware'
    antivirus     = 'Get-AntivirusStatus'
    security      = 'Get-SecurityPosture'
    hardening     = 'Get-Hardening'
    accounts      = 'Get-AccountPolicy'
    remote_access = 'Get-RemoteAccess'
    persistence   = 'Get-PersistenceState'
    network       = 'Get-NetworkExposure'
    data          = 'Get-DataProtection'
    backup        = 'Get-BackupStatus'
    system        = 'Get-SystemState'
    events        = 'Get-EventsSummary'
    health        = 'Get-HardwareHealth'
    performance   = 'Get-PerformanceState'
}
# Profiles = WHAT the technician wants to learn about the PC. 'core' (identity/OS/hardware) always runs.
# A compliance report (e.g. OEA) is NOT a capture profile: it is a lens of the report generator and needs a Full capture.
$script:Profiles = [ordered]@{
    Full        = @($script:ModuleCatalog.Keys)
    Hardware    = @('core', 'health', 'performance')
    Inventory   = @('core', 'license', 'office', 'software', 'health')
    Performance = @('core', 'performance', 'health', 'events', 'system')
    Security    = @('core', 'license', 'office', 'antivirus', 'accounts', 'security', 'hardening', 'remote_access', 'persistence', 'network', 'data', 'backup', 'events', 'system')
}
$script:ProfileAliases = @{ Base = 'Full'; OEA = 'Full' }   # legacy names (<= 2.x) keep working
$script:ProfileLabels = [ordered]@{   # client-facing (Spanish) menu text
    Full        = 'Full - todo (recomendado; requerido para informes de cumplimiento como OEA)'
    Hardware    = 'Hardware - equipo, salud del hardware y uso de recursos'
    Inventory   = 'Inventario - hardware + software + licencias'
    Performance = 'Rendimiento - por que anda lenta / que se llena / que falla'
    Security    = 'Seguridad - antivirus, malware en el arranque, acceso remoto, licencias, cuentas, configuracion, red y datos'
}

function Invoke-AuditModule {
    param([string]$Name, [string]$FunctionName)
    try {
        return (& $FunctionName)
    } catch {
        [void]$script:Errors.Add([ordered]@{ module = $Name; message = $_.Exception.Message })
        Write-Host ("  [modulo '$Name' fallo] " + $_.Exception.Message) -ForegroundColor Red
        return $null
    }
}

# ============================ INTERACTIVE MENU (when run with no flags) ============
# Double-click / plain run -> friendly menu, so the operator never needs to remember a flag.
if ($script:Interactive) {
    Write-Host ''
    Write-Host ('=' * 52) -ForegroundColor DarkCyan
    Write-Host '   netlogic-signal  ' -NoNewline -ForegroundColor Cyan
    Write-Host 'NetLogic' -ForegroundColor DarkCyan
    Write-Host ('=' * 52) -ForegroundColor DarkCyan
    Write-Host '   1) Relevar esta computadora'
    Write-Host '   2) Consolidar una carpeta (juntar los .json en un Excel/CSV)'
    Write-Host '   3) Salir'
    Write-Host ''
    $menuOption = (Read-Host '   Elegi una opcion [1]').Trim()
    if ($menuOption -eq '3') { return }
    if ($menuOption -eq '2') {
        $Consolidate = $true
        $Path = (Read-Host '   Carpeta con los .json a consolidar').Trim().Trim('"')
    }
    else {
        $script:Organization = (Read-Host '   Empresa / cliente').Trim()
        $script:AssignedUser = (Read-Host '   Usuario/responsable de esta PC (ENTER para omitir)').Trim()
        Write-Host '   Tipo de relevamiento:'
        $profileNames = @($script:ProfileLabels.Keys)
        for ($i = 0; $i -lt $profileNames.Count; $i++) { Write-Host ("     {0}) {1}" -f ($i + 1), $script:ProfileLabels[$profileNames[$i]]) }
        $pick = (Read-Host '   Opcion [1]').Trim()
        $Profile = if ($pick -match '^\d+$' -and [int]$pick -ge 1 -and [int]$pick -le $profileNames.Count) { $profileNames[[int]$pick - 1] } else { 'Full' }
    }
}

# ============================ CONSOLIDATE MODE ====================================
# Merge every audit JSON in a folder into one CSV (one row per endpoint). Read-only on inputs.
if ($Consolidate) {
    $inFolder = if ([string]::IsNullOrWhiteSpace($Path)) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { $Path }
    if (-not $inFolder) { $inFolder = (Get-Location).Path }
    $outCsv = Join-Path $inFolder '_netlogic-signal-master.csv'

    # Navigate a dotted path on a ConvertFrom-Json object; $null if any segment is missing.
    function Get-JsonPath($obj, [string]$dotted) {
        $cur = $obj
        foreach ($seg in $dotted.Split('.')) {
            if ($null -eq $cur) { return $null }
            $cur = $cur.PSObject.Properties[$seg].Value
        }
        return $cur
    }

    $jsons = Get-ChildItem -Path $inFolder -Filter '*.json' -File -ErrorAction SilentlyContinue
    if (-not $jsons) { Write-Host "No se encontraron .json en: $inFolder" -ForegroundColor Yellow; return }

    $rows = @()
    foreach ($jf in $jsons) {
        try { $d = Get-Content $jf.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch {
            Write-Host ("  ! No se pudo leer {0}: {1}" -f $jf.Name, $_.Exception.Message) -ForegroundColor Red; continue
        }
        if (-not (Get-JsonPath $d 'identity.computer_name')) { continue }   # not an netlogic-signal JSON
        $findings = @(Get-JsonPath $d 'findings')
        # first non-null path: current schema first, then older ones (a folder may mix tool versions)
        # count of a JSON list: null when the field is absent (older capture / module not run), 0 when present but empty -
        # read from the parent object because a function returning an empty array hands $null to the caller
        function Get-ListCount([string]$Parent, [string]$Field) { $po = Get-JsonPath $d $Parent; if ($null -eq $po -or -not $po.PSObject.Properties[$Field] -or $null -eq $po.PSObject.Properties[$Field].Value) { return $null }; return @($po.$Field | Where-Object { $null -ne $_ }).Count }   # null = not measured, 0 = measured and empty
        function Get-Any([string[]]$Paths) { foreach ($pth in $Paths) { $v = Get-JsonPath $d $pth; if ($null -ne $v) { return $v } }; return $null }
        function Join-Items($Items, [scriptblock]$Pick, [string]$Sep = ', ') { ((@($Items) | Where-Object { $_ } | ForEach-Object $Pick | Where-Object { $_ } | Select-Object -Unique) -join $Sep) }
        $findingText = { if ($_ -is [string]) { $_ } else { $_.message } }   # string findings = schema <= 5
        $rows += [pscustomobject][ordered]@{
            # identity
            organization          = Get-JsonPath $d 'identity.organization'
            computer_name         = Get-JsonPath $d 'identity.computer_name'
            assigned_user         = Get-JsonPath $d 'identity.assigned_user'
            audited_user          = Get-JsonPath $d 'meta.audited_user.name'
            is_audited_user_admin = Get-JsonPath $d 'meta.audited_user.is_admin'
            administrators        = ((@(Get-JsonPath $d 'accounts.administrators')) -join ', ')
            # hardware
            manufacturer          = Get-JsonPath $d 'hardware.manufacturer'
            model                 = Get-JsonPath $d 'hardware.model'
            product_version       = Get-JsonPath $d 'hardware.product_version'
            sku                   = Get-JsonPath $d 'hardware.sku'
            family                = Get-JsonPath $d 'hardware.family'
            uuid                  = Get-JsonPath $d 'hardware.uuid'
            serial                = Get-JsonPath $d 'hardware.serial'
            chassis_kind          = Get-JsonPath $d 'hardware.chassis_kind'
            cpu                   = Get-JsonPath $d 'hardware.cpu'
            cpu_socket            = Get-JsonPath $d 'hardware.cpu_socket'
            cpu_mounting          = Get-JsonPath $d 'hardware.cpu_mounting'
            motherboard           = Get-JsonPath $d 'hardware.motherboard'
            ram_gb                = Get-JsonPath $d 'hardware.ram_gb'
            ram_mounting          = Get-JsonPath $d 'hardware.ram_mounting'
            is_ram_mounting_confirmed = Get-JsonPath $d 'hardware.is_ram_mounting_confirmed'
            ram_empty_position_count = Get-JsonPath $d 'hardware.ram_slots.empty_position_count'
            disk_c_free_percent   = Get-JsonPath $d 'hardware.disk_c.free_percent'
            # operating system + licensing
            os                    = Get-JsonPath $d 'os.caption'
            os_build              = Get-JsonPath $d 'os.build'
            os_release            = Get-JsonPath $d 'os.release'
            os_build_revision     = Get-JsonPath $d 'os.build_revision'
            os_servicing_channel  = Get-JsonPath $d 'os.servicing_channel'
            os_esu_license_year   = Get-JsonPath $d 'os.extended_security_updates.license_year'
            os_esu_has_updates    = Get-JsonPath $d 'os.extended_security_updates.has_esu_updates'
            os_end_of_support_date = Get-Any @('os.end_of_support_date', 'os.end_of_support_at')
            license_status        = Get-JsonPath $d 'license.status'
            license_channel       = Get-JsonPath $d 'license.channel'
            activation_indicators = Join-Items (Get-JsonPath $d 'license.activation_tampering.indicators') { $_ }
            office_products       = Join-Items (Get-JsonPath $d 'office.products') { "$($_.version_year) $($_.activation_kind) $($_.status)" } ' ; '
            office_click_to_run   = Join-Items (Get-JsonPath $d 'office.click_to_run.product_release_ids') { $_ }
            software_end_of_support = Join-Items (Get-JsonPath $d 'software.end_of_support_items') { $_.product }
            # protection
            antivirus             = Get-JsonPath $d 'antivirus.summary'
            is_antivirus_active   = Get-JsonPath $d 'antivirus.is_active'
            defender_signature_age_days = Get-JsonPath $d 'antivirus.defender.signature_age_days'
            bitlocker_status      = Get-JsonPath $d 'security.bitlocker.protection_status'
            bitlocker_encryption_status = Get-JsonPath $d 'security.bitlocker.status'
            device_encryption_support = Get-JsonPath $d 'security.device_encryption.support'
            firmware_mode         = Get-JsonPath $d 'security.firmware_mode'
            kernel_dma_protection = Get-JsonPath $d 'security.kernel_dma_protection'
            is_autologin_enabled  = Get-Any @('security.is_autologin_enabled', 'compliance.oea.is_autologin_enabled')
            screen_lock_timeout_seconds = Get-Any @('security.screen_lock.inactivity_timeout_seconds', 'compliance.oea.screen_lock.inactivity_timeout_seconds')
            usb_storage_status    = Get-Any @('data.usb_storage.status', 'compliance.oea.usb_storage.status')
            is_rdp_enabled        = Get-Any @('remote_access.rdp.is_enabled', 'security.is_rdp_enabled')
            remote_tools          = Join-Items (@(Get-JsonPath $d 'remote_access.tools') | Where-Object { $_ -and "$($_.kind)$($_.source)" -ne 'process' }) { $_.name }   # 'source' = schema <= 8
            remote_tools_running  = Join-Items (@(Get-JsonPath $d 'remote_access.tools') | Where-Object { $_ -and "$($_.kind)" -eq 'process' }) { $_.name }
            rdp_internet_logon_count = Get-JsonPath $d 'remote_access.rdp.logons.internet_logon_count'
            ultraviewer_fixed_password_connection_count = Get-JsonPath $d 'remote_access.ultraviewer.fixed_password_connection_count'
            suspicious_autorun_count = Get-ListCount 'persistence' 'suspicious_autoruns'
            reviewable_autorun_count = Get-ListCount 'persistence' 'reviewable_autoruns'
            defender_detection_count = Get-ListCount 'antivirus.defender' 'detections'
            is_smb1_enabled       = if ($null -ne (Get-JsonPath $d 'hardening')) { [bool]((Get-JsonPath $d 'hardening.smb.is_smb1_server_enabled') -or (Get-JsonPath $d 'hardening.smb.is_smb1_client_installed')) } else { $null }
            is_llmnr_disabled     = Get-JsonPath $d 'hardening.is_llmnr_disabled'
            lsa_protection        = Get-JsonPath $d 'hardening.credential_protection.lsa_protection'
            shared_folders        = Join-Items (Get-Any @('hardening.shared_folders', 'compliance.oea.shared_folders')) { $_ } ' ; '
            # accounts
            password_min_length   = Get-JsonPath $d 'accounts.password_policy.min_length'
            is_password_complexity_required = Get-Any @('accounts.password_policy.is_complexity_required', 'compliance.oea.password.is_complexity_required')
            password_history_count = Get-Any @('accounts.password_policy.history_count', 'compliance.oea.password.history_count')
            account_lockout_threshold = Get-Any @('accounts.account_lockout.threshold', 'compliance.oea.account_lockout.threshold')
            is_guest_enabled      = Get-Any @('accounts.is_guest_enabled', 'compliance.oea.is_guest_enabled')
            passwordless_account_count = @((Get-Any @('accounts.passwordless_accounts', 'compliance.oea.passwordless_accounts')) | Where-Object { $_ }).Count
            inactive_accounts     = Join-Items (Get-JsonPath $d 'accounts.inactive_accounts') { $_ }
            hidden_accounts       = Join-Items (Get-JsonPath $d 'accounts.hidden_accounts') { $_ }
            # operations
            last_hotfix_date      = ConvertTo-IsoDate (Get-Any @('system.patching.last_hotfix_date', 'compliance.oea.patching.last_patch_at'))
            is_reboot_pending     = Get-JsonPath $d 'system.reboot.is_pending'
            backup                = Get-JsonPath $d 'backup.summary'
            has_real_backup       = Get-JsonPath $d 'backup.has_real_backup'
            restore_point_count   = Get-Any @('backup.restore_point_count', 'compliance.oea.restore_point_count')
            is_logon_audited      = Get-Any @('events.audit_policy.is_logon_audited', 'compliance.oea.audit_policy.is_logon_audited')
            security_log_max_size_mb = Get-Any @('events.security_log.max_size_mb', 'compliance.oea.security_log.max_size_mb')
            unexpected_shutdown_count = Get-JsonPath $d 'events.unexpected_shutdown_count'
            disk_error_count      = Get-JsonPath $d 'events.disk_error_count'
            failed_logon_count    = Get-JsonPath $d 'events.failed_logon_count'
            crash_date_count      = Get-ListCount 'events' 'crash_dates'
            system_log_covered_days = Get-JsonPath $d 'events.system_log_covered_days'
            problem_device_count  = Get-ListCount 'health' 'problem_devices'
            ram_used_percent      = Get-JsonPath $d 'performance.ram_used_percent'
            stability_index       = Get-JsonPath $d 'performance.stability_index.current'
            # findings
            finding_count         = $findings.Count
            high_finding_count    = @($findings | Where-Object { $_.severity -eq 'high' }).Count
            medium_finding_count  = @($findings | Where-Object { $_.severity -eq 'medium' }).Count
            finding_codes         = Join-Items $findings { $_.code }
            findings              = Join-Items $findings $findingText ' | '
            # meta
            profile               = Get-JsonPath $d 'meta.profile'
            tool_version          = Get-JsonPath $d 'meta.tool_version'
            schema_version        = Get-JsonPath $d 'meta.schema_version'
            audited_at            = Get-JsonPath $d 'meta.audited_at'
        }
        Write-Host ("  + {0}  ({1})" -f $jf.Name, (Get-JsonPath $d 'identity.computer_name')) -ForegroundColor DarkGray
    }
    if (@($rows).Count -eq 0) { Write-Host "Ningun .json era un relevamiento valido en: $inFolder" -ForegroundColor Yellow; return }
    $rows = $rows | Sort-Object organization, computer_name
    try {
        $rows | Export-Csv -Path $outCsv -Delimiter ';' -Encoding UTF8 -NoTypeInformation
        Write-Host ''
        Write-Host ("OK -> {0} equipos consolidados en:" -f @($rows).Count) -ForegroundColor Green
        Write-Host ("     $outCsv") -ForegroundColor Green
    } catch { Write-Host ("Error al escribir el CSV: {0}" -f $_.Exception.Message) -ForegroundColor Red }
    return
}

# ============================ COMPARE MODE ==========================================
# "What changed on THIS PC between two audits" (fleet monitoring north star: recurring capture + drift report,
# so a technician can act on trends — not just a snapshot). Purely additive: reads two existing JSONs, writes
# nothing back into them, produces one new report. No "authorized software list" needed — new/removed software
# IS the signal (diff against the PC's own prior state), same principle as the rest of the tool: measure, don't
# assume an external artifact that does not exist.
if ($Compare) {
    function Get-JsonPath($obj, [string]$dotted) {
        $cur = $obj
        foreach ($seg in $dotted.Split('.')) {
            if ($null -eq $cur) { return $null }
            $cur = $cur.PSObject.Properties[$seg].Value
        }
        return $cur
    }
    if (-not (Test-Path $Baseline) -or -not (Test-Path $Current)) {
        Write-Host "Uso: -Compare -Baseline <json_viejo> -Current <json_nuevo>" -ForegroundColor Yellow
        if (-not (Test-Path $Baseline)) { Write-Host "  No existe -Baseline: $Baseline" -ForegroundColor Red }
        if (-not (Test-Path $Current))  { Write-Host "  No existe -Current: $Current" -ForegroundColor Red }
        return
    }
    try { $b = Get-Content $Baseline -Raw -Encoding UTF8 | ConvertFrom-Json } catch { Write-Host "No se pudo leer -Baseline: $($_.Exception.Message)" -ForegroundColor Red; return }
    try { $c = Get-Content $Current  -Raw -Encoding UTF8 | ConvertFrom-Json } catch { Write-Host "No se pudo leer -Current: $($_.Exception.Message)" -ForegroundColor Red; return }

    $bName = Get-JsonPath $b 'identity.computer_name'; $cName = Get-JsonPath $c 'identity.computer_name'
    $bAt   = Get-JsonPath $b 'meta.audited_at';        $cAt   = Get-JsonPath $c 'meta.audited_at'
    Write-Section 'COMPARACION ENTRE DOS RELEVAMIENTOS'
    Write-Field 'Equipo (baseline)' "$bName  ($bAt)"
    Write-Field 'Equipo (actual)'   "$cName  ($cAt)"
    $bTool = Get-JsonPath $b 'meta.tool_version'; $cTool = Get-JsonPath $c 'meta.tool_version'
    if ("$bTool" -and "$cTool" -and "$bTool" -ne "$cTool") {
        Write-Host "  AVISO: los relevamientos son de versiones distintas del motor ($bTool -> $cTool): un hallazgo NUEVO puede deberse a una deteccion mejorada, no a un cambio del equipo." -ForegroundColor Yellow
    }
    $bAdm = Get-JsonPath $b 'meta.is_admin'; $cAdm = Get-JsonPath $c 'meta.is_admin'
    if ($null -ne $bAdm -and $null -ne $cAdm -and [bool]$bAdm -ne [bool]$cAdm) {
        Write-Host '  AVISO: uno de los relevamientos se corrio SIN permisos de administrador: lo que solo se mide con admin aparece como NUEVO o RESUELTO sin serlo.' -ForegroundColor Yellow
    }
    if ("$bName" -and "$cName" -and "$bName" -ne "$cName") {
        Write-Host "  ADVERTENCIA: los nombres de equipo no coinciden ($bName vs $cName) - verificar que sean el mismo PC (nombre pudo cambiar, o son equipos distintos)." -ForegroundColor Yellow
    }
    $bSerial = Get-JsonPath $b 'hardware.serial'; $cSerial = Get-JsonPath $c 'hardware.serial'
    if ($bSerial -and $cSerial -and $bSerial -ne $cSerial) {
        Write-Host "  ADVERTENCIA: el numero de serie cambio ($bSerial vs $cSerial) - esto NO deberia pasar en el mismo equipo fisico; revisar los archivos." -ForegroundColor Red
    }

    # ---- software: added / removed / version changed (both schemas expose software.items[].name/version) ----
    $bSw = @(Get-JsonPath $b 'software.items' | ForEach-Object { $_ }); $cSw = @(Get-JsonPath $c 'software.items' | ForEach-Object { $_ })
    $bSwMap = @{}; foreach ($x in $bSw) { if ($x.name) { $bSwMap[$x.name] = $x.version } }
    $cSwMap = @{}; foreach ($x in $cSw) { if ($x.name) { $cSwMap[$x.name] = $x.version } }
    $swAdded   = @($cSwMap.Keys | Where-Object { -not $bSwMap.ContainsKey($_) } | Sort-Object)
    $swRemoved = @($bSwMap.Keys | Where-Object { -not $cSwMap.ContainsKey($_) } | Sort-Object)
    $swUpdated = @($cSwMap.Keys | Where-Object { $bSwMap.ContainsKey($_) -and "$($bSwMap[$_])" -ne "$($cSwMap[$_])" } | ForEach-Object { [ordered]@{ name = $_; from_version = "$($bSwMap[$_])"; to_version = "$($cSwMap[$_])" } })

    # ---- findings: new / resolved / persisting (only when BOTH captures have structured findings - schema 6+) ----
    $bF = @(Get-JsonPath $b 'findings'); $cF = @(Get-JsonPath $c 'findings')
    $findingsComparable = (@($bF | Where-Object { $_ -is [System.Management.Automation.PSCustomObject] -and $_.PSObject.Properties['code'] }).Count -gt 0 -or $bF.Count -eq 0) -and
                          (@($cF | Where-Object { $_ -is [System.Management.Automation.PSCustomObject] -and $_.PSObject.Properties['code'] }).Count -gt 0 -or $cF.Count -eq 0)
    $findingsNew = $null; $findingsResolved = $null; $findingsPersisting = $null; $findingsReclassified = $null; $findingsNewlyDetected = $null; $findingsNotComparable = $null
    if ($findingsComparable) {
        $bCodes = @{}; foreach ($f in $bF) { if ($f.code) { $bCodes[$f.code] = $f.message } }
        $cCodes = @{}; foreach ($f in $cF) { if ($f.code) { $cCodes[$f.code] = $f.message } }
        $findingsNew        = @($cCodes.Keys | Where-Object { -not $bCodes.ContainsKey($_) } | Sort-Object | ForEach-Object { [ordered]@{ code = $_; message = $cCodes[$_] } })
        $findingsResolved   = @($bCodes.Keys | Where-Object { -not $cCodes.ContainsKey($_) } | Sort-Object | ForEach-Object { [ordered]@{ code = $_; message = $bCodes[$_] } })
        $findingsPersisting = @($cCodes.Keys | Where-Object { $bCodes.ContainsKey($_) } | Sort-Object)
        # A newer engine can split one code into more precise ones: only when the baseline PREDATES the split is the
        # pair a change in the diagnosis rather than in the PC - report it apart instead of as resolved + new.
        $codeSplits = @(
            @{ from = 'bitlocker_suspended'; to = 'device_encryption_not_activated'; since = '3.2.0' },
            @{ from = 'disk_unencrypted';    to = 'disk_decryption_in_progress';     since = '3.2.0' },
            # 3.3.4 split Windows 10 22H2 end of support by ESU evidence (license year + build revision)
            @{ from = 'os_end_of_support';   to = 'os_extended_security_updates';             since = '3.3.4' },
            @{ from = 'os_end_of_support';   to = 'os_extended_security_updates_not_applied'; since = '3.3.4' },
            @{ from = 'os_end_of_support';   to = 'os_extended_security_updates_expired';     since = '3.3.4' }
        )
        $bVer = $null; $cVer = $null
        try { $bVer = [version]"$(Get-JsonPath $b 'meta.tool_version')" } catch { }
        try { $cVer = [version]"$(Get-JsonPath $c 'meta.tool_version')" } catch { }
        $findingsReclassified = @()
        foreach ($split in $codeSplits) {
            $since = [version]$split.since
            if ($bVer -and $cVer -and $bVer -lt $since -and $cVer -ge $since -and
                $bCodes.ContainsKey($split.from) -and -not $cCodes.ContainsKey($split.from) -and
                $cCodes.ContainsKey($split.to) -and -not $bCodes.ContainsKey($split.to)) {
                $findingsReclassified += [ordered]@{ from_code = $split.from; to_code = $split.to; message = $cCodes[$split.to] }
            }
        }
        $reFrom = @($findingsReclassified | ForEach-Object { $_.from_code }); $reTo = @($findingsReclassified | ForEach-Object { $_.to_code })
        $findingsNew      = @($findingsNew | Where-Object { $_.code -notin $reTo })
        $findingsResolved = @($findingsResolved | Where-Object { $_.code -notin $reFrom })
        # A code the baseline engine could not emit yet is a new DETECTION, not a new problem on the PC
        # (states the old engine reported under ANOTHER code are handled by $codeSplits, not here)
        $codeSince = @{ 'kernel_dma_protection_off' = '3.3.0'; 'devices_with_errors' = '3.3.0'; 'event_log_short_coverage' = '3.3.0' }
        foreach ($code in 'suspicious_autorun', 'autorun_needs_review', 'winlogon_modified', 'accessibility_debugger_hijack', 'remote_tool_portable', 'remote_assistance_running',
                          'rdp_session_active', 'rdp_logons_from_internet', 'remote_tool_fixed_password', 'defender_remediation_failed', 'defender_recent_detections', 'hidden_local_account') { $codeSince[$code] = '3.4.0' }
        # EVENT-based findings carry 'evidence_at' = the newest event behind THAT finding (not any detection of the PC): when
        # it is newer than the baseline capture, the finding is a real change on the PC, not something the old engine missed.
        $toOffset = { param($v) $o = [datetimeoffset]::MinValue; if ($v -and [datetimeoffset]::TryParse("$v", [ref]$o)) { $o } else { $null } }
        $bAtOffset = & $toOffset $bAt
        $evidenceOf = @{}
        foreach ($f in @($cF | Where-Object { $_ -and $_.PSObject.Properties['evidence_at'] -and $_.evidence_at })) { $evidenceOf["$($f.code)"] = & $toOffset $f.evidence_at }
        $isNewEvent = { param($code) [bool]($bAtOffset -and $evidenceOf[$code] -and $evidenceOf[$code] -gt $bAtOffset) }
        $findingsNewlyDetected = @($findingsNew | Where-Object { $codeSince.ContainsKey($_.code) -and $bVer -and $bVer -lt [version]$codeSince[$_.code] -and -not (& $isNewEvent $_.code) })
        # 3.4.0 widened the remote-tool list (UltraViewer, NetSupport...): 'remote_access_tools' is an engine change, not a PC
        # change, when every tool it names was already in the baseline's software list (measured on ROD-PC 3.3.3 -> 3.4.0).
        # Compared by the recognized tool, not the display name: 'UltraViewer version 6.6.113' -> '6.6.124' is the same tool.
        if ($bVer -and $bVer -lt [version]'3.4.0' -and $cVer -and $cVer -ge [version]'3.4.0') {
            $toolOf = { param($n) $m = [regex]::Match("$n", $script:RemoteTools, 'IgnoreCase'); if ($m.Success) { $m.Value.ToLower() } }
            $bTools = @($bSw | ForEach-Object { & $toolOf $_.name } | Where-Object { $_ })
            $cTools = @(@(Get-JsonPath $c 'remote_access.tools') | Where-Object { $_ -and "$($_.kind)$($_.source)" -eq 'software' } | ForEach-Object { & $toolOf $_.name } | Where-Object { $_ })
            $rt = @($findingsNew | Where-Object { $_.code -eq 'remote_access_tools' })
            if ($rt.Count -gt 0 -and $cTools.Count -gt 0 -and @($cTools | Where-Object { $bTools -notcontains $_ }).Count -eq 0) { $findingsNewlyDetected += $rt }
        }
        $ndCodes = @($findingsNewlyDetected | ForEach-Object { $_.code })
        $findingsNew = @($findingsNew | Where-Object { $_.code -notin $ndCodes })
        # msinfo32-based findings only exist when msinfo32 ran (skipped without admin / in unattended runs)
        $msinfoCodes = @('kernel_dma_protection_off')
        $findingsNotComparable = @()
        if ("$(Get-JsonPath $b 'security.msinfo32_status')" -ne 'collected' -or "$(Get-JsonPath $c 'security.msinfo32_status')" -ne 'collected') {
            $findingsNotComparable = @(@($findingsNew) + @($findingsResolved) | Where-Object { $_ -and $_.code -in $msinfoCodes })
            $findingsNew      = @($findingsNew | Where-Object { $_.code -notin $msinfoCodes })
            $findingsResolved = @($findingsResolved | Where-Object { $_.code -notin $msinfoCodes })
        }
    }

    # ---- accounts: administrators + local users added/removed (both schemas expose these the same way) ----
    $bAdmins = @(Get-JsonPath $b 'accounts.administrators'); $cAdmins = @(Get-JsonPath $c 'accounts.administrators')
    $adminsAdded   = @($cAdmins | Where-Object { $_ -notin $bAdmins } | Sort-Object)
    $adminsRemoved = @($bAdmins | Where-Object { $_ -notin $cAdmins } | Sort-Object)
    $bUsers = @(@(Get-JsonPath $b 'accounts.local_users') | ForEach-Object { $_.name }); $cUsers = @(@(Get-JsonPath $c 'accounts.local_users') | ForEach-Object { $_.name })
    $usersAdded   = @($cUsers | Where-Object { $_ -notin $bUsers } | Sort-Object)
    $usersRemoved = @($bUsers | Where-Object { $_ -notin $cUsers } | Sort-Object)

    # ---- identity / OS / hardware sanity (rare but high-signal: reimage, hardware swap) ----
    $osChanged  = "$(Get-JsonPath $b 'os.build')" -ne "$(Get-JsonPath $c 'os.build')"
    $ramChanged = "$(Get-JsonPath $b 'hardware.ram_gb')" -ne "$(Get-JsonPath $c 'hardware.ram_gb')"

    # ---- numeric trend (best-effort: only when BOTH captures ran the relevant module) ----
    $ramTrend   = [ordered]@{ from = Get-JsonPath $b 'performance.ram_used_percent'; to = Get-JsonPath $c 'performance.ram_used_percent' }
    $stabTrend  = [ordered]@{ from = Get-JsonPath $b 'performance.stability_index.current'; to = Get-JsonPath $c 'performance.stability_index.current' }
    $battTrend  = [ordered]@{ from = Get-JsonPath $b 'health.battery.health_percent'; to = Get-JsonPath $c 'health.battery.health_percent' }
    $diskFreeTrend = [ordered]@{ from = Get-JsonPath $b 'hardware.disk_c.free_percent'; to = Get-JsonPath $c 'hardware.disk_c.free_percent' }

    # ---- new hotfixes installed since baseline (informative: what Windows Update applied in the interim) ----
    # 'system.hotfixes' did not exist before schema_version 6 - $null (field absent, module never ran) must NOT
    # be read as "0 patches back then" (that would flag every current hotfix as falsely "new"). Only compare
    # when the baseline capture actually HAD this field.
    $bHotfixRaw = Get-JsonPath $b 'system.hotfixes'
    $hotfixesComparable = ($null -ne $bHotfixRaw) -or ($null -ne (Get-JsonPath $b 'system'))
    $hotfixIdOf = { param($h) if ($h.PSObject.Properties['provider_hotfix_id']) { $h.provider_hotfix_id } else { $h.id } }   # 'id' = schema <= 8
    # '@($null)' is ONE null element: a capture without the field (another profile) must not reach the property lookup
    $bHotfix = @(@($bHotfixRaw) | Where-Object { $_ } | ForEach-Object { & $hotfixIdOf $_ }); $cHotfix = @(@(Get-JsonPath $c 'system.hotfixes') | Where-Object { $_ } | ForEach-Object { & $hotfixIdOf $_ })
    # NOTE: '$x = if (cond) {@(...)} else {$null}' collapses an EMPTY array to {} on ConvertTo-Json (PowerShell
    # quirk, same family as the ,@() issue found earlier in 'events'). Assign in two steps instead: verified.
    $hotfixesNew = $null
    if ($hotfixesComparable) { $hotfixesNew = @($cHotfix | Where-Object { $_ -and $_ -notin $bHotfix } | Sort-Object) }

    $report = [ordered]@{
        baseline = [ordered]@{ file = (Resolve-Path $Baseline).Path; audited_at = $bAt; tool_version = Get-JsonPath $b 'meta.tool_version' }
        current  = [ordered]@{ file = (Resolve-Path $Current).Path;  audited_at = $cAt; tool_version = Get-JsonPath $c 'meta.tool_version' }
        computer_name_changed = ("$bName" -ne "$cName")
        serial_changed         = ("$bSerial" -ne "$cSerial")
        os_build_changed       = $osChanged
        ram_gb_changed         = $ramChanged
        software_added         = $swAdded
        software_removed       = $swRemoved
        software_updated       = $swUpdated
        administrators_added   = $adminsAdded
        administrators_removed = $adminsRemoved
        local_users_added      = $usersAdded
        local_users_removed    = $usersRemoved
        hotfixes_new            = $hotfixesNew
        ram_used_percent_trend  = $ramTrend
        stability_index_trend   = $stabTrend
        battery_health_trend    = $battTrend
        disk_c_free_percent_trend = $diskFreeTrend
        findings_comparable = $findingsComparable
        findings_new         = $findingsNew
        findings_resolved     = $findingsResolved
        findings_reclassified = $findingsReclassified
        findings_newly_detected = $findingsNewlyDetected
        findings_not_comparable = $findingsNotComparable
        is_tool_version_changed = ("$(Get-JsonPath $b 'meta.tool_version')" -ne "$(Get-JsonPath $c 'meta.tool_version')")
        is_admin_changed        = ($null -ne (Get-JsonPath $b 'meta.is_admin') -and $null -ne (Get-JsonPath $c 'meta.is_admin') -and [bool](Get-JsonPath $b 'meta.is_admin') -ne [bool](Get-JsonPath $c 'meta.is_admin'))
        findings_persisting_count = if ($null -ne $findingsPersisting) { $findingsPersisting.Count } else { $null }
    }

    Write-Host ''
    Write-Host '  SOFTWARE:' -ForegroundColor Cyan
    if ($swAdded.Count -eq 0 -and $swRemoved.Count -eq 0 -and $swUpdated.Count -eq 0) { Write-Host '   - Sin cambios.' -ForegroundColor Green }
    foreach ($n in $swAdded)   { Write-Host "   + $n" -ForegroundColor Yellow }
    foreach ($n in $swRemoved) { Write-Host "   - $n" -ForegroundColor DarkGray }
    foreach ($u in $swUpdated) { Write-Host ("   ~ {0} ({1} -> {2})" -f $u.name, $u.from_version, $u.to_version) -ForegroundColor Cyan }

    Write-Host ''
    Write-Host '  CUENTAS:' -ForegroundColor Cyan
    if (-not ($adminsAdded + $adminsRemoved + $usersAdded + $usersRemoved)) { Write-Host '   - Sin cambios.' -ForegroundColor Green }
    foreach ($n in $adminsAdded)   { Write-Host "   + Administrador nuevo: $n" -ForegroundColor Red }
    foreach ($n in $adminsRemoved) { Write-Host "   - Ya no es administrador: $n" -ForegroundColor Yellow }
    foreach ($n in $usersAdded)    { Write-Host "   + Usuario local nuevo: $n" -ForegroundColor Yellow }
    foreach ($n in $usersRemoved)  { Write-Host "   - Usuario local eliminado: $n" -ForegroundColor DarkGray }

    Write-Host ''
    Write-Host '  HALLAZGOS:' -ForegroundColor Cyan
    if (-not $findingsComparable) { Write-Host '   - No comparable: uno de los dos relevamientos es de una version del motor sin hallazgos con codigo.' -ForegroundColor DarkGray }
    else {
        if ($findingsNew.Count -eq 0 -and $findingsResolved.Count -eq 0) { Write-Host '   - Sin cambios.' -ForegroundColor Green }
        foreach ($f in $findingsNew)      { Write-Host "   + NUEVO: $($f.message)" -ForegroundColor Red }
        foreach ($f in $findingsResolved) { Write-Host "   - RESUELTO: $($f.message)" -ForegroundColor Green }
        foreach ($f in $findingsReclassified) { Write-Host "   ~ RECLASIFICADO (cambio de version del motor, no del equipo): $($f.message)" -ForegroundColor Cyan }
        foreach ($f in $findingsNotComparable) { Write-Host "   ? NO COMPARABLE (msinfo32 no corrio en uno de los dos relevamientos): $($f.message)" -ForegroundColor DarkGray }
        foreach ($f in $findingsNewlyDetected) { Write-Host "   * DETECCION NUEVA (la version anterior del motor no lo media): $($f.message)" -ForegroundColor Cyan }
        if ($findingsPersisting.Count -gt 0) { Write-Host "   ($($findingsPersisting.Count) hallazgo(s) sin cambios)" -ForegroundColor DarkGray }
    }

    Write-Host ''
    Write-Host '  TENDENCIA:' -ForegroundColor Cyan
    foreach ($t in @(@{ n = 'RAM en uso'; v = $ramTrend; suf = '%' }, @{ n = 'Indice de estabilidad'; v = $stabTrend; suf = '/10' },
                     @{ n = 'Salud de bateria'; v = $battTrend; suf = '%' }, @{ n = 'C: libre'; v = $diskFreeTrend; suf = '%' })) {
        if ($null -ne $t.v.from -and $null -ne $t.v.to) { Write-Host ("   {0}: {1}{3} -> {2}{3}" -f $t.n, $t.v.from, $t.v.to, $t.suf) -ForegroundColor Gray }
    }
    if ($hotfixesNew.Count -gt 0) { Write-Host ''; Write-Host "  PARCHES NUEVOS: $($hotfixesNew -join ', ')" -ForegroundColor Gray }
    if ($osChanged)  { Write-Host ''; Write-Host "  Windows cambio de build: $(Get-JsonPath $b 'os.build') -> $(Get-JsonPath $c 'os.build') (reinstalacion o actualizacion mayor)." -ForegroundColor Yellow }
    if ($ramChanged) { Write-Host "  RAM fisica cambio: $(Get-JsonPath $b 'hardware.ram_gb') GB -> $(Get-JsonPath $c 'hardware.ram_gb') GB (upgrade de hardware)." -ForegroundColor Gray }

    $outDir = if ([string]::IsNullOrWhiteSpace($OutputPath)) { Split-Path -Parent (Resolve-Path $Current).Path } else { $OutputPath }
    # date+time (not just date) in the filename: two comparisons run the same day must not overwrite each other.
    function ConvertTo-FileStamp([string]$Iso) { ("$Iso" -replace '[+-]\d\d:\d\d$', '') -replace '[:T ]', '-' }   # strip tz offset, then ':'/'T'/' '
    $outFile = Join-Path $outDir ("compare-{0}-{1}_a_{2}.json" -f ($cName -replace '[^\w\.-]', '_'), (ConvertTo-FileStamp $bAt), (ConvertTo-FileStamp $cAt))
    try { $report | ConvertTo-Json -Depth 6 | Out-File -FilePath $outFile -Encoding UTF8; Write-Host ''; Write-Host "Informe de comparacion guardado: $outFile" -ForegroundColor Green } catch { Write-Host "No se pudo guardar el informe: $($_.Exception.Message)" -ForegroundColor Red }
    return
}

# ============================ MAIN: AUDIT =========================================
$isAdmin = Test-IsAdmin
$script:IsAdmin = $isAdmin   # module-visible (oea uses it for secedit/auditpol branches)

# Resolve output folder + module list.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = $scriptDir }
if (-not (Test-Path $OutputPath)) { try { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null } catch { $OutputPath = $scriptDir } }

$requestedProfile = $Profile
if ($script:ProfileAliases.ContainsKey($Profile)) { $Profile = $script:ProfileAliases[$Profile] }
if ($Module) { $selected = @($Module | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.ToLower().Trim() } | Where-Object { $_ }) }   # "-File x.ps1 -Module a,b" arrives as ONE string
else         { $selected = @($script:Profiles[$Profile]) }
$selected = @('core') + @($selected | Where-Object { $_ -ne 'core' })   # identity/OS always present, and FIRST (performance reads core's RAM data)
$selected = @($selected | Where-Object { $script:ModuleCatalog.Contains($_) })

# Ask for the assigned user if not provided (only in flag mode; the menu already asked; never under -Silent,
# a Scheduled Task has no console to answer it and Read-Host would hang forever).
if ((-not $script:Interactive) -and (-not $Silent) -and [string]::IsNullOrWhiteSpace($script:AssignedUser)) {
    $script:AssignedUser = (Read-Host 'Usuario/responsable de esta PC (ENTER para omitir)').Trim()
}

Write-Section 'AUDITORIA DE ENDPOINT  (solo lectura)'
Write-Field 'Equipo'       $env:COMPUTERNAME White
Write-Field 'Responsable'  $script:AssignedUser White
Write-Field 'Organizacion' $script:Organization White
Write-Field 'Perfil'       $Profile White
Write-Field 'Modulos'      ($selected -join ', ')
if ($isAdmin) { Write-Host '  Privilegios           : ADMINISTRADOR (cobertura completa)' -ForegroundColor Green }
else {
    Write-Host '  Privilegios           : SIN admin (cobertura parcial)' -ForegroundColor Yellow
    Add-Finding -Code 'audit_not_elevated' -Severity 'info' -Oea @() -Message 'Se corrio SIN admin: la cobertura es parcial. Re-correr como administrador.'
}

# Build the result root (meta first, then each module's top-level keys, then findings/errors).
# Audited user (the person who uses the PC) - may differ from the elevating account. hive_root is internal.
$au = Resolve-AuditedUser
# NOTE: PowerShell variable names are case-insensitive - do NOT name this $auditedUser (it would overwrite $script:AuditedUser).
$auditedUserMeta = [ordered]@{}
foreach ($k in $au.Keys) { if ($k -ne 'hive_root') { $auditedUserMeta[$k] = $au[$k] } }
Write-Field 'Usuario auditado' ("{0}  (origen: {1})" -f $au.name, $au.detected_via) White
if (-not $au.is_runner) {
    Write-Field 'Ejecutado como' $au.runner_name
    if (-not $au.is_hive_available) {
        Write-Host '  ATENCION: el perfil del usuario no esta cargado (no inicio sesion): los datos por usuario quedan N/D.' -ForegroundColor Yellow
        Add-Finding -Code 'user_hive_unavailable' -Severity 'info' -Oea @() -Message ("Datos por usuario NO medidos: la sesion de '$($au.name)' no estaba cargada. Re-correr con el usuario logueado.")
    }
}

$root = [ordered]@{
    meta = [ordered]@{
        tool_version   = $script:ToolVersion
        schema_version = $script:SchemaVersion
        profile        = $Profile
        requested_profile = if ($requestedProfile -ne $Profile) { $requestedProfile } else { $null }   # legacy alias used (Base/OEA)
        modules_run    = $selected
        is_admin       = $isAdmin
        is_silent      = [bool]$Silent   # true = unattended run (e.g. Scheduled Task), not a technician at the keyboard
        audited_user   = $auditedUserMeta
        audited_at     = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    }
}
$moduleDurations = [ordered]@{}   # ms per module -> diagnose slow/hanging modules on client PCs
if (-not $Silent) { Disable-ConsoleQuickEdit }
try {   # QuickEdit stays off until the JSON is written (the freeze seen 2026-09-29 was at the summary); restored in finally
$moduleIndex = 0
foreach ($m in $selected) {
    $moduleIndex++
    if (-not $Silent) { Write-Host ('  [{0,2}/{1}] {2}' -f $moduleIndex, $selected.Count, $script:ModuleLabels[$m]) -ForegroundColor DarkGray }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $script:CurrentModule = $m
    $data = Invoke-AuditModule -Name $m -FunctionName $script:ModuleCatalog[$m]
    $script:CurrentModule = $null
    $sw.Stop(); $moduleDurations[$m] = [int]$sw.ElapsedMilliseconds
    if ($null -ne $data -and $data -is [System.Collections.IDictionary]) {
        foreach ($k in $data.Keys) { $root[$k] = $data[$k] }
    }
}
$root.meta['module_durations_ms'] = $moduleDurations
# by severity, keeping emission order inside each level (PowerShell 5.1 has no Sort-Object -Stable -> explicit index)
$seq = 0
$sortedFindings = @(@($script:Findings) | ForEach-Object { [pscustomobject]@{ rank = $script:SeverityRank[$_.severity]; seq = $seq++; item = $_ } } | Sort-Object rank, seq | ForEach-Object { $_.item })
$root['findings'] = $sortedFindings
$root['errors']   = @($script:Errors)

# ---- console summary (Spanish, user-facing) ----
Write-Section 'RESUMEN'
if ($root.Contains('identity')) {
    Write-Field 'Equipo'   ("{0} ({1})" -f $root.identity.computer_name, $root.os.caption)
    $hw = $root.hardware
    Write-Field 'Modelo'   ((@($hw.manufacturer, $hw.model, $hw.product_version) | Where-Object { $_ } | Select-Object -Unique) -join ' ')
    Write-Field 'SKU / Serie' ("{0} / {1}" -f $(if ($hw.sku) { $hw.sku } else { '-' }), $(if ($hw.serial) { $hw.serial } else { '-' }))
    $mountLabel = @{ soldered = $(if ($hw.is_ram_mounting_confirmed) { 'soldada' } else { 'probablemente soldada' }); socketed = $(if ($hw.is_ram_mounting_confirmed) { 'en ranuras' } else { 'en ranura segun el BIOS, sin confirmar' }); mixed = 'soldada + ranura'; unknown = 'montaje desconocido'; virtual = 'virtual' }
    $ramExtra = if ($hw.ram_mounting) { " ($($mountLabel[$hw.ram_mounting])$(if ($hw.ram_mounting -ne 'soldered' -and $hw.ram_slots.is_table_consistent -eq $false) { ', ranuras: BIOS inconsistente' } elseif ($hw.ram_slots.empty_position_count -gt 0) { ", BIOS: $($hw.ram_slots.empty_position_count) posicion(es) vacia(s), confirmar en ficha" }))" } else { '' }
    $cpuMountLabel = @{ soldered = 'soldado'; socketed = 'en zocalo'; unknown = 'sin confirmar'; virtual = 'virtual' }
    if ($hw.motherboard -or $hw.cpu_socket) { Write-Field 'Placa / zocalo' ("{0} | zocalo {1}{2}" -f $(if ($hw.motherboard) { $hw.motherboard } else { '-' }), $(if ($hw.cpu_socket) { $hw.cpu_socket } else { '-' }), $(if ($hw.cpu_mounting) { " ($($cpuMountLabel[$hw.cpu_mounting]))" } else { '' })) }
    Write-Field 'Hardware' ("{0} | {1} GB RAM{2} | {3}" -f $hw.cpu, $hw.ram_gb, $ramExtra,
        ((@($hw.disks) | ForEach-Object { "$($_.kind) $($_.size_gb)GB" }) -join ' / '))
    Write-Field 'Disco C:' ("{0}% libre" -f $root.hardware.disk_c.free_percent)
}
if ($root.Contains('persistence') -and $root.persistence) {
    $pe = $root.persistence
    $examined = 0; foreach ($n in @($pe.run_key_count, $pe.startup_file_count, $pe.scheduled_task_action_count, $pe.service_count)) { if ($null -ne $n) { $examined += [int]$n } }
    # honest scope: known malware PATTERNS in what starts automatically; it does not replace an antivirus scan
    Write-Field 'Arranque automatico' ("{0} entradas revisadas, {1} con patron de malware, {2} para verificar (no reemplaza un antivirus)" -f $examined, @($pe.suspicious_autoruns).Count, @($pe.reviewable_autoruns).Count)
}
Write-Host ''
Write-Host '  HALLAZGOS:' -ForegroundColor Cyan
$sevLabel = @{ high = 'ALTO '; medium = 'MEDIO'; low = 'BAJO '; info = 'INFO ' }
$sevColor = @{ high = 'Red'; medium = 'Yellow'; low = 'Gray'; info = 'DarkGray' }
if ($sortedFindings.Count -eq 0) { Write-Host '   - Sin hallazgos.' -ForegroundColor Green }
else { $i = 1; foreach ($f in $sortedFindings) { Write-Host ("   {0,2}. [{1}] {2}" -f $i, $sevLabel[$f.severity], $f.message) -ForegroundColor $sevColor[$f.severity]; $i++ } }
if ($script:Errors.Count -gt 0) { Write-Host ("  Modulos con error: " + (@($script:Errors) | ForEach-Object { $_.module }) -join ', ') -ForegroundColor Red }

# ---- write JSON (snake_case, nested by module) ----
$userSan = (($script:AssignedUser -replace '[^\w\s\.\-]', '').Trim() -replace '\s+', '_')
$jsonPath = if ($userSan) { Join-Path $OutputPath "$userSan-$($env:COMPUTERNAME).json" }
            else          { Join-Path $OutputPath "audit-$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd-HHmmss').json" }
try {
    $root | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host ''
    Write-Host "  Archivo generado (JSON con todo el detalle):" -ForegroundColor Green
    Write-Host "   - $jsonPath" -ForegroundColor DarkGray
} catch {
    Write-Host "  [error JSON] $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host ''
} finally { Restore-ConsoleMode }
if (-not $Silent) { Read-Host 'Presione ENTER para cerrar' }   # -Silent: a Scheduled Task has no one to press ENTER
