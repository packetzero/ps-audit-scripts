
$AuditCatgoryNames = (
"Account Logon",
"Account Management",
"Detailed Tracking",
"DS Access",
"Logon/Logoff",
"Object Access",
"Policy Change",
"Privilege Use",
"System"
)

#------------------------------------------------------------------------
# ZAuditSetting - represents a single event log audit setting
#------------------------------------------------------------------------
class ZAuditSetting
{
    [string] $Category
    [string] $SubCategory
    [string] $CharFlags
    [bool]   $IsSuccessEnabled
    [bool]   $IsFailureEnabled
    [string] $Id

    ZAuditSetting([string]$cat, [string]$subcat, [bool]$bSuccess, [bool]$bFailure, [string]$charFlags) {
        $this.Category = $cat
        $this.SubCategory = $subcat
        $this.IsSuccessEnabled = $bSuccess
        $this.IsFailureEnabled = $bFailure
        $this.CharFlags = $charFlags
    }

    [string] ToString( ) {
        return "AuditSetting cat:'" + $this.Category + "' subcat:'" + $this.SubCategory + "' isSuccessEnabled:" + $this.IsSuccessEnabled + " isFailureEnabled:" + $this.IsFailureEnabled
    }

    [string] GetKey() { return $this.Category + "|" + $this.SubCategory }
}


#------------------------------------------------------------------------
# GetAuditpolVal($isEnabled)
#
# Designed to return english setting values used with auditpol.exe
#
# Returns "enable" if isEnabled == TRUE, otherwise returns "false"
#------------------------------------------------------------------------
Function GetAuditpolVal
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [bool]$isEnabled
        )
    if ($isEnabled) { return "enable" }
    return "disable"
}

#------------------------------------------------------------------------
# GetAuditpolVals($charFlagsString)
#
# if $charFlagsString
#   contains 'S', $successValue = "enable" otherwise "disable"
#   contains 'F', $failureValue = "enable", otherwise "disable"
# 
# Returns an array with two string values [$successValue, $successValue]
#------------------------------------------------------------------------
Function GetAuditpolVals
{
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$charFlagsString
        )
    $s = GetAuditpolVal $charFlagsString.Contains("S")
    $f = GetAuditpolVal $charFlagsString.Contains("F")
    return $s,$f
}

#------------------------------------------------------------------------
# SetAuditPol($category,$subcategory,$isSuccessEnabled,$isFailureEnabled)
#
# Constructs a commandline and runs auditpol.exe to set values for
# a single policy.
#------------------------------------------------------------------------
Function SetAuditPol
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$TheCategory,
        [Parameter(Mandatory=$True,Position=2)]
        [string]$SubCategory,
        [Parameter(Mandatory=$True,Position=3)]
        [bool]$isSuccessEnabled,
        [Parameter(Mandatory=$True,Position=4)]
        [boolean]$isFailureEnabled
        )

    $s = GetAuditpolVal($isSuccessEnabled)
    $f = GetAuditpolVal($isFailureEnabled)

    Write-Host "auditpol.exe /set /subcategory:'$SubCategory' /success:$s /failure:$f"

    $cmd = auditpol.exe /set /subcategory:"$SubCategory" /success:$s /failure:$f
    $cmd
}

#------------------------------------------------------------------------
# SetAuditPolWithChars($category,$subcategory,$charFlagsString)
#
# See GetAuditpolVals() for description of $charFlagsString
#
# Constructs a commandline and runs auditpol.exe to set values for
# a single policy.
#------------------------------------------------------------------------
Function SetAuditPolWithChars
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$TheCategory,
        [Parameter(Mandatory=$True,Position=2)]
        [string]$SubCategory,
        [Parameter(Mandatory=$True,Position=3)]
        [string]$Charvals
        )

    $s,$f = GetAuditpolVals($Charvals)

    SetAuditPol $TheCategory $SubCategory $s $f
}

#------------------------------------------------------------------------
# Returns array of objects describing audit settings
# Each object:
#  {
#    Category          string
#    SubCategory       string
#    IsSuccessEnabled  bool
#    IsFailureEnabled  bool
#    CharFlags         string
#  }
#------------------------------------------------------------------------
Function LoadSettingsFromCsv
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$filename
    )

    # initialize empty array to hold defs

    $cfgObjects=@()
    
    # Read in CSV file
    # Lines contain two columns: charflags and name
    # Special lines:
    #  ===,Category name
    # Regular lines:
    #  SF,some sub category
    #  - ,some subcategory for no audit
    #  F ,some subcat for failure audit
    
    Import-Csv $filename -Header charflags,name | ForEach-Object {

        # parse line

        if ($_.charflags.Contains("=")) {

            # This line signifies a new category only

            $CurrentCategory = $_.name
            return
        }

        # regular entry

        $subcat = $_.name.Trim()
        $charflags = $_.charflags.Trim()
        $isSuccessEnabled = $_.charflags.Contains("S")
        $isFailureEnabled = $_.charflags.Contains("F")

        # package in an object for easier use

        $obj = New-Object ZAuditSetting( $CurrentCategory, $subcat, $isSuccessEnabled, $isFailureEnabled, $charflags)

        # add to array

        $cfgObjects += $obj
    }

    return $cfgObjects    
}

#------------------------------------------------------------------------
# Parses setting value strings present in auditpol output,
# Example values are "Success", "Success and Failure", "No Auditing"
# returns (bool isSuccessEnabled, bool isFailureEnabled, string charFlags)
#------------------------------------------------------------------------
Function ParseAuditSettingVal($strval)
{
    if ($strval -eq "Success and Failure") { return $TRUE,$TRUE,"SF" }
    if ($strval -eq "Success") { return $TRUE,$FALSE,"S" }
    if ($strval -eq "Failure") { return $FALSE,$TRUE,"F" }
    return $FALSE,$FALSE,""
}

#------------------------------------------------------------------------
# Get individual settings for a single category.
# auditpol output does not contain category name, so we query values
# per category.
#
# returns array of ZAuditSettings objects
#------------------------------------------------------------------------
Function GetAuditSettingsForCategory($CategoryName)
{
    $retval = @()

    # get settings list - first line contains headers

    $lines = (auditpol.exe /get /category:$CategoryName /r) |
        Where-Object { -not [String]::IsNullOrEmpty($_) }

    foreach ($line in $lines) {
        $a = $line.Split(",")
        if ($a[0] -eq "Machine Name") {
            #Write-Host "HDR: $($line)"
        } else {
            $subcat = $a[2]
            $objid = $a[3]
            $valstr = $a[4]
            ##Write-Host $a[2] $a[4]

            $isSuccessEnabled, $isFailureEnabled, $charflags = ParseAuditSettingVal $valstr

            #Write-Host $valstr " suc:" $isSuccessEnabled " fail:" $isFailureEnabled " flags:" $charflags

            $obj = New-Object ZAuditSetting( $CategoryName, $subcat, $isSuccessEnabled, $isFailureEnabled, $charflags)
            $obj.Id = $objid
            $retval += $obj
        }
    }

    return $retval
}

#------------------------------------------------------------------------
# Get single individual setting.
#
# returns ZAuditSettings object
#------------------------------------------------------------------------
Function GetAuditSetting($CategoryName, $SubCat)
{
    $objs = GetAuditSettingsForCategory $CategoryName

    foreach ($obj in $objs) {
        if ($obj.SubCategory -eq $SubCat) { return $obj }
    }

    return $FALSE
}

#------------------------------------------------------------------------
# Get single individual setting.
#
# Ideally use GUID as subcat, otherwise passs subcategory name
#
# returns ZAuditSettings object
#------------------------------------------------------------------------
Function GetAuditSettingBySubcat($subcat)
{

    $lines = (auditpol.exe /get /subcategory:$subcat /r) |
        Where-Object { -not [String]::IsNullOrEmpty($_) }

    foreach ($line in $lines) {
        $a = $line.Split(",")
        if ($a[0] -eq "Machine Name") {
            #Write-Host "HDR: $($line)"
        } else {
            $subcat = $a[2]
            $objid = $a[3]
            $valstr = $a[4]
            ##Write-Host $a[2] $a[4]

            $isSuccessEnabled, $isFailureEnabled, $charflags = ParseAuditSettingVal $valstr

            #Write-Host $valstr " suc:" $isSuccessEnabled " fail:" $isFailureEnabled " flags:" $charflags

            $obj = New-Object ZAuditSetting( $CategoryName, $subcat, $isSuccessEnabled, $isFailureEnabled, $charflags)
            $obj.Id = $objid
            return $obj
        }
    }

    return $FALSE
}

#------------------------------------------------------------------------
# CheckAuditSetting()
# Calls GetAuditSettingBySubcat($obj.Id or $obj.SubCategory)
# and returns TRUE if settings for success and failure, FALSE otherwise.
#------------------------------------------------------------------------
Function CheckAuditSetting([ZAuditSetting]$obj, [ZAuditSetting]$desired)
{
    $subcat = GetBestSubcategoryId $obj

    $actual = GetAuditSettingBySubcat $subcat
    if ($actual -eq $FALSE) {
        Write-Host "ERROR: GetAuditSettingBySubcat() returned FALSE"
        return $FALSE
    } else {
        $status = ($desired.IsSuccessEnabled -eq $actual.IsSuccessEnabled) -and ($desired.IsFailureEnabled -eq $actual.IsFailureEnabled)
        return $status
    }
}

#------------------------------------------------------------------------
# Returns array of ZAuditSettings objects for all settings.
#------------------------------------------------------------------------
Function GetAuditSettings()
{
    $allobjs=@()

    foreach ($cat in $AuditCatgoryNames)
    {
        # get array of settings for this category

        $items = GetAuditSettingsForCategory $cat

        # add to allobjs array

        foreach ($obj in $items) { $allobjs += $obj }
    }
    return $allobjs
}

#------------------------------------------------------------------------
# Compare desired vs actual settings
#------------------------------------------------------------------------
Function CompareActualWithDesired() {
    foreach ($desired in $desiredAuditSettings) {
        $key = $desired.GetKey()
        if ($actualAuditMap.ContainsKey($key)) {
            $actual = $actualAuditMap.$key
            if (($desired.IsSuccessEnabled -eq $actual.IsSuccessEnabled) -and ($desired.IsFailureEnabled -eq $actual.IsFailureEnabled)) {
                Write-Host "+ "  $key
            } else {
                Write-Host "- D:" $desired.CharFlags " A:" $actual.CharFlags " " $key
            }
        } else {
            Write-Host "? " $key
        }
    }
}

#------------------------------------------------------------------------
# GetBestSubcategoryId($AuditSettingA, $AuditSettingB=null)
# Ideally we want to use GUID of setting as subcategory when getting
# or setting a value.
# This function will return [string] the .Id of either parameter
# if present, otherwise return $AuditSettingA.SubCategory 
#------------------------------------------------------------------------
Function GetBestSubcategoryId
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$TRUE,Position=1)]
        [ZAuditSetting]$AuditSettingA,
        [Parameter(Mandatory=$FALSE,Position=2)]
        [ZAuditSetting]$AuditSettingB
        )

    # if a has Id, use it
    if (-not [String]::IsNullOrEmpty($AuditSettingA.Id) ) { return $AuditSettingA.Id }

    # if b as Id, use it
    if ($AuditSettingB -and -not [String]::IsNullOrEmpty($AuditSettingB.Id) ) { return $AuditSettingB.Id }

    # otherwise, use a.SubCategory
    return $AuditSettingA.SubCategory
}

#------------------------------------------------------------------------
# If actual setting equals desired, do nothing.
# Otherwise, set to desired values and check
#------------------------------------------------------------------------
Function SyncActualWithDesired() {
    foreach ($desired in $desiredAuditSettings) {
        $key = $desired.GetKey()
        if ($actualAuditMap.ContainsKey($key)) {
            $actual = $actualAuditMap.$key
            if (($desired.IsSuccessEnabled -eq $actual.IsSuccessEnabled) -and ($desired.IsFailureEnabled -eq $actual.IsFailureEnabled)) {
                #Write-Host "+ " + $key
            } else {
                
                $subcat = GetBestSubcategoryId $desired $actual

                SetAuditPol $desired.Category $subcat $desired.IsSuccessEnabled $desired.IsFailureEnabled
                
                $status = CheckAuditSetting $actual $desired
                
                if ($status -eq $TRUE) {
                    Write-Host "SUCCESS updating " $key
                } else {
                    Write-Host "FAILED updated " $key
                }
            }
        } else {
            Write-Host "Failure: setting not found: "  $key
        }
    }
}


#------------------------------------------------------------------------
# PrintAuditSettings
#------------------------------------------------------------------------
Function PrintAuditSettings()
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [ZAuditSetting[]]$objs,
        [Parameter(Mandatory=$FALSE,Position=2)]
        [string]$description
        )
    $str = "Audit Settings"
    if ($description) { $str += "($description)" }
    Write-Host $str
    Write-Host "--------------------------"

    foreach ($obj in $objs) { Write-Host $obj }

    Write-Host ""
}

# load desired settings from CSV file
# TODO: get from command-line

$desiredAuditSettings = LoadSettingsFromCsv "system-audit-settings.csv"

# put in map for easy lookup

$desiredAuditMap = @{}
foreach ($obj in $cfgObjects) {
    $key = $obj.GetKey() #$obj.Category + "/" + $obj.SubCategory
    $desiredAuditMap[$key] = $obj
}

#PrintAuditSettings $desiredAuditSettings "Desired"

# Load actual settings

$actualAuditSettings = GetAuditSettings
$actualAuditMap = @{}
foreach ($obj in $actualAuditSettings) { $actualAuditMap[$obj.GetKey()] = $obj }

#PrintAuditSettings $actualAuditSettings "Actual"

# compare desired with actual


SyncActualWithDesired

#reload
$actualAuditSettings = GetAuditSettings
$actualAuditMap = @{}
foreach ($obj in $actualAuditSettings) { $actualAuditMap[$obj.GetKey()] = $obj }

CompareActualWithDesired


#SetAuditPol "System" "Logon" $TRUE $TRUE
#SetAuditPolWithChars "System" "Logon" "F"


