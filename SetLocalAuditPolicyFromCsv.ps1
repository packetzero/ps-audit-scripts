

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
        [string]$charvals
        )
    $s = GetAuditpolVal $charvals.Contains("S")
    $f = GetAuditpolVal $charvals.Contains("F")
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

    $cmd = auditpol.exe /set /category:"$TheCategory" /subcategory:"$SubCategory" /success:$s /failure:$f
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

    $cmd = auditpol.exe /set /category:"$TheCategory" /subcategory:"$SubCategory" /success:$s /failure:$f
    $cmd
}


class ZAuditSetting
{
    [string] $Category
    [string] $SubCategory
    [string] $CharFlags
    [bool]   $IsSuccessEnabled
    [bool]   $IsFailureEnabled

    ZAuditSetting([string]$cat, [string]$subcat, [bool]$bSuccess, [bool]$bFailure, [string]$charFlags) {
        $this.Category = $cat
        $this.SubCategory = $subcat
        $this.IsSuccessEnabled = $bSuccess
        $this.IsFailureEnabled = $bFailure
        $this.CharFlags = $charFlags
    }
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

#        $obj = New-Object ZAuditSetting $CurrentCategory $subcat $isSuccessEnabled $isFailureEnabled $charflags
        $obj = New-Object ZAuditSetting( $CurrentCategory, $subcat, $isSuccessEnabled, $isFailureEnabled, $charflags)

#        $obj = [PSCustomObject]@{
#            Category = $CurrentCategory
#            SubCategory = $subcat
#            CharFlags = $charflags
#            IsSuccessEnabled = $isSuccessEnabled
#            IsFailureEnabled = $isFailureEnabled
#         }

        # add to array

        $cfgObjects += $obj
    }

#    foreach ($obj in $cfgObjects) { Write-Host "OBJ cat:'$($obj.Category)' subcat:'$($obj.SubCategory)' val:'$($obj.CharFlags)'" }

    return $cfgObjects    
}

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

Function GetAuditSettings($CategoryName)
{
    $retval = @()

    # get settings list - first line contains headers

    $lines = (auditpol.exe /get /category:$CategoryName /r) |
        Where-Object { -not [String]::IsNullOrEmpty($_) }

    $objs = @()
    foreach ($line in $lines) {
        $a = $line.Split(",")
        if ($a[0] -eq "Machine Name") {
            Write-Host "HDR: $($line)"
        } else {
            $subcat = $a[2]
            $valstr = $a[4]
            Write-Host $a[2] $a[4]
            
        }

    }
}


# load desired settings from CSV file
# TODO: get from command-line

$desiredAuditSettings = LoadSettingsFromCsv "C:\\dev\\ps\system-audit-settings.csv"

# put in map for easy lookup

$desiredAuditMap = @{}
foreach ($obj in $cfgObjects) {
    $key = $obj.Category + "/" + $obj.SubCategory
    $desiredAuditMap[$key] = $obj
}

# Load actual settings

$actualAuditSettings = GetAuditSettings
#foreach ($obj in $actualAuditSettings) {
#    Write-Host $obj
#}

#SetAuditPol "System" "Logon" $TRUE $TRUE
#SetAuditPolWithChars "System" "Logon" "F"


