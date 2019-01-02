Function Log {
    
    Param ([string]$logText,
        [string]$informationLevel = "Information")

    
    $logfile = Join-Path $pwd "IntuneConfig.log"
    $informationLevel = "[" + $informationLevel + "]"
    "[$(get-date)] $($informationLevel.PadRight(13," ")) [$((Get-PSCallStack)[1].FunctionName):$($myinvocation.ScriptLineNumber)] $logText" | Out-File $logfile -Append -Force
    
}
###################################

Function MsgBox {
    Param([string]$msg = "Message")
    Add-Type -AssemblyName PresentationFramework
    $answer = [System.Windows.MessageBox]::Show($msg,'Install module to continue','YesNo','Error')
    Log "Customer chose $answer"

}
###################################

Function ExceptionHandler {
    Param($ex)
    
    try {$errorResponse = $ex.Response.GetResponseStream()    
    $ex.InvocationInfo.PositionMessage
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Log "Response content:`n $($responseBody.tostring())" -informationLevel Error
    Log "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)" -informationLevel Error
    }
    catch {}
    Log $Error[0].Exception
    Log $Error[0].ScriptStackTrace
    
    }

####################################

Function Parse-Assignment {
    Param ($groupAssignments)
    $assignments = @{}
    $assignments.ExcludedGroups = @()
    $assignments.AssignedGroups  = @()
                     
     

    # microsoft.graph.groupAssignmentTarget
    #
    # microsoft.graph.exclusionGroupAssignmentTarget
    #
    # microsoft.graph.allLicensedUsersAssignmentTarget
    #
    #@{@odata.type=#microsoft.graph.allLicensedUsersAssignmentTarget}
    #@{id=f9e79a0d-9a46-4894-927e-5d777df34696_adadadad-808e-44e2-905a-0b7873a8a531; targetGroupId=adadadad-808e-44e2-905a-0b7873a8a531; excludeGroup=False}
    ##microsoft.graph.windowsUpdateForBusinessConfiguration
 
    if ($groupAssignments) {
    
            foreach ($grp in $groupAssignments) {
                $grp| out-file foo.txt -Append 

                if ($grp.targetGroupId) {
                    if ($grp.excludeGroup -eq "True") {
                        $assignments.ExcludedGroups += $(Get-AADGroup -id $grp.targetGroupId).displayName
                    }

                   else  {
                        $assignments.AssignedGroups += $(Get-AADGroup -id  $grp.targetgroupid).displayName

                   }
                }
               <# Device Configuration
           
               elseif ($grp.target.'@odata.type' -eq "microsoft.graph.groupAssignmentTarget"){
               
                   Log "TargetGroupID $grp.target"
                   $TargetGroup = Get-AADGroup -id $grp.target.groupid
                   $AssignedGroups += "$($TargetGroup.displayName)`r`n$(" " * 12)"
                   }
                

                elseif ( $grp.target.'@odata.type' -eq "exclusionGroupAssignmentTarget") {
                        Log "Exclued groups: $groupAssignments.target.groupId"
                        $ExcludedGroups += $(Get-AADGroup -id $groupAssignments.target.groupId).displayName
                }#>
                else {

                    Write-Host "unknown $grp"
                }
        
        
        
        }

    }


  else  { $assignments.AssignedGroups += "No assignments" }

  $assignments
}



####################################



function Prompt-InstallAzureADModule{
    $install = MsgBox -msg 'Install AzureAD PowerShell Module?'
    if ($install -eq 'Yes') {
        Log "Installing AzureAd PS Module"
        Install-Module AzureAd -Force -SkipPublisherCheck -AcceptLicense
    }
    else {
        Log "User chose not to install AzureAd module"
        exit
    }
}
###################################

Function Check-Modules {
    [bool]$isModulePresent = $false
      
    if (Get-Module -Name "AzureAD" -ListAvailable) {
        $isModulePresent = $true
        Log "AzureAD module found"
        }
    elseif (Get-Module -Name "AzureADPreview" -ListAvailable) {
        $isModulePresent = $true
        Log "AzureADPreview module found"
        }
    else {
        Log "No AzureAD module found.  Prompting for install."
        Prompt-InstallAzureADModule

    }
  
    $isModulePresent
}
###################################

Function Check-PreReqs {
    [bool]$preReqsMet = $false

    if ($MyInvocation.ScriptName -match "IntuneConfig") { $preReqsMet = $true}
    
    if ( -not (Check-Modules)) {
        $preReqsMet = $false
    }

    $preReqsMet
}
###################################

Function Export-JSONData(){

<#
.SYNOPSIS
This function is used to export JSON data returned from Graph
.DESCRIPTION
This function is used to export JSON data returned from Graph
.EXAMPLE
Export-JSONData -JSON $JSON
Export the JSON inputted on the function
.NOTES
NAME: Export-JSONData
#>

param (

$JSON,
$ExportPath 

)

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        Log "No JSON specified, please specify valid JSON..." -informationLevel "Error"
        Log "Called from $((Get-PSCallStack)[1].FunctionName):$($myinvocation.ScriptLineNumber)"  
        }

        elseif(!$ExportPath){
        $ExportPath = $pwd
       

        }

        elseif(!(Test-Path $ExportPath)){

        Log "$ExportPath doesn't exist, can't export JSON Data" -informationLevel "Error"

        }

        else {

        $JSON1 = ConvertTo-Json $JSON -Depth 5

        $JSON_Convert = $JSON1 | ConvertFrom-Json

        $displayName = $JSON_Convert.displayName

        # Updating display name to follow file naming conventions - https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247%28v=vs.85%29.aspx
        $DisplayName = $DisplayName -replace '\<|\>|:|"|/|\\|\||\?|\*', "_"

        $Properties = ($JSON_Convert | Get-Member | ? { $_.MemberType -eq "NoteProperty" }).Name

            $FileName_JSON = "$DisplayName" + "_" + $(get-date -f dd-MM-yyyy-H-mm-ss) + ".json"

            Log "Export Path: $ExportPath"

            $JSON1 | Set-Content -LiteralPath "$ExportPath\$FileName_JSON"
            Log "JSON created in $ExportPath\$FileName_JSON..." 
            
        }

    }

    catch {
        $ex =  $_.Exception
        ExceptionHandler $ex

    }

} 
###################################

Function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)
Log "Attempting to connect as $User"
$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Log "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Log "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        
        Log "AzureAD Powershell module not installed..."
        Log  "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" 
        Log "Script can't continue..." 
                
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
$resourceAppIdURI = "https://graph.microsoft.com"
$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        
        Log "Authorization Access Token is null, please re-run authentication..." -informationLevel Error
        
        break

        }

    }

    catch {

    Log $_.Exception.Message -informationLevel Error
    Log $_.Exception.ItemName -informationLevel Error
    
    break

    }

}
###################################

Function Get-ApplicationCategory(){

<#
.SYNOPSIS
This function is used to get application categories from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any application category
.EXAMPLE
Get-ApplicationCategory
Returns any application categories configured in Intune
.NOTES
NAME: Get-ApplicationCategory
#>

[cmdletbinding()]

param
(
    $Name
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileAppCategories"

    try {

        if($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $results = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $results = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }
        
        $results | Out-File -FilePath "$(($MyInvocation).InvocationName).txt" -Append -Force
        
    }

    catch {

    $ex = $_.Exception
    ExceptionHandler $ex

    }

}
###################################

Function Get-DeviceCompliancePolicy(){

<#
.SYNOPSIS
This function is used to get device compliance policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device compliance policies
.EXAMPLE
Get-DeviceCompliancePolicy
Returns any device compliance policies configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -Android
Returns any device compliance policies for Android configured in Intune
.EXAMPLE
Get-DeviceCompliancePolicy -iOS
Returns any device compliance policies for iOS configured in Intune
.NOTES
NAME: Get-DeviceCompliancePolicy
#>

[cmdletbinding()]

param
(
    [switch]$Android,
    [switch]$iOS,
    [switch]$Win10
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/deviceCompliancePolicies"
    
    try {

        $Count_Params = 0

        if($Android.IsPresent){ $Count_Params++ }
        if($iOS.IsPresent){ $Count_Params++ }
        if($Win10.IsPresent){ $Count_Params++ }

        if($Count_Params -gt 1){
        
        Log "Multiple parameters set, specify a single parameter -Android -iOS or -Win10 against the function" -informationLevel Error
        
        }
        
        elseif($Android){
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $results = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("android") }
        
        }
        
        elseif($iOS){
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $results = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("ios") }
        
        }

        elseif($Win10){
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $results = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("windows10CompliancePolicy") }
        
        }
        
        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $results = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value  

        foreach ($pol in $results) {
            $pol | Out-File -FilePath "$(($MyInvocation).InvocationName).txt" -Append -Force

            $DCPA = Get-DeviceCompliancePolicyAssignment -id $pol.id
            "Assignments for policy `"$($pol.DisplayName)`":`t" | Out-File -FilePath "$(($MyInvocation).InvocationName).txt" -Append -Force
             
            if($DCPA){
                
                
                $assignments = Parse-Assignment $DCPA 
                foreach ($assignment in $assignments.Keys) { 
                    "$assignment`:`r`n" | Out-File "$(($MyInvocation).InvocationName).txt" -Append -Force -Width 4096
                    foreach ($a in $($assignments.$assignment)) { "`t`t$a"   | Out-File "$(($MyInvocation).InvocationName).txt" -Append -Force -Width 4096 }
                    
                    
                    }
                
                }
           
        }
        

        }
    }
    
    catch {

    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

}
###################################

Function Get-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to get device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device configuration policies
.EXAMPLE
Get-DeviceConfigurationPolicy
Returns any device configuration policies configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicy
#>

[cmdletbinding()]

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"
    
    try {
    
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
    Log "Connecting to $uri" 
    $configurationPolicies = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value 
    foreach ($c in $configurationPolicies) {
        #decode base64 payload
        
        if ($c.payload) { $c.payload = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($c.payload)) }
        if ($c.startMenuLayoutXml) { $c.startMenuLayoutXML = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($c.startMenuLayoutXml)) }
        if ($c.trustedRootCertificate) { $c.trustedRootCertificate | out-file "$(($c).displayname).cer" }

        $c | Out-File -FilePath "$(($MyInvocation).InvocationName).txt" -Append -Force
        $DCPA = Get-DeviceConfigurationPolicyAssignment -id $c.id
        "Assignments for policy `"$($c.DisplayName)`":`t" | Out-File -FilePath "$(($MyInvocation).InvocationName).txt" -Append -Force
        if($DCPA){
                $assignments = Parse-Assignment $DCPA 
                                foreach ($assignment in $assignments.Keys) { 
                    "$assignment`:`r`n" | Out-File "$(($MyInvocation).InvocationName).txt" -Append -Force -Width 4096
                    foreach ($a in $($assignments.$assignment)) { "`t`t$a"  | Out-File "$(($MyInvocation).InvocationName).txt" -Append -Force -Width 4096 }
                    
                    
                    }
            }
        }

        
       
    }
    
    catch {

    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

}
###################################

Function Get-IntuneBrand(){

<#
.SYNOPSIS
This function is used to get the Company Intune Branding resources from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets the Intune Branding Resource
.EXAMPLE
Get-IntuneBrand
Returns the Company Intune Branding configured in Intune
.NOTES
NAME: Get-IntuneBrand
#>

[cmdletbinding()]

$graphApiVersion = "Beta"
$Resource = "deviceManagement/intuneBrand"

    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
    Log "Connecting to $uri" 
    $result = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
    $result | Out-File -FilePath "$(($MyInvocation).InvocationName).txt" -Append -Force 
    }
    
    catch {

    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

}
###################################

Function Get-CertificateConnector(){

<#
.SYNOPSIS
This function is used to get Certificate Connectors from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Certificate Connectors configured
.EXAMPLE
Get-CertificateConnector
Returns all Certificate Connectors configured in Intune
Get-CertificateConnector -Name "certificate_connector_3/20/2017_11:52 AM"
Returns a specific Certificate Connector by name configured in Intune
.NOTES
NAME: Get-CertificateConnector
#>

[cmdletbinding()]

param
(
    $name
)

$graphApiVersion = "beta"
$Resource = "deviceManagement/ndesconnectors"

    try {

        if($Name){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $result = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $result = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | fl *

        }
        $result | Out-File -FilePath "$(($MyInvocation).InvocationName).txt" -Append -Force 
    }

    catch {

    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

}
###################################

Function Get-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to get managed app policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app policies
.EXAMPLE
Get-ManagedAppPolicy
Returns any managed app policies configured in Intune
.NOTES
NAME: Get-ManagedAppPolicy
#>

[cmdletbinding()]

param
(
    $Name
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/managedAppPolicies"

    try {
    
        if($Name){
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $result = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'displayName').contains("$Name") }
    
        }
    
        else {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        $result = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | Where-Object { ($_.'@odata.type').contains("ManagedAppProtection") -or ($_.'@odata.type').contains("InformationProtectionPolicy") }
    
        }
    $result  
    }
    
    catch {
    
    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }
    
}
###################################

Function Get-ManagedAppProtection(){

<#
.SYNOPSIS
This function is used to get managed app protection configuration from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any managed app protection policy
.EXAMPLE
Get-ManagedAppProtection -id $id -OS "Android"
Returns a managed app protection policy for Android configured in Intune
Get-ManagedAppProtection -id $id -OS "iOS"
Returns a managed app protection policy for iOS configured in Intune
Get-ManagedAppProtection -id $id -OS "WIP_WE"
Returns a managed app protection policy for Windows 10 without enrollment configured in Intune
.NOTES
NAME: Get-ManagedAppProtection
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $id,
    [Parameter(Mandatory=$true)]
    [ValidateSet("Android","iOS","WIP_WE","WIP_MDM")]
    $OS    
)

$graphApiVersion = "Beta"

    try {
    
        if($id -eq "" -or $id -eq $null){
    
        Log "No Managed App Policy id specified, please provide a policy id..." -informationLevel "Error"
        break
    
        }
    
        else {
    
            if($OS -eq "" -or $OS -eq $null){
    
            Log "No OS parameter specified, please provide an OS. Supported value are Android,iOS,WIP_WE,WIP_MDM..." -informationLevel "Error"
            break
    
            }
    
            elseif($OS -eq "Android"){
    
            $Resource = "deviceAppManagement/androidManagedAppProtections('$id')/?`$expand=apps"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Log "Connecting to $uri" 
            $result = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get 
            $result |  Out-File "androidManagedAppProtections-$($result.displayName).txt" -Force
              
            }
    
            elseif($OS -eq "iOS"){
    
            $Resource = "deviceAppManagement/iosManagedAppProtections('$id')/?`$expand=apps"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Log "Connecting to $uri" 
            $result = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            $result |  Out-File "iosManagedAppProtections-$($result.displayName).txt"  -Force
            $result
    
            }

            elseif($OS -eq "WIP_WE"){
    
            $Resource = "deviceAppManagement/windowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Log "Connecting to $uri" 
            $result = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            $result |  Out-File "windowsInformationProtectionPolicies-$($result.displayName).txt"  -Force
            $result
    
            }

            elseif($OS -eq "WIP_MDM"){
    
            $Resource = "deviceAppManagement/mdmWindowsInformationProtectionPolicies('$id')?`$expand=protectedAppLockerFiles,exemptAppLockerFiles,assignments"
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Log "Connecting to $uri" 
            $result = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            $result |  Out-File "mdmWindowsInformationProtectionPolicies-$($result.displayName).txt"  -Force
            $result
            }
    
        }
    
    }

    catch {
    
    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

}
###################################

function Get-ManagedAppProtectionPolicies {

    $ManagedAppPolicies = Get-ManagedAppPolicy | ? { ($_.'@odata.type').contains("ManagedAppProtection") }
    $ExportPath = $pwd

    "**** $ManagedAppPolicies"

    if($ManagedAppPolicies){
        $ManagedAppPolicies | fl * | Log
        
        foreach($ManagedAppPolicy in $ManagedAppPolicies){
            
            

            if($ManagedAppPolicy.'@odata.type' -eq "#microsoft.graph.androidManagedAppProtection"){

                $AppProtectionPolicy = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS "Android"
                Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS "Android"
                $AppProtectionPolicy | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value "#microsoft.graph.androidManagedAppProtection"
                $AppProtectionPolicy | Out-File -FilePath "$(($MyInvocation).InvocationName).txt" -Append -Force
                Export-JSONData -JSON $AppProtectionPolicy -ExportPath "$ExportPath"

            }

            elseif($ManagedAppPolicy.'@odata.type' -eq "#microsoft.graph.iosManagedAppProtection"){

                $AppProtectionPolicy = Get-ManagedAppProtection -id $ManagedAppPolicy.id -OS "iOS"
                $AppProtectionPolicy | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value "#microsoft.graph.iosManagedAppProtection"
                $AppProtectionPolicy | Out-File -FilePath "$(($MyInvocation).InvocationName).txt" -Append -Force
                Log "Exporting managed app policy `"$($AppProtectionPolicy.DisplayName)`""
                Export-JSONData -JSON $AppProtectionPolicy -ExportPath "$ExportPath"

                }
            }

        }

}
###################################

Function Get-IntuneMAMApplication(){

<#
.SYNOPSIS
This function is used to get MAM applications from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any MAM applications
.EXAMPLE
Get-IntuneMAMApplication -Android
Returns any Android MAM applications configured in Intune
Get-IntuneMAMApplication -iOS
Returns any iOS MAM applications configured in Intune
Get-IntuneMAMApplication
Returns all MAM applications configured in Intune
.NOTES
NAME: Get-IntuneMAMApplication
#>

[cmdletbinding()]

param
(
[switch]$Android,
[switch]$iOS
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps"

    try {

        $Count_Params = 0

        if($Android.IsPresent){ $Count_Params++ }
        if($iOS.IsPresent){ $Count_Params++ }

        if($Count_Params -gt 1){

        Log "Multiple parameters set, specify a single parameter -Android or -iOS against the function" -informationLevel "Error"
        

        }
        
        elseif($Android){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
        Log "Connecting to $uri" 
        $result = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains("managedAndroidStoreApp") }

        }

        elseif($iOS){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
        Log "Connecting to $uri" 
        $result = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains("managedIOSStoreApp") }

        }

        else {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
        Log "Connecting to $uri" 
        $result = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value | ? { ($_.'@odata.type').Contains("managed") }

        }
        $result | Out-File "$(($MyInvocation).InvocationName).txt" -Append -Force 
    }

    catch {

    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

}
###################################

Function Get-ApplePushNotificationCertificate(){

<#
.SYNOPSIS
This function is used to get applecPushcNotificationcCertificate from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a configured apple Push Notification Certificate
.EXAMPLE
Get-ApplePushNotificationCertificate
Returns apple Push Notification Certificate configured in Intune
.NOTES
NAME: Get-ApplePushNotificationCertificate
#>

[cmdletbinding()]


$graphApiVersion = "v1.0"
$Resource = "devicemanagement/applePushNotificationCertificate"

    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Log "Connecting to $uri" 
    $result =(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get)
    
    }
    
    catch {

    $ex = $_.Exception

        if(($ex.message).contains("404")){
        
        Write-Host "Resource Not Configured" -ForegroundColor Red
        
        }

        else {

        ExceptionHandler $ex
        Continue
        }

    }
    $result | fl * | Out-File "$(($MyInvocation).InvocationName).txt" -Append -Force 
}
###################################

Function Get-DEPOnboardingSettings {

<#
.SYNOPSIS
This function retrieves the DEP onboarding settings for your tenant. DEP Onboarding settings contain information such as Token ID, which is used to sync DEP and VPP
.DESCRIPTION
The function connects to the Graph API Interface and gets a retrieves the DEP onboarding settings.
.EXAMPLE
Get-DEPOnboardingSettings
Gets all DEP Onboarding Settings for each DEP token present in the tenant
.NOTES
NAME: Get-DEPOnboardingSettings
#>

[cmdletbinding()]

Param(
[parameter(Mandatory=$false)]
[string]$tokenid
)

$graphApiVersion = "beta"

    try {

        if ($tokenid){
        
        $Resource = "deviceManagement/depOnboardingSettings/$tokenid/"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get)
                
        }

        else {
        
        $Resource = "deviceManagement/depOnboardingSettings/"
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Log "Connecting to $uri" 
        (Invoke-RestMethod -Uri $uri –Headers $authToken –Method Get).value
        
        }
               
    }
    
    catch {

    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

} 

###################################

Function Get-DeviceConfigurationPolicyAssignment(){

<#
.SYNOPSIS
This function is used to get device configuration policy assignment from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a device configuration policy assignment
.EXAMPLE
Get-DeviceConfigurationPolicyAssignment $id guid
Returns any device configuration policy assignment configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicyAssignment
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true,HelpMessage="Enter id (guid) for the Device Configuration Policy you want to check assignment")]
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"

    try {

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/groupAssignments"
    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }

    catch {

    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

}


####################################################


Function Get-DeviceCompliancePolicyAssignment(){
<#
.SYNOPSIS
This function is used to get device compliance policy assignment from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets a device configuration policy assignment
.EXAMPLE
Get-DeviceConfigurationPolicyAssignment $id guid
Returns any device configuration policy assignment configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicyAssignment
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true,HelpMessage="Enter id (guid) for the Device Configuration Policy you want to check assignment")]
    $id
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceCompliancePolicies"

    try {
    Log "Checking $id for assignments"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    }

    catch {

    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

}

####################################################

Function Get-AADGroup(){

<#
.SYNOPSIS
This function is used to get AAD Groups from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Groups registered with AAD
.EXAMPLE
Get-AADGroup
Returns all users registered with Azure AD
.NOTES
NAME: Get-AADGroup
#>

[cmdletbinding()]

param
(
    
    $id,
    $GroupName,
    [switch]$Members
)
Log "Args ========= $id,    $GroupName,$Members "
# Defining Variables
$graphApiVersion = "v1.0"
$Group_resource = "groups"
# pseudo-group identifiers for all users and all devices
[string]$AllUsers   = "acacacac-9df4-4c7d-9d50-4ef0226f57a9"
[string]$AllDevices = "adadadad-808e-44e2-905a-0b7873a8a531"
Log "__________Checking id: $id"
    try {

        if($id){
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=id eq '$id'"
        Log "checking $uri"
        switch ( $id ) {
                $AllUsers   { $grp = [PSCustomObject]@{ displayName = "All users"}; $grp           }
                $AllDevices { $grp = [PSCustomObject]@{ displayName = "All devices"}; $grp         }
                default     { (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value  }
                }
                
        }

        elseif($GroupName -eq "" -or $GroupName -eq $null){

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)"
        (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }

        else {

            if(!$Members){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

            }

            elseif($Members){

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
            $Group = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                if($Group){

                $GID = $Group.id

                $Group.displayName
                

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

                }

            }

        }

    }

    catch {

    $ex = $_.Exception
    ExceptionHandler $ex
    Continue
    }

}


####################################################

Function Get-SoftwareUpdatePolicy(){

<#
.SYNOPSIS
This function is used to get Software Update policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any Software Update policies
.EXAMPLE
Get-SoftwareUpdatePolicy -Windows10
Returns Windows 10 Software Update policies configured in Intune
.EXAMPLE
Get-SoftwareUpdatePolicy -iOS
Returns iOS update policies configured in Intune
.NOTES
NAME: Get-SoftwareUpdatePolicy
#>

[cmdletbinding()]

param
(
    [switch]$Windows10,
    [switch]$iOS
)

$graphApiVersion = "Beta"
$result = ""
    try {

        $Count_Params = 0

        if($iOS.IsPresent){ $Count_Params++ }
        if($Windows10.IsPresent){ $Count_Params++ }

        if($Count_Params -gt 1){
                Log  "Multiple parameters set, specify a single parameter -iOS or -Windows10 against the function" -informationLevel "Error"
        }

        elseif($Count_Params -eq 0){
                Write-Host "Parameter -iOS or -Windows10 required against the function..." -ForegroundColor Red
                break

        }

        elseif($Windows10){

            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$expand=groupAssignments"

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            $result = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).value

        }

        elseif($iOS){

            $Resource = "deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.iosUpdateConfiguration')&`$expand=groupAssignments"

            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            $result = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value

        }
        $result | Out-File "$(($MyInvocation).InvocationName).txt" -Append -Force        
        $assignments = Parse-Assignment $result.groupAssignments 
                        foreach ($assignment in $assignments.Keys) { 
                    "$assignment`:`r`n" | Out-File "$(($MyInvocation).InvocationName).txt" -Append -Force -Width 4096
                    foreach ($a in $($assignments.$assignment)) { "`t`t$a" | Out-File "$(($MyInvocation).InvocationName).txt" -Append -Force -Width 4096 }
                    
                    
                    }
    }

    catch {

        $ex = $_.Exception
        if ($ex) { ExceptionHandler $ex }
        Continue
    }

}



###################################
# Region Main

 "mhi@markstanhi.onmicrosoft.com" | clip

if ( Check-PreReqs -and Check-Modules) {
    $global:authToken = Get-AuthToken
  <#  Get-ApplicationCategory
    #>
    #Get-DeviceCompliancePolicy 
    Get-DeviceConfigurationPolicy
    
    <#
    Get-IntuneBrand
    Get-CertificateConnector
    
    Get-ManagedAppPolicy | Out-File Get-ManagedAppPolicy.txt -Force
    Get-ManagedAppProtectionPolicies | Out-File Get-ManagedAppProtectionPolicies.txt -Force
    Get-IntuneMAMApplication
 
    Get-SoftwareUpdatePolicy -iOS
    Get-SoftwareUpdatePolicy -Windows10
    
    Get-ApplePushNotificationCertificate
    Get-DEPOnboardingSettings
    #>
    }

 