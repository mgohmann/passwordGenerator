targetScope = 'resourceGroup'

@description('Required. Key Vault name.')
param vaultName string

@secure()
@description('Required. Secret name.')
param secretName string

@description('Required. Password length from 16 to 128 characters.')
@minValue(16)
@maxValue(128)
param length int

@description('Optional. Used to customize the special characters when a particular service/system cannot use certain special characters. Default special characters are: "!#$%&()*+,-./<=>?@[]^_"')
param specialCharSet string = '!#$%&()*+,-./<=>?@[]^_'

@description('Optional. Set whether every character type (uppercase, lowercase, numbers, and special characters) is required.')
param mustUseEveryCharType bool = true

@description('Optional. Leave blank. Used to force the deployment script to run on demand.')
param timestamp string = utcNow()

resource pwsh 'Microsoft.Resources/deploymentScripts@2020-10-01' = {
  name: 'pwsh'
  #disable-next-line no-loc-expr-outside-params
  location: resourceGroup().location
  kind: 'AzurePowerShell'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      // To Do: Add identity reference here.
    }
  }
  properties: {
    azPowerShellVersion: '7.2'
    retentionInterval: 'PT3M' // deploymentScript resource will delete itself in 3 min
    timeout: 'PT2M' // timeout in 2 min
    forceUpdateTag: timestamp // script will run every time
    cleanupPreference: 'Always'
    arguments: '-length ${length} -specialCharSet ${specialCharSet} -vaultName ${vaultName} -keyName ${secretName} -mustUseEveryCharType ${mustUseEveryCharType}'
    scriptContent: '''
    param ([ValidateRange(16, 128)][int]$length = 30, [bool]$mustUseEveryCharType = $true, [string]$specialCharSet = '!#$%&()*+,-./<=>?@[]^_', [string]$vaultName, [string]$keyName)
    [string]$charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' + $specialCharSet
    Function getRndNum ($range) {
        [Byte[]] $bytes = 1..4  #4 byte array for int32/uint32
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rng.getbytes($bytes)
        $number = [System.BitConverter]::ToUInt32(($bytes), 0)
        $number = $number % ($range - 1)
        return $number
    }
    if ($mustUseEveryCharType -eq $false) { for ($i = 0; $i -lt $length; $i++) { $password += $charSet[(getRndNum $range)] } }
    else {
        do {
            [string]$password = ''; [bool]$lower = $false; [bool]$upper = $false; [bool]$num = $false; [bool]$special = $false
            if ($specialCharSet.Length -gt 0) { [int]$range = ($charSet.Length - 1) }
            else { [int]$range = 61; [bool]$special = $true }
            for ($i = 0; $i -lt $length; $i++) {
                $rndNum = getRndNum $range
                if ($rndNum -lt 26) { $lower = $true }
                if ($rndNum -ge 26 -and $rndNum -lt 52) { $upper = $true }
                if ($rndNum -ge 52 -and $rndNum -lt 62) { $num = $true }
                if ($rndNum -ge 62) { $special = $true }
                $password += $charSet[$rndNum]
            }
        } until ($false -notin @($lower, $upper, $num, $special))
    }
    $secureString = ConvertTo-SecureString -String $password -AsPlainText -Force
    $password = $null
    Set-AzKeyVaultSecret -VaultName $vaultName -Name $keyName -SecretValue $secureString
    '''
  }
}
