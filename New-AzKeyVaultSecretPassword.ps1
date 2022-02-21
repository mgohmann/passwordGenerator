function New-kvPassword ([ValidateRange(16,128)][int]$length = 30, [bool]$mustUseEveryCharType = $true, [string]$specialCharSet = '!#$%&()*+,-./<=>?@[]^_',[string]$vaultName,[string]$keyName) {
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
}