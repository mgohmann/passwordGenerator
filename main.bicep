targetScope = 'resourceGroup'

// create a new 24 character password and strore it in the keyVault
module pwGenMod 'deploymentScript_store.bicep' = {
  name: 'pwGen'
  params: {
    secretName: guid('someResourceId')
    vaultName: '/subscriptions/<subId>/resourceGroups/pwdgenerator-001/providers/Microsoft.KeyVault/vaults/<vaultId>'
    length: 24
  }
}
