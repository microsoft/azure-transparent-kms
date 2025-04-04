# Deploy to mCCF using AKV member key
## Get service cert
```


//mCCF
export KEYS_DIR=vol
export CCF_NAME=accconfinferencedebug
export KMS_URL=https://${CCF_NAME}.confidential-ledger.azure.com
export identityurl=https://identity.confidential-ledger.core.azure.com/ledgerIdentity/${CCF_NAME}
curl $identityurl | jq ' .ledgerTlsCertificate' | xargs echo -e > $KEYS_DIR/service_cert.pem

//ACL
export KEYS_DIR=vol
export KMS_URL=https://accconfinferenceprepod.confidential-ledger.azure.com
export identityurl=https://identity.confidential-ledger.core.azure.com/ledgerIdentity/accconfinferenceprepod
curl $identityurl | jq ' .ledgerTlsCertificate' | xargs echo -e > $KEYS_DIR/service_cert.pem
```


## Login to azure
```
sudo apt-get update
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login
```

## Set AKV env variables
```
export AKV_VAULT_NAME="mccfconfinference"
export AKV_CERTIFICATE_NAME="mCCFConfInferenceIdentityCert"
export AKV_CERTIFICATE_VERSION="16d1f5c48143457fb1f16d4196a78f8c"
export AKV_KID="https://$AKV_VAULT_NAME.vault.azure.net/certificates/$AKV_CERTIFICATE_NAME/$AKV_CERTIFICATE_VERSION"


export AKV_KID="https://mccfconfinference.vault.azure.net/certificates/mCCFConfInferenceIdentityCert/16d1f5c48143457fb1f16d4196a78f8c"
export TOKEN=$(az account get-access-token --resource=https://vault.azure.net --query accessToken -o tsv)
export AKV_AUTHORIZATION="Bearer $TOKEN"
```


## Retrieve the certificate from AKV
```
az keyvault certificate download --vault-name $AKV_VAULT_NAME --name $AKV_CERTIFICATE_NAME --file $KEYS_DIR/${AKV_CERTIFICATE_NAME}_cert.pem --encoding PEM
```
## Retrieve all members of KMS
```
curl $KMS_URL/gov/members --cacert $KEYS_DIR/service_cert.pem | jq
```

## Deploy
```
make deploy
```


## Set custom constitution
```
make set-constitution-maa
```

<!-- ## Propose and vote new key release policy, settings, jwt policy and create first key
```
make setup-mCCF -->
```
# List public keys
```
curl ${KMS_URL}/app/listpubkeys  --cacert $KEYS_DIR/service_cert.pem  -H "Content-Type: application/json" -i  -w '\n'
```
# Show key release policy
```
export MAA=""
export AUTHORIZATION="Bearer $MAA"
curl ${KMS_URL}/app/keyReleasePolicy --cacert ${KEYS_DIR}/service_cert.pem -H "Authorization:$AUTHORIZATION" -H "Content-Type: application/json" -w '\n' | jq
AUTHORIZATION: Managed identity supported by KMS JWT policy