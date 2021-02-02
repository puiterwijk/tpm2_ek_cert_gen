# tpm2_ek_cert_gen

This tool will create an Endorsement Key Certificate for a TPM2.
Use in case your TPM's vendor decided to be lazy (or non-helpful?) and not insert a EK certificate into your TPM.

## Inserting into the TPM, the manual way

`openssl x509 -in - -inform pem -out ek.der -outform der`
<paste the printed EK PEM>

`stat ek.der`
<grab the "size" field>

`tpm2_nvdefine -C o -s <size> 0x0100002`

`tpm2_nvwrite -i ek.der -C o 0x0100002`

`tpm2_nvread 0x0100002 | openssl x509 -in - -inform der -noout -text`
