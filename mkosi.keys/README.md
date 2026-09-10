# Local trust material

Trust inputs are stored here:

- `uefi-db/openSUSE_Secure_Boot_CA_2013.crt`: the public openSUSE Secure
  Boot CA enrolled in U-Boot's UEFI `db`. This trusts EFI binaries
  signed by openSUSE, including updated systemd-boot binaries.
- `uefi-db/*.crt`: additional PEM or DER certificates appended to `db`.
- `uefi-dbx/*.esl`: maintained EFI signature lists appended to `dbx`.
- `rpi-boot/private.pem`: the Raspberry Pi owner key. If
  `rpi-eeprom-digest` is available, the build uses it to create `boot.sig`.

The first-test UKI key is generated under `.mkosi-private/`, is valid for 30
days, and is not included in the image.
