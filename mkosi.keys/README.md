# Local trust material

Trust inputs are stored here:

- `uefi-db/openSUSE_Secure_Boot_CA_2013.crt`: the public openSUSE Secure
  Boot CA enrolled in U-Boot's UEFI `db`. This trusts EFI binaries
  signed by openSUSE, including updated systemd-boot binaries.
- `obs-project.crt`: public certificate of the OBS project. In OBS, the
  injected `_projectcert.crt` takes precedence so certificate rotations are
  picked up automatically. The checked-in copy permits local construction of
  the U-Boot variable payloads
- `obs-project.pgp.b64`: binary OpenPGP public key encoded as base64 for the
  immutable `/usr/lib/systemd/import-pubring.pgp`. It authenticates the OBS
  `SHA256SUMS.gpg` manifest used by `systemd-sysupdate`.
- `uefi-db/*.crt`: additional PEM or DER certificates appended to `db`.
- `uefi-dbx/*.esl`: maintained EFI signature lists appended to `dbx`.
- `rpi-boot/private.pem`: the Raspberry Pi owner key. If
  `rpi-eeprom-digest` is available, the build uses it to create `boot.sig`.

UKIs, EFI bootloaders and dm-verity root hashes are submitted to the OBS
signing service by the `mkosi-obs` integration.