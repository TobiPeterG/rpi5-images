# Keep interactive systemd-sysext/systemd-confext commands consistent with
# the corresponding system services.
if [ -r /etc/extkit/extension-environment ]; then
    . /etc/extkit/extension-environment
    export SYSTEMD_SYSEXT_HIERARCHIES
    export SYSTEMD_ALLOW_USERSPACE_VERITY
    export SYSTEMD_DISSECT_VERITY_SIGNATURE
    export SYSTEMD_DISSECT_VERITY_SIDECAR
fi
