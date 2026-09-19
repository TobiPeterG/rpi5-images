# Keep interactive systemd-sysext/systemd-confext commands consistent with
# the corresponding system services.
export SYSTEMD_SYSEXT_HIERARCHIES=/usr:/opt:/var
export SYSTEMD_SYSEXT_MUTABLE_MODE=yes
export SYSTEMD_CONFEXT_MUTABLE_MODE=yes
