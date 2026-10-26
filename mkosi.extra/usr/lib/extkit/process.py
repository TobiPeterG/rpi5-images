"""Subprocess adapter."""

import subprocess


def run(command, *, executor=None, **options):
    return (subprocess.run if executor is None else executor)(command, **options)
