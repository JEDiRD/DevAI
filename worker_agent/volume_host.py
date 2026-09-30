"""SYSTEM helper mounts one fixed managed VHDX; never follows Controller input."""
import os
from pathlib import Path
import subprocess
from .windows_security import no_reparse
from .workspace import WorkspaceManager


def attach_workspace_volume(config):
    state=Path(os.environ['ProgramData'])/'DevAIWorker'
    vhd=state/'volumes'/'workspace.vhdx'
    no_reparse(vhd)
    manager_args={'volume_guid':config['volume_guid']}
    try:
        WorkspaceManager(state/'workspace-volume',config['service_sid'],**manager_args)
        return
    except Exception:
        pass  # Mount missing after reboot; only this pinned file may be attached.
    commands=state/'volumes'/'attach.txt'
    no_reparse(commands)
    expected=f'select vdisk file="{vhd}"\nattach vdisk\nexit\n'
    if commands.read_text()!=expected:
        raise RuntimeError('UNSAFE_VOLUME_ATTACH_CONFIG')
    result=subprocess.run([str(Path(os.environ['SystemRoot'])/'System32'/'diskpart.exe'),'/s',str(commands)],capture_output=True,timeout=30)
    if result.returncode:
        raise RuntimeError('WORKSPACE_VOLUME_ATTACH_FAILED')
    # Never format, repartition, select a system disk, or accept a new volume GUID.
    WorkspaceManager(state/'workspace-volume',config['service_sid'],**manager_args)
