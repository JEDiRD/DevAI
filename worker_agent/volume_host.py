"""SYSTEM helper mounts one fixed managed VHDX; never follows Controller input."""
import os
import base64
from pathlib import Path
import subprocess
from .windows_security import no_reparse
from .workspace import WorkspaceManager


def attach_workspace_volume(config):
    state=Path(os.environ['ProgramData'])/'DevAIWorker'
    vhd=state/'volumes'/'workspace.vhdx'
    no_reparse(vhd)
    commands=state/'volumes'/'attach.txt'
    no_reparse(commands)
    expected=f'select vdisk file="{vhd}"\nattach vdisk\nexit\n'
    if commands.read_text()!=expected:
        raise RuntimeError('UNSAFE_VOLUME_ATTACH_CONFIG')
    # Keep validating the original administrator-owned attach description for
    # compatibility, but never execute DiskPart. Mount only the fixed image,
    # suppressing letters without changing global automount settings.
    script=r'''
$ErrorActionPreference='Stop'
$env:PSModulePath=Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/Modules'
$path=Join-Path $env:ProgramData 'DevAIWorker/volumes/workspace.vhdx'
$image=Get-DiskImage -ImagePath $path
if (!$image.Attached) {$image=Mount-DiskImage -ImagePath $path -NoDriveLetter -PassThru}
$disks=@($image | Get-Disk)
if ($disks.Count -ne 1) {exit 11}
$disk=$disks[0]
if ($disk.IsBoot -or $disk.IsSystem -or $disk.Size -ne 134217728 -or
    ([string]$disk.BusType).Replace(' ','') -ne 'FileBackedVirtual' -or $disk.Location -ne $path) {exit 12}
foreach($partition in Get-Partition -DiskNumber $disk.Number) {
  if ([int][char]$partition.DriveLetter -ne 0) {exit 13}
}
'''
    encoded=base64.b64encode(script.encode('utf-16-le')).decode()
    powershell=Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe'
    result=subprocess.run([str(powershell),'-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,timeout=30)
    if result.returncode:
        raise RuntimeError('WORKSPACE_VOLUME_ATTACH_FAILED')
    # Never format, repartition, select a system disk, or accept a new volume GUID.
    WorkspaceManager(state/'workspace-volume',config['service_sid'],volume_guid=config['volume_guid'])
