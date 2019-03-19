# PSAlert

A small bash utility that scans for occurances of suspicious string signatures within a powershell script. Based on the list used within [powershell.exe](https://github.com/PowerShell/PowerShell/blob/759c4abde811aff1490dec92e438d61e341c3181/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs#L1654).

## Examples

```shell
bash PSAlert.sh -s Invoke-Mimikatz.ps1
```