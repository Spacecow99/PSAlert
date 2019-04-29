# PSAlert

A small bash utility that scans for occurances of suspicious string signatures within a powershell script. Based on the list used within [powershell.exe](https://github.com/PowerShell/PowerShell/blob/759c4abde811aff1490dec92e438d61e341c3181/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs#L1654). String scanning will fail if the string is split or obfuscated meaning scans should be done on an unobfuscated copy for maximum efficiency. Lack of suspicious strings does not mean that there will be no powershell log entries.

## Examples

### PSAlert.sh

```shell
bash PSAlert.sh -s Invoke-Mimikatz.ps1
```

### Find-SuspiciousString.ps1

```powershell
Find-SuspiciousString -Path "Invoke-Payload.ps1"
```