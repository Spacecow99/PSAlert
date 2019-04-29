
Function Find-SuspiciousString()
{
<#

.SYNOPSIS
    A small utility that scans for occurances of suspicious string signatures within a powershell script. Based on the list used within powershell.exe

.DESCRIPTION
    A small utility that scans for occurances of suspicious string signatures within a powershell script. Based on the list used within powershell.exe.
    String scanning will fail if the string is split or obfuscated meaning scans should be done on an unobfuscated copy for maximum efficiency.

.PARAMETER Path
    Path to the powershell script file to scan.

.EXAMPLE
    Find-SuspiciousString -Path "Invoke-Payload.ps1"

.LINK
    https://github.com/Spacecow99/PSAlert
    https://github.com/PowerShell/PowerShell/blob/759c4abde811aff1490dec92e438d61e341c3181/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs#L1654

.NOTES
    Lack of suspicious strings does not mean that there will be no powershell log entries.

#>

    Param(
        [Parameter(Mandatory=$True, Position=0)]
        [String] $Path
    )

    $Signatures=@(
        # Calling Add-Type
        "Add-Type"
        "DllImport"

        # Doing dynamic assembly building / method indirection
        "DefineDynamicAssembly"
        "DefineDynamicModule"
        "DefineType"
        "DefineConstructor"
        "CreateType"
        "DefineLiteral"
        "DefineEnum"
        "DefineField"
        "ILGenerator"
        "Emit"
        "UnverifiableCodeAttribute"
        "DefinePInvokeMethod"
        "GetTypes"
        "GetAssemblies"
        "Methods"
        "Properties"

        # Suspicious methods / properties on "Type"
        "GetConstructor"
        "GetConstructors"
        "GetDefaultMembers"
        "GetEvent"
        "GetEvents"
        "GetField"
        "GetFields"
        "GetInterface"
        "GetInterfaceMap"
        "GetInterfaces"
        "GetMember"
        "GetMembers"
        "GetMethod"
        "GetMethods"
        "GetNestedType"
        "GetNestedTypes"
        "GetProperties"
        "GetProperty"
        "InvokeMember"
        "MakeArrayType"
        "MakeByRefType"
        "MakeGenericType"
        "MakePointerType"
        "DeclaringMethod"
        "DeclaringType"
        "ReflectedType"
        "TypeHandle"
        "TypeInitializer"
        "UnderlyingSystemType"

        # Doing things with System.Runtime.InteropServices
        "InteropServices"
        "Marshal"
        "AllocHGlobal"
        "PtrToStructure"
        "StructureToPtr"
        "FreeHGlobal"
        "IntPtr"

        # General Obfuscation
        "MemoryStream"
        "DeflateStream"
        "FromBase64String"
        "EncodedCommand"
        "Bypass"
        "ToBase64String"
        "ExpandString"
        "GetPowerShell"

        # Suspicious Win32 API calls
        "OpenProcess"
        "VirtualAlloc"
        "VirtualFree"
        "WriteProcessMemory"
        "CreateUserThread"
        "CloseHandle"
        "GetDelegateForFunctionPointer"
        "kernel32"
        "CreateThread"
        "memcpy"
        "LoadLibrary"
        "GetModuleHandle"
        "GetProcAddress"
        "VirtualProtect"
        "FreeLibrary"
        "ReadProcessMemory"
        "CreateRemoteThread"
        "AdjustTokenPrivileges"
        "WriteByte"
        "WriteInt32"
        "OpenThreadToken"
        "PtrToString"
        "FreeHGlobal"
        "ZeroFreeGlobalAllocUnicode"
        "OpenProcessToken"
        "GetTokenInformation"
        "SetThreadToken"
        "ImpersonateLoggedOnUser"
        "RevertToSelf"
        "GetLogonSessionData"
        "CreateProcessWithToken"
        "DuplicateTokenEx"
        "OpenWindowStation"
        "OpenDesktop"
        "MiniDumpWriteDump"
        "AddSecurityPackage"
        "EnumerateSecurityPackages"
        "GetProcessHandle"
        "DangerousGetHandle"

        # Crypto - ransomware, etc.
        "CryptoServiceProvider"
        "Cryptography"
        "RijndaelManaged"
        "SHA1Managed"
        "CryptoStream"
        "CreateEncryptor"
        "CreateDecryptor"
        "TransformFinalBlock"
        "DeviceIoControl"
        "SetInformationProcess"
        "PasswordDeriveBytes"

        # Keylogging
        "GetAsyncKeyState"
        "GetKeyboardState"
        "GetForegroundWindow"

        # Using internal types
        "BindingFlags"
        "NonPublic"

        # Changing logging settings
        "ScriptBlockLogging"
        "LogPipelineExecutionDetails"
        "ProtectedEventLogging"
    )

    ForEach ($Entry in $Signatures)
    {
        $Caught = Select-String -Path $Path -Pattern "$Entry"
        If ($Caught.Length -gt 0)
        {
            Write-Out ("`n[+] Signature: {0}" -f $Entry)
            ForEach ($Line in $Caught)
            {
                Write-Out $Line
            }
        }
    }
}