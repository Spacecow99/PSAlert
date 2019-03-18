#!/bin/bash
#
#  Author: Spacecow
#  Date: 23/04/2017
#  Description:
#   A small utility that scans for occurances of suspicious string signatures
#   within a powershell script. Based on the list used within powershell.exe
#

function main() {
    local SCRIPT
    while getopts 'hs:' OPT; do
        case ${OPT} in
            h)
                printf "${0} [-h] -s <FILE>\n"
                printf "\t-s: Path to powershell script.\n"
                exit 0
                ;;
            s)
                if [[ -f "${OPTARG}" ]]; then
                    SCRIPT="${OPTARG}"
                fi
                ;;
        esac
    done

    if [[ -z ${SCRIPT} ]]; then
        printf "Must provide a script using '-s <script.ps1>'\n" 1>&2
        exit 1
    fi

    local SIGNATURES=(
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

    for ENTRY in "${SIGNATURES[@]}"; do
        local CAUGHT=$(grep -n "${ENTRY}" "${SCRIPT}")
        if [[ -n ${CAUGHT} ]]; then
            echo -e "\n[+] Signature: ${ENTRY}"
            for LINE in "${CAUGHT}"; do
                echo -e "${LINE}"
            done
        fi
    done
}


main ${@}
