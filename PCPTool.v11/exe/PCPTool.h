/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    PCPTool.h

Abstract:

    Definitions, types and prototypes for PCPTool.

--*/

#define EV_PREBOOT_CERT (0x00000000)
#define EV_POST_CODE (0x00000001)
#define EV_UNUSED (0x00000002)
#define EV_NO_ACTION (0x00000003)
#define EV_SEPARATOR (0x00000004)
#define EV_ACTION (0x00000005)
#define EV_EVENT_TAG (0x00000006)
#define EV_S_CRTM_CONTENTS (0x00000007)
#define EV_S_CRTM_VERSION (0x00000008)
#define EV_CPU_MICROCODE (0x00000009)
#define EV_PLATFORM_CONFIG_FLAGS (0x0000000A)
#define EV_TABLE_OF_DEVICES (0x0000000B)
#define EV_COMPACT_HASH (0x0000000C)
#define EV_IPL (0x0000000D)
#define EV_IPL_PARTITION_DATA (0x0000000E)
#define EV_NONHOST_CODE (0x0000000F)
#define EV_NONHOST_CONFIG (0x00000010)
#define EV_NONHOST_INFO (0x00000011)
#define EV_EFI_EVENT_BASE (0x80000000)
#define EV_EFI_VARIABLE_DRIVER_CONFIG (0x80000001)
#define EV_EFI_VARIABLE_BOOT (0x80000002)
#define EV_EFI_BOOT_SERVICES_APPLICATION (0x80000003)
#define EV_EFI_BOOT_SERVICES_DRIVER (0x80000004)
#define EV_EFI_RUNTIME_SERVICES_DRIVER (0x80000005)
#define EV_EFI_GPT_EVENT (0x80000006)
#define EV_EFI_ACTION (0x80000007)
#define EV_EFI_PLATFORM_FIRMWARE_BLOB (0x80000008)
#define EV_EFI_HANDOFF_TABLES (0x80000009)

typedef struct {
    UINT32 Id;
    WCHAR* Name;
} EVENT_TYPE_DATA;

// Support.cpp

void
PcpToolLevelPrefix(
    UINT32 level
    );

void
PcpToolPrintBufferAsRawBytes(
    _In_reads_bytes_(cbBuffer) PBYTE pbBuffer,
    UINT32 cbBuffer);

HRESULT
PcpToolDisplaySIPAVsmIdkInfo(
    _In_reads_bytes_(cbSipaEventData) PBYTE pbSipaData,
    UINT32 cbSipaEventData,
    UINT32 level
    );

HRESULT
PcpToolDisplaySIPASIPolicy(
    _In_reads_bytes_(cbSipaEventData) PBYTE pbSipaData,
    UINT32 cbSipaEventData,
    UINT32 level
    );

HRESULT
PcpToolDisplaySIPA(
    _In_reads_opt_(cbWBCL) PBYTE pbWBCL,
    UINT32 cbWBCL,
    UINT32 level
    );

HRESULT
PcpToolDisplayLog(
    _In_reads_opt_(cbWBCL) PBYTE pbWBCL,
    UINT32 cbWBCL,
    UINT32 level
    );

HRESULT
PcpToolDisplayKey(
    _In_ PCWSTR lpKeyName,
    _In_reads_(cbKey) PBYTE pbKey,
    DWORD cbKey,
    UINT32 level
    );

HRESULT
PcpToolDisplayKeyBlob(
    _In_ PCWSTR lpKeyName,
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    DWORD cbKeyBlob,
    UINT32 level
    );

HRESULT
PcpToolDisplayPlatformAttestation(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    DWORD cbAttestation,
    UINT32 level
    );

HRESULT
PcpToolDisplayKeyAttestation(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    DWORD cbAttestation,
    UINT32 level
    );

HRESULT
PcpToolWriteFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData
    );

HRESULT
PcpToolAppendFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData
    );

HRESULT
PcpToolReadFile(
    _In_ PCWSTR lpFileName,
    _In_reads_opt_(cbData) PBYTE pbData,
    UINT32 cbData,
    _Out_ PUINT32 pcbData
    );

HRESULT
PcpToolReadFile(
    _In_ PCWSTR lpFileName,
    UINT32 offset,
    _In_reads_(cbData) PBYTE pbData,
    UINT32 cbData
    );

void
PcpToolCallResult(
    _In_ WCHAR* func,
    HRESULT hr
    );

// SDKSample.cpp

HRESULT
GetCACertContext(
    _In_reads_z_(MAX_PATH) LPWSTR szUserStore,
    _Out_ PCCERT_CONTEXT* ppCaCert
    );

#define ISSUECERTIFICATE_EKCERT      0x00000001
HRESULT
IssueCertificate(
    PCCERT_CONTEXT pCaCert,
    _In_reads_z_(MAX_PATH) LPWSTR szSubject,
    NCRYPT_KEY_HANDLE hSubjectKeyPub,
    ULONGLONG serialNumber,
    SYSTEMTIME validityPeriod,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult,
    DWORD dwFlags);

HRESULT
ProtectData(
    BOOLEAN tEncrypt,
    _In_reads_(cbSymKey) PBYTE pbSymKey,
    UINT32 cbSymKey,
    _Inout_updates_bytes_(cbData) PBYTE pbData,
    UINT32 cbData
    );

HRESULT
PcpToolGetVersion(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetEK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetEKCert(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetNVEKCert(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolAddEKCert(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolExtractEK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetRandom(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetRandomPcrs(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetSRK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetLog(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolDecodeLog(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolCreateAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolCreateKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetUserCertStore(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolChallengeAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolActivateAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolRegisterAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolEnumerateAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolEnumerateKeys(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolChangeKeyUsageAuth(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolImportKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolExportKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolDeleteKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
);

HRESULT
PcpToolDeleteKeys(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
);

HRESULT
PcpToolGetPubKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetPubAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolDisplayPlatformAttestationFile(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetPlatformAttestation(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetPlatformCounters(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetPCRs(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetArchivedLog(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolValidatePlatformAttestation(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolCreatePlatformAttestationFromLog(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetKeyAttestation(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetKeyAttestationFromKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolValidateKeyAttestation(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetKeyProperties(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolEncrypt(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolDecrypt(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolWrapPlatformKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolImportPlatformKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolGetVscKeyAttestationFromKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolIssueEkCert(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

HRESULT
PcpToolPrivacyCaChallenge(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

    HRESULT
PcpToolPrivacyCaActivate(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    );

// PCPTool.cpp

void
PcpToolGetHelp(
    );

