/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    TpmAtt.h

Abstract:

    Definitions, types and prototypes for TpmAtt.dll.

--*/

#ifdef _MSC_VER
#pragma once
#endif

#ifndef TPMATT_H
#define TPMATT_H

#define DllExport __declspec(dllexport)

// Platform attestation properties
#define PCP_ATTESTATION_PROPERTIES_CONTAINS_BOOT_COUNT (0x00000001)
#define PCP_ATTESTATION_PROPERTIES_CONTAINS_EVENT_COUNT (0x00000002)
#define PCP_ATTESTATION_PROPERTIES_EVENT_COUNT_NON_CONTIGUOUS (0x00000004)
#define PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED (0x00000008)
#define PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_WINLOAD (0x00000010)
#define PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_WINRESUME (0x00000020)
#define PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_OTHER (0x00000040)
#define PCP_ATTESTATION_PROPERTIES_BOOT_DEBUG_ON (0x00000100)
#define PCP_ATTESTATION_PROPERTIES_OS_DEBUG_ON (0x00000200)
#define PCP_ATTESTATION_PROPERTIES_CODEINTEGRITY_OFF (0x00000400)
#define PCP_ATTESTATION_PROPERTIES_TESTSIGNING_ON (0x00000800)
#define PCP_ATTESTATION_PROPERTIES_BITLOCKER_UNLOCK (0x00001000)
#define PCP_ATTESTATION_PROPERTIES_OS_SAFEMODE (0x00002000)
#define PCP_ATTESTATION_PROPERTIES_OS_WINPE (0x00004000)
#define PCP_ATTESTATION_PROPERTIES_OS_HV (0x00008000)

// Key attestation properties
#define PCP_KEY_PROPERTIES_NON_MIGRATABLE (0x80000000)
#define PCP_KEY_PROPERTIES_PIN_PROTECTED (0x40000000)
#define PCP_KEY_PROPERTIES_PCR_PROTECTED (0x20000000)
#define PCP_KEY_PROPERTIES_SIGNATURE_KEY (0x00000001)
#define PCP_KEY_PROPERTIES_ENCRYPTION_KEY (0x00000002)
#define PCP_KEY_PROPERTIES_GENERIC_KEY (0x00000003)
#define PCP_KEY_PROPERTIES_STORAGE_KEY (0x00000004)
#define PCP_KEY_PROPERTIES_IDENTITY_KEY (0x00000005)

typedef enum PCP_KEY_FLAGS_WIN8 {
    PCP_KEY_FLAGS_WIN8_authRequired = 0x00000001
} PCP_KEY_FLAGS_WIN8;

typedef enum PCP_KEY_FLAGS {
    PCP_KEY_FLAGS_authRequired = 0x00000001
} PCP_KEY_FLAGS;

#define BCRYPT_PCP_KEY_MAGIC 'MPCP' // Platform Crypto Provider Magic

#define PCPTYPE_TPM12 (0x00000001)
#define PCPTYPE_TPM20 (0x00000002)

// SHA related constants
#ifndef SHA1_DIGEST_SIZE
#define SHA1_DIGEST_SIZE   (20)
#endif
#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE (32)
#endif
#ifndef MAX_DIGEST_SIZE
#define MAX_DIGEST_SIZE    (64)
#endif

#ifndef TPM_API_ALG_ID_SHA1
#define TPM_API_ALG_ID_SHA1         ((UINT16)0x0004)
#endif
#ifndef TPM_API_ALG_ID_SHA256
#define TPM_API_ALG_ID_SHA256       ((UINT16)0x000B)
#endif
#ifndef TPM_API_ALG_ID_SHA384
#define TPM_API_ALG_ID_SHA384       ((UINT16)0x000C)
#endif

typedef struct PCP_KEY_BLOB_WIN8 // Storage structure for 2.0 keys
{
    DWORD   magic;
    DWORD   cbHeader;
    DWORD   pcpType;
    DWORD   flags;
    ULONG   cbPublic;
    ULONG   cbPrivate;
    ULONG   cbMigrationPublic;
    ULONG   cbMigrationPrivate;
    ULONG   cbPolicyDigestList;
    ULONG   cbPCRBinding;
    ULONG   cbPCRDigest;
    ULONG   cbEncryptedSecret;
    ULONG   cbTpm12HostageBlob;
} PCP_KEY_BLOB_WIN8, *PPCP_KEY_BLOB_WIN8;

typedef struct PCP_20_KEY_BLOB // Storage structure for 2.0 keys
{
    DWORD   magic;
    DWORD   cbHeader;
    DWORD   pcpType;
    DWORD   flags;
    ULONG   cbPublic;
    ULONG   cbPrivate; 
    ULONG   cbMigrationPublic;
    ULONG   cbMigrationPrivate;
    ULONG   cbPolicyDigestList;
    ULONG   cbPCRBinding;
    ULONG   cbPCRDigest;
    ULONG   cbEncryptedSecret;
    ULONG   cbTpm12HostageBlob;
    USHORT  pcrAlgId;
} PCP_20_KEY_BLOB, *PPCP_20_KEY_BLOB;

typedef struct PCP_KEY_BLOB
{
    DWORD   magic;
    DWORD   cbHeader;
    DWORD   pcpType;
    DWORD   flags;
    ULONG   cbTpmKey;
} PCP_KEY_BLOB, *PPCP_KEY_BLOB;

#define PCP_PLATFORM_ATTESTATION_MAGIC 'SDAP' // Platform Attestation Data Structure
typedef struct _PCP_PLATFORM_ATTESTATION_BLOB {
    ULONG Magic;
    ULONG Platform;
    ULONG HeaderSize;
    ULONG cbPcrValues;
    ULONG cbQuote;
    ULONG cbSignature;
    ULONG cbLog;
} PCP_PLATFORM_ATTESTATION_BLOB, *PPCP_PLATFORM_ATTESTATION_BLOB;

#define PCP_PLATFORM_ATTESTATION_MAGIC2 '2DAP' // Platform Attestation Data Structure, version 2
typedef struct _PCP_PLATFORM_ATTESTATION_BLOB2 {
    ULONG Magic;
    ULONG Platform;
    ULONG HeaderSize;
    ULONG cbPcrValues;
    ULONG cbQuote;
    ULONG cbSignature;
    ULONG cbLog;
    ULONG PcrAlgorithmId;
} PCP_PLATFORM_ATTESTATION_BLOB2, *PPCP_PLATFORM_ATTESTATION_BLOB2;

#define PCP_KEY_ATTESTATION_MAGIC 'SDAK' // Key Attestation Data Structure
typedef struct _PCP_KEY_ATTESTATION_BLOB {
    ULONG Magic;
    ULONG Platform;
    ULONG HeaderSize;
    ULONG cbKeyAttest;
    ULONG cbSignature;
    ULONG cbKeyBlob;
} PCP_KEY_ATTESTATION_BLOB, *PPCP_KEY_ATTESTATION_BLOB;

// TPM info location
#define TPM_STATIC_CONFIG_DATA L"System\\CurrentControlSet\\services\\TPM"
#define TPM_STATIC_CONFIG_QUOTE_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\PlatformQuoteKeys"
#define TPM_STATIC_CONFIG_KEYATTEST_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\KeyAttestationKeys"
#define TPM_VOLATILE_CONFIG_DATA L"System\\CurrentControlSet\\Control\\IntegrityServices"

// WBCL parser APIs
#pragma pack(push,1)

#define TPM_AVAILABLE_PLATFORM_PCRS (24)

//
// These values are aligned with TPM 2.0 ALG_ID.
//
typedef UINT16 WBCL_DIGEST_ALG_ID;

#define WBCL_DIGEST_ALG_ID_SHA_1            0x0004
#define WBCL_DIGEST_ALG_ID_SHA_2_256        0x000B
#define WBCL_DIGEST_ALG_ID_SHA_2_384        0x000C
#define WBCL_DIGEST_ALG_ID_SHA_2_512        0x000D

//
// These values are aligned with the TPM 2.0 algorithm bitmap
//
#define WBCL_DIGEST_ALG_BITMAP_SHA_1        0x00000001
#define WBCL_DIGEST_ALG_BITMAP_SHA_2_256    0x00000002
#define WBCL_DIGEST_ALG_BITMAP_SHA_2_384    0x00000004
#define WBCL_DIGEST_ALG_BITMAP_SHA_2_512    0x00000008

#pragma pack(pop)

#if defined(__cplusplus)
extern "C" {
#endif

// Our own implementation of the WBCL parser functions (wbcl.h)
// We're implementing them ourselves because this repo does not have tpmapi.lib to link against.

DllExport HRESULT MyWbclApiInitIterator(
    _In_    PVOID  pLogBuffer,
    _In_    UINT32 logSize,
    _Out_   WBCL_Iterator* pWbclIterator);

DllExport HRESULT MyWbclApiGetCurrentElement(
    _In_            WBCL_Iterator* pWbclIterator,
    _Out_           UINT32* pcrIndex,
    _Out_           UINT32* eventType,
    _Outptr_opt_result_bytebuffer_(pWbclIterator->digestSize) BYTE** ppDigest,
    _Out_opt_       UINT32* pcbElementDataSize,
    _Outptr_opt_result_bytebuffer_(*pcbElementDataSize) BYTE** ppbElementData
    );

DllExport HRESULT MyWbclApiMoveToNextElement(
    _In_ WBCL_Iterator* pWbclIterator);

#ifndef NCRYPT_PCP_PLATFORM_BINDING_PCRALGID_PROPERTY
#define NCRYPT_PCP_PLATFORM_BINDING_PCRALGID_PROPERTY L"PCP_PLATFORM_BINDING_PCRALGID"
#endif

// Internal helper functions

/// <summary>
///    Calculate SHA hash or HMAC.
/// </summary>
/// <param name="pszAlgId">BCrypt algorithm string.</param>
/// <param name="pbKey">pointer to Optional HMAC key.</param>
/// <param name="cbKey">size of Optional HMAC key.</param>
/// <param name="pbData">pointer to Data to be hashed.</param>
/// <param name="cbData">size of Data to be hashed.</param>
/// <param name="pbResult">Upon successful return, pointer to the digest.</param>
/// <param name="cbResult">Initial size of digest buffer.</param>
/// <param name="pcbResult">pointer to actually used size of digest buffer.</param>
/// <returns>
///    S_OK - Success.
///    E_INVALIDARG - Parameter error.
///    E_FAIL - Internal consistency error.
///    Others as propagated by called functions.
///</returns>
DllExport HRESULT TpmAttiShaHash(
    LPCWSTR pszAlgId,
    _In_reads_opt_(cbKey) PBYTE pbKey,
    UINT32 cbKey,
    _In_reads_(cbData) PBYTE pbData,
    UINT32 cbData,
    _Out_writes_to_opt_(cbResult, *pcbResult) PBYTE pbResult,
    UINT32 cbResult,
    _Deref_out_range_(0,cbResult) PUINT32 pcbResult
    );

/// <summary>
/// Release all hash providers.
/// </summary>
DllExport void TpmAttiReleaseHashProviders();

/// <summary>
/// Obtain the TPM version of the platform.
/// </summary>
/// <param name="pTpmVersion">Pointer to variable that will receive TPM version</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttiGetTpmVersion(
    _Out_ PUINT32 pTpmVersion
    );

/// <summary>
/// Calculate a bank of SHA-1 PCRs from a given TCG log.
/// </summary>
/// <param name="pbEventLog">pointer to EventLog to be parsed.</param>
/// <param name="cbEventLog">size of EventLog to be parsed.</param>
/// <param name="pbSwPcr">Pointer to PCR bank.</param>
/// <param name="pPcrMask">PCR mask that will indicate for which PCRs were log entries present</param>
/// <returns>
/// S_OK - Success.
/// E_INVALIDARG - Parameter error.
/// E_FAIL - Internal consistency error.
/// Others as propagated by called functions.
/// </returns>
HRESULT TpmAttiComputeSoftPCRs(
    _In_reads_(cbEventLog) PBYTE pbEventLog,
    UINT32 cbEventLog,
    UINT16 pcrAlgId,
    _Inout_updates_bytes_(cbSwPcr) PBYTE pbSwPcr,
    UINT32 cbSwPcr,
    _Out_opt_ PUINT32 pPcrMask
    );

/// <summary>
/// Filter eventlog to contain only entries that are specified in the PCRMask.
/// </summary>
/// <param name="pbEventLog">pointer to EventLog to be filtered.</param>
/// <param name="cbEventLog">size of EventLog to be filtered.</param>
/// <param name="pcrMask">filter mask.</param>
/// <param name="pbOutput">Upon successful return, contains the digest</param>
/// <param name="cbOutput">input size of the digest buffer</param>
/// <param name="pcbResult">output size of the digest buffer</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
HRESULT TpmAttiFilterLog(
    _In_reads_(cbEventLog) PBYTE pbEventLog,
    UINT32 cbEventLog,
    UINT32 pcrMask,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0,cbOutput) PUINT32 pcbResult
    );

// API functions

/// <summary>
/// Retrieve BCrypt key handle from IDBinding. This function is typically called on a server.
/// </summary>
/// <param name="pbIdBinding">pointer to IDBinding from Client.</param>
/// <param name="cbIdBinding">size of IDBinding from Client.</param>
/// <param name="hRsaAlg">Provider handle in which the handle should be opened.</param>
/// <param name="phAikPub">Upon successful return, contains handle to key</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttPubKeyFromIdBinding(
    _In_reads_(cbIdBinding) PBYTE pbIdBinding,
    UINT32 cbIdBinding,
    BCRYPT_ALG_HANDLE hRsaAlg,
    _Out_ BCRYPT_KEY_HANDLE* phAikPub
    );

/// <summary>
/// Generate Activation Blob from IDBinding, with a given secret. If a nonce is provided,
/// it will be validated with the nonce in the IDBinding
/// </summary>
/// <param name="hEkPub">Public key to encrypt the activation.</param>
/// <param name="pbIdBinding">pointer to IDBinding from the client.</param>
/// <param name="cbIdBinding">size of IDBinding from the client.</param>
/// <param name="pbNonce">pointer to Nonce provided to the client for key creation.</param>
/// <param name="cbNonce">size of Nonce provided to the client for key creation.</param>
/// <param name="pbSecret">pointer to Secret to be wrapped in activation.</param>
/// <param name="cbSecret">size of Secret to be wrapped in activation.</param>
/// <param name="pbOutput">Upon successful return, contains the activation blob.</param>
/// <param name="cbOutput">input size of activation blob</param>
/// <param name="pcbResult">output size of activation blob.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGenerateActivation(
    BCRYPT_KEY_HANDLE hEkPub,
    _In_reads_(cbIdBinding) PBYTE pbIdBinding,
    UINT32 cbIdBinding,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbSecret) PBYTE pbSecret,
    UINT16 cbSecret,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0,cbOutput) PUINT32 pcbResult
    );

/// <summary>
/// Generate platform attestation blob with provided AIK over the PCRs indicated and an optional nonce
/// </summary>
/// <param name="hAik">AIK key handle, fully authorized if required.</param>
/// <param name="pcrMask">Filter for events.</param>
/// <param name="pbNonce">pointer to Nonce provided to be included in signature.</param>
/// <param name="cbNonce">size of Nonce provided to be included in signature.</param>
/// <param name="pbOutput">Upon successful return, contains the attestation blob.</param>
/// <param name="cbOutput">input size of attestation blob buffer.</param>
/// <param name="pcbResult">output size of attestation blob.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGeneratePlatformAttestation(
    NCRYPT_KEY_HANDLE hAik,
    UINT32 pcrMask,
    _In_reads_opt_ (cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0,cbOutput) PUINT32 pcbResult
    );

/// <summary>
/// Integrity verification of a platform attestation. This operation is typically done on a server.
/// </summary>
/// <param name="hAik">AIKPub handle for signature validation</param>
/// <param name="pbNonce">Optional nonce verification that was provided by the server to ensure that the attestation is fresh.</param>
/// <param name="cbNonce">size of optional nonce.</param>
/// <param name="pbAttestation">pointer to Attestation blob</param>
/// <param name="cbAttestation">size of Attestation blob</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttValidatePlatformAttestation(
    BCRYPT_KEY_HANDLE hAik,
    _In_reads_opt_ (cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_ (cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation
    );

/// <summary>
/// Read and return all platform counters
/// </summary>
/// <param name="pOsBootCount">OS Boot counter - insecure index for log files.</param>
/// <param name="pOsResumeCount">OS Resume counter - insecure index for log files.</param>
/// <param name="pCurrentTpmBootCount">TPM 2.0 backed counter, not available on 1.2.</param>
/// <param name="pCurrentTpmEventCount">TPM backed monotonic counter.</param>
/// <param name="pCurrentTpmCounterId">Counter ID on 1.2 TPMs.</param>
/// <param name="pInitialTpmBootCount">TPM 2.0 backed counter, not available on 1.2 when the platform was booted.</param>
/// <param name="pInitialTpmEventCount">TPM backed monotonic counter when the platform was booted.</param>
/// <param name="pInitialTpmCounterId">Counter ID on 1.2 TPMs when the platform was booted.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGetPlatformCounters(
    _Out_opt_ PUINT32 pOsBootCount,
    _Out_opt_ PUINT32 pOsResumeCount,
    _Out_opt_ PUINT64 pCurrentTpmBootCount,
    _Out_opt_ PUINT64 pCurrentTpmEventCount,
    _Out_opt_ PUINT64 pCurrentTpmCounterId,
    _Out_opt_ PUINT64 pInitialTpmBootCount,
    _Out_opt_ PUINT64 pInitialTpmEventCount,
    _Out_opt_ PUINT64 pInitialTpmCounterId
    );

/// <summary>
/// Obtain a log from the archive on the disk. The log is selected by the OS boot and resume counter
/// </summary>
/// <param name="OsBootCount">Selector for boot index</param>
/// <param name="OsResumeCount">Selector for resume index</param>
/// <param name="pbOutput">Upon successful return, contains the requested log.</param>
/// <param name="cbOutput">input size of log buffer</param>
/// <param name="pcbResult">output size of log buffer</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGetPlatformLogFromArchive(
    UINT32 OsBootCount,
    UINT32 OsResumeCount,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0,cbOutput) PUINT32 pcbResult
    );

/// <summary>
/// Turn a log with a trust point into an attestation blob, so it can be validated as any other attestation blob
/// </summary>
/// <param name="pbLog">pointer to Event log with trust point</param>
/// <param name="cbLog">size of Event log with trust point</param>
/// <param name="szAikNameRequested">Optional AIK name selection, if multiple AIK are registered</param>
/// <param name="pszAikName">
/// Upon successful return, contains a pointer to the AIK name that signed the trust point.
/// This is a pointer into pbLog, cbLog and does not need to be explicitly freed.
/// </param>
/// <param name="pbAikPubDigest">pointer to receive AIK pub digest.</param>
/// <param name="pbOutput">Upon successful return, contains the attestation blob.</param>
/// <param name="cbOutput">input size of attestation blob buffer.</param>
/// <param name="pcbResult">output size of attestation blob buffer.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttCreateAttestationfromLog(
    _In_reads_(cbLog) PBYTE pbLog,
    UINT32 cbLog,
    _In_reads_z_(MAX_PATH) PWSTR szAikNameRequested,
    _Outptr_result_z_ PWSTR* pszAikName,
    _Out_writes_all_opt_(SHA1_DIGEST_SIZE) PBYTE pbAikPubDigest,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0,cbOutput) PUINT32 pcbResult
    );

/// <summary>
/// Parse an attestation blob and return specific properties from it
/// </summary>
/// <param name="pbAttestation">pointer to Event log with trust point.</param>
/// <param name="cbAttestation">size of Event log with trust point.</param>
/// <param name="pEventCount">Starting event count in the log.</param>
/// <param name="pEventIncrements">Number of event increments in the log.</param>
/// <param name="pEventCounterId">Event counter ID - only valid on 1.2.</param>
/// <param name="pBootCount">Power-up counter - only valid on 2.0.</param>
/// <param name="pdwPropertyFlags">Property flags for this attestation.</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGetPlatformAttestationProperties(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    _Out_opt_ PUINT64 pEventCount,
    _Out_opt_ PUINT64 pEventIncrements,
    _Out_opt_ PUINT64 pEventCounterId,
    _Out_opt_ PUINT64 pBootCount,
    _Out_opt_ PUINT32 pdwPropertyFlags
    );

/// <summary>
/// Generate a key attestation. Both keys have to be on the TPM within the same provider handle.
/// </summary>
/// <param name="hAik">Key to sign the attestation - has to be fully authorized if necessary</param>
/// <param name="hKey">Key to be attested - has to be fully authorized if necessary</param>
/// <param name="pbNonce">pointer to optional nonce included in the signature</param>
/// <param name="cbNonce">size of optional nonce</param>
/// <param name="pbOutput">Upon successful return, contains the key certification blob.</param>
/// <param name="cbOutput">input size of certification blob buffer</param>
/// <param name="pcbResult">output size of certification blob buffer</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGenerateKeyAttestation(
    NCRYPT_KEY_HANDLE hAik,
    NCRYPT_KEY_HANDLE hKey,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0,cbOutput) PUINT32 pcbResult
    );

/// <summary>
/// Get a key attestation that was created by the provider.
/// </summary>
/// <param name="hKey">Key to be attested - has to be fully authorized if necessary</param>
/// <param name="szAikNameRequested">Optional AIK name selection, if multiple AIK are registered</param>
/// <param name="pszAikName">
/// Upon successful return, contains a pointer to the AIK name that signed the trust point.
/// This is a pointer into pbLog, cbLog and does not need to be explicitly freed.
/// </param>
/// <param name="pbAikPubDigest">pointer to receive AIK pub digest.</param>
/// <param name="pbOutput">Upon successful return, contains the key certification blob.</param>
/// <param name="cbOutput">input size of certification blob buffer</param>
/// <param name="pcbResult">output size of certification blob buffer</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttCreateAttestationfromKey(
    NCRYPT_KEY_HANDLE hKey,
    _In_reads_z_(MAX_PATH) PWSTR szAikNameRequested,
    _Out_writes_z_(MAX_PATH) PWSTR szAikName,
    _Out_writes_all_opt_(SHA1_DIGEST_SIZE) PBYTE pbAikPubDigest,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0,cbOutput) PUINT32 pcbResult
    );

/// <summary>
/// Integrity validation of a key certification. Usually done on a server.
/// </summary>
/// <param name="hAik">Public key to validate the attestation.</param>
/// <param name="pbNonce">Optional nonce validated with certification if provided.</param>
/// <param name="cbNonce">size of optional nonce.</param>
/// <param name="pbAttestation">Key certification blob.</param>
/// <param name="cbAttestation">size of key certification blob.</param>
/// <param name="pcrMask">Expected pceMask of key. Validated with pcrMask in the key.</param>
/// <param name="pcrTable">
/// All 24 PCRs that the pcr digest is validated with.
/// This is used to check the PCR policy a key is bound to.
/// </param>
/// <param name="cbPcrTable">size of PCR table</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttValidateKeyAttestation(
    BCRYPT_KEY_HANDLE hAik,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    UINT32 pcrMask,
    UINT16 pcrAlgId,
    _In_reads_opt_(cbPcrTable) PBYTE pcrTable,
    UINT32 cbPcrTable
    );

/// <summary>
/// Retrieve a public key handle and key property flags form a key attestation. This function is usually called on a server.
/// </summary>
/// <param name="pbAttestation">Validated attestation blob.</param>
/// <param name="cbAttestation">size of validated attestation blob.</param>
/// <param name="pPropertyFlags">Upon successful return, contains the key property flags.</param>
/// <param name="hAlg">Provider that should be used to open the key handle in.</param>
/// <param name="phKey">Upon successful return, contains the public key handle</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttGetKeyAttestationProperties(
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    _Out_opt_ PUINT32 pPropertyFlags,
    BCRYPT_ALG_HANDLE hAlg,
    _Out_opt_ BCRYPT_KEY_HANDLE* phKey
    );

/// <summary>
/// Wrap a platform key with a given set of policies for a particular target machine. This function is usually called on a server.
/// </summary>
/// <param name="hInKey">Handle to an exportable key pair.</param>
/// <param name="hStorageKey">Public storage key that will be the new parent of inKey. Has to be a storage key.</param>
/// <param name="tpmVersion">Selector if a 1.2 or 2.0 key blob is to be created.</param>
/// <param name="keyUsage">Key usage restriction.</param>
/// <param name="pbPIN">Optional user PIN value that the key should be bound to.</param>
/// <param name="cbPIN">size of optional PIN value</param>
/// <param name="pcrMask">Optional PCRMask the key will be bound to</param>
/// <param name="pcrTable">PCR table of 24 digests that will be used to calculate the PCR digest with the pcrMask</param>
/// <param name="cbPcrTable">size of PCR table</param>
/// <param name="pbOutput">Upon successful return, contains the wrapped key blob.</param>
/// <param name="cbOutput">input size of key blob</param>
/// <param name="pcbResult">output size of key blob</param>
/// <returns>
///  S_OK - Success.
///  E_INVALIDARG - Parameter error.
///  E_FAIL - Internal consistency error.
///  Others as propagated by called functions.
/// </returns>
DllExport HRESULT TpmAttWrapPlatformKey(
    NCRYPT_KEY_HANDLE hInKey,
    BCRYPT_KEY_HANDLE hStorageKey,
    UINT32 tpmVersion,
    UINT32 keyUsage,
    _In_reads_opt_(cbPIN) PBYTE pbPIN,
    UINT32 cbPIN,
    UINT32 pcrMask,
    UINT16 pcrAlgId,
    _In_reads_opt_(cbPcrTable) PBYTE pcrTable,
    UINT32 cbPcrTable,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0,cbOutput) PUINT32 pcbResult
    );

#if defined(__cplusplus)
}
#endif

#endif //TPMATT_H
