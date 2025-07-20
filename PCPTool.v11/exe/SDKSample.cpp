/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    SDKSample.cpp

Abstract:

    This file contains the actual SDK samples for the Platform Crypto Provider.

--*/

#include "stdafx.h"

const GUID FOLDERID_Windows = { 0xF38BF404, 0x1D43, 0x42F2, 0x93, 0x05, 0x67, 0xDE, 0x0B, 0x28, 0xFC, 0x23 };

typedef
DWORD
(*fnPromptForCredentials)
    (
    __in_opt     PCREDUI_INFOW pUiInfo,
    __in         DWORD dwAuthError,
    __inout      ULONG *pulAuthPackage,
    __in_opt     LPCVOID pvInAuthBuffer,
    __in         ULONG ulInAuthBufferSize,
    __out        LPVOID *ppvOutAuthBuffer,
    __out        ULONG *pulOutAuthBufferSize,
    __inout_opt  BOOL *pfSave,
    __in         DWORD dwFlags
    );

typedef
BOOL
(*fnCryptUIDlgViewContext)
    (
    IN          DWORD dwContextType,
    IN          const void *pvContext,
    IN OPTIONAL HWND hwnd,              // Defaults to the desktop window      
    IN OPTIONAL LPCWSTR pwszTitle,      // Defaults to the context type title      
    IN          DWORD dwFlags,  
    IN          void *pvReserved
    );

typedef
PCCERT_CONTEXT
(*fnCryptUIDlgSelectCertificateFromStore)
    (
    IN HCERTSTORE hCertStore,
    IN OPTIONAL HWND hwnd,              // Defaults to the desktop window      
    IN OPTIONAL LPCWSTR pwszTitle,
    IN OPTIONAL LPCWSTR pwszDisplayString,
    IN DWORD dwDontUseColumn,
    IN DWORD dwFlags,
    IN void *pvReserved
    );

HRESULT
CryptUIDlgViewContextWrapper(
    PCCERT_CONTEXT *pcCertContext
    )
{
    HRESULT hr = S_FALSE;
    HMODULE hModule = NULL;
    fnCryptUIDlgViewContext fpCUIDVC = NULL;

    hModule = LoadLibraryExW(L"cryptui.dll", NULL, 0);

    if (hModule == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    fpCUIDVC = (fnCryptUIDlgViewContext)GetProcAddress(hModule, "CryptUIDlgViewContext");

    if (fpCUIDVC == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if (!fpCUIDVC(
        CERT_STORE_CERTIFICATE_CONTEXT,
        pcCertContext,
        NULL,
        NULL,
        0,
        NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

Cleanup:

    if (hModule)
    {
        FreeLibrary(hModule);
        hModule = NULL;
    }
    return hr;
}

HRESULT
CryptUIDlgSelectCertificateFromStoreWrapper(
    PCCERT_CONTEXT *pcCertContext,
    HCERTSTORE *hStore
    )
{
    HRESULT hr = S_OK;
    HMODULE hModule = NULL;
    fnCryptUIDlgSelectCertificateFromStore fpCUIDSCFS = NULL;

    hModule = LoadLibraryExW(L"cryptui.dll", NULL, 0);

    if (hModule == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    fpCUIDSCFS = (fnCryptUIDlgSelectCertificateFromStore)GetProcAddress(hModule, "CryptUIDlgSelectCertificateFromStore");

    if (fpCUIDSCFS == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if ((*pcCertContext = fpCUIDSCFS(
        hStore,
        NULL,
        NULL,
        NULL,
        0,
        0,
        NULL)) == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

Cleanup:

    if (hModule)
    {
        FreeLibrary(hModule);
        hModule = NULL;
    }
    return hr;
}

DWORD
CredUIPromptForWindowsCredentialsWrapper(
    CREDUI_INFOW UIInfo,
    ULONG ulAuthPackage,
    READER_SEL_REQUEST rsRequest,
    VOID* pvOutAuthBuffer,
    ULONG ulOutAuthBufferSize
)
{
    DWORD result = ERROR_SUCCESS;
    HMODULE hModule = NULL;
    fnPromptForCredentials fpPFC = NULL;

    hModule = LoadLibraryExW(L"credui.dll", NULL, 0);

    if (hModule == NULL)
    {
        result = ERROR_DLL_NOT_FOUND;
        goto Cleanup;
    }

    fpPFC = (fnPromptForCredentials)GetProcAddress(hModule, "CredUIPromptForWindowsCredentialsW");

    if (fpPFC == NULL)
    {
        result = ERROR_NOT_FOUND;
        goto Cleanup;
    }

    result = fpPFC(
        &UIInfo,
        ERROR_SUCCESS,
        &ulAuthPackage,
        &rsRequest,
        sizeof(rsRequest),
        &pvOutAuthBuffer,
        &ulOutAuthBufferSize,
        NULL,
        CREDUIWIN_AUTHPACKAGE_ONLY
        );

Cleanup:

    if (hModule)
    {
        FreeLibrary(hModule);
        hModule = NULL;
    }
    return result;
}

HRESULT
GetCACertContext(
    _In_reads_z_(MAX_PATH) LPWSTR szUserStore,
    _Out_ PCCERT_CONTEXT* ppCaCert
    )
{
    HRESULT hr = S_OK;
    PCCERT_CONTEXT pCert = NULL;
    PCCERT_CONTEXT pCaCert = NULL;
    HCERTSTORE hStore = NULL;
    HCERTSTORE hCaStore = NULL;
    DWORD dwCaCertsFound = 0;

    if((szUserStore == NULL) ||
       (wcslen(szUserStore) == 0) ||
       (ppCaCert == NULL))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Open the indicated system store
    if((hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                               0,
                               NULL,
                               CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
                               szUserStore)) == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Create a store that will be used to hold all found CA certs
    if((hCaStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
                                 0,
                                 NULL,
                                 CERT_STORE_CREATE_NEW_FLAG | CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
                                 NULL)) == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Browse through the store and copy all CA certs to the CA store
    while((pCert = CertEnumCertificatesInStore(hStore,
                                               pCert)) != NULL)
    {
        BYTE keyUsage[2] = {0};
        if(!CertGetIntendedKeyUsage(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                    pCert->pCertInfo,
                                    keyUsage,
                                    sizeof(keyUsage)))
        {
            continue;
        }
        if((keyUsage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE) != 0)
        {
            if(pCaCert != NULL)
            {
                CertFreeCertificateContext(pCaCert);
                pCaCert = NULL;
            }
            if(CertAddCertificateContextToStore(hCaStore,
                                                pCert,
                                                CERT_STORE_ADD_ALWAYS,
                                                &pCaCert))
            {
                dwCaCertsFound++;
            }
        }
    }

    // Have the user pick a cert from the CA store.
    if(dwCaCertsFound > 1)
    {
        if(pCaCert != NULL)
        {
            CertFreeCertificateContext(pCaCert);
            pCaCert = NULL;
        }
        if (FAILED(hr = CryptUIDlgSelectCertificateFromStoreWrapper(&pCaCert, &hCaStore)))
        {
            goto Cleanup;
        }
    }

    *ppCaCert = pCaCert;
    pCaCert = NULL;

Cleanup:
    if(pCaCert != NULL)
    {
        CertFreeCertificateContext(pCaCert);
        pCaCert = NULL;
    }
    if(pCert != NULL)
    {
        CertFreeCertificateContext(pCert);
        pCert = NULL;
    }
    if(hStore != NULL)
    {
        CertCloseStore(hStore, 0);
        hStore = NULL;
    }
    if(hCaStore != NULL)
    {
        CertCloseStore(hCaStore, 0);
        hCaStore = NULL;
    }
    return hr;
}

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
    DWORD dwFlags)
{
    HRESULT hr = S_OK;
    DWORD dwKeySpec = 0;
    BOOL fCallerFreeProvOrNCryptKey = FALSE;
    NCRYPT_KEY_HANDLE hCaKey = NULL;
    CERT_PUBLIC_KEY_INFO* pSubjectKeyInfo = NULL;
    DWORD cbSubjectKeyInfo = 0;
    CERT_INFO certInfo = {0};
    SYSTEMTIME systemTime = {0};
    PBYTE pbEncoded = NULL;
    DWORD cbEncoded = 0;
    CRYPT_ALGORITHM_IDENTIFIER certAlgId = {szOID_RSA_SHA1RSA,
                                            {0, NULL}};

    // Subject encoding structure
    BYTE subjectCommonName[MAX_PATH] = "";
    CERT_RDN_ATTR rgSubjectCommonNameAttr =
    {
        szOID_COMMON_NAME,
        CERT_RDN_PRINTABLE_STRING,
        0,
        subjectCommonName
    };
    CERT_RDN rgRDNSubject = 
    {
       1,
       &rgSubjectCommonNameAttr
    };
    CERT_NAME_INFO subjectName = 
    {
        1,
        &rgRDNSubject
    };

    /* Hard coded RSA_OIAP parameter for EKs
    0000: 30 15                                     ; SEQUENCE (15 Bytes)
    0002:    a2 13                                  ; OPTIONAL[2] (13 Bytes)
    0004:       30 11                               ; SEQUENCE (11 Bytes)
    0006:          06 09                            ; OBJECT_ID (9 Bytes)
    0008:          |  2a 86 48 86 f7 0d 01 01  09
                   |     ; 1.2.840.113549.1.1.9
    0011:          04 04                            ; OCTET_STRING (4 Bytes)
    0013:             54 43 50 41                                       ; TCPA
    */
    BYTE oaepParameter[23] = {
    0x30, 0x15, 0xA2, 0x13, 0x30, 0x11, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 
    0x09, 0x04, 0x04, 0x54, 0x43, 0x50, 0x41
    };

    // Certificate extensions encoding structure
    CERT_BASIC_CONSTRAINTS2_INFO basicConstraintsInfo = {FALSE,
                                                         FALSE,
                                                         0};
    CERT_AUTHORITY_KEY_ID2_INFO keyIdInfo = {0};
    CERT_EXTENSION certExtensions[] = {{szOID_BASIC_CONSTRAINTS2,
                                        TRUE,
                                       {0, NULL}},
                                       {szOID_AUTHORITY_KEY_IDENTIFIER2,
                                        FALSE,
                                        {0, NULL}}};

    // Parameter checks
    if((pCaCert == NULL) ||
       (szSubject == NULL) ||
       (wcslen(szSubject) == 0) ||
       (hSubjectKeyPub == NULL) ||
       ((cbOutput != 0) && (pbOutput == NULL)) ||
       (pcbResult == NULL))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    *pcbResult = 0;

    // Open the CA cert to get the issuer information and a handle to sign the cert
    if(!CryptAcquireCertificatePrivateKey(pCaCert,
                                          CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG,
                                          NULL,
                                          &hCaKey,
                                          &dwKeySpec,
                                          &fCallerFreeProvOrNCryptKey))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Get the subject key info
    if(!CryptExportPublicKeyInfoEx(hSubjectKeyPub,
                                    0,
                                    X509_ASN_ENCODING,
                                    szOID_RSA_RSA,
                                    0,
                                    NULL,
                                    NULL,
                                    &cbSubjectKeyInfo))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pSubjectKeyInfo, cbSubjectKeyInfo)))
    {
        goto Cleanup;
    }
    if(!CryptExportPublicKeyInfoEx(hSubjectKeyPub,
                                    0,
                                    X509_ASN_ENCODING,
                                    szOID_RSA_RSA,
                                    0,
                                    NULL,
                                    pSubjectKeyInfo,
                                    &cbSubjectKeyInfo))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Convert the subject name from WCHAR to ASCII
    if(!WideCharToMultiByte(CP_UTF8,
                            WC_ERR_INVALID_CHARS,
                            szSubject,
                            (int)wcslen(szSubject),
                            (LPSTR)subjectCommonName,
                            MAX_PATH,
                            NULL,
                            NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }
    rgSubjectCommonNameAttr.Value.cbData = (DWORD)strlen((LPSTR)subjectCommonName) + 1;

    // Put the certificate together
    certInfo.dwVersion = CERT_V3;
    certInfo.SerialNumber.cbData = sizeof(serialNumber);
    certInfo.SerialNumber.pbData = (PBYTE)&serialNumber;
    certInfo.SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
    certInfo.Issuer.cbData = pCaCert->pCertInfo->Issuer.cbData;
    certInfo.Issuer.pbData = pCaCert->pCertInfo->Issuer.pbData;
    GetSystemTime(&systemTime);
    SystemTimeToFileTime(&systemTime, &certInfo.NotBefore);

    // Set validity period
    systemTime.wMilliseconds += validityPeriod.wMilliseconds;
    systemTime.wSecond += validityPeriod.wSecond;
    systemTime.wMinute += validityPeriod.wMinute;
    systemTime.wHour += validityPeriod.wHour;
    systemTime.wDay += validityPeriod.wDay;
    systemTime.wMonth += validityPeriod.wMonth;
    systemTime.wYear += validityPeriod.wYear;
    SystemTimeToFileTime(&systemTime, &certInfo.NotAfter);

    // Encode the subject
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING,
                            X509_NAME,
                            &subjectName,
                            CRYPT_ENCODE_ALLOC_FLAG,
                            NULL,
                            &certInfo.Subject.pbData,
                            &certInfo.Subject.cbData))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Encode the public key info
    if(dwFlags & ISSUECERTIFICATE_EKCERT)
    {
        certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId = szOID_RSAES_OAEP;
        certInfo.SubjectPublicKeyInfo.Algorithm.Parameters.cbData = sizeof(oaepParameter);
        certInfo.SubjectPublicKeyInfo.Algorithm.Parameters.pbData = oaepParameter;
    }
    else
    {
        certInfo.SubjectPublicKeyInfo.Algorithm.pszObjId = szOID_RSA_RSA;
    }
    certInfo.SubjectPublicKeyInfo.PublicKey.cbData = pSubjectKeyInfo->PublicKey.cbData;
    certInfo.SubjectPublicKeyInfo.PublicKey.cUnusedBits = pSubjectKeyInfo->PublicKey.cUnusedBits;
    certInfo.SubjectPublicKeyInfo.PublicKey.pbData = pSubjectKeyInfo->PublicKey.pbData;

    // Encode the basic constraints extension
    if( !CryptEncodeObjectEx(X509_ASN_ENCODING, 
                             X509_BASIC_CONSTRAINTS2,
                             &basicConstraintsInfo,
                             CRYPT_ENCODE_ALLOC_FLAG,
                             NULL,
                             &certExtensions[0].Value.pbData,
                             &certExtensions[0].Value.cbData))
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        goto Cleanup;
    }

    // Encode the authority public key info
    if(!CryptEncodeObjectEx(X509_ASN_ENCODING, 
                            X509_PUBLIC_KEY_INFO,
                            &pCaCert->pCertInfo->SubjectPublicKeyInfo,
                            CRYPT_ENCODE_ALLOC_FLAG,
                            NULL,
                            &pbEncoded,
                            &cbEncoded))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }
    keyIdInfo.KeyId.cbData = SHA1_DIGEST_SIZE;
    if(FAILED(hr = AllocateAndZero((PVOID*)&keyIdInfo.KeyId.pbData, keyIdInfo.KeyId.cbData)))
    {
        goto Cleanup;
    }
    if(!CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM,
                              0,
                              NULL,
                              pbEncoded,
                              cbEncoded,
                              keyIdInfo.KeyId.pbData,
                              &keyIdInfo.KeyId.cbData))
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        goto Cleanup;
    }
    keyIdInfo.AuthorityCertSerialNumber.cbData = pCaCert->pCertInfo->SerialNumber.cbData;
    keyIdInfo.AuthorityCertSerialNumber.pbData = pCaCert->pCertInfo->SerialNumber.pbData;
    if( !CryptEncodeObjectEx(X509_ASN_ENCODING, 
                             X509_AUTHORITY_KEY_ID2,
                             &keyIdInfo,
                             CRYPT_ENCODE_ALLOC_FLAG,
                             NULL,
                             &certExtensions[1].Value.pbData,
                             &certExtensions[1].Value.cbData))
    {
        hr = HRESULT_FROM_WIN32( GetLastError() );
        goto Cleanup;
    }

    // Set the extensions
    certInfo.cExtension = 2;
    certInfo.rgExtension = certExtensions;

    // Issue the certificate
    *pcbResult = cbOutput;
    if(!CryptSignAndEncodeCertificate(hCaKey,
                                      dwKeySpec,
                                      X509_ASN_ENCODING,
                                      X509_CERT_TO_BE_SIGNED,
                                      &certInfo,
                                      &certAlgId,
                                      NULL,
                                      pbOutput,
                                      (DWORD*)pcbResult))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

Cleanup:
    if((fCallerFreeProvOrNCryptKey != FALSE) && (hCaKey != NULL))
    {
        if(dwKeySpec == CERT_NCRYPT_KEY_SPEC)
        {
            NCryptFreeObject(hCaKey);
        }
        else
        {
            CryptReleaseContext(hCaKey, 0);
        }
        hCaKey = NULL;
    }
    if(certInfo.Subject.pbData != NULL)
    {
        LocalFree(certInfo.Subject.pbData);
        certInfo.Subject.pbData = NULL;
    }
    ZeroAndFree((PVOID*)&pSubjectKeyInfo, cbSubjectKeyInfo);
    return hr;
}

HRESULT
ProtectData(
    BOOLEAN tEncrypt,
    _In_reads_(cbSymKey) PBYTE pbSymKey,
    UINT32 cbSymKey,
    _Inout_updates_bytes_(cbData) PBYTE pbData,
    UINT32 cbData
    )
{
    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PBYTE pbBuffer = NULL;
    ULONG cbBuffer = 0;

    // Parameter checks
    if((pbSymKey == NULL) ||
       (cbSymKey == 0) ||
       (pbData == NULL) ||
       (cbData == 0))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    cbBuffer = ((cbData + cbSymKey - 1) / cbSymKey) * cbSymKey;
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbBuffer, cbBuffer)))
    {
        goto Cleanup;
    }
    memcpy(pbBuffer, pbData, min(cbData, cbBuffer));

    // Create the key and set up the AES engine
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(&hAlg,
                                                               BCRYPT_AES_ALGORITHM,
                                                               NULL,
                                                               0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptGenerateSymmetricKey(hAlg,
                                                              &hKey,
                                                              NULL,
                                                              0,
                                                              pbSymKey,
                                                              cbSymKey,
                                                              0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptSetProperty(hKey,
                                                     BCRYPT_CHAINING_MODE,
                                                     (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                                                     (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC),
                                                     0))))
    {
        goto Cleanup;
    }

    // Perform requested operation
    if(tEncrypt)
    {
        if(FAILED(hr = HRESULT_FROM_NT(BCryptEncrypt(hKey,
                                                     pbBuffer,
                                                     cbBuffer,
                                                     NULL,
                                                     NULL,
                                                     0,
                                                     pbBuffer,
                                                     cbBuffer,
                                                     &cbBuffer,
                                                     0))))
        {
            goto Cleanup;
        }
    }
    else
    {
        if(FAILED(hr = HRESULT_FROM_NT(BCryptDecrypt(hKey,
                                                     pbBuffer,
                                                     cbBuffer,
                                                     NULL,
                                                     NULL,
                                                     0,
                                                     pbBuffer,
                                                     cbBuffer,
                                                     &cbBuffer,
                                                     0))))
        {
            goto Cleanup;
        }
    }

    // Copy the output
    memcpy(pbData, pbBuffer, cbData);

Cleanup:
    if(hKey != NULL)
    {
        BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbBuffer, cbBuffer);
    return hr;
}

HRESULT
GetActivePcrAlgorithm(
    _Out_ PUINT16 AlgorithmId
    )
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    BYTE pcrTable[TPM_AVAILABLE_PLATFORM_PCRS * MAX_DIGEST_SIZE] = {0};
    DWORD cbPcrTable = sizeof(pcrTable);
    UINT16 algorithmId = TPM_API_ALG_ID_SHA1;

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                            &hProv,
                            MS_PLATFORM_CRYPTO_PROVIDER,
                            0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(hProv,
                            NCRYPT_PCP_PCRTABLE_PROPERTY,
                            pcrTable,
                            sizeof(pcrTable),
                            &cbPcrTable,
                            0))))
    {
        goto Cleanup;
    }

    // PCR table property on a PC is always returning a table of
    // 24 (TPM_AVAILABLE_PLATFORM_PCRS) PCRs.
    if ((cbPcrTable / TPM_AVAILABLE_PLATFORM_PCRS) == SHA256_DIGEST_SIZE)
    {
        algorithmId = TPM_API_ALG_ID_SHA256;
    }

    if (AlgorithmId != NULL)
    {
        *AlgorithmId = algorithmId;
    }

Cleanup:
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    return hr;
}

HRESULT
PcpToolGetVersion(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Retrieve the version strings from the PCP provider and the TPM.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProvTpm = NULL;
    WCHAR versionData[256] = L"";
    DWORD cbData = 0;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    ZeroMemory(versionData, sizeof(versionData));

    if (FAILED(hr = HRESULT_FROM_NT(NCryptOpenStorageProvider(
                                        &hProvTpm,
                                        MS_PLATFORM_KEY_STORAGE_PROVIDER,
                                        NCRYPT_IGNORE_DEVICE_STATE_FLAG))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_NT(NCryptGetProperty(
                                        hProvTpm,
                                        BCRYPT_PCP_PROVIDER_VERSION_PROPERTY,
                                        (PUCHAR)versionData,
                                        sizeof(versionData) - sizeof(WCHAR),
                                        &cbData,
                                        0))))
    {
        goto Cleanup;
    }

    if(cbData > sizeof(versionData) - sizeof(WCHAR))
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }
    versionData[cbData / sizeof(WCHAR)] = 0x0000;

    wprintf(L"<Version>\n");
    wprintf(L"  <Provider>%s</Provider>\n", versionData);

    if(FAILED(hr = HRESULT_FROM_NT(NCryptGetProperty(
                                        hProvTpm,
                                        BCRYPT_PCP_PLATFORM_TYPE_PROPERTY,
                                        (PUCHAR)versionData,
                                        sizeof(versionData) - sizeof(WCHAR),
                                        &cbData,
                                        0))))
    {
        goto Cleanup;
    }

    if(cbData > sizeof(versionData) - sizeof(WCHAR))
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }
    versionData[cbData / sizeof(WCHAR)] = 0x0000;

    wprintf(L"  <TPM>\n    %s\n  </TPM>\n", versionData);
    wprintf(L"</Version>\n");

Cleanup:
    if(hProvTpm != NULL)
    {
        NCryptFreeObject(hProvTpm);
        hProvTpm = NULL;
    }
    PcpToolCallResult(L"PcpToolGetVersion()", hr);
    return hr;
}

HRESULT
PcpToolGetEK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Retrieve the EKPub from the TPM through the PCP. The key is provided as a
BCRYPT_RSAKEY_BLOB structure.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    BYTE pbEkPub[1024] = {0};
    DWORD cbEkPub = 0;

    if(argc > 2)
    {
        fileName = argv[2];
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                            &hProv,
                            MS_PLATFORM_CRYPTO_PROVIDER,
                            0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(hProv,
                            NCRYPT_PCP_EKPUB_PROPERTY,
                            pbEkPub,
                            sizeof(pbEkPub),
                            &cbEkPub,
                            0))))
    {
        goto Cleanup;
    }

    if((fileName != NULL) &&
       (FAILED(hr = PcpToolWriteFile(fileName, pbEkPub, cbEkPub))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = PcpToolDisplayKey(L"EndorsementKey", pbEkPub, cbEkPub, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolGetEK()", hr);
    return hr;
}

HRESULT
PcpToolGetEKCert(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Retrieve the EKCert from the TPM EKStore. The cert is provided in
a certificate store. In the future there may be several certificates for the
platforms EKs in the returned store.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    HCERTSTORE hStore = NULL;
    DWORD cbhStore = 0;
    PCCERT_CONTEXT pcCertContext = NULL;
    UINT32 certCount = 0;
    BOOL fSilent = TRUE;


    for ( int i=2; i<argc; i++ )
    {
        if ( !_wcsicmp(argv[i], L"/i") || !_wcsicmp(argv[i], L"-i") )
        {
            fSilent = FALSE;
        }
        else
        {
            fileName = argv[i];
        }
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                            &hProv,
                            MS_PLATFORM_CRYPTO_PROVIDER,
                            0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                            hProv,
                            NCRYPT_PCP_EKCERT_PROPERTY,
                            (PBYTE)&hStore,
                            sizeof(hStore),
                            &cbhStore,
                            0))))
    {
        goto Cleanup;
    }

    // Count the EK certs in the returned store
    while((pcCertContext = CertEnumCertificatesInStore(
                                hStore,
                                pcCertContext)) != NULL)
    {
        certCount++;
    }

    if(certCount == 0)
    {
        wprintf(L"No EK Certificates found.\n");
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto Cleanup;
    }
    else if(fSilent)
    {
        // Pick the first cert
        if((pcCertContext = CertEnumCertificatesInStore(hStore, NULL)) == NULL)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
    }
    else if(certCount == 1)
    {
        // Pick the first and only cert
        if((pcCertContext = CertEnumCertificatesInStore(hStore, NULL)) == NULL)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }

        // Show the cert
        if (FAILED(hr = CryptUIDlgViewContextWrapper(&pcCertContext)))
        {
            goto Cleanup;
        }
    }
    else
    {
        // Have the user select one
        if (FAILED(hr = CryptUIDlgSelectCertificateFromStoreWrapper(&pcCertContext, &hStore)))
        {
            goto Cleanup;
        }
    }

    if(fileName != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(
                            fileName,
                            pcCertContext->pbCertEncoded,
                            pcCertContext->cbCertEncoded)))
        {
            goto Cleanup;
        }
    }
    wprintf(L"OK.\n");

Cleanup:
    if(pcCertContext != NULL)
    {
        CertFreeCertificateContext(pcCertContext);
        pcCertContext = NULL;
    }
    if(hStore != NULL)
    {
        CertCloseStore(hStore, 0);
        hStore = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolGetEKCert()", hr);
    return hr;
}

HRESULT
PcpToolGetNVEKCert(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Retrieve the EKCert from the TPM NVRAM through the PCP. The cert is provided in
a certificate store. In the future there may be several certificates for the
platforms EKs in the returned store.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    HCERTSTORE hStore = NULL;
    DWORD cbhStore = 0;
    PCCERT_CONTEXT pcCertContext = NULL;
    UINT32 certCount = 0;

    if(argc > 2)
    {
        fileName = argv[2];
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                            &hProv,
                            MS_PLATFORM_CRYPTO_PROVIDER,
                            0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                            hProv,
                            NCRYPT_PCP_EKNVCERT_PROPERTY,
                            (PBYTE)&hStore,
                            sizeof(hStore),
                            &cbhStore,
                            0))))
    {
        goto Cleanup;
    }

    // Count the EK certs in the returned store
    while((pcCertContext = CertEnumCertificatesInStore(
                                hStore,
                                pcCertContext)) != NULL)
    {
        certCount++;
    }

    if(certCount == 0)
    {
        wprintf(L"No EK Certificates found.\n");
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto Cleanup;
    }
    else if(certCount == 1)
    {
        // Pick the first and only cert
        if((pcCertContext = CertEnumCertificatesInStore(hStore, NULL)) == NULL)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }

        // Show the cert
        // Show the cert
        if (FAILED(hr = CryptUIDlgViewContextWrapper(&pcCertContext)))
        {
            goto Cleanup;
        }
    }
    else
    {
        // Have the user select one
        if (FAILED(hr = CryptUIDlgSelectCertificateFromStoreWrapper(&pcCertContext, &hStore)))
        {
            goto Cleanup;
        }
    }

    if(fileName != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(
                            fileName,
                            pcCertContext->pbCertEncoded,
                            pcCertContext->cbCertEncoded)))
        {
            goto Cleanup;
        }
    }
    wprintf(L"OK.\n");

Cleanup:
    if(pcCertContext != NULL)
    {
        CertFreeCertificateContext(pcCertContext);
        pcCertContext = NULL;
    }
    if(hStore != NULL)
    {
        CertCloseStore(hStore, 0);
        hStore = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolGetEKCert()", hr);
    return hr;
}

HRESULT
PcpToolAddEKCert(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Add an EKCert to the EKCert store. The cert is persistent in the registry
certificate store. An enterprise may create their own EK certificates to indicate
that it is an enterprise asset.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR certFile = NULL;
    PBYTE pbEkCert = NULL;
    UINT32 cbEkCert = 0;
    PCCERT_CONTEXT pcCertContext = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    HCERTSTORE hStore = NULL;
    DWORD cbhStore = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: cert file
    if(argc > 2)
    {
        certFile = argv[2];

        if(FAILED(hr = PcpToolReadFile(
                            certFile,
                            NULL,
                            0,
                            &cbEkCert)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbEkCert, cbEkCert)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                            certFile,
                            pbEkCert,
                            cbEkCert,
                            &cbEkCert)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [cert file]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Open Certificate and create context
    if((pcCertContext = CertCreateCertificateContext(
                                                X509_ASN_ENCODING |
                                                PKCS_7_ASN_ENCODING,
                                                pbEkCert,
                                                cbEkCert)) == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Get EKCert store
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                            &hProv,
                            MS_PLATFORM_CRYPTO_PROVIDER,
                            0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                            hProv,
                            NCRYPT_PCP_EKCERT_PROPERTY,
                            (PBYTE)&hStore,
                            sizeof(hStore),
                            &cbhStore,
                            0))))
    {
        goto Cleanup;
    }

    // Open Certificate and create context
    if(!CertAddCertificateContextToStore(
                                hStore,
                                pcCertContext,
                                CERT_STORE_ADD_ALWAYS,
                                NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    wprintf(L"Ok.\n");

Cleanup:
    if(pcCertContext != NULL)
    {
        CertFreeCertificateContext(pcCertContext);
        pcCertContext = NULL;
    }
    if(hStore != NULL)
    {
        CertCloseStore(hStore, 0);
        hStore = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbEkCert, cbEkCert);
    PcpToolCallResult(L"PcpToolAddEKCert()", hr);
    return hr;
}

HRESULT
PcpToolExtractEK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Retrieve the EKPub from the EKCert as BCRYPT_RSAKEY_BLOB structure. This code
is used on the server side after the EKCert has been validated and deemed
trustworthy.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR certFile = NULL;
    PCWSTR ekPubFile = NULL;
    PCCERT_CONTEXT pcCertContext = NULL;
    PBYTE pbEkCert = NULL;
    UINT32 cbEkCert = 0;
    BCRYPT_KEY_HANDLE hEK = NULL;
    BYTE pbEkPub[1024] = {0};
    DWORD cbEkPub = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: cert file
    if(argc > 2)
    {
        certFile = argv[2];

        if(FAILED(hr = PcpToolReadFile(
                            certFile,
                            NULL,
                            0,
                            &cbEkCert)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbEkCert, cbEkCert)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                            certFile,
                            pbEkCert,
                            cbEkCert,
                            &cbEkCert)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [cert file] {key file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: EKpub file
    if(argc > 3)
    {
        ekPubFile = argv[3];
    }

    // Open Certificate
    if((pcCertContext = CertCreateCertificateContext(
                                    X509_ASN_ENCODING |
                                    PKCS_7_ASN_ENCODING,
                                    pbEkCert,
                                    cbEkCert)) == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }


    // Since this is a PKCS_RSAES_OAEP_PARAMETERS encoded public key
    // that is not directly consumed by Windows, we have to tinker with it
    // a little so Windows will ignore the OAEP OCTET_STRING in it and just
    // process the RSA public key.
    pcCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId = szOID_RSA_RSA;

    // Instantiate the key from the cert
    if(!CryptImportPublicKeyInfoEx2(
                               X509_ASN_ENCODING,
                               &pcCertContext->pCertInfo->SubjectPublicKeyInfo,
                               0,
                               NULL,
                               &hEK))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Export the public key
    if(FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(
                                hEK,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                pbEkPub,
                                sizeof(pbEkPub),
                                &cbEkPub,
                                0))))
    {
        goto Cleanup;
    }

    // Store the key
    if(ekPubFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(ekPubFile, pbEkPub, cbEkPub)))
        {
            goto Cleanup;
        }
    }

    // Output results
    PcpToolDisplayKey(L"EndorsementKey", pbEkPub, cbEkPub, 0);

Cleanup:
    if(pcCertContext != NULL)
    {
        CertFreeCertificateContext(pcCertContext);
        pcCertContext = NULL;
    }
    if(hEK != NULL)
    {
        BCryptDestroyKey(hEK);
        hEK = NULL;
    }
    ZeroAndFree((PVOID*)&pbEkCert, cbEkCert);
    PcpToolCallResult(L"PcpToolExtractEK()", hr);
    return hr;
}

HRESULT
PcpToolGetRandom(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Obtain entropy from the TPM. Optionally stir the entropy generator in the TPM.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    PBYTE pbRandom = NULL;
    UINT32 cbRandom = 0;
    UINT32 cbSeedLen = 0;
    DWORD dwFlags = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: Size of random buffer
    if(argc > 2)
    {
        if(swscanf_s(argv[2], L"%u", &cbRandom) == 0)
        {
            wprintf(L"%s %s [size] {seed data} {output file}\n", argv[0], argv[1]);
            goto Cleanup;
        }

        if(FAILED(hr = AllocateAndZero((PVOID*)&pbRandom, cbRandom)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [size] {seed data} {output file}\n", argv[0], argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional Parameter: Seed value
    if(argc > 3)
    {
        cbSeedLen = (UINT32)wcslen(argv[3]) * sizeof(WCHAR);
        if(cbSeedLen > 0)
        {
            if((UINT32)cbSeedLen <= cbRandom)
            {
                if(memcpy_s(pbRandom, cbRandom, argv[3], cbSeedLen))
                {
                    hr = E_FAIL;
                    goto Cleanup;
                }
            }
            else
            {
                if(memcpy_s(pbRandom, cbRandom, argv[3], cbRandom))
                {
                    hr = E_FAIL;
                    goto Cleanup;
                }
            }
            dwFlags = BCRYPT_RNG_USE_ENTROPY_IN_BUFFER;
        }
    }

    if(argc > 4)
    {
        fileName = argv[4];
    }

    // Fill the buffer with entropy
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                &hAlg,
                                BCRYPT_RNG_ALGORITHM,
                                MS_PRIMITIVE_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_NT(BCryptGenRandom(hAlg,
                                pbRandom,
                                cbRandom,
                                dwFlags))))
    {
        goto Cleanup;
    }

    if((fileName != NULL) &&
       (FAILED(hr = PcpToolWriteFile(fileName, pbRandom, cbRandom))))
    {
        goto Cleanup;
    }

    // Output the result
    wprintf(L"<Random size=\"%u\">\n  ", cbRandom);
    for(UINT32 n = 0; n < cbRandom; n++)
    {
        wprintf(L"%02x", pbRandom[n]);
    }
    wprintf(L"\n</Random>\n");

Cleanup:
    ZeroAndFree((PVOID*)&pbRandom, cbRandom);
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    PcpToolCallResult(L"PcpToolGetRandom()", hr);
    return hr;
}

HRESULT
PcpToolGetRandomPcrs(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Obtain entropy from the TPM. Optionally stir the entropy generator in the TPM. 
Generate the required number of random bytes for a PCR table.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    PBYTE pbRandom = NULL;
    UINT32 cbRandom = 0;
    UINT32 cbSeedLen = 0;
    DWORD dwFlags = 0;
    UINT16 pcrAlgorithm = TPM_API_ALG_ID_SHA1;
    UINT32 digestSize = SHA1_DIGEST_SIZE;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional Parameter: PCR algorithm ID
    if (argc > 2)
    {
        if (wcslen(argv[2]) == 0)
        {
            if (FAILED(GetActivePcrAlgorithm(&pcrAlgorithm)))
            {
                goto Cleanup;
            }
        }
        else
        {
            int argument = 0; // need int for scanf("%x")
            if (swscanf_s(argv[7], L"%x", &argument) == 0)
            {
                wprintf(L"%s %s {pcrAlgorithm} {seed data} {output file}\n",
                        argv[0],
                        argv[1]);
                goto Cleanup;
            }
            pcrAlgorithm = (UINT16)argument;
        }
        // sanity check:
        if (pcrAlgorithm != TPM_API_ALG_ID_SHA1 &&   // SHA1
            pcrAlgorithm != TPM_API_ALG_ID_SHA256)     // SHA256
        {
            wprintf(L"%s %s {pcrAlgorithm = either 4 or B} {seed data} {output file}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
    }
    else if (FAILED(GetActivePcrAlgorithm(&pcrAlgorithm)))
    {
        goto Cleanup;
    }

    if (pcrAlgorithm == TPM_API_ALG_ID_SHA1)
    {
        digestSize = SHA1_DIGEST_SIZE;
        cbRandom = TPM_AVAILABLE_PLATFORM_PCRS * digestSize;
    }
    else if (pcrAlgorithm == TPM_API_ALG_ID_SHA256)
    {
        digestSize = SHA256_DIGEST_SIZE;
        cbRandom = TPM_AVAILABLE_PLATFORM_PCRS * digestSize;
    }

    if(FAILED(hr = AllocateAndZero((PVOID*)&pbRandom, cbRandom)))
    {
        goto Cleanup;
    }

    // Optional Parameter: Seed value
    if(argc > 3)
    {
        cbSeedLen = (UINT32)wcslen(argv[3]) * sizeof(WCHAR);
        if(cbSeedLen > 0)
        {
            if((UINT32)cbSeedLen <= cbRandom)
            {
                if(memcpy_s(pbRandom, cbRandom, argv[3], cbSeedLen))
                {
                    hr = E_FAIL;
                    goto Cleanup;
                }
            }
            else
            {
                if(memcpy_s(pbRandom, cbRandom, argv[3], cbRandom))
                {
                    hr = E_FAIL;
                    goto Cleanup;
                }
            }
            dwFlags = BCRYPT_RNG_USE_ENTROPY_IN_BUFFER;
        }
    }

    if(argc > 4)
    {
        fileName = argv[4];
    }

    // Fill the buffer with entropy
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                &hAlg,
                                BCRYPT_RNG_ALGORITHM,
                                MS_PRIMITIVE_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_NT(BCryptGenRandom(hAlg,
                                pbRandom,
                                cbRandom,
                                dwFlags))))
    {
        goto Cleanup;
    }

    if((fileName != NULL) &&
       (FAILED(hr = PcpToolWriteFile(fileName, pbRandom, cbRandom))))
    {
        goto Cleanup;
    }

    // Output the result
    wprintf(L"<RandomPCRs>\n");
    for(UINT32 n = 0; n < TPM_AVAILABLE_PLATFORM_PCRS; n++)
    {
        PcpToolLevelPrefix(1);
        wprintf(L"<PCR Index=\"%02u\">", n);
        for(UINT32 m = 0; m < digestSize; m++)
        {
            wprintf(L"%02x", pbRandom[n * digestSize + m]);
        }
        wprintf(L"</PCR>\n");
    }
    wprintf(L"</RandomPCRs>\n");

Cleanup:
    ZeroAndFree((PVOID*)&pbRandom, cbRandom);
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    PcpToolCallResult(L"PcpToolGetRandomPcrs()", hr);
    return hr;
}

HRESULT
PcpToolGetSRK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
/*++
Retrieve the SRKPub from the TPM as BCRYPT_RSAKEY_BLOB structure. This key may
be used to wrap a key for the TPM remotely with PcpToolImportKeyHostage().
--*/
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    BYTE pbSrkPub[1024] = {0};
    DWORD cbSrkPub = 0;

    // Optional parameter: Export file for public key
    if(argc > 2)
    {
        fileName = argv[2];
    }

    // Open provider and read SRKPub
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                hProv,
                                NCRYPT_PCP_SRKPUB_PROPERTY,
                                pbSrkPub,
                                sizeof(pbSrkPub),
                                &cbSrkPub,
                                0))))
    {
        goto Cleanup;
    }

    // Store key if requested
    if(fileName != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(fileName, pbSrkPub, cbSrkPub)))
        {
            goto Cleanup;
        }
    }

    // Output result
    if(FAILED(hr = PcpToolDisplayKey(L"StorageRootKey", pbSrkPub, cbSrkPub, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolGetSRK()", hr);
    return hr;
}

HRESULT
PcpToolGetLog(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Obtain the current Windows Boot Configuration Log (WBCL) for the platform. This
log can be used to calculate the PCRs in the TPM.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    TBS_HCONTEXT hContext = NULL;
    TBS_CONTEXT_PARAMS2 contextParams = {0};
    TPM_DEVICE_INFO deviceInfo = {0};
    PBYTE pbLog = NULL;
    UINT32 cbLog = 0;
    PWSTR TpmVersion[] = {L"TPM_VERSION_UNKNOWN",
                          L"TPM_VERSION_12",
                          L"TPM_VERSION_20"};
    const UINT32 TpmVersionCount = 3;
    PWSTR TpmIFType[] = {L"TPM_IFTYPE_UNKNOWN",
                         L"TPM_IFTYPE_1",
                         L"TPM_IFTYPE_TRUSTZONE",
                         L"TPM_IFTYPE_HW",
                         L"TPM_IFTYPE_EMULATOR"};
    const UINT32 TpmIFTypeCount = 5;

    // Optional parameter: Export file for log
    if(argc > 2)
    {
        fileName = argv[2];
    }

    // Open TBS and read the current log
    contextParams.version = TBS_CONTEXT_VERSION_TWO;
    contextParams.asUINT32 = 0;
    contextParams.includeTpm12 = 1;
    contextParams.includeTpm20 = 1;
    if(FAILED(hr = Tbsi_Context_Create((PTBS_CONTEXT_PARAMS)&contextParams, &hContext)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = Tbsi_GetDeviceInfo(sizeof(deviceInfo), &deviceInfo)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = Tbsi_Get_TCG_Log(hContext, NULL, &cbLog)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbLog, cbLog)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = Tbsi_Get_TCG_Log(hContext, pbLog, &cbLog)))
    {
        goto Cleanup;
    }

    // Write log to file if requested
    if(fileName != NULL)
    {
       if(FAILED(hr = PcpToolWriteFile(fileName, pbLog, cbLog)))
        {
            goto Cleanup;
        }
    }

    wprintf(L"<PlatformInfo>\n");
    if(deviceInfo.structVersion == 1)
    {
        PcpToolLevelPrefix(1);
        wprintf(L"<DeviceInfo>\n");
        PcpToolLevelPrefix(2);
        wprintf(L"<TPMVersion>%s</TPMVersion>\n", deviceInfo.tpmVersion < TpmVersionCount ? TpmVersion[deviceInfo.tpmVersion] : TpmVersion[0]);
        PcpToolLevelPrefix(2);
        wprintf(L"<TPMInterfaceType>%s</TPMInterfaceType>\n", deviceInfo.tpmInterfaceType < TpmIFTypeCount ? TpmIFType[deviceInfo.tpmInterfaceType] : TpmIFType[0]);
        PcpToolLevelPrefix(2);
        wprintf(L"<TPMImplementationRevision>%d</TPMImplementationRevision>\n", deviceInfo.tpmImpRevision);
        PcpToolLevelPrefix(1);
        wprintf(L"</DeviceInfo>\n");
    }
    else
    {
        PcpToolLevelPrefix(1);
        wprintf(L"<DeviceInfo>INVALID</DeviceInfo>\n");
    }

    // Output result
    if(FAILED(hr = PcpToolDisplayLog(pbLog, cbLog, 1)))
    {
        goto Cleanup;
    }
    wprintf(L"</PlatformInfo>\n");

Cleanup:
    if (hContext != NULL)
    {
        Tbsip_Context_Close(hContext);
        hContext = NULL;
    }
    ZeroAndFree((PVOID*)&pbLog, cbLog);
    PcpToolCallResult(L"PcpToolGetLog()", hr);
    return hr;
}

HRESULT
PcpToolDecodeLog(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Decode an archived WBCL (for example from %SystemRoot%\Logs\MeasuredBoot). This
log can be used to calculate the PCRs in the TPM which may be validated with a
Quote in the log.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    PBYTE pbLog = NULL;
    UINT32 cbLog = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Log file
    if(argc > 2)
    {
        fileName = argv[2];
        if(FAILED(hr = PcpToolReadFile(fileName, NULL, 0, &cbLog)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbLog, cbLog)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(fileName, pbLog, cbLog, &cbLog)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [log file]\n", argv[0], argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Output result
    if(FAILED(hr = PcpToolDisplayLog(pbLog, cbLog, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    ZeroAndFree((PVOID*)&pbLog, cbLog);
    PcpToolCallResult(L"PcpToolDecodeLog()", hr);
    return hr;
}

HRESULT
PcpToolCreateKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function will create a key on the KSP. Optionally it may be created with a
usageAuth value and a migrationAuth
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PCWSTR usageAuth = NULL;
    PCWSTR migrationAuth = NULL;
    PCWSTR pcrsName = NULL;
    PBYTE pbPcrTable = NULL;
    UINT32 cbPcrTable = 0;
    UINT32 pcrMask = 0;
    BYTE pbKeyPub[1024] = {0};
    DWORD cbKeyPub = 0;
    BOOLEAN tUIRequested = false;
    LPCWSTR optionalPIN = L"This key requires usage consent and an optional PIN.";
    LPCWSTR mandatoryPIN = L"This key has a mandatory PIN.";
    NCRYPT_UI_POLICY rgbUiPolicy = {1, 0, L"PCPTool", NULL, NULL};
    UINT16 pcrAlgorithm = TPM_API_ALG_ID_SHA1;
    UINT32 numberOfPcrs;
    UINT32 currentPcr;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key Name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] {usageAuth} {migrationAuth} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                argv[0],
                argv[1]);
       hr = E_INVALIDARG;
       goto Cleanup;
    }

    // Optional parameter: usageAuth
    if((argc > 3) && (argv[3] != NULL) && (wcslen(argv[3]) != 0))
    {
        usageAuth = argv[3];
        if(!wcscmp(usageAuth, L"@"))
        {
            // Caller requested UI
            usageAuth = NULL;
            tUIRequested = TRUE;
            rgbUiPolicy.pszFriendlyName = keyName;
            rgbUiPolicy.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG;
            rgbUiPolicy.pszDescription = optionalPIN;
        }
        else if(!wcscmp(usageAuth, L"!"))
        {
            // Caller requested UI
            usageAuth = NULL;
            tUIRequested = TRUE;
            rgbUiPolicy.pszFriendlyName = keyName;
            rgbUiPolicy.dwFlags = NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;
            rgbUiPolicy.pszDescription = mandatoryPIN;
        }
    }

    // Optional parameter: migrationAuth
    if((argc > 4) && (argv[4] != NULL) && (wcslen(argv[4]) != 0))
    {
        migrationAuth = argv[4];
    }

    // Optional parameter: pcrMask
    if(argc > 5)
    {
        if(swscanf_s(argv[5], L"%x", &pcrMask) == 0)
        {
            wprintf(L"%s %s [key name] {usageAuth} {migrationAuth} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
    }

    // Optional parameter: pcrTable
    if(argc > 6)
    {
        pcrsName = argv[6];
        if(FAILED(hr = PcpToolReadFile(
                                pcrsName,
                                NULL,
                                0,
                                &cbPcrTable)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbPcrTable, cbPcrTable)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                                pcrsName,
                                pbPcrTable,
                                cbPcrTable,
                                &cbPcrTable)))
        {
            goto Cleanup;
        }
    }

    // Optional parameter: pcrAlgorithm
    if (argc > 7)
    {
        int argument = 0; // need int for scanf("%x")
        if (swscanf_s(argv[7], L"%x", &argument) == 0)
        {
            wprintf(L"%s %s [key name] {usageAuth} {migrationAuth} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
        pcrAlgorithm = (UINT16)argument;
        // sanity check:
        if (pcrAlgorithm != TPM_API_ALG_ID_SHA1 &&   // SHA1
            pcrAlgorithm != TPM_API_ALG_ID_SHA256)     // SHA256
        {
            wprintf(L"%s %s [key name] {usageAuth} {migrationAuth} {pcrMask} {pcrs} {pcrAlgorithm = either 4 or B}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
    }
    else if (pbPcrTable != NULL)
    {
        numberOfPcrs = TPM_AVAILABLE_PLATFORM_PCRS;
        if (pcrMask != 0)
        {
            // count the number of PCRs that are supposed to be in the PCR table
            numberOfPcrs = 0;
            for (currentPcr = 1; currentPcr < pcrMask; currentPcr <<= 1)
            {
                if ((pcrMask & currentPcr) != 0)
                {
                    numberOfPcrs++;
                }
            }
        }
        if (numberOfPcrs * SHA256_DIGEST_SIZE == cbPcrTable)
        {
            pcrAlgorithm = TPM_API_ALG_ID_SHA256;
        }
        else if (TPM_AVAILABLE_PLATFORM_PCRS * SHA256_DIGEST_SIZE == cbPcrTable)
        {
            // pcrMask may contain less PCRs than are in PCR file
            // if PCR file has been generated by PCPTool it contains 24 PCRs
            pcrAlgorithm = TPM_API_ALG_ID_SHA256;
        }
    }
    else if (pcrMask != 0)
    {
        // if no pcrAlgorithm nor pcrTable are given, the current active PCR values 
        // are used. Because PCP KSP does not select PCR bank automatically, detect 
        // it here and set it explicitly.
        if (FAILED(GetActivePcrAlgorithm(&pcrAlgorithm)))
        {
            goto Cleanup;
        }
    }

    // Create the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptCreatePersistedKey(
                                hProv,
                                &hKey,
                                BCRYPT_RSA_ALGORITHM,
                                keyName,
                                0,
                                NCRYPT_OVERWRITE_KEY_FLAG))))
    {
        goto Cleanup;
    }

    if(tUIRequested == FALSE)
    {
        if((usageAuth != NULL) && (wcslen(usageAuth) != 0))
        {
            if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                        hKey,
                                        NCRYPT_PIN_PROPERTY,
                                        (PBYTE)usageAuth,
                                        (DWORD)((wcslen(usageAuth) + 1) * sizeof(WCHAR)),
                                        0))))
            {
                goto Cleanup;
            }
        }
    }
    else
    {
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                    hKey,
                                    NCRYPT_UI_POLICY_PROPERTY,
                                    (PBYTE)&rgbUiPolicy,
                                    sizeof(NCRYPT_UI_POLICY),
                                    0))))
        {
            goto Cleanup;
        }
    }

    if((migrationAuth != NULL) && (wcslen(migrationAuth) != 0))
    {
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                    hKey,
                                    NCRYPT_PCP_MIGRATIONPASSWORD_PROPERTY,
                                    (PBYTE)migrationAuth,
                                    (DWORD)((wcslen(migrationAuth) + 1) * sizeof(WCHAR)),
                                    0))))
        {
            goto Cleanup;
        }
    }

    if(pcrMask != 0)
    {
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                    hKey,
                                    NCRYPT_PCP_PLATFORM_BINDING_PCRMASK_PROPERTY,
                                    (PBYTE)&pcrMask,
                                    0x00000003,
                                    0))))
        {
            goto Cleanup;
        }
        // default PCR algorithm stored in BCrypt for the key is SHA1
        // have to set it to SHA256 if we are using SHA256 PCRs
        if (pcrAlgorithm != TPM_API_ALG_ID_SHA1)
        {
            if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                        hKey,
                                        NCRYPT_PCP_PLATFORM_BINDING_PCRALGID_PROPERTY,
                                        (PBYTE)&pcrAlgorithm,
                                        sizeof(pcrAlgorithm),
                                        0))))
            {
                goto Cleanup;
            }
        }
        if(pbPcrTable != NULL)
        {
            if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                        hKey,
                                        NCRYPT_PCP_PLATFORM_BINDING_PCRDIGESTLIST_PROPERTY,
                                        pbPcrTable,
                                        cbPcrTable,
                                        0))))
            {
                goto Cleanup;
            }
        }
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptFinalizeKey(hKey, 0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(hKey,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                NULL,
                                pbKeyPub,
                                sizeof(pbKeyPub),
                                &cbKeyPub,
                                0))))
    {
        goto Cleanup;
    }

    // Output results
    if(FAILED(hr = PcpToolDisplayKey(keyName, pbKeyPub, cbKeyPub, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbPcrTable, cbPcrTable);
    PcpToolCallResult(L"PcpToolCreateKey()", hr);
    return hr;
}

HRESULT
PcpToolCreateAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function will create an AIK. The AIK is completely usable after creation.
If strong remote trust has to be established in that key for platform or key
attestation for example, the AIK handshake has to be used.

This is the second step in the AIK handshake: Step one is a nonce that is
randomly generated by the validator of the AIK. In this step the client creates
the key and Identity Binding, that is the proof of possession.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    DWORD dwKeyUsage = NCRYPT_PCP_IDENTITY_KEY;
    PCWSTR keyName = NULL;
    PCWSTR idBindingFile = NULL;
    PCWSTR nonce = NULL;
    PCWSTR usageAuth = NULL;
    BYTE pbIdBinding[1024] = {0};
    DWORD cbIdBinding = 0;
    BYTE pbAikPub[1024] = {0};
    DWORD cbAikPub = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = {0};
    UINT32 result = 0;
    BOOLEAN tUIRequested = false;
    LPCWSTR optionalPIN = L"This AIK requires usage consent and an optional PIN.";
    LPCWSTR mandatoryPIN = L"This AIK has a mandatory a PIN.";
    NCRYPT_UI_POLICY rgbUiPolicy = {1, 0, L"PCPTool", NULL, NULL};

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key Name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] {idBinding file} {nonce} {usageAuth}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: File to store IdBinding
    if((argc > 3) && (argv[3] != NULL) && (wcslen(argv[3]) != 0))
    {
        idBindingFile = argv[3];
    }

    // Optional parameter: nonce
    if((argc > 4) && (argv[4] != NULL) && (wcslen(argv[4]) != 0))
    {
        nonce = argv[4];
        if(FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                                    NULL,
                                                    0,
                                                    (PBYTE)nonce,
                                                    (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
                                                    nonceDigest,
                                                    sizeof(nonceDigest),
                                                    &result)))
        {
            goto Cleanup;
        }
    }

    // Optional parameter: usageAuth
    if((argc > 5) && (argv[5] != NULL) && (wcslen(argv[5]) != 0))
    {
        usageAuth = argv[5];
        if(!wcscmp(usageAuth, L"@"))
        {
            // Caller requested UI
            usageAuth = NULL;
            tUIRequested = TRUE;
            rgbUiPolicy.pszFriendlyName = keyName;
            rgbUiPolicy.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG;
            rgbUiPolicy.pszDescription = optionalPIN;
        }
        else if(!wcscmp(usageAuth, L"!"))
        {
            // Caller requested UI
            usageAuth = NULL;
            tUIRequested = TRUE;
            rgbUiPolicy.pszFriendlyName = keyName;
            rgbUiPolicy.dwFlags = NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;
            rgbUiPolicy.pszDescription = mandatoryPIN;
        }
    }

    // Create the AIK
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptCreatePersistedKey(
                                hProv,
                                &hKey,
                                BCRYPT_RSA_ALGORITHM,
                                keyName,
                                0,
                                NCRYPT_OVERWRITE_KEY_FLAG))))
    {
        goto Cleanup;
    }

    if(tUIRequested == FALSE)
    {
        if((usageAuth != NULL) && (wcslen(usageAuth) != 0))
        {
            if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                        hKey,
                                        NCRYPT_PIN_PROPERTY,
                                        (PBYTE)usageAuth,
                                        (DWORD)((wcslen(usageAuth) + 1) * sizeof(WCHAR)),
                                        0))))
            {
                goto Cleanup;
            }
        }
    }
    else
    {
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                    hKey,
                                    NCRYPT_UI_POLICY_PROPERTY,
                                    (PBYTE)&rgbUiPolicy,
                                    sizeof(NCRYPT_UI_POLICY),
                                    0))))
        {
            goto Cleanup;
        }
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                hKey,
                                NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                                (PBYTE)&dwKeyUsage,
                                sizeof(dwKeyUsage),
                                0))))
    {
        goto Cleanup;
    }

    if(nonce != NULL)
    {
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(hKey,
                                      NCRYPT_PCP_TPM12_IDBINDING_PROPERTY,
                                      nonceDigest,
                                      sizeof(nonceDigest),
                                      0))))
        {
            goto Cleanup;
        }
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptFinalizeKey(hKey, 0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                hKey,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                NULL,
                                pbAikPub,
                                sizeof(pbAikPub),
                                &cbAikPub,
                                0))))
    {
        goto Cleanup;
    }

    // Store the IdBinding
    if(idBindingFile != NULL)
    {
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(hKey,
                                      NCRYPT_PCP_TPM12_IDBINDING_PROPERTY,
                                      pbIdBinding,
                                      sizeof(pbIdBinding),
                                      &cbIdBinding,
                                      0))))
        {
            goto Cleanup;
        }

        if(FAILED(hr = PcpToolWriteFile(
                                idBindingFile,
                                pbIdBinding,
                                cbIdBinding)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"<AIK>\n");
    if(FAILED(hr = PcpToolDisplayKey(keyName, pbAikPub, cbAikPub, 1)))
    {
        goto Cleanup;
    }
    PcpToolLevelPrefix(1);
    wprintf(L"<IdentityBinding size=\"%u\">", cbIdBinding);
    for(UINT32 n = 0; n < cbIdBinding; n++)
    {
        wprintf(L"%02x", pbIdBinding[n]);
    }
    wprintf(L"</IdentityBinding>\n");
    wprintf(L"</AIK>\n");

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolCreateAIK()", hr);
    return hr;
}

HRESULT
PcpToolGetPubAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Export the public portion from an AIK as
BCRYPT_RSAKEY_BLOB structure.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR idBindingFile = NULL;
    PBYTE pbIdBinding = NULL;
    UINT32 cbIdBinding = 0;
    BCRYPT_ALG_HANDLE hProv = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyFile = NULL;
    BYTE pbPubKey[1024] = {0};
    DWORD cbPubKey = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: IdBinding
    if(argc > 2)
    {
        idBindingFile = argv[2];
        if(FAILED(hr = PcpToolReadFile(
                            idBindingFile,
                            NULL,
                            0,
                            &cbIdBinding)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbIdBinding, cbIdBinding)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(idBindingFile,
                                       pbIdBinding,
                                       cbIdBinding,
                                       &cbIdBinding)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [idBinding file] {key File}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Export file
    if(argc > 3)
    {
        keyFile = argv[3];
    }

    // Open key
    if(FAILED(hr = BCryptOpenAlgorithmProvider(
                                &hProv,
                                BCRYPT_RSA_ALGORITHM,
                                NULL,
                                0)))
    {
        goto Cleanup;
    }

    if(FAILED(hr = TpmAttPubKeyFromIdBinding(
                                pbIdBinding,
                                cbIdBinding,
                                hProv,
                                &hKey)))
    {
        goto Cleanup;
    }

    // Export public key
    if(FAILED(hr = BCryptExportKey(
                                hKey,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                pbPubKey,
                                sizeof(pbPubKey),
                                &cbPubKey,
                                0)))
    {
        goto Cleanup;
    }

    // Export key
    if(keyFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(keyFile, pbPubKey, cbPubKey)))
        {
            goto Cleanup;
        }
    }

    // Output results
    if(FAILED(hr = PcpToolDisplayKey(L"AIK", pbPubKey, cbPubKey, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if(hKey != NULL)
    {
        BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        BCryptCloseAlgorithmProvider(hProv, 0);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbIdBinding, cbIdBinding);
    PcpToolCallResult(L"PcpToolGetPubAIK()", hr);
    return hr;
}

HRESULT
PcpToolChallengeAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function is the third step in what is known as the AIK handshake and
executed on the server. The server will have already looked at the EKCert and
extracted the EKPub from it. This step will generate the activation blob, which
is the challenge to the client. The secret may be a nonce or a symmetric key
that encrypts a certificate for the AIK for example.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR idBindingFile = NULL;
    PCWSTR ekPubFile = NULL;
    PCWSTR activationSecret = NULL;
    PCWSTR activationBlobFile = NULL;
    PCWSTR nonce = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hEK = NULL;
    BCRYPT_KEY_HANDLE hAik = NULL;
    PBYTE pbIdBinding = NULL;
    UINT32 cbIdBinding = 0;
    PBYTE pbEkPub = NULL;
    UINT32 cbEkPub = 0;
    PBYTE pbAikPub = NULL;
    UINT32 cbAikPub = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = {0};
    PBYTE pbActivationBlob = NULL;
    UINT32 cbActivationBlob = 0;
    UINT32 result = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: IdBinding
    if(argc > 2)
    {
        idBindingFile = argv[2];
        if(FAILED(hr = PcpToolReadFile(
                            idBindingFile,
                            NULL,
                            0,
                            &cbIdBinding)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbIdBinding, cbIdBinding)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(idBindingFile,
                                       pbIdBinding,
                                       cbIdBinding,
                                       &cbIdBinding)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [idBinding file] [EKPub File] [secret] {Blob file} {nonce}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: EKPub
    if(argc > 3)
    {
        ekPubFile = argv[3];
        if(FAILED(hr = PcpToolReadFile(ekPubFile, NULL, 0, &cbEkPub)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbEkPub, cbEkPub)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(ekPubFile,
                                       pbEkPub,
                                       cbEkPub,
                                       &cbEkPub)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [idBinding file] [EKPub File] [secret] {Blob file} {nonce}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: Activation secret
    if(argc > 4)
    {
        activationSecret = argv[4];
    }
    else
    {
        wprintf(L"%s %s [idBinding file] [EKPub File] [secret] {Blob file} {nonce}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Activation blob
    if(argc > 5)
    {
        activationBlobFile = argv[5];
    }

    // Optional parameter: Nonce
    if(argc > 6)
    {
        nonce = argv[6];
        if(FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                                    NULL,
                                                    0,
                                                    (PBYTE)nonce,
                                                    (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
                                                    nonceDigest,
                                                    sizeof(nonceDigest),
                                                    &result)))
        {
            goto Cleanup;
        }
    }

    // Load the keys
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                &hAlg,
                                BCRYPT_RSA_ALGORITHM,
                                MS_PRIMITIVE_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
                                hAlg,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                &hEK,
                                pbEkPub,
                                cbEkPub,
                                0))))
    {
        goto Cleanup;
    }

    // Get a handle to the AIK and export it
    if(FAILED(hr = TpmAttPubKeyFromIdBinding(
                        pbIdBinding,
                        cbIdBinding,
                        hAlg,
                        &hAik)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(
                                hAik,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                NULL,
                                0,
                                (PULONG)&cbAikPub,
                                0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbAikPub, cbAikPub)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(
                                hAik,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                pbAikPub,
                                cbAikPub,
                                (PULONG)&cbAikPub,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = TpmAttGenerateActivation(
                        hEK,
                        pbIdBinding,
                        cbIdBinding,
                        (nonce) ? nonceDigest : NULL,
                        (nonce) ? sizeof(nonceDigest) : 0,
                        (PBYTE)activationSecret,
                        (UINT16)((wcslen(activationSecret) + 1) *
                            sizeof(WCHAR)),
                        NULL,
                        0,
                        &cbActivationBlob)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbActivationBlob, cbActivationBlob)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = TpmAttGenerateActivation(
                        hEK,
                        pbIdBinding,
                        cbIdBinding,
                        (nonce) ? nonceDigest : NULL,
                        (nonce) ? sizeof(nonceDigest) : 0,
                        (PBYTE)activationSecret,
                        (UINT16)((wcslen(activationSecret) + 1) *
                            sizeof(WCHAR)),
                        pbActivationBlob,
                        cbActivationBlob,
                        &cbActivationBlob)))
    {
        goto Cleanup;
    }

    // Store the activation if required
    if(idBindingFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(
                                activationBlobFile,
                                pbActivationBlob,
                                cbActivationBlob)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"<Activation>\n");
    if(FAILED(hr = PcpToolDisplayKey(L"AIK", pbAikPub, cbAikPub, 1)))
    {
        goto Cleanup;
    }
    PcpToolLevelPrefix(1);
    wprintf(L"<ActivationBlob size=\"%u\">\n", cbActivationBlob);
    PcpToolLevelPrefix(2);
    for(UINT32 n = 0; n < cbActivationBlob; n++)
    {
        wprintf(L"%02x", pbActivationBlob[n]);
    }
    wprintf(L"\n");
    PcpToolLevelPrefix(1);
    wprintf(L"</ActivationBlob>\n");
    wprintf(L"</Activation>\n");

Cleanup:
    if(hEK != NULL)
    {
        BCryptDestroyKey(hEK);
        hEK = NULL;
    }
    if(hAik != NULL)
    {
        BCryptDestroyKey(hAik);
        hAik = NULL;
    }
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbIdBinding, cbIdBinding);
    ZeroAndFree((PVOID*)&pbEkPub, cbEkPub);
    ZeroAndFree((PVOID*)&pbAikPub, cbAikPub);
    ZeroAndFree((PVOID*)&pbActivationBlob, cbActivationBlob);
    PcpToolCallResult(L"PcpToolChallengeAIK()", hr);
    return hr;
}

HRESULT
PcpToolActivateAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function is the last step in what is known as the AIK handshake. The client
will load the AIK into the TPM and perform the activation to retrieve the secret
challenge. If the specified EK and AIK reside in the same TPM, it will release
the secret. The secret may be a nonce or a symmetric key that protects other
data that may be release if the handshake was successful.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PCWSTR activationFile = NULL;
    PBYTE pbActivationBlob = NULL;
    UINT32 cbActivationBlob = 0;
    BYTE pbSecret[256] = {0};
    DWORD cbSecret = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: AIK name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] [Blob file]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: Activation blob
    if(argc > 3)
    {
        activationFile = argv[3];
        if(FAILED(hr = PcpToolReadFile(activationFile,
                                       NULL,
                                       0,
                                       &cbActivationBlob)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbActivationBlob, cbActivationBlob)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(activationFile,
                                       pbActivationBlob,
                                       cbActivationBlob,
                                       &cbActivationBlob)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [key name] [Blob file]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Open AIK
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                0))))
    {
        goto Cleanup;
    }

    // Perform the activation
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                hKey,
                                NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
                                pbActivationBlob,
                                cbActivationBlob,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                hKey,
                                NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
                                pbSecret,
                                sizeof(pbSecret),
                                &cbSecret,
                                0))))
    {
        goto Cleanup;
    }

    // Output results
    wprintf(L"<Activation>\n");
    PcpToolLevelPrefix(1);
    wprintf(L"<Secret size=\"%u\">%s</Secret>\n", cbSecret, (PWCHAR)pbSecret);
    wprintf(L"</Activation>\n");

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbActivationBlob, cbActivationBlob);
    PcpToolCallResult(L"PcpToolActivateAIK()", hr);
    return hr;
}

HRESULT
PcpToolRegisterAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function will register an AIK in the registry. Every time the machine
boots or resumes from hibernation, it will generate a Quote in the log and make
it permanently trustworthy. There may be multiple keys registered at the same
time and the system will make a Quote with each key. However this may lead
system boot time degradation. An average 1.2 TPM for example requires around
500ms to create a quote in the log.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PBYTE pbAik = NULL;
    UINT32 cbAik = 0;
    HKEY hRegKey = NULL;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: AIK name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Export AIK pub
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                hKey,
                                NULL,
                                BCRYPT_OPAQUE_KEY_BLOB,
                                NULL,
                                NULL,
                                0,
                                (PDWORD)&cbAik,
                                0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbAik, cbAik)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                hKey,
                                NULL,
                                BCRYPT_OPAQUE_KEY_BLOB,
                                NULL,
                                pbAik,
                                cbAik,
                                (PDWORD)&cbAik,
                                0))))
    {
        goto Cleanup;
    }

    // Register AIK for trust point generation
    if(FAILED(hr = HRESULT_FROM_WIN32(RegCreateKeyW(
                                HKEY_LOCAL_MACHINE,
                                TPM_STATIC_CONFIG_QUOTE_KEYS,
                                &hRegKey))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(RegSetValueExW(
                                hRegKey,
                                keyName,
                                NULL,
                                REG_BINARY,
                                pbAik,
                                cbAik))))
    {
        goto Cleanup;
    }

    RegCloseKey(hRegKey);
    hRegKey = NULL;

    // Register AIK for key attestation generation
    if(FAILED(hr = HRESULT_FROM_WIN32(RegCreateKeyW(
                                HKEY_LOCAL_MACHINE,
                                TPM_STATIC_CONFIG_KEYATTEST_KEYS,
                                &hRegKey))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(RegSetValueExW(
                                hRegKey,
                                keyName,
                                NULL,
                                REG_BINARY,
                                pbAik,
                                cbAik))))
    {
        goto Cleanup;
    }

    // Output results
    wprintf(L"Key '%s' registered. OK!\n", keyName);

Cleanup:
    if(hRegKey != NULL)
    {
        RegCloseKey(hRegKey);
        hRegKey = NULL;
    }
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbAik, cbAik);
    PcpToolCallResult(L"PcpToolRegisterAIK()", hr);
    return hr;
}

HRESULT
PcpToolEnumerateAIK(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function show all currently registered AIKs in the registry. Every time the
machine boots or resumes from hibernation, it will generate a Quote in the log
and make it permanently trustworthy. There may be multiple keys registered at
the same time and the system will make a Quote with each key. However this may
lead to system boot time degradation. An average 1.2 TPM for example requires
around 500ms to create a quote in the log.
--*/
{
    HRESULT hr = S_OK;
    WCHAR keyName[256] = L"";
    DWORD cchKeyName = sizeof(keyName) / sizeof(WCHAR);
    DWORD valueType = 0;
    BYTE pbAikPub[1024] = {0};
    DWORD cbAikPub = sizeof(pbAikPub);
    HKEY hRegKey = NULL;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    if(FAILED(hr = HRESULT_FROM_WIN32(RegCreateKeyW(
                                HKEY_LOCAL_MACHINE,
                                TPM_STATIC_CONFIG_QUOTE_KEYS,
                                &hRegKey))))
    {
        goto Cleanup;
    }

    wprintf(L"<RegisteredAIK>\n");
    PcpToolLevelPrefix(1);
    wprintf(L"<PlatformAttestationKeys>\n");
    for(DWORD index = 0; SUCCEEDED(hr); index++)
    {
        cbAikPub = sizeof(pbAikPub);
        cchKeyName = sizeof(keyName) / sizeof(WCHAR);
        hr = HRESULT_FROM_WIN32(RegEnumValueW(
                        hRegKey,
                        index,
                        (LPWSTR)keyName,
                        &cchKeyName,
                        NULL,
                        &valueType,
                        pbAikPub,
                        &cbAikPub));
        if(FAILED(hr))
        {
            if(hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                hr = S_OK;
                break;
            }
            else if (hr != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                goto Cleanup;
            }
        }
        if(valueType == REG_BINARY)
        {
            PcpToolLevelPrefix(2);
            wprintf(L"<QuoteKey name=\"%s\" size=\"%u\">", keyName, cbAikPub);
            for(UINT32 n = 0; n < cbAikPub; n++)
            {
                wprintf(L"%02x", pbAikPub[n]);
            }
            wprintf(L"</QuoteKey>\n");
        }
    }
    PcpToolLevelPrefix(1);
    wprintf(L"</PlatformAttestationKeys>\n");
    RegCloseKey(hRegKey);
    hRegKey = NULL;


    if(FAILED(hr = HRESULT_FROM_WIN32(RegCreateKeyW(
                                HKEY_LOCAL_MACHINE,
                                TPM_STATIC_CONFIG_KEYATTEST_KEYS,
                                &hRegKey))))
    {
        goto Cleanup;
    }
    PcpToolLevelPrefix(1);
    wprintf(L"<KeyAttestationKeys>\n");
    for(DWORD index = 0; SUCCEEDED(hr); index++)
    {
        cbAikPub = sizeof(pbAikPub);
        cchKeyName = sizeof(keyName) / sizeof(WCHAR);
        hr = HRESULT_FROM_WIN32(RegEnumValueW(
                        hRegKey,
                        index,
                        (LPWSTR)keyName,
                        &cchKeyName,
                        NULL,
                        &valueType,
                        pbAikPub,
                        &cbAikPub));
        if(FAILED(hr))
        {
            if(hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                hr = S_OK;
                break;
            }
            else if (hr != HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                goto Cleanup;
            }
        }
        if(valueType == REG_BINARY)
        {
            PcpToolLevelPrefix(2);
            wprintf(L"<QuoteKey name=\"%s\" size=\"%u\">", keyName, cbAikPub);
            for(UINT32 n = 0; n < cbAikPub; n++)
            {
                wprintf(L"%02x", pbAikPub[n]);
            }
            wprintf(L"</QuoteKey>\n");
        }
    }
    PcpToolLevelPrefix(1);
    wprintf(L"</KeyAttestationKeys>\n");
    wprintf(L"</RegisteredAIK>\n");

Cleanup:
    if(hRegKey != NULL)
    {
        RegCloseKey(hRegKey);
        hRegKey = NULL;
    }
    PcpToolCallResult(L"PcpToolEnumerateAIK()", hr);
    return hr;
}

HRESULT
PcpToolEnumerateKeys(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function will enumerate all keys that are held on the PCPKSP for this user
or in the machine context.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCryptKeyName* pKeyName = NULL;
    PVOID pEnumState = NULL;
    DWORD dwFlags[2] = {
                        NCRYPT_SILENT_FLAG | NCRYPT_MACHINE_KEY_FLAG,
                        NCRYPT_SILENT_FLAG };
    NCRYPT_KEY_HANDLE hKey = NULL;
    DWORD dwKeyUsage = NCRYPT_PCP_IDENTITY_KEY;
    DWORD cbRequired = 0;
    DWORD keyLength = 0;
    DWORD exportPolicy = 0;
    BOOLEAN passwordRequired = FALSE;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    wprintf(L"<Keys>\n");
    for(UINT32 n = 0; n < (sizeof(dwFlags) / sizeof(DWORD)); n++)
    {
        hr = S_OK;
        BYTE pubKey[512] = {0};
        BCRYPT_RSAKEY_BLOB* pPubKey = (BCRYPT_RSAKEY_BLOB*) pubKey;
        BYTE pubKeyDigest[SHA1_DIGEST_SIZE] = {0};

        while(SUCCEEDED(hr))
        {
            hr = HRESULT_FROM_WIN32(NCryptEnumKeys(
                            hProv,
                            NULL,
                            &pKeyName,
                            &pEnumState,
                            dwFlags[n]));
            if(FAILED(hr))
            {
                if(hr == HRESULT_FROM_WIN32((ULONG)NTE_NO_MORE_ITEMS))
                {
                    if(pEnumState != NULL)
                    {
                        NCryptFreeBuffer(pEnumState);
                        pEnumState = NULL;
                    }
                    hr = S_OK;
                    break;
                }
                else
                {
                    goto Cleanup;
                }
            }
            else
            {
                if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                            hProv,
                                            &hKey,
                                            pKeyName->pszName,
                                            0,
                    dwFlags[n] & NCRYPT_MACHINE_KEY_FLAG))))
                {
                    wprintf(L"Could not open key: %s (0x%08lx)\n", pKeyName->pszName, hr);
                    if (pKeyName != NULL)
                    {
                        NCryptFreeBuffer(pKeyName);
                        pKeyName = NULL;
                    }
                    hr = S_OK;
                    // Try next key
                    continue;
                }

                if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hKey,
                                            NCRYPT_LENGTH_PROPERTY,
                                            (PBYTE)&keyLength,
                                            sizeof(keyLength),
                                            &cbRequired,
                                            0))))
                {
                    goto Cleanup;
                }

                if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hKey,
                                            NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
                                            (PBYTE)&dwKeyUsage,
                                            sizeof(dwKeyUsage),
                                            &cbRequired,
                                            0))))
                {
                    goto Cleanup;
                }

                if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hKey,
                                            NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY,
                                            (PBYTE)&passwordRequired,
                                            sizeof(passwordRequired),
                                            &cbRequired,
                                            0))))
                {
                    goto Cleanup;
                }

                if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                            hKey,
                                            NCRYPT_EXPORT_POLICY_PROPERTY,
                                            (PBYTE)&exportPolicy,
                                            sizeof(exportPolicy),
                                            &cbRequired,
                                            0))))
                {
                    goto Cleanup;
                }

                if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                            hKey,
                                            NULL,
                                            BCRYPT_RSAPUBLIC_BLOB,
                                            NULL,
                                            pubKey,
                                            sizeof(pubKey),
                                            &cbRequired,
                                            0))))
                {
                    goto Cleanup;
                }
                if((cbRequired < sizeof(BCRYPT_RSAKEY_BLOB)) ||
                   (pPubKey->Magic != BCRYPT_RSAPUBLIC_MAGIC) ||
                   (cbRequired != sizeof(BCRYPT_RSAKEY_BLOB) +
                                  pPubKey->cbPublicExp +
                                  pPubKey->cbModulus +
                                  pPubKey->cbPrime1 +
                                  pPubKey->cbPrime2) ||
                   (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                                            NULL,
                                                            0,
                                                            &pubKey[sizeof(BCRYPT_RSAKEY_BLOB) +
                                                                    pPubKey->cbPublicExp],
                                                            pPubKey->cbModulus,
                                                            pubKeyDigest,
                                                            sizeof(pubKeyDigest),
                                                            (PUINT32)&cbRequired))))
                {
                    hr = E_FAIL;
                    goto Cleanup;
                }

                PcpToolLevelPrefix(1);
                wprintf(L"<Key>\n");
                PcpToolLevelPrefix(2);
                wprintf(L"<Algorithm>%s</Algorithm>\n", pKeyName->pszAlgid);
                PcpToolLevelPrefix(2);
                wprintf(L"<MachineKey>%s</MachineKey>\n",
                        ((dwFlags[n] & NCRYPT_MACHINE_KEY_FLAG) != 0) ?
                         L"TRUE" :
                         L"FALSE");
                PcpToolLevelPrefix(2);
                wprintf(L"<Name>%s</Name>\n",pKeyName->pszName);
                PcpToolLevelPrefix(2);
                wprintf(L"<KeyLength>%u</KeyLength>\n", keyLength);
                PcpToolLevelPrefix(2);
                wprintf(L"<PubKeyDigest>");
                for(UINT32 n = 0; n < sizeof(pubKeyDigest); n++)
                {
                    wprintf(L"%02x", pubKeyDigest[n]);
                }
                wprintf(L"</PubKeyDigest>\n");
                PcpToolLevelPrefix(2);
                switch(dwKeyUsage & 0x0000ffff)
                {
                    case NCRYPT_PCP_SIGNATURE_KEY:
                        wprintf(L"<KeyUsage>SIGNATURE</KeyUsage>\n");
                        break;
                    case NCRYPT_PCP_ENCRYPTION_KEY:
                        wprintf(L"<KeyUsage>ENCRYPTION</KeyUsage>\n");
                        break;
                    case NCRYPT_PCP_GENERIC_KEY:
                        wprintf(L"<KeyUsage>GENERIC</KeyUsage>\n");
                        break;
                    case NCRYPT_PCP_STORAGE_KEY:
                        wprintf(L"<KeyUsage>STORAGE</KeyUsage>\n");
                        break;
                    case NCRYPT_PCP_IDENTITY_KEY:
                        wprintf(L"<KeyUsage>IDENTITY</KeyUsage>\n");
                        break;
                    default:
                        wprintf(L"<KeyUsage>UNKNOWN</KeyUsage>\n");
                        break;
                }
                PcpToolLevelPrefix(2);
                wprintf(L"<PINRequired>%s</PINRequired>\n",
                        passwordRequired ?
                         L"TRUE" :
                         L"FALSE");
                PcpToolLevelPrefix(2);
                wprintf(L"<ExportAllowed>%s</ExportAllowed>\n",
                        (exportPolicy & NCRYPT_ALLOW_EXPORT_FLAG) ?
                         L"TRUE" :
                         L"FALSE");
                PcpToolLevelPrefix(1);
                wprintf(L"</Key>\n");

                NCryptFreeObject(hKey);
                hKey = NULL;
                NCryptFreeBuffer(pKeyName);
                pKeyName = NULL;
            }
        }
    }
    wprintf(L"</Keys>\n");

Cleanup:
    if(pKeyName != NULL)
    {
        NCryptFreeBuffer(pKeyName);
        pKeyName = NULL;
    }
    if(pEnumState != NULL)
    {
        NCryptFreeBuffer(pEnumState);
        pEnumState = NULL;
    }
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolEnumerateKeys()", hr);
    return hr;
}

HRESULT
PcpToolGetUserCertStore(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function will retrieve all certificates that are backed by keys on the PCPKSP for this user.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    HCERTSTORE hStore = NULL;
    DWORD cbhStore = 0;
    PCCERT_CONTEXT pcCertContext = NULL;
    UINT32 certCount = 0;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                            &hProv,
                            MS_PLATFORM_CRYPTO_PROVIDER,
                            0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                            hProv,
                            NCRYPT_USER_CERTSTORE_PROPERTY,
                            (PBYTE)&hStore,
                            sizeof(hStore),
                            &cbhStore,
                            0))))
    {
        goto Cleanup;
    }

    // Count the certs in the returned store
    while((pcCertContext = CertEnumCertificatesInStore(
                                hStore,
                                pcCertContext)) != NULL)
    {
        certCount++;
    }

    if(certCount == 0)
    {
        wprintf(L"No EK Certificates found.\n");
        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
        goto Cleanup;
    }
    else if(certCount == 1)
    {
        // Pick the first and only cert
        if((pcCertContext = CertEnumCertificatesInStore(hStore, NULL)) == NULL)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }

        // Show the cert
        if (FAILED(hr = CryptUIDlgViewContextWrapper(&pcCertContext)))
        {
            goto Cleanup;
        }
    }
    else
    {
        // Have the user select one
        if (FAILED(hr = CryptUIDlgSelectCertificateFromStoreWrapper(&pcCertContext, &hStore)))
        {
            goto Cleanup;
        }
    }
    wprintf(L"OK.\n");

Cleanup:
    if(pcCertContext != NULL)
    {
        CertFreeCertificateContext(pcCertContext);
        pcCertContext = NULL;
    }
    if(hStore != NULL)
    {
        CertCloseStore(hStore, 0);
        hStore = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolGetEKCert()", hr);
    return hr;
}

HRESULT
PcpToolChangeKeyUsageAuth(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Change the useageAuth on a key.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PCWSTR usageAuth = NULL;
    PCWSTR newUsageAuth = NULL;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key Name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] [usageAuth] [newUsageAuth]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: usageAuth
    if(argc > 3)
    {
        usageAuth = argv[3];
    }
    else
    {
        wprintf(L"%s %s [key name] [usageAuth] [newUsageAuth]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: newUsageAuth
    if(argc > 4)
    {
        newUsageAuth = argv[4];
    }
    else
    {
        wprintf(L"%s %s [key name] [usageAuth] [newUsageAuth]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Open the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                0))))
    {
        goto Cleanup;
    }

    // authorize the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                hKey,
                                NCRYPT_PIN_PROPERTY,
                                (PBYTE)usageAuth,
                                (DWORD)((wcslen(usageAuth) + 1) * sizeof(WCHAR)),
                                0))))
    {
        goto Cleanup;
    }

    // change the usageAuth the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                hKey,
                                NCRYPT_PCP_CHANGEPASSWORD_PROPERTY,
                                (PBYTE)newUsageAuth,
                                (DWORD)((wcslen(newUsageAuth) + 1) * sizeof(WCHAR)),
                                0))))
    {
        goto Cleanup;
    }

    wprintf(L"Ok.\n");

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolChangeKeyUsageAuth()", hr);
    return hr;
}

HRESULT
PcpToolImportKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function will import a key on the KSP. Optionally it may be imported with a
usageAuth value and a migrationAuth
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyFile = NULL;
    PCWSTR keyName = NULL;
    PCWSTR usageAuth = NULL;
    PCWSTR migrationAuth = NULL;
    PBYTE pbKey = NULL;
    UINT32 cbKey = 0;
    DWORD importFlags = NCRYPT_OVERWRITE_KEY_FLAG;
    NCryptBuffer keyImportParameters[] =
        {{0,
          NCRYPTBUFFER_PKCS_KEY_NAME,
          NULL},
         {sizeof(BCRYPT_RSA_ALGORITHM),
          NCRYPTBUFFER_PKCS_ALG_ID,
          (PVOID)BCRYPT_RSA_ALGORITHM}};
    NCryptBufferDesc parameterList = {NCRYPTBUFFER_VERSION,
                                      2,
                                      keyImportParameters};
    BYTE pbPubKey[1024] = {0};
    DWORD cbPubKey = 0;
    BOOLEAN tUIRequested = false;
    LPCWSTR optionalPIN = L"This key requires usage consent and an optional PIN.";
    LPCWSTR mandatoryPIN = L"This key has a mandatory PIN.";
    NCRYPT_UI_POLICY rgbUiPolicy = {1, 0, L"PCPTool", NULL, NULL};

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key File
    if(argc > 2)
    {
        keyFile = argv[2];

        if(FAILED(hr = PcpToolReadFile(keyFile, NULL, 0, &cbKey)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbKey, cbKey)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                            keyFile,
                            pbKey,
                            cbKey,
                            &cbKey)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [key file] [key name] {usageAuth} {migrationAuth}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key Name
    if(argc > 3)
    {
        keyName = argv[3];
    }
    else
    {
        wprintf(L"%s %s [key file] [key name] {usageAuth} {migrationAuth}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: usageAuth
    if(argc > 4)
    {
        usageAuth = argv[4];
        importFlags |= NCRYPT_DO_NOT_FINALIZE_FLAG;
        if(!wcscmp(usageAuth, L"@"))
        {
            // Caller requested UI
            usageAuth = NULL;
            tUIRequested = TRUE;
            rgbUiPolicy.pszFriendlyName = keyName;
            rgbUiPolicy.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG;
            rgbUiPolicy.pszDescription = optionalPIN;
        }
        else if(!wcscmp(usageAuth, L"!"))
        {
            // Caller requested UI
            usageAuth = NULL;
            tUIRequested = TRUE;
            rgbUiPolicy.pszFriendlyName = keyName;
            rgbUiPolicy.dwFlags = NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;
            rgbUiPolicy.pszDescription = mandatoryPIN;
        }
    }

    // Optional parameter: migrationAuth
    if(argc > 5)
    {
        migrationAuth = argv[5];
        importFlags |= NCRYPT_DO_NOT_FINALIZE_FLAG;
    }

    // Create the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    keyImportParameters[0].cbBuffer = (ULONG)((wcslen(keyName) + 1) * sizeof(WCHAR));
    keyImportParameters[0].BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
    keyImportParameters[0].pvBuffer = (PVOID)keyName;

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptImportKey(
                                hProv,
                                NULL,
                                BCRYPT_RSAPRIVATE_BLOB,
                                &parameterList,
                                &hKey,
                                pbKey,
                                cbKey,
                                importFlags))))
    {
        goto Cleanup;
    }

    if((importFlags & NCRYPT_DO_NOT_FINALIZE_FLAG) != NULL)
    {
        if(tUIRequested == FALSE)
        {
            if((usageAuth != NULL) && (wcslen(usageAuth) != 0))
            {
                if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                            hKey,
                                            NCRYPT_PIN_PROPERTY,
                                            (PBYTE)usageAuth,
                                            (DWORD)((wcslen(usageAuth) + 1) * sizeof(WCHAR)),
                                            0))))
                {
                    goto Cleanup;
                }
            }
        }
        else
        {
            if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                        hKey,
                                        NCRYPT_UI_POLICY_PROPERTY,
                                        (PBYTE)&rgbUiPolicy,
                                        sizeof(NCRYPT_UI_POLICY),
                                        0))))
            {
                goto Cleanup;
            }
        }

        if(migrationAuth != NULL)
        {
            if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                        hKey,
                                        NCRYPT_PCP_MIGRATIONPASSWORD_PROPERTY,
                                        (PBYTE)migrationAuth,
                                        (DWORD)((wcslen(migrationAuth) + 1) * sizeof(WCHAR)),
                                        0))))
            {
                goto Cleanup;
            }
        }

        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptFinalizeKey(hKey, 0))))
        {
            goto Cleanup;
        }
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                hKey,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                NULL,
                                pbPubKey,
                                sizeof(pbPubKey),
                                &cbPubKey,
                                0))))
    {
        goto Cleanup;
    }

    // Output results
    if(FAILED(hr = PcpToolDisplayKey(keyName, pbPubKey, cbPubKey, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbKey, cbKey);
    PcpToolCallResult(L"PcpToolImportKey()", hr);
    return hr;
}

HRESULT
PcpToolExportKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Export a user key from the PCP storage.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PCWSTR keyFile = NULL;
    PCWSTR migrationAuth = NULL;
    BYTE pbKey[1024] = {0};
    DWORD cbKey = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key Name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] [migrationAuth] {key file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: migrationAuth
    if(argc > 3)
    {
        migrationAuth = argv[3];
    }
    else
    {
        wprintf(L"%s %s [key name] [migrationAuth] {key file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Key File
    if(argc > 4)
    {
        keyFile = argv[4];
    }

    // Open the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                0))))
    {
        goto Cleanup;
    }

    // Authorize the export of the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                hKey,
                                NCRYPT_PCP_MIGRATIONPASSWORD_PROPERTY,
                                (PBYTE)migrationAuth,
                                (DWORD)((wcslen(migrationAuth) + 1) * sizeof(WCHAR)),
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                hKey,
                                NULL,
                                BCRYPT_RSAPRIVATE_BLOB,
                                NULL,
                                pbKey,
                                sizeof(pbKey),
                                &cbKey,
                                0))))
    {
        goto Cleanup;
    }

    // Export key
    if(keyFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(keyFile, pbKey, cbKey)))
        {
            goto Cleanup;
        }
    }

    // Output results
    if(FAILED(hr = PcpToolDisplayKey(keyName, pbKey, cbKey, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolExportKey()", hr);
    return hr;
}

HRESULT
PcpToolDeleteKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Delete a user key from the PCP storage.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key Name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Open the key
    if(FAILED(hr = (NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = (NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                0))))
    {
        if (FAILED(hr = (NCryptOpenKey(
            hProv,
            &hKey,
            keyName,
            0,
            NCRYPT_MACHINE_KEY_FLAG))))
        {
            goto Cleanup;
        }
    }

    // Delete the key
    if(FAILED(hr = (NCryptDeleteKey(hKey,0))))
    {
        goto Cleanup;
    }
    hKey = NULL;

    wprintf(L"Ok.\n");

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolDeleteKey()", hr);
    return hr;
}


HRESULT
PcpToolDeleteKeys(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
)
/*++
This function will enumerate all keys that are held on the PCPKSP for this user
or in the machine context.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCryptKeyName* pKeyName = NULL;
    PVOID pEnumState = NULL;
    DWORD dwFlags[2] = {
                        NCRYPT_SILENT_FLAG | NCRYPT_MACHINE_KEY_FLAG,
                        NCRYPT_SILENT_FLAG };
    NCRYPT_KEY_HANDLE hKey = NULL;
    basic_regex<wchar_t> regexKeyName;
    int matchingKeys = 0;

    // Mandatory parameter: Key Name
    if (argc > 2)
    {
        regexKeyName = basic_regex<wchar_t>(argv[2]);
    }
    else
    {
        wprintf(L"%s %s [key name]\n",
            argv[0],
            argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
        &hProv,
        MS_PLATFORM_CRYPTO_PROVIDER,
        0))))
    {
        goto Cleanup;
    }

    for (UINT32 n = 0; n < (sizeof(dwFlags) / sizeof(DWORD)); n++)
    {
        hr = S_OK;

        while (SUCCEEDED(hr))
        {
            hr = HRESULT_FROM_WIN32(NCryptEnumKeys(
                hProv,
                NULL,
                &pKeyName,
                &pEnumState,
                dwFlags[n]));
            if (FAILED(hr))
            {
                if (hr == HRESULT_FROM_WIN32((ULONG)NTE_NO_MORE_ITEMS))
                {
                    if (pEnumState != NULL)
                    {
                        NCryptFreeBuffer(pEnumState);
                        pEnumState = NULL;
                    }
                    hr = S_OK;
                    break;
                }
                else
                {
                    goto Cleanup;
                }
            }
            else
            {
                if (regex_match(pKeyName->pszName, regexKeyName)) {
                    matchingKeys++;

                    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                        hProv,
                        &hKey,
                        pKeyName->pszName,
                        0,
                        dwFlags[n] & NCRYPT_MACHINE_KEY_FLAG))))
                    {
                        wprintf(L"Could not open key: %s (0x%08lx)\n", pKeyName->pszName, hr);
                        if (pKeyName != NULL)
                        {
                            NCryptFreeBuffer(pKeyName);
                            pKeyName = NULL;
                        }
                        hr = S_OK;
                        continue;
                    }

                    wprintf(L"Deletes key: %s ", pKeyName->pszName);
                    // Delete the key
                    if (FAILED(hr = (NCryptDeleteKey(hKey, 0))))
                    {
                        wprintf(L" Failed (0x%08lx)\n", hr);
                    }
                    else 
                    {
                        wprintf(L" Deleted\n");
                    }

                    NCryptFreeObject(hKey);
                    hKey = NULL;
                    NCryptFreeBuffer(pKeyName);
                    pKeyName = NULL;
                }
            }
        }
    }

    if (matchingKeys == 0) 
    {
        wprintf(L"No matching keys found\n");
    }

Cleanup:
    if (pKeyName != NULL)
    {
        NCryptFreeBuffer(pKeyName);
        pKeyName = NULL;
    }
    if (pEnumState != NULL)
    {
        NCryptFreeBuffer(pEnumState);
        pEnumState = NULL;
    }
    if (hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if (hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolDeleteKeys()", hr);
    return hr;
}



HRESULT
PcpToolGetPubKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
Export the public portion from a user key in the PCP storage as
BCRYPT_RSAKEY_BLOB structure.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PCWSTR keyFile = NULL;
    BYTE pbPubKey[1024] = {0};
    DWORD cbPubKey = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key Name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] {key File}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Export file
    if(argc > 3)
    {
        keyFile = argv[3];
    }

    // Open key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                0))))
    {
        goto Cleanup;
    }

    // Export public key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                hKey,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                NULL,
                                pbPubKey,
                                sizeof(pbPubKey),
                                &cbPubKey,
                                0))))
    {
        goto Cleanup;
    }

    // Export key
    if(keyFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(keyFile, pbPubKey, cbPubKey)))
        {
            goto Cleanup;
        }
    }

    // Output results
    if(FAILED(hr = PcpToolDisplayKey(keyName, pbPubKey, cbPubKey, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolGetPubKey()", hr);
    return hr;
}

HRESULT
PcpToolGetPlatformAttestation(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function will create an AIK signed platform attestation blob. In this case
the attestation is signed and nonces are supported. This attestation is tamper
proof.
--*/
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hAik = NULL;
    PCWSTR aikName = NULL;
    PCWSTR attestationFile = NULL;
    PCWSTR nonce = NULL;
    PCWSTR aikAuthValue = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = {0};
    UINT32 result = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Aik name
    if(argc > 2)
    {
        aikName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [aik name] {attestation file} {nonce}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Attestation file
    if(argc > 3)
    {
        attestationFile = argv[3];
    }

    // Optional parameter: Nonce
    if(argc > 4)
    {
        nonce = argv[4];
        if(FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                                    NULL,
                                                    0,
                                                    (PBYTE)nonce,
                                                    (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
                                                    nonceDigest,
                                                    sizeof(nonceDigest),
                                                    &result)))
        {
            goto Cleanup;
        }
    }

    // Optional parameter: aik auth
    if(argc > 5)
    {
        aikAuthValue = argv[5];
    }

    if(wcslen(aikName) > 0)
    {
        // Open AIK
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                    &hProv,
                                    MS_PLATFORM_CRYPTO_PROVIDER,
                                    0))))
        {
            goto Cleanup;
        }
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                    hProv,
                                    &hAik,
                                    aikName,
                                    0,
                                    0))))
        {
            goto Cleanup;
        }
        if((aikAuthValue != NULL) && (wcslen(aikAuthValue) != 0))
        {
            if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                        hAik,
                                        NCRYPT_PIN_PROPERTY,
                                        (PBYTE)aikAuthValue,
                                        (DWORD)((wcslen(aikAuthValue) + 1) * sizeof(WCHAR)),
                                        0))))
            {
                goto Cleanup;
            }
        }
    }

    if(FAILED(hr = TpmAttGeneratePlatformAttestation(
                                hAik,
                                0x0000f77f, // Default PCR mask PCR[0-6, 8-10, 12-15]
                                (nonce) ? nonceDigest : NULL,
                                (nonce) ? sizeof(nonceDigest) : 0,
                                NULL,
                                0,
                                &cbAttestation)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = TpmAttGeneratePlatformAttestation(
                                hAik,
                                0x0000f77f, // Default PCR mask PCR[0-6, 8-10, 12-15]
                                (nonce) ? nonceDigest : NULL,
                                (nonce) ? sizeof(nonceDigest) : 0,
                                pbAttestation,
                                cbAttestation,
                                &cbAttestation)))
    {
        goto Cleanup;
    }

    // Export attestation blob
    if(attestationFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(
                                attestationFile,
                                pbAttestation,
                                cbAttestation)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"<PlatformAttestation size=\"%u\">\n", cbAttestation);
    if(FAILED(hr = PcpToolDisplayPlatformAttestation(pbAttestation, cbAttestation, 1)))
    {
        goto Cleanup;
    }
    wprintf(L"</PlatformAttestation>\n");

Cleanup:
    if(hAik != NULL)
    {
        NCryptFreeObject(hAik);
        hAik = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    PcpToolCallResult(L"PcpToolGetPlatformAttestation()", hr);
    return hr;
}

HRESULT
PcpToolGetPlatformCounters(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    UINT32 OsBootCount = 0;
    UINT32 OsResumeCount = 0;
    UINT64 CurrentTPMBootCount = 0L;
    UINT64 CurrentTPMEventCount = 0L;
    UINT64 CurrentTPMCounterId = 0L;
    UINT64 InitialTPMBootCount = 0L;
    UINT64 InitialTPMEventCount = 0L;
    UINT64 InitialTPMCounterId = 0L;

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    if(FAILED(hr = TpmAttGetPlatformCounters(
                        &OsBootCount,
                        &OsResumeCount,
                        &CurrentTPMBootCount,
                        &CurrentTPMEventCount,
                        &CurrentTPMCounterId,
                        &InitialTPMBootCount,
                        &InitialTPMEventCount,
                        &InitialTPMCounterId
                        )))
    {
        goto Cleanup;
    }

    // Output results
    wprintf(L"<PlatformCounters>\n");
    PcpToolLevelPrefix(1);
    wprintf(L"<OsBootCount>%u</OsBootCount>\n", OsBootCount);
    PcpToolLevelPrefix(1);
    wprintf(L"<OsResumeCount>%u</OsResumeCount>\n", OsResumeCount);
    PcpToolLevelPrefix(1);
    wprintf(L"<CurrentBootCount>%I64d</CurrentBootCount>\n", CurrentTPMBootCount);
    PcpToolLevelPrefix(1);
    wprintf(L"<CurrentEventCount>%I64d</CurrentEventCount>\n", CurrentTPMEventCount);
    PcpToolLevelPrefix(1);
    wprintf(L"<CurrentCounterId>%I64d</CurrentCounterId>\n", CurrentTPMCounterId);
    PcpToolLevelPrefix(1);
    wprintf(L"<InitialBootCount>%I64d</InitialBootCount>\n", InitialTPMBootCount);
    PcpToolLevelPrefix(1);
    wprintf(L"<InitialEventCount>%I64d</InitialEventCount>\n", InitialTPMEventCount);
    PcpToolLevelPrefix(1);
    wprintf(L"<InitialCounterId>%I64d</InitialCounterId>\n", InitialTPMCounterId);
    wprintf(L"</PlatformCounters>\n");

Cleanup:
    PcpToolCallResult(L"PcpToolGetPlatformCounters()", hr);
    return hr;
}

HRESULT
PcpToolGetPCRs(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    PCWSTR fileName = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    BYTE pcrTable[TPM_AVAILABLE_PLATFORM_PCRS * MAX_DIGEST_SIZE] = {0};
    DWORD cbPcrTable = sizeof(pcrTable);
    DWORD digestSize = SHA1_DIGEST_SIZE;

    if(argc > 2)
    {
        fileName = argv[2];
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                            &hProv,
                            MS_PLATFORM_CRYPTO_PROVIDER,
                            0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(hProv,
                            NCRYPT_PCP_PCRTABLE_PROPERTY,
                            pcrTable,
                            sizeof(pcrTable),
                            &cbPcrTable,
                            0))))
    {
        goto Cleanup;
    }

    if ((cbPcrTable / TPM_AVAILABLE_PLATFORM_PCRS) == SHA256_DIGEST_SIZE)
    {
        digestSize = SHA256_DIGEST_SIZE;
    }

    if((fileName != NULL) &&
       (FAILED(hr = PcpToolWriteFile(fileName, pcrTable, cbPcrTable))))
    {
        goto Cleanup;
    }

    wprintf(L"<PCRs>\n");
    for(UINT32 n = 0; n < TPM_AVAILABLE_PLATFORM_PCRS; n++)
    {
        PcpToolLevelPrefix(1);
        wprintf(L"<PCR Index=\"%02u\">", n);
        for(UINT32 m = 0; m < digestSize; m++)
        {
                wprintf(L"%02x", pcrTable[n * digestSize + m]);
        }
        wprintf(L"</PCR>\n");
    }
    wprintf(L"</PCRs>\n");

Cleanup:
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolGetPCRs()", hr);
    return hr;
}

HRESULT
PcpToolGetArchivedLog(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    UINT32 bootCount = 0;
    UINT32 resumeCount = 0;
    PCWSTR fileName = NULL;
    PBYTE pbLog = NULL;
    UINT32 cbLog = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: OSBootCount
    if(argc > 2)
    {
        if(!_wcsicmp(argv[2], L"@"))
        {
            if(FAILED(hr = TpmAttGetPlatformCounters(
                                &bootCount,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL
                                )))
            {
                goto Cleanup;
            }
        }
        else
        {
            if(swscanf_s(argv[2], L"%d", &bootCount) != 1)
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }
        }
    }
    else
    {
        wprintf(L"%s %s [OSBootCount] [OSResumeCount] {log file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: OSResumeCount
    if(argc > 3)
    {
        if(!_wcsicmp(argv[2], L"@"))
        {
            if(FAILED(hr = TpmAttGetPlatformCounters(
                                NULL,
                                &resumeCount,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL
                                )))
            {
                goto Cleanup;
            }
        }
        else
        {
            if(swscanf_s(argv[3], L"%d", &resumeCount) != 1)
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }
        }
    }
    else
    {
        wprintf(L"%s %s [OSBootCount] [OSResumeCount] {log file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Export file for log
    if(argc > 4)
    {
        fileName = argv[4];
    }

    if(FAILED(hr = TpmAttGetPlatformLogFromArchive(
                        bootCount,
                        resumeCount,
                        NULL,
                        0,
                        &cbLog)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbLog, cbLog)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = TpmAttGetPlatformLogFromArchive(
                        bootCount,
                        resumeCount,
                        pbLog,
                        cbLog,
                        &cbLog)))
    {
        goto Cleanup;
    }

    // Write log to file if requested
    if(fileName != NULL)
    {
       if(FAILED(hr = PcpToolWriteFile(fileName, pbLog, cbLog)))
        {
            goto Cleanup;
        }
    }

    // Show the log
    if(FAILED(hr = PcpToolDisplayLog(pbLog, cbLog, 0)))
    {
        goto Cleanup;
    }

Cleanup:
    ZeroAndFree((PVOID*)&pbLog, cbLog);
    PcpToolCallResult(L"PcpToolGetArchivedLog()", hr);
    return hr;
}

HRESULT
PcpToolDisplayPlatformAttestationFile(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function will display the contents of a platform attestation blob.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR attestationFile = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    UINT64 eventCountStartLocal = 0L;
    UINT64 eventCountIncrementsLocal = 0L;
    UINT64 eventCountIdLocal = 0L;
    UINT64 powerUpCountLocal = 0L;
    UINT32 dwPropertyFlags = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: attestation file
    if(argc > 2)
    {
        attestationFile = argv[2];
        if(FAILED(hr = PcpToolReadFile(
                                attestationFile,
                                NULL,
                                0,
                                &cbAttestation)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                                attestationFile,
                                pbAttestation,
                                cbAttestation,
                                &cbAttestation)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [attestation file]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    if(FAILED(hr = TpmAttGetPlatformAttestationProperties(
                                    pbAttestation,
                                    cbAttestation,
                                    &eventCountStartLocal,
                                    &eventCountIncrementsLocal,
                                    &eventCountIdLocal,
                                    &powerUpCountLocal,
                                    &dwPropertyFlags)))
    {
        goto Cleanup;
    }


    // Output results
    wprintf(L"<PlatformAttestation size=\"%u\">\n", cbAttestation);
    if(FAILED(hr = PcpToolDisplayPlatformAttestation(pbAttestation, cbAttestation, 1)))
    {
        goto Cleanup;
    }
    PcpToolLevelPrefix(1);
    wprintf(L"<TCGLogProperties>\n");
    PcpToolLevelPrefix(2);
    wprintf(L"<EventCountStart>%I64u</EventCountStart>\n",
            eventCountStartLocal);
    PcpToolLevelPrefix(2);
    wprintf(L"<EventsIncrements>%I64u</EventIncrements>\n",
            eventCountIncrementsLocal);
    PcpToolLevelPrefix(2);
    wprintf(L"<EventCountId>%I64u</EventCountId>\n", 
            eventCountIdLocal);
    PcpToolLevelPrefix(2);
    wprintf(L"<PowerUpCount>%I64u</PowerUpCount>\n",
            powerUpCountLocal);
    PcpToolLevelPrefix(2);
    wprintf(L"<ContainsBootCount>%s</ContainsBootCount>\n",
            (dwPropertyFlags &
             PCP_ATTESTATION_PROPERTIES_CONTAINS_BOOT_COUNT) ?
                 L"TRUE" :
                 L"FALSE");
    PcpToolLevelPrefix(2);
    wprintf(L"<ContainsEventCount>%s</ContainsEventCount>\n",
            (dwPropertyFlags &
             PCP_ATTESTATION_PROPERTIES_CONTAINS_EVENT_COUNT) ?
                 L"TRUE" :
                 L"FALSE");
    PcpToolLevelPrefix(2);
    wprintf(L"<EventCountNonContiguous>%s</EventCountNonContiguous>\n",
            (dwPropertyFlags &
             PCP_ATTESTATION_PROPERTIES_EVENT_COUNT_NON_CONTIGUOUS) ?
                 L"TRUE" :
                 L"FALSE");
    PcpToolLevelPrefix(2);
    wprintf(L"<IntegrityServices>%s</IntegrityServices>\n",
            (dwPropertyFlags & PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED) ?
                    L"DISABLED" :
                    L"ENABLED");
    if((dwPropertyFlags & PCP_ATTESTATION_PROPERTIES_INTEGRITY_SERVICES_DISABLED) == 0)
    {
        if(dwPropertyFlags &
           PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_WINLOAD)
        {
            PcpToolLevelPrefix(2);
            wprintf(L"<Transition>Winload</Transition>\n");
        }
        else if(dwPropertyFlags &
           PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_WINRESUME)
        {
            PcpToolLevelPrefix(2);
            wprintf(L"<Transition>Winresume</Transition>\n");
        }
        else if(dwPropertyFlags &
           PCP_ATTESTATION_PROPERTIES_TRANSITION_TO_OTHER)
        {
            PcpToolLevelPrefix(2);
            wprintf(L"<Transition>Other</Transition>\n");
        }
        else
        {
            PcpToolLevelPrefix(2);
            wprintf(L"<Transition>Unspecified</Transition>\n");
        }
        PcpToolLevelPrefix(2);
        wprintf(L"<BootDebugOn>%s</BootDebugOn>\n",
                (dwPropertyFlags &
                 PCP_ATTESTATION_PROPERTIES_BOOT_DEBUG_ON) ?
                     L"TRUE" :
                     L"FALSE");
        PcpToolLevelPrefix(2);
        wprintf(L"<OsDebugOn>%s</OsDebugOn>\n",
                (dwPropertyFlags &
                 PCP_ATTESTATION_PROPERTIES_OS_DEBUG_ON) ?
                     L"TRUE" :
                     L"FALSE");
        PcpToolLevelPrefix(2);
        wprintf(L"<CodeIntegrityOff>%s</CodeIntegrityOff>\n",
                (dwPropertyFlags &
                 PCP_ATTESTATION_PROPERTIES_CODEINTEGRITY_OFF) ?
                 L"TRUE" :
                 L"FALSE");
        PcpToolLevelPrefix(2);
        wprintf(L"<TestsigningOn>%s</TestsigningOn>\n",
                (dwPropertyFlags &
                 PCP_ATTESTATION_PROPERTIES_TESTSIGNING_ON) ?
                     L"TRUE" :
                     L"FALSE");
        PcpToolLevelPrefix(2);
        wprintf(L"<BitLockerUnlock>%s</BitLockerUnlock>\n",
                (dwPropertyFlags &
                 PCP_ATTESTATION_PROPERTIES_BITLOCKER_UNLOCK) ?
                     L"TRUE" :
                     L"FALSE");
        PcpToolLevelPrefix(2);
        wprintf(L"<OsSafeMode>%s</OsSafeMode>\n",
                (dwPropertyFlags &
                 PCP_ATTESTATION_PROPERTIES_OS_SAFEMODE) ?
                     L"TRUE" :
                     L"FALSE");
        PcpToolLevelPrefix(2);
        wprintf(L"<WinPE>%s</WinPE>\n",
                (dwPropertyFlags &
                 PCP_ATTESTATION_PROPERTIES_OS_WINPE) ?
                     L"TRUE" :
                     L"FALSE");
        PcpToolLevelPrefix(2);
        wprintf(L"<Hypervisor>%s</Hypervisor>\n",
                (dwPropertyFlags &
                 PCP_ATTESTATION_PROPERTIES_OS_HV) ?
                     L"TRUE" :
                     L"FALSE");
    }
    PcpToolLevelPrefix(1);
    wprintf(L"</TCGLogProperties>\n");
    wprintf(L"</PlatformAttestation>\n");

Cleanup:
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    PcpToolCallResult(L"PcpToolDisplayPlatformAttestationFile()", hr);
    return hr;
}

HRESULT
PcpToolValidatePlatformAttestation(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function will validate an AIK signed platform attestation blob. In this case
the attestation is signed and nonces are supported. This attestation is tamper
proof.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR aikName = NULL;
    PCWSTR attestationFile = NULL;
    PCWSTR nonce = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hAik = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    PBYTE pbAikPub = NULL;
    UINT32 cbAikPub = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = {0};
    UINT32 cbNonceDigest = sizeof(nonceDigest);

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Attestation blob file
    if(argc > 2)
    {
        attestationFile = argv[2];
        if(FAILED(hr = PcpToolReadFile(
                                attestationFile,
                                NULL,
                                0,
                                &cbAttestation)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                                attestationFile,
                                pbAttestation,
                                cbAttestation,
                                &cbAttestation)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [attestation file] [aikpub file] {nonce}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: AIK pub
    if(argc > 3)
    {
        aikName = argv[3];
        if(wcslen(aikName) > 0)
        {
            if(FAILED(hr = PcpToolReadFile(aikName, NULL, 0, &cbAikPub)))
            {
                goto Cleanup;
            }
            if(FAILED(hr = AllocateAndZero((PVOID*)&pbAikPub, cbAikPub)))
            {
                goto Cleanup;
            }
            if(FAILED(hr = PcpToolReadFile(
                                    aikName,
                                    pbAikPub,
                                    cbAikPub,
                                    &cbAikPub)))
            {
                goto Cleanup;
            }
        }
    }
    else
    {
        wprintf(L"%s %s [attestation file] [aikpub file] {nonce}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Nonce
    if(argc > 4)
    {
        nonce = argv[4];
        if(wcslen(nonce) > 0)
        {
            if(FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                                        NULL,
                                                        0,
                                                        (PBYTE)nonce,
                                                        (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
                                                        nonceDigest,
                                                        sizeof(nonceDigest),
                                                        &cbNonceDigest)))
            {
                goto Cleanup;
            }
        }
        else
        {
            nonce = NULL;
        }
    }

    // Load the AIKPub
    if(wcslen(aikName) > 0)
    {
        if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                        &hAlg,
                                        BCRYPT_RSA_ALGORITHM,
                                        MS_PRIMITIVE_PROVIDER,
                                        0))))
        {
            goto Cleanup;
        }

        if(FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
                                        hAlg,
                                        NULL,
                                        BCRYPT_RSAPUBLIC_BLOB,
                                        &hAik,
                                        pbAikPub,
                                        cbAikPub,
                                        0))))
        {
            goto Cleanup;
        }
    }

    // Validate the Attestation Blob
    if(FAILED(hr = TpmAttValidatePlatformAttestation(
                                   hAik,
                                   (nonce) ? nonceDigest : NULL,
                                   (nonce) ? sizeof(nonceDigest) : 0,
                                   pbAttestation,
                                   cbAttestation)))
    {
        goto Cleanup;
    }

    // Output
    wprintf(L"Verified - OK.\n");

Cleanup:
    if(hAik != NULL)
    {
        BCryptDestroyKey(hAik);
        hAik = NULL;
    }
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    ZeroAndFree((PVOID*)&pbAikPub, cbAikPub);
    PcpToolCallResult(L"PcpToolValidatePlatformAttestation()", hr);
    return hr;
}

HRESULT
PcpToolCreatePlatformAttestationFromLog(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    PCWSTR logFile = NULL;
    PCWSTR fileName = NULL;
    PCWSTR requestedAikName = NULL;
    PWSTR aikName = NULL;
    PBYTE pbLog = NULL;
    UINT32 cbLog = 0;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Log file
    if(argc > 2)
    {
        logFile = argv[2];
        if(FAILED(hr = PcpToolReadFile(
                                logFile,
                                NULL,
                                0,
                                &cbLog)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbLog, cbLog)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                                logFile,
                                pbLog,
                                cbLog,
                                &cbLog)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [log file] {attestation file} {aik name}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Export file for log
    if(argc > 3)
    {
        fileName = argv[3];
    }

    // Optional parameter: Requested AIK name
    if(argc > 4)
    {
        requestedAikName = argv[4];
    }

    // Turn the log with trustpoints into an attestation blob
    if(FAILED(hr = TpmAttCreateAttestationfromLog(pbLog,
                                                  cbLog,
                                                  (PWSTR)requestedAikName,
                                                  &aikName,
                                                  NULL,
                                                  NULL,
                                                  0,
                                                  &cbAttestation)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = TpmAttCreateAttestationfromLog(pbLog,
                                                  cbLog,
                                                  (PWSTR)requestedAikName,
                                                  &aikName,
                                                  NULL,
                                                  pbAttestation,
                                                  cbAttestation,
                                                  &cbAttestation)))
    {
        goto Cleanup;
    }

    // Write log to file if requested
    if(fileName != NULL)
    {
       if(FAILED(hr = PcpToolWriteFile(fileName, pbAttestation, cbAttestation)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"AIK identifier for Trustpoint: '%s'. Log converted - OK!\n", aikName);

Cleanup:
    ZeroAndFree((PVOID*)&pbLog, cbLog);
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    PcpToolCallResult(L"PcpToolCreatePlatformAttestationFromLog()", hr);
    return hr;
}

HRESULT
PcpToolGetKeyAttestationFromKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PCWSTR aikName = NULL;
    PCWSTR attestationFile = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    WCHAR szAikName[MAX_PATH] = L"";
    BYTE aikDigest[SHA1_DIGEST_SIZE] = {0};

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] {attest} {AIK name}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Attestation file
    if((argc > 3) && (wcslen(argv[3]) > 0))
    {
        attestationFile = argv[3];
    }

    // Optional parameter: AIK name
    if((argc > 4) && (wcslen(argv[4]) > 0))
    {
        aikName = argv[4];
    }

    // Open Key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = TpmAttCreateAttestationfromKey(
                                hKey,
                                (PWSTR)aikName,
                                szAikName,
                                NULL,
                                NULL,
                                0,
                                &cbAttestation)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = TpmAttCreateAttestationfromKey(
                                hKey,
                                (PWSTR)aikName,
                                szAikName,
                                aikDigest,
                                pbAttestation,
                                cbAttestation,
                                &cbAttestation)))
    {
        goto Cleanup;
    }

    // Export attestation blob
    if(attestationFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(
                                attestationFile,
                                pbAttestation,
                                cbAttestation)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"<KeyAttestation size=\"%u\" aikName=\"%s\" aikDigest=\"", cbAttestation, szAikName);
    for(UINT32 n = 0; n < SHA1_DIGEST_SIZE; n++)
    {
            wprintf(L"%02x", aikDigest[n]);
    }
    wprintf(L"\">\n");
    if(FAILED(hr = PcpToolDisplayKeyAttestation(pbAttestation, cbAttestation, 1)))
    {
        goto Cleanup;
    }
    wprintf(L"</KeyAttestation>\n");


Cleanup:
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    PcpToolCallResult(L"PcpToolGetKeyAttestationFromKey()", hr);
    return hr;
}

HRESULT
PcpToolGetKeyAttestation(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hAik = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR aikName = NULL;
    PCWSTR keyName = NULL;
    PCWSTR attestationFile = NULL;
    PCWSTR nonce = NULL;
    PCWSTR keyAuthValue = NULL;
    PCWSTR aikAuthValue = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = {0};
    BYTE aikPub[512] = {0};
    BCRYPT_RSAKEY_BLOB* pAikPub = (BCRYPT_RSAKEY_BLOB*)aikPub;
    UINT32 cbAikPub = 0;
    BYTE aikDigest[SHA1_DIGEST_SIZE] = {0};
    UINT32 result = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] [aik name] {exportfile} {nonce} {keyAuth} {aikAuth}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Aik name
    if(argc > 3)
    {
        aikName = argv[3];
    }
    else
    {
        wprintf(L"%s %s [key name] [aik name] {exportfile} {nonce} {keyAuth} {aikAuth}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Attestation file
    if(argc > 4)
    {
        attestationFile = argv[4];
    }

    // Optional parameter: Nonce
    if(argc > 5)
    {
        nonce = argv[5];
        if(FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                      NULL,
                                      0,
                                      (PBYTE)nonce,
                                      (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
                                      nonceDigest,
                                      sizeof(nonceDigest),
                                      &result)))
        {
            goto Cleanup;
        }
    }

    // Optional parameter: key auth
    if((argc > 6) && (argv[6] != NULL) && (wcslen(argv[6]) != 0))
    {
        keyAuthValue = argv[6];
    }

    // Optional parameter: aik auth
    if((argc > 7) && (argv[7] != NULL) && (wcslen(argv[7]) != 0))
    {
        aikAuthValue = argv[7];
    }

    // Open Key and AIK
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                0))))
    {
        goto Cleanup;
    }
    if((keyAuthValue != NULL) && (wcslen(keyAuthValue) != 0))
    {
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                    hKey,
                                    NCRYPT_PIN_PROPERTY,
                                    (PBYTE)keyAuthValue,
                                    (DWORD)((wcslen(keyAuthValue) + 1) * sizeof(WCHAR)),
                                    0))))
        {
            goto Cleanup;
        }
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hAik,
                                aikName,
                                0,
                                0))))
    {
        goto Cleanup;
    }
    if ((aikAuthValue != NULL) && (wcslen(aikAuthValue) != 0))
    {
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                                hAik,
                                                NCRYPT_PIN_PROPERTY,
                                                (PBYTE)aikAuthValue,
                                                (DWORD)((wcslen(aikAuthValue) + 1) * sizeof(WCHAR)),
                                                0))))
        {
            goto Cleanup;
        }
    }
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
                                            hAik,
                                            NULL,
                                            BCRYPT_RSAPUBLIC_BLOB,
                                            NULL,
                                            aikPub,
                                            sizeof(aikPub),
                                            (PDWORD)&cbAikPub,
                                            0))))
    {
        goto Cleanup;
    }
    if((cbAikPub < sizeof(BCRYPT_RSAKEY_BLOB)) ||
       (cbAikPub != sizeof(BCRYPT_RSAKEY_BLOB) +
                    pAikPub->cbPublicExp +
                    pAikPub->cbModulus +
                    pAikPub->cbPrime1 +
                    pAikPub->cbPrime2))
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    if(FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                  NULL,
                                  0,
                                  &aikPub[sizeof(BCRYPT_RSAKEY_BLOB) +
                                          pAikPub->cbPublicExp],
                                  pAikPub->cbModulus,
                                  aikDigest,
                                  sizeof(aikDigest),
                                  &result)))
    {
        goto Cleanup;
    }

    if(FAILED(hr = TpmAttGenerateKeyAttestation(
                                hAik,
                                hKey,
                                (nonce) ? nonceDigest : NULL,
                                (nonce) ? sizeof(nonceDigest) : 0,
                                NULL,
                                0,
                                &cbAttestation)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = TpmAttGenerateKeyAttestation(
                                hAik,
                                hKey,
                                (nonce) ? nonceDigest : NULL,
                                (nonce) ? sizeof(nonceDigest) : 0,
                                pbAttestation,
                                cbAttestation,
                                &cbAttestation)))
    {
        goto Cleanup;
    }

    // Export attestation blob
    if(attestationFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(
                                attestationFile,
                                pbAttestation,
                                cbAttestation)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"<KeyAttestation size=\"%u\" aikName=\"%s\" aikDigest=\"", cbAttestation, aikName);
    for(UINT32 n = 0; n < SHA1_DIGEST_SIZE; n++)
    {
            wprintf(L"%02x", aikDigest[n]);
    }
    wprintf(L"\">\n");
    if(FAILED(hr = PcpToolDisplayKeyAttestation(pbAttestation, cbAttestation, 1)))
    {
        goto Cleanup;
    }
    wprintf(L"</KeyAttestation>\n");

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hAik != NULL)
    {
        NCryptFreeObject(hAik);
        hAik = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    PcpToolCallResult(L"PcpToolGetKeyAttestation()", hr);
    return hr;
}

HRESULT
PcpToolValidateKeyAttestation(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    PCWSTR aikName = NULL;
    PCWSTR attestationFile = NULL;
    PCWSTR nonce = NULL;
    PCWSTR pcrsName = NULL;
    PBYTE pbPcrTable = NULL;
    UINT32 cbPcrTable = 0;
    UINT32 pcrMask = 0;
    UINT16 pcrAlgId = TPM_API_ALG_ID_SHA1;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hAik = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    PBYTE pbAikPub = NULL;
    UINT32 cbAikPub = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = {0};
    UINT32 cbNonceDigest = sizeof(nonceDigest);
    UINT32 currentPcr;
    UINT32 numberOfPcrs;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Attestation blob file
    if(argc > 2)
    {
        attestationFile = argv[2];
        if(FAILED(hr = PcpToolReadFile(
                                attestationFile,
                                NULL,
                                0,
                                &cbAttestation)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                                attestationFile,
                                pbAttestation,
                                cbAttestation,
                                &cbAttestation)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [attest] [aikpub file] {nonce} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: AIK pub
    if(argc > 3)
    {
        aikName = argv[3];
        if(wcslen(aikName) > 0)
        {
            if(FAILED(hr = PcpToolReadFile(aikName, NULL, 0, &cbAikPub)))
            {
                goto Cleanup;
            }
            if(FAILED(hr = AllocateAndZero((PVOID*)&pbAikPub, cbAikPub)))
            {
                goto Cleanup;
            }
            if(FAILED(hr = PcpToolReadFile(
                                    aikName,
                                    pbAikPub,
                                    cbAikPub,
                                    &cbAikPub)))
            {
                goto Cleanup;
            }
        }
    }
    else
    {
        wprintf(L"%s %s [attestation file] [aikpub file] {nonce} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Nonce
    if(argc > 4)
    {
        nonce = argv[4];
        if(wcslen(nonce) > 0)
        {
            nonce = argv[4];
            if(FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                                        NULL,
                                                        0,
                                                        (PBYTE)nonce,
                                                        (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
                                                        nonceDigest,
                                                        sizeof(nonceDigest),
                                                        &cbNonceDigest)))
            {
                goto Cleanup;
            }
        }
        else
        {
            nonce = NULL;
        }
    }

    // Optional parameter: pcrMask
    if(argc > 5)
    {
        if(swscanf_s(argv[5], L"%x", &pcrMask) == 0)
        {
            wprintf(L"%s %s [attestation file] [aikpub file] {nonce} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
    }

    // Optional parameter: pcrTable
    if(argc > 6)
    {
        pcrsName = argv[6];
        if(FAILED(hr = PcpToolReadFile(
                                pcrsName,
                                NULL,
                                0,
                                &cbPcrTable)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbPcrTable, cbPcrTable)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                                pcrsName,
                                pbPcrTable,
                                cbPcrTable,
                                &cbPcrTable)))
        {
            goto Cleanup;
        }
    }

    // Optional parameter: pcrAlgorithm (defaults to SHA1)
    if (argc > 7)
    {
        int argument = 0; // need int for scanf("%x")
        if (swscanf_s(argv[7], L"%x", &argument) == 0)
        {
            wprintf(L"%s %s [attestation file] [aikpub file] {nonce} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
        pcrAlgId = (UINT16)argument;
        // sanity check:
        if (pcrAlgId != TPM_API_ALG_ID_SHA1 &&   // SHA1
            pcrAlgId != TPM_API_ALG_ID_SHA256)     // SHA256
        {
            wprintf(L"%s %s [attestation file] [aikpub file] {nonce} {pcrMask} {pcrs} {pcrAlgorithm = either 4 or B}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
    }
    else if (pbPcrTable != NULL)
    {
        numberOfPcrs = TPM_AVAILABLE_PLATFORM_PCRS;
        if (pcrMask != 0)
        {
            // count the number of PCRs that are supposed to be in the PCR table
            numberOfPcrs = 0;
            for (currentPcr = 1; currentPcr < pcrMask; currentPcr <<= 1)
            {
                if ((pcrMask & currentPcr) != 0)
                {
                    numberOfPcrs++;
                }
            }
        }
        if (numberOfPcrs * SHA256_DIGEST_SIZE == cbPcrTable)
        {
            pcrAlgId = TPM_API_ALG_ID_SHA256;
        }
        else if (TPM_AVAILABLE_PLATFORM_PCRS * SHA256_DIGEST_SIZE == cbPcrTable)
        {
            // pcrMask may contain less PCRs than are in PCR file
            // if PCR file has been generated by PCPTool it contains 24 PCRs
            pcrAlgId = TPM_API_ALG_ID_SHA256;
        }
    }
    else if (pcrMask != 0)
    {
        // if no pcrAlgorithm nor pcrTable are given, the current active PCR values 
        // are used. Because PCP KSP does not select PCR bank automatically, detect 
        // it here and set it explicitly.
        if (FAILED(GetActivePcrAlgorithm(&pcrAlgId)))
        {
            goto Cleanup;
        }
    }

    // Load the AIKPub
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                    &hAlg,
                                    BCRYPT_RSA_ALGORITHM,
                                    MS_PRIMITIVE_PROVIDER,
                                    0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
                                    hAlg,
                                    NULL,
                                    BCRYPT_RSAPUBLIC_BLOB,
                                    &hAik,
                                    pbAikPub,
                                    cbAikPub,
                                    0))))
    {
        goto Cleanup;
    }

    // Validate the Attestation Blob
    if(FAILED(hr = TpmAttValidateKeyAttestation(
                                   hAik,
                                   (nonce) ? nonceDigest : NULL,
                                   (nonce) ? sizeof(nonceDigest) : 0,
                                   pbAttestation,
                                   cbAttestation,
                                   pcrMask,
                                   pcrAlgId,
                                   pbPcrTable,
                                   cbPcrTable)))
    {
        goto Cleanup;
    }

    // Output
    wprintf(L"Verified - OK.\n");

Cleanup:
    if(hAik != NULL)
    {
        BCryptDestroyKey(hAik);
        hAik = NULL;
    }
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbPcrTable, cbPcrTable);
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    ZeroAndFree((PVOID*)&pbAikPub, cbAikPub);
    PcpToolCallResult(L"PcpToolValidateKeyAttestation()", hr);
    return hr;
}

HRESULT
PcpToolGetKeyProperties(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    PCWSTR attestationFile = NULL;
    PCWSTR keyFile = NULL;
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;
    UINT32 propertyFlags = 0;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE pbPubKey[1024] = {0};
    DWORD cbPubKey = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Attestation blob file
    if(argc > 2)
    {
        attestationFile = argv[2];
        if(FAILED(hr = PcpToolReadFile(
                                attestationFile,
                                NULL,
                                0,
                                &cbAttestation)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                                attestationFile,
                                pbAttestation,
                                cbAttestation,
                                &cbAttestation)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [attest]\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Export file
    if(argc > 3)
    {
        keyFile = argv[3];
    }


    // Open the provider
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                    &hAlg,
                                    BCRYPT_RSA_ALGORITHM,
                                    MS_PRIMITIVE_PROVIDER,
                                    0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = TpmAttGetKeyAttestationProperties(
                                pbAttestation,
                                cbAttestation,
                                &propertyFlags,
                                hAlg,
                                &hKey)))
    {
        goto Cleanup;
    }

    // Export public key
    if(FAILED(hr = BCryptExportKey(
                                hKey,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                pbPubKey,
                                sizeof(pbPubKey),
                                &cbPubKey,
                                0)))
    {
        goto Cleanup;
    }

    // Export key
    if(keyFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(keyFile, pbPubKey, cbPubKey)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"<PCPKey>\n");
    if(FAILED(hr = PcpToolDisplayKey(NULL, pbPubKey, cbPubKey, 1)))
    {
        goto Cleanup;
    }
    PcpToolLevelPrefix(1);
    wprintf(L"<NON_MIGRATABLE>%s</NON_MIGRATABLE>\n", (propertyFlags & PCP_KEY_PROPERTIES_NON_MIGRATABLE) ? L"TRUE" : L"FALSE");
    PcpToolLevelPrefix(1);
    wprintf(L"<PIN_PROTECTED>%s</PIN_PROTECTED>\n", (propertyFlags & PCP_KEY_PROPERTIES_PIN_PROTECTED) ? L"TRUE" : L"FALSE");
    PcpToolLevelPrefix(1);
    wprintf(L"<PCR_PROTECTED>%s</PCR_PROTECTED>\n", (propertyFlags & PCP_KEY_PROPERTIES_PCR_PROTECTED) ? L"TRUE" : L"FALSE");
    PcpToolLevelPrefix(1);
    switch(propertyFlags & 0x0000FFFF)
    {
        case PCP_KEY_PROPERTIES_SIGNATURE_KEY:
            wprintf(L"<KEY_USAGE>SIGNATURE_KEY</KEY_USAGE>\n");
            break;
        case PCP_KEY_PROPERTIES_ENCRYPTION_KEY:
            wprintf(L"<KEY_USAGE>ENCRYPTION_KEY</KEY_USAGE>\n");
            break;
        case PCP_KEY_PROPERTIES_GENERIC_KEY:
            wprintf(L"<KEY_USAGE>GENERIC_KEY</KEY_USAGE>\n");
            break;
        case PCP_KEY_PROPERTIES_STORAGE_KEY:
            wprintf(L"<KEY_USAGE>STORAGE_KEY</KEY_USAGE>\n");
            break;
        case PCP_KEY_PROPERTIES_IDENTITY_KEY:
            wprintf(L"<KEY_USAGE>IDENTITY_KEY</KEY_USAGE>\n");
            break;
        default:
            wprintf(L"<KEY_USAGE>UNSPECIFIED</KEY_USAGE>\n");
            break;
    }
    wprintf(L"</PCPKey>\n");

Cleanup:
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    PcpToolCallResult(L"PcpToolGetKeyProperties()", hr);
    return hr;
}

HRESULT
PcpToolEncrypt(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyFile = NULL;
    PCWSTR decData = NULL;
    PCWSTR blobFile = NULL;
    UINT32 cbPubkey = 0;
    PBYTE pbPubkey = NULL;
    UINT32 cbBlob = 0;
    PBYTE pbBlob = NULL;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key File
    if(argc > 2)
    {
        keyFile = argv[2];

        if(FAILED(hr = PcpToolReadFile(keyFile, NULL, 0, &cbPubkey)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbPubkey, cbPubkey)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                            keyFile,
                            pbPubkey,
                            cbPubkey,
                            &cbPubkey)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [pubkey file] [data] {blob file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Data
    if(argc > 3)
    {
        decData = argv[3];
    }
    else
    {
        wprintf(L"%s %s [pubkey file] [data] {blob file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Data
    if(argc > 4)
    {
        blobFile = argv[4];
    }

    // Open the key
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                    &hAlg,
                                    BCRYPT_RSA_ALGORITHM,
                                    MS_PRIMITIVE_PROVIDER,
                                    0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
                                    hAlg,
                                    NULL,
                                    BCRYPT_RSAPUBLIC_BLOB,
                                    &hKey,
                                    pbPubkey,
                                    cbPubkey,
                                    0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_NT(BCryptEncrypt(
                                    hKey,
                                    (PBYTE)decData,
                                    (DWORD)((wcslen(decData) + 1) * sizeof(WCHAR)),
                                    NULL,
                                    NULL,
                                    0,
                                    NULL,
                                    0,
                                    (PULONG)&cbBlob,
                                    BCRYPT_PAD_PKCS1))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbBlob, cbBlob)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptEncrypt(
                                    hKey,
                                    (PBYTE)decData,
                                    (DWORD)((wcslen(decData) + 1) * sizeof(WCHAR)),
                                    NULL,
                                    NULL,
                                    0,
                                    pbBlob,
                                    cbBlob,
                                    (PULONG)&cbBlob,
                                    BCRYPT_PAD_PKCS1))))
    {
        goto Cleanup;
    }

    if(blobFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(blobFile, pbBlob, cbBlob)))
        {
            goto Cleanup;
        }
    }

    // Output the result
    wprintf(L"<Blob size=\"%u\">\n  ", cbBlob);
    for(UINT32 n = 0; n < cbBlob; n++)
    {
        wprintf(L"%02x", pbBlob[n]);
    }
    wprintf(L"\n</Blob>\n");

Cleanup:
    if(hKey != NULL)
    {
        BCryptDestroyKey(hKey);
        hKey = NULL;
    }
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbBlob, cbBlob);
    ZeroAndFree((PVOID*)&pbPubkey, cbPubkey);
    PcpToolCallResult(L"PcpToolEncrypt()", hr);
    return hr;
}

HRESULT
PcpToolDecrypt(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PCWSTR blobFile = NULL;
    PCWSTR keyAuthValue = NULL;
    PBYTE pbBlob = NULL;
    UINT32 cbBlob = 0;
    PBYTE pbSecret = NULL;
    UINT32 cbSecret = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: key name
    if(argc > 2)
    {
        keyName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] [blob file] {usageAuth}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: blob file
    if(argc > 3)
    {
        blobFile = argv[3];
        if(FAILED(hr = PcpToolReadFile(
                                blobFile,
                                NULL,
                                0,
                                &cbBlob)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbBlob, cbBlob)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                                blobFile,
                                pbBlob,
                                cbBlob,
                                &cbBlob)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [key name] [blob file] {usageAuth}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: key auth
    if(argc > 4)
    {
        keyAuthValue = argv[4];
    }

    // Open key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                (keyAuthValue!= 0) ? NCRYPT_SILENT_FLAG : 0))))
    {
        goto Cleanup;
    }
    if((keyAuthValue != NULL) && (wcslen(keyAuthValue) != 0))
    {
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                    hKey,
                                    NCRYPT_PIN_PROPERTY,
                                    (PBYTE)keyAuthValue,
                                    (DWORD)((wcslen(keyAuthValue) + 1) * sizeof(WCHAR)),
                                    0))))
        {
            goto Cleanup;
        }
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptDecrypt(
                            hKey,
                            pbBlob,
                            cbBlob,
                            NULL,
                            NULL,
                            0,
                            (PDWORD)&cbSecret,
                            BCRYPT_PAD_PKCS1))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbSecret, cbSecret)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptDecrypt(
                            hKey,
                            pbBlob,
                            cbBlob,
                            NULL,
                            pbSecret,
                            cbSecret,
                            (PDWORD)&cbSecret,
                            BCRYPT_PAD_PKCS1))))
    {
        goto Cleanup;
    }

    // Output secret
    wprintf(L"<Secret size=\"%u\">%s</Secret>\n", cbSecret, (PWCHAR)pbSecret);

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbBlob, cbBlob);
    ZeroAndFree((PVOID*)&pbSecret, cbSecret);
    PcpToolCallResult(L"PcpToolDecrypt()", hr);
    return hr;
}

HRESULT
PcpToolWrapPlatformKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hInKey = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hStorageKey = NULL;
    DWORD keySpec = 0;
    BOOL fCallerFreeProvOrNCryptKey = FALSE;
    LPWSTR certFile = NULL;
    UINT32 cbCert = 0;
    PBYTE pbCert = NULL;
    PCCERT_CONTEXT pCert = NULL;
    PCCERT_CONTEXT pCertInStore = NULL;
    HCERTSTORE hMyStore = NULL;
    LPWSTR storageName = NULL;
    UINT32 cbStoragePub = 0;
    PBYTE pbStoragePub = NULL;
    LPWSTR outName = NULL;
    LPWSTR usageAuth = NULL;
    UINT32 pcrMask = 0;
    UINT32 currentPcr;
    UINT32 numberOfPcrs = 0;
    UINT16 pcrAlgId = TPM_API_ALG_ID_SHA1; // TPM_ALG_SHA
    LPWSTR pcrsName = NULL;
    UINT32 cbPcrTable = 0;
    PBYTE pbPcrTable = NULL;
    UINT32 cbOutput = 0;
    PBYTE pbOutput = NULL;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: Key name
    if(argc > 2)
    {
        certFile = argv[2];

        // Open the users MY cert store
        hMyStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                                    0,
                                    NULL,
                                    CERT_SYSTEM_STORE_CURRENT_USER,
                                    L"MY");
        if(!hMyStore)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }

        if(wcslen(certFile) == 0)
        {
            if (FAILED(hr = CryptUIDlgSelectCertificateFromStoreWrapper(&pCertInStore, &hMyStore)))
            {
                goto Cleanup;
            }
        }
        else
        {
            if(FAILED(hr = PcpToolReadFile(certFile, NULL, 0, &cbCert)))
            {
                goto Cleanup;
            }
            if(FAILED(hr = AllocateAndZero((PVOID*)&pbCert, cbCert)))
            {
                goto Cleanup;
            }
            if(FAILED(hr = PcpToolReadFile(certFile, pbCert, cbCert, &cbCert)))
            {
                goto Cleanup;
            }

            // Open the cert from the file
            pCert = CertCreateCertificateContext(
                            X509_ASN_ENCODING |
                            PKCS_7_ASN_ENCODING,
                            pbCert,
                            cbCert);
            if(!pCert)
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                goto Cleanup;
            }

            // Look up the matching cert in the cert store via the public key
            pCertInStore = CertFindCertificateInStore(hMyStore,
                                                      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                                      0,
                                                      CERT_FIND_PUBLIC_KEY,
                                                      &pCert->pCertInfo->SubjectPublicKeyInfo,
                                                      pCertInStore);
            if(!pCertInStore)
            {
                hr = HRESULT_FROM_WIN32(GetLastError());
                goto Cleanup;
            }
        }

        // Get a handle to the private CNG key
        if(!CryptAcquireCertificatePrivateKey(pCertInStore,
                                              CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                                              NULL,
                                              &hInKey,
                                              &keySpec,
                                              &fCallerFreeProvOrNCryptKey))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [cert] [storagePub file] {key file} {usageAuth} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: storage pub
    if(argc > 3)
    {
        storageName = argv[3];
        if(wcslen(storageName) > 0)
        {
            if(FAILED(hr = PcpToolReadFile(storageName, NULL, 0, &cbStoragePub)))
            {
                goto Cleanup;
            }
            if(FAILED(hr = AllocateAndZero((PVOID*)&pbStoragePub, cbStoragePub)))
            {
                goto Cleanup;
            }
            if(FAILED(hr = PcpToolReadFile(
                                    storageName,
                                    pbStoragePub,
                                    cbStoragePub,
                                    &cbStoragePub)))
            {
                goto Cleanup;
            }
        }
    }
    else
    {
        wprintf(L"%s %s [key Name] [storagePub file] {key file} {usageAuth} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: export name
    if(argc > 4)
    {
        outName = argv[4];
    }

    // Optional parameter: usageAuth
    if((argc > 5) && (argv[5] != NULL) && (wcslen(argv[5]) != 0))
    {
        usageAuth = argv[5];
    }

    // Optional parameter: pcrMask
    if(argc > 6)
    {
        if(swscanf_s(argv[6], L"%x", &pcrMask) == 0)
        {
            wprintf(L"%s %s [key Name] [storagePub file] {key file} {usageAuth} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
    }

    // Optional parameter: pcrTable
    if(argc > 7)
    {
        pcrsName = argv[7];
        if(FAILED(hr = PcpToolReadFile(
                                pcrsName,
                                NULL,
                                0,
                                &cbPcrTable)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbPcrTable, cbPcrTable)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(
                                pcrsName,
                                pbPcrTable,
                                cbPcrTable,
                                &cbPcrTable)))
        {
            goto Cleanup;
        }
    }

    // Optional parameter: pcrAlgId
    if(argc > 8)
    {
        int argument = 0;
        if(swscanf_s(argv[8], L"%x", &argument) == 0)
        {
            wprintf(L"%s %s [key Name] [storagePub file] {key file} {usageAuth} {pcrMask} {pcrs} {pcrAlgorithm}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
        pcrAlgId = (UINT16)argument;
        // sanity check
        if ((pcrAlgId != TPM_API_ALG_ID_SHA1) && // SHA1
            (pcrAlgId != TPM_API_ALG_ID_SHA256))   // SHA256
        {
            wprintf(L"%s %s [key Name] [storagePub file] {key file} {usageAuth} {pcrMask} {pcrs} {pcrAlgorithm = one of 4 or B}\n",
                    argv[0],
                    argv[1]);
            goto Cleanup;
        }
    }
    else if (pbPcrTable != NULL)
    {
        numberOfPcrs = TPM_AVAILABLE_PLATFORM_PCRS;
        if (pcrMask != 0)
        {
            // count the number of PCRs that are supposed to be in the PCR table
            numberOfPcrs = 0;
            for (currentPcr = 1; currentPcr < pcrMask; currentPcr <<= 1)
            {
                if ((pcrMask & currentPcr) != 0)
                {
                    numberOfPcrs++;
                }
            }
        }
        if (cbPcrTable == (numberOfPcrs * SHA256_DIGEST_SIZE))
        {
            // default PCR algorithm is SHA1
            // set it to SHA256 if we are using SHA256 sized PCRs
            pcrAlgId = TPM_API_ALG_ID_SHA256;
        }
        else if (TPM_AVAILABLE_PLATFORM_PCRS * SHA256_DIGEST_SIZE == cbPcrTable)
        {
            // pcrMask may contain less PCRs than are in PCR file
            // if PCR file has been generated by PCPTool it contains 24 PCRs
            pcrAlgId = TPM_API_ALG_ID_SHA256;
        }
    }
    else if (pcrMask != 0)
    {
        // if no pcrAlgorithm nor pcrTable are given, the current active PCR values 
        // are used. Because PCP KSP does not select PCR bank automatically, detect 
        // it here and set it explicitly.
        if (FAILED(GetActivePcrAlgorithm(&pcrAlgId)))
        {
            goto Cleanup;
        }
    }

    // Import the public storage key
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                    &hAlg,
                                    BCRYPT_RSA_ALGORITHM,
                                    MS_PRIMITIVE_PROVIDER,
                                    0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
                                    hAlg,
                                    NULL,
                                    BCRYPT_RSAPUBLIC_BLOB,
                                    &hStorageKey,
                                    pbStoragePub,
                                    cbStoragePub,
                                    0))))
    {
        goto Cleanup;
    }

    // We are going to do this twice, since we do not know what platform this key is intended for
    for(UINT32 n = TPM_VERSION_12; n < TPM_VERSION_20 + 1; n++)
    {
        if(FAILED(hr = TpmAttWrapPlatformKey(hInKey,
                                             hStorageKey,
                                             n,
                                             NCRYPT_PCP_GENERIC_KEY,
                                             (PBYTE)usageAuth,
                                             usageAuth ? (DWORD)(wcslen(usageAuth) * sizeof(WCHAR)) : 0,
                                             pcrMask,
                                             pcrAlgId,
                                             pbPcrTable,
                                             cbPcrTable,
                                             NULL,
                                             0,
                                             &cbOutput)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbOutput, cbOutput)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = TpmAttWrapPlatformKey(hInKey,
                                             hStorageKey,
                                             n,
                                             NCRYPT_PCP_GENERIC_KEY,
                                             (PBYTE)usageAuth,
                                             usageAuth ? (DWORD)(wcslen(usageAuth) * sizeof(WCHAR)) : 0,
                                             pcrMask,
                                             pcrAlgId,
                                             pbPcrTable,
                                             cbPcrTable,
                                             pbOutput,
                                             cbOutput,
                                             &cbOutput)))
        {
            goto Cleanup;
        }
        if(outName != NULL)
        {
            WCHAR exportFile[MAX_PATH] = {0};
            LPWSTR extension[] = {L"", L".TPM12", L".TPM20"};
            if(FAILED(hr = StringCchCopyW(exportFile, MAX_PATH, outName)))
            {
                goto Cleanup;
            }
            if(FAILED(hr = StringCchCatW(exportFile, MAX_PATH, extension[n])))
            {
                goto Cleanup;
            }
            if(FAILED(hr = PcpToolWriteFile(
                                    exportFile,
                                    pbOutput,
                                    cbOutput)))
            {
                goto Cleanup;
            }
        }
        ZeroAndFree((PVOID*)&pbOutput, cbOutput);
        cbOutput = 0;

        LPWSTR blobType[] = {L"", L"TPM1.2", L"TPM2.0"};
        wprintf(L"Keyblob created for %s - OK.\n", blobType[n]);

        if ((n == TPM_VERSION_12) &&
            (pcrAlgId != TPM_API_ALG_ID_SHA1))
        {
            wprintf(L"Warning: Keyblob for TPM1.2 might not be usable because used PCR bank is not SHA1.\n");
        }
    }

Cleanup:
    if((hInKey != NULL) && (fCallerFreeProvOrNCryptKey != FALSE))
    {
        if(keySpec != CERT_NCRYPT_KEY_SPEC)
        {
            NCryptFreeObject(hInKey);
        }
        else
        {
            CryptReleaseContext(hInKey, 0);
        }
        hInKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    if(hStorageKey != NULL)
    {
        BCryptDestroyKey(hStorageKey);
        hStorageKey = NULL;
    }
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbOutput, cbOutput);
    ZeroAndFree((PVOID*)&pbStoragePub, cbStoragePub);
    ZeroAndFree((PVOID*)&pbPcrTable, cbPcrTable);
    PcpToolCallResult(L"PcpToolWrapPlatformKey()", hr);
    return hr;
}

HRESULT
PcpToolImportPlatformKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    UINT32 tpmVersion = 0;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PCWSTR certFile = NULL;
    PBYTE pbKey = NULL;
    UINT32 cbKey = 0;
    PBYTE pbCert = NULL;
    UINT32 cbCert = 0;
    PCCERT_CONTEXT pCert = NULL;
    NCryptBuffer keyProperties[] = {{0,
                                     NCRYPTBUFFER_PKCS_KEY_NAME,
                                     NULL},
                                    {sizeof(BCRYPT_RSA_ALGORITHM),
                                     NCRYPTBUFFER_PKCS_ALG_ID,
                                     BCRYPT_RSA_ALGORITHM}};
    NCryptBufferDesc keyParameters = {NCRYPTBUFFER_VERSION,
                                      2,
                                      keyProperties};
    HCERTSTORE hMyStore = NULL;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Get the TPM version from the platform
    if(FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
    {
        goto Cleanup;
    }

    // Mandatory parameter: Key file
    if(argc > 2)
    {
        // Grab the file for this platform
        WCHAR fileName[MAX_PATH] = {0};
        LPWSTR extension[] = {L"", L".TPM12", L".TPM20"};

        if(FAILED(hr = StringCchCopyW(fileName, MAX_PATH, argv[2])))
        {
            goto Cleanup;
        }
        if(FAILED(hr = StringCchCatW(fileName, MAX_PATH, extension[tpmVersion])))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(fileName, NULL, 0, &cbKey)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbKey, cbKey)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(fileName, pbKey, cbKey, &cbKey)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [key file] [key name] {cert file}\n",
                    argv[0],
                    argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory parameter: key name
    if(argc > 3)
    {
        keyName = argv[3];
        keyProperties[0].cbBuffer = (ULONG)((wcslen(keyName) + 1) * sizeof(WCHAR));
        keyProperties[0].pvBuffer = (PVOID)keyName;
    }
    else
    {
        wprintf(L"%s %s [key file] [key name] {cert file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: cert file
    if(argc > 4)
    {
        certFile = argv[4];
        if(FAILED(hr = PcpToolReadFile(certFile, NULL, 0, &cbCert)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbCert, cbCert)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(certFile, pbCert, cbCert, &cbCert)))
        {
            goto Cleanup;
        }

        // Open the cert
        pCert = CertCreateCertificateContext(
                        X509_ASN_ENCODING |
                        PKCS_7_ASN_ENCODING,
                        pbCert,
                        cbCert);
        if(!pCert)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }

        // Link cert to the private key
        CRYPT_KEY_PROV_INFO keyInfo = {(LPWSTR)keyName,
                                       MS_PLATFORM_CRYPTO_PROVIDER,
                                       0,
                                       0,
                                       0,
                                       NULL,
                                       0};
        if(!CertSetCertificateContextProperty(
                                    pCert,
                                    CERT_KEY_PROV_INFO_PROP_ID,
                                    0,
                                    &keyInfo))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
    }

    // Open Provider
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                        &hProv,
                                        MS_PLATFORM_CRYPTO_PROVIDER,
                                        0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptImportKey(
                                        hProv,
                                        NULL,
                                        BCRYPT_OPAQUE_KEY_BLOB,
                                        &keyParameters,
                                        &hKey,
                                        pbKey,
                                        cbKey,
                                        NCRYPT_OVERWRITE_KEY_FLAG))))
    {
        goto Cleanup;
    }

    // Process the cert
    if(pCert != NULL)
    {
        // Set the cert property on the key
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                            hKey,
                                            NCRYPT_CERTIFICATE_PROPERTY,
                                            pbCert,
                                            cbCert,
                                            0))))
        {
            goto Cleanup;
        }

        // Add the cert to the MY store
        hMyStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                                 0,
                                 NULL,
                                 CERT_SYSTEM_STORE_CURRENT_USER,
                                 L"MY");
        if(!hMyStore)
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }

        if(!CertAddCertificateContextToStore(hMyStore,
                                             pCert,
                                             CERT_STORE_ADD_REPLACE_EXISTING,
                                             NULL))
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"Ok.\n");

Cleanup:
    PcpToolCallResult(L"PcpToolImportPlatformKey()", hr);
    return hr;
}

HRESULT
PcpToolGetVscKeyAttestationFromKey(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    CREDUI_INFOW UIInfo = {0};
    DWORD dwSts = ERROR_SUCCESS;
    SCARDCONTEXT hSC = NULL;
    WCHAR szReader[MAX_PATH] = L"";
    WCHAR szCard[MAX_PATH] = L"";
    READER_SEL_REQUEST rsRequest;
    READER_SEL_RESPONSE* prsResponse = NULL;
    ULONG ulAuthPackage = SCARD_READER_SEL_AUTH_PACKAGE;
    VOID* pvOutAuthBuffer = NULL;
    ULONG ulOutAuthBufferSize = 0;
    LPWSTR szCaption = L"PCPTool: Please select Virtual Smart Card from which the attestation catalog is supposed to be created.";
    WCHAR szProvider[MAX_PATH] = L"";
    DWORD dwProviderLen = MAX_PATH;
    BCRYPT_KEY_HANDLE hCertKey = NULL;
    NCRYPT_PROV_HANDLE hScProv = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    NCryptKeyName* pKeyName = NULL;
    PVOID pEnumState = NULL;
    HCERTSTORE hCertStore = NULL;
    UINT32 cbhCertStore = 0;
    PCCERT_CONTEXT pcCertContext = NULL;
    PBYTE pbCertPubKey = NULL;
    UINT32 cbCertPubKey = 0;
    PWSTR szWindowsDir = NULL;
    WCHAR szServiceKeyFolder[MAX_PATH] = L"";
    WCHAR szAikName[MAX_PATH] = L"";
    PCWSTR attestationFile = NULL;
    PCWSTR aikName = NULL;
    BYTE aikDigest[SHA1_DIGEST_SIZE] = {0};
    PBYTE pbAttestation = NULL;
    UINT32 cbAttestation = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Attestation file
    if(argc > 2)
    {
        attestationFile = argv[2];
    }

    // Optional parameter: AIK name
    if((argc > 3) && (wcslen(argv[3]) > 0))
    {
        aikName = argv[3];
    }

    // Have the user pick a smart card
    UIInfo.cbSize = sizeof(CREDUI_INFO);
    UIInfo.hwndParent = 0;
    UIInfo.pszCaptionText = szCaption;

    ZeroMemory(&rsRequest, sizeof(READER_SEL_REQUEST));

    rsRequest.MatchType = RSR_MATCH_TYPE_ALL_CARDS;
    rsRequest.dwShareMode = SCARD_SHARE_SHARED;
    rsRequest.dwPreferredProtocols = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;

    dwSts = CredUIPromptForWindowsCredentialsWrapper(UIInfo, ulAuthPackage, rsRequest, pvOutAuthBuffer, ulOutAuthBufferSize);
    if (ERROR_CANCELLED == dwSts)
    {
        hr = SCARD_W_CANCELLED_BY_USER;
        goto Cleanup;

    }
    else if (ERROR_SUCCESS != dwSts)
    {
        hr = HRESULT_FROM_WIN32(dwSts);
        goto Cleanup;

    }

    prsResponse = (READER_SEL_RESPONSE*)pvOutAuthBuffer;
    if((ulOutAuthBufferSize < sizeof(READER_SEL_RESPONSE)) ||
       (prsResponse->cchReaderNameLength == 0) ||
       (prsResponse->cchCardNameLength == 0) ||
       (ulOutAuthBufferSize < prsResponse->cbReaderNameOffset + prsResponse->cchReaderNameLength * sizeof(WCHAR)) ||
       (ulOutAuthBufferSize < prsResponse->cbCardNameOffset + prsResponse->cchCardNameLength * sizeof(WCHAR)) ||
       (ulOutAuthBufferSize < sizeof(READER_SEL_RESPONSE) + prsResponse->cchReaderNameLength * sizeof(WCHAR) + prsResponse->cchCardNameLength * sizeof(WCHAR)))
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }

    // Ensure null termination
    ((LPWSTR)(((PBYTE)prsResponse) + prsResponse->cbReaderNameOffset))[prsResponse->cchReaderNameLength-1] = L'\0';
    ((LPWSTR)(((PBYTE)prsResponse) + prsResponse->cbCardNameOffset))[prsResponse->cchCardNameLength-1] = L'\0';

    if(FAILED(hr = StringCchCopyW(szReader,
                                  MAX_PATH,
                                  (LPWSTR)(((PBYTE)prsResponse) +
                                    prsResponse->cbReaderNameOffset))))
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }

    if(FAILED(hr = StringCchCopyW(szCard,
                                  MAX_PATH,
                                  (LPWSTR)(((PBYTE)prsResponse) +
                                    prsResponse->cbCardNameOffset))))
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(SCardEstablishContext(
                                            SCARD_SCOPE_USER,
                                            NULL,
                                            NULL,
                                            &hSC))))
    {
        goto Cleanup;
    }

    // Get the KSP provider who can handle this card
    if(FAILED(hr = HRESULT_FROM_WIN32(SCardGetCardTypeProviderNameW(
                                                hSC,
                                                szCard,
                                                SCARD_PROVIDER_KSP,
                                                szProvider,
                                                &dwProviderLen))))
    {
        goto Cleanup;
    }

    // Open the indicated KSP provider.
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                          &hScProv,
                                          szProvider,
                                          0))))
    {
        goto Cleanup;
    }

    // Select the specified reader.
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                          hScProv,
                                          NCRYPT_READER_PROPERTY,
                                          (PBYTE)szReader,
                                          ((DWORD)wcslen(szReader)+1) * sizeof(WCHAR),
                                          0))))
    {
        goto Cleanup;
    }

    // Get the smart card cert store
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                        hScProv,
                                        NCRYPT_USER_CERTSTORE_PROPERTY,
                                        (PBYTE)&hCertStore,
                                        sizeof(hCertStore),
                                        (PDWORD)&cbhCertStore,
                                        0))))
    {
        goto Cleanup;
    }

    if (FAILED(hr = CryptUIDlgSelectCertificateFromStoreWrapper(&pcCertContext, &hCertStore)))
    {
        goto Cleanup;
    }

    // Get the public key from the cert
    if(!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
                                    &pcCertContext->pCertInfo->SubjectPublicKeyInfo,
                                    0,
                                    NULL,
                                    &hCertKey))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(hCertKey,
                                                   NULL,
                                                   BCRYPT_RSAPUBLIC_BLOB,
                                                   NULL,
                                                   0,
                                                   (PDWORD)&cbCertPubKey,
                                                   0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbCertPubKey, cbCertPubKey)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(hCertKey,
                                                   NULL,
                                                   BCRYPT_RSAPUBLIC_BLOB,
                                                   pbCertPubKey,
                                                   cbCertPubKey,
                                                   (PDWORD)&cbCertPubKey,
                                                   0))))
    {
        goto Cleanup;
    }

    // Open the Platform Crypto provider
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                        &hProv,
                                        MS_PLATFORM_CRYPTO_PROVIDER,
                                        0))))
    {
        goto Cleanup;
    }

    // Select the key storage directory that is used by Local Services. We have to be elevated to do that.
    // Since all VSC keys are password protected, all keys are not DPAPI encrypted and may be opened. However
    // we will not be able to perform any private key operations since we do not know the usage auth of the
    // keys.
    if(FAILED(hr = SHGetKnownFolderPath(FOLDERID_Windows,
                                             0,
                                             NULL,
                                             &szWindowsDir)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = StringCchPrintfW(
                               szServiceKeyFolder,
                               MAX_PATH,
                               L"%s\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Crypto\\PCPKSP\\",
                               szWindowsDir)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                          hProv,
                                          NCRYPT_PCP_ALTERNATE_KEY_STORAGE_LOCATION_PROPERTY,
                                          (PBYTE)szServiceKeyFolder,
                                          ((DWORD)wcslen(szServiceKeyFolder)+1) * sizeof(WCHAR),
                                          0))))
    {
        goto Cleanup;
    }

    // Find the corresponding PCPKey blob from all the keys created by local service.
    // VSC does have its own names for the keys, that are unrelated to the VSC key names,
    // So we have to look at the keys and compare public keys. If the key was imported
    // and maybe even multiple times it will not have attestation information.
    while((pbAttestation == NULL) &&
         (SUCCEEDED(hr)))
    {
        BYTE pbPubKey[1024] = {0};
        UINT32 cbPubKey = 0;
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptEnumKeys(
                                hProv,
                                NULL,
                                &pKeyName,
                                &pEnumState,
                                NCRYPT_SILENT_FLAG))))
        {
            if(hr == HRESULT_FROM_WIN32((ULONG)NTE_NO_MORE_ITEMS))
            {
                hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
            }
            goto Cleanup;
        }
        if(SUCCEEDED(NCryptOpenKey(
                            hProv,
                            &hKey,
                            pKeyName->pszName,
                            0,
                            0)))
        {
            // Export public key
            if(SUCCEEDED(NCryptExportKey(
                                hKey,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                NULL,
                                pbPubKey,
                                sizeof(pbPubKey),
                                (PDWORD)&cbPubKey,
                                0)))
            {
                if((cbCertPubKey == cbPubKey) &&
                    (!memcmp(pbCertPubKey,
                                pbPubKey,
                                cbCertPubKey)))
                {
                    // We found a match, now get the attestation data
                    if(FAILED(hr = TpmAttCreateAttestationfromKey(
                            hKey,
                            (PWSTR)aikName,
                            szAikName,
                            aikDigest,
                            NULL,
                            0,
                            &cbAttestation)))
                    {
                        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
                        goto Cleanup;
                    }
                    if(FAILED(hr = AllocateAndZero((PVOID*)&pbAttestation, cbAttestation)))
                    {
                        goto Cleanup;
                    }
                    if(FAILED(hr = TpmAttCreateAttestationfromKey(
                            hKey,
                            (PWSTR)aikName,
                            szAikName,
                            aikDigest,
                            pbAttestation,
                            cbAttestation,
                            &cbAttestation)))
                    {
                        hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
                        goto Cleanup;
                    }
                    break;
                }
            }
        }
        NCryptFreeObject(hKey);
        hKey = NULL;
        NCryptFreeBuffer(pKeyName);
        pKeyName = NULL;
    }

    // Export attestation blob
    if(attestationFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(
                                attestationFile,
                                pbAttestation,
                                cbAttestation)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"<KeyAttestation size=\"%u\" aikName=\"%s\" aikDigest=\"", cbAttestation, szAikName);
    for(UINT32 n = 0; n < SHA1_DIGEST_SIZE; n++)
    {
            wprintf(L"%02x", aikDigest[n]);
    }
    wprintf(L"\">\n");
    if(FAILED(hr = PcpToolDisplayKeyAttestation(pbAttestation, cbAttestation, 1)))
    {
        goto Cleanup;
    }
    wprintf(L"</KeyAttestation>\n");

Cleanup:
    ZeroAndFree((PVOID*)&pbAttestation, cbAttestation);
    if(pKeyName != NULL)
    {
        NCryptFreeBuffer(pKeyName);
        pKeyName = NULL;
    }
    if(pEnumState != NULL)
    {
        NCryptFreeBuffer(pEnumState);
        pEnumState = NULL;
    }
    if (NULL != pvOutAuthBuffer)
    {
        CoTaskMemFree(pvOutAuthBuffer);
        pvOutAuthBuffer = NULL;
    }
    if (NULL != szWindowsDir)
    {
        CoTaskMemFree(szWindowsDir);
        szWindowsDir = NULL;
    }
    if(pcCertContext != NULL)
    {
        CertFreeCertificateContext(pcCertContext);
        pcCertContext = NULL;
    }
    if(hCertStore != NULL)
    {
        CertCloseStore(hCertStore, 0);
        hCertStore = NULL;
    }
    if(hSC != NULL)
    {
        SCardReleaseContext(hSC);
        hSC = NULL;
    }
    if(hCertKey != NULL)
    {
        BCryptDestroyKey(hCertKey);
        hCertKey = NULL;
    }
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hScProv != NULL)
    {
        NCryptFreeObject(hScProv);
        hScProv = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    PcpToolCallResult(L"PcpToolGetVscKeyAttestationFromKey()", hr);
    return hr;
}

HRESULT
PcpToolIssueEkCert(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
{
    HRESULT hr = S_OK;
    LPWSTR ekPubFile = NULL;
    LPWSTR subject = NULL;
    LPWSTR certOutName = NULL;
    PCCERT_CONTEXT pCaCert = NULL;
    PBYTE pbEkPub = NULL;
    UINT32 cbEkPub = 0;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hEK = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    ULONGLONG certSerial = 0L;
    SYSTEMTIME validityPeriod = {5, 0, 0, 0, 0, 0, 0, 0};
    UINT32 cbCertOut = 0;
    PBYTE pbCertOut = NULL;
    PCCERT_CONTEXT ekCert = NULL;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: EKPub
    if(argc > 2)
    {
        ekPubFile = argv[2];
        // Extract the public EK info
        if(FAILED(hr = PcpToolReadFile(ekPubFile, NULL, 0, &cbEkPub)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbEkPub, cbEkPub)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(ekPubFile,
                                       pbEkPub,
                                       cbEkPub,
                                       &cbEkPub)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                              &hProv,
                                              NULL,
                                              0))))
        {
            goto Cleanup;
        }
        if(FAILED(hr = HRESULT_FROM_WIN32(NCryptImportKey(
                                              hProv,
                                              NULL,
                                              BCRYPT_RSAPUBLIC_BLOB,
                                              NULL,
                                              &hEK,
                                              pbEkPub,
                                              cbEkPub,
                                              0))))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [EKPub File] [Subject Name] {Cert file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: Subject Name
    if(argc > 3)
    {
        subject = argv[3];
    }
    else
    {
        wprintf(L"%s %s [EKPub File] [Subject Name] {Cert file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    if(argc > 4)
    {
        certOutName = argv[4];
    }

    // Make up a random serial number
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                    &hAlg,
                                    BCRYPT_RNG_ALGORITHM,
                                    MS_PRIMITIVE_PROVIDER,
                                    0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptGenRandom(hAlg,
                                                   (PUCHAR)&certSerial,
                                                   sizeof(certSerial),
                                                   0))))
    {
        goto Cleanup;
    }

    // Issue the EK Certificate
    if(FAILED(hr = GetCACertContext(L"MY", &pCaCert)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = IssueCertificate(pCaCert,
                                    subject,
                                    hEK,
                                    certSerial,
                                    validityPeriod,
                                    NULL,
                                    0,
                                    &cbCertOut,
                                    ISSUECERTIFICATE_EKCERT)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbCertOut, cbCertOut)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = IssueCertificate(pCaCert,
                                    subject,
                                    hEK,
                                    certSerial,
                                    validityPeriod,
                                    pbCertOut,
                                    cbCertOut,
                                    &cbCertOut,
                                    ISSUECERTIFICATE_EKCERT)))
    {
        goto Cleanup;
    }

    // Open the cert to see that it does work
    ekCert = CertCreateCertificateContext(X509_ASN_ENCODING,
                                          pbCertOut,
                                          cbCertOut);
    if(ekCert == NULL)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    if(certOutName == NULL)
    {
        // Display the cert
        if (FAILED(hr = CryptUIDlgViewContextWrapper(&ekCert)))
        {
            goto Cleanup;
        }
    }
    else
    {
        // Store it if required
        if(FAILED(hr = PcpToolWriteFile(certOutName, pbCertOut, cbCertOut)))
        {
            goto Cleanup;
        }
    }

    wprintf(L"OK.");

Cleanup:
    if(pCaCert != NULL)
    {
        CertFreeCertificateContext(pCaCert);
        pCaCert = NULL;
    }
    if(hEK != NULL)
    {
        NCryptFreeObject(hEK);
        hEK = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    if(ekCert != NULL)
    {
        CertFreeCertificateContext(ekCert);
        ekCert = NULL;
    }
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbCertOut, cbCertOut);
    ZeroAndFree((PVOID*)&pbEkPub, cbEkPub);
    PcpToolCallResult(L"PcpToolComposeEkCert()", hr);
    return hr;
}

HRESULT
PcpToolPrivacyCaChallenge(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function is the third step in what is known as the AIK handshake and
executed on the server. The server will have already looked at the EKCert and
extracted the EKPub from it. This step will generate the Aik certificate and the
activation blob, which is the challenge to the client. The secret is a symmetric key
that encrypts the certificate for the AIK.
--*/
{
    HRESULT hr = S_OK;
    PCWSTR idBindingFile = NULL;
    PCWSTR ekPubFile = NULL;
    PCWSTR subject = NULL;
    BYTE activationSecret[0x10] = {0};
    PCWSTR activationBlobFile = NULL;
    PCWSTR nonce = NULL;
    BCRYPT_ALG_HANDLE hRng = NULL;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hEK = NULL;
    BCRYPT_KEY_HANDLE hAik = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hAikPub = NULL;
    PBYTE pbIdBinding = NULL;
    UINT32 cbIdBinding = 0;
    PBYTE pbEkPub = NULL;
    UINT32 cbEkPub = 0;
    PBYTE pbAikPub = NULL;
    UINT32 cbAikPub = 0;
    BYTE nonceDigest[SHA1_DIGEST_SIZE] = {0};
    PBYTE pbActivationBlob = NULL;
    UINT32 cbActivationBlob = 0;
    PCCERT_CONTEXT pCaCert = NULL;
    ULONGLONG certSerial = 0L;
    SYSTEMTIME validityPeriod = {1, 0, 0, 0, 0, 0, 0, 0};
    UINT32 cbCertOut = 0;
    PBYTE pbCertOut = NULL;
    UINT32 result = 0;

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: IdBinding
    if(argc > 2)
    {
        idBindingFile = argv[2];
        if(FAILED(hr = PcpToolReadFile(
                            idBindingFile,
                            NULL,
                            0,
                            &cbIdBinding)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbIdBinding, cbIdBinding)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(idBindingFile,
                                       pbIdBinding,
                                       cbIdBinding,
                                       &cbIdBinding)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [idBinding file] [EKPub File] [Subject] {Blob file} {nonce}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: EKPub
    if(argc > 3)
    {
        ekPubFile = argv[3];
        if(FAILED(hr = PcpToolReadFile(ekPubFile, NULL, 0, &cbEkPub)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbEkPub, cbEkPub)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(ekPubFile,
                                       pbEkPub,
                                       cbEkPub,
                                       &cbEkPub)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [idBinding file] [EKPub File] [Subject] {Blob file} {nonce}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: subject
    if(argc > 4)
    {
        subject = argv[4];
    }
    else
    {
        wprintf(L"%s %s [idBinding file] [EKPub File] [Subject] {Blob file} {nonce}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Optional parameter: Activation blob
    if(argc > 5)
    {
        activationBlobFile = argv[5];
    }

    // Optional parameter: Nonce
    if(argc > 6)
    {
        nonce = argv[6];
        if(FAILED(hr = TpmAttiShaHash(BCRYPT_SHA1_ALGORITHM,
                                                    NULL,
                                                    0,
                                                    (PBYTE)nonce,
                                                    (UINT32)(wcslen(nonce) * sizeof(WCHAR)),
                                                    nonceDigest,
                                                    sizeof(nonceDigest),
                                                    &result)))
        {
            goto Cleanup;
        }
    }

    // Generate a random activation secret
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                    &hRng,
                                    BCRYPT_RNG_ALGORITHM,
                                    MS_PRIMITIVE_PROVIDER,
                                    0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptGenRandom(hRng,
                                                   activationSecret,
                                                   sizeof(activationSecret),
                                                   0))))
    {
        goto Cleanup;
    }

    // make up cert serial
    if(FAILED(hr = HRESULT_FROM_NT(BCryptGenRandom(hRng,
                                                   (PBYTE)&certSerial,
                                                   sizeof(certSerial),
                                                   0))))
    {
        goto Cleanup;
    }

    // Load the keys
    if(FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
                                &hAlg,
                                BCRYPT_RSA_ALGORITHM,
                                MS_PRIMITIVE_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_NT(BCryptImportKeyPair(
                                hAlg,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                &hEK,
                                pbEkPub,
                                cbEkPub,
                                0))))
    {
        goto Cleanup;
    }

    // Get a handle to the AIK and export it
    if(FAILED(hr = TpmAttPubKeyFromIdBinding(
                        pbIdBinding,
                        cbIdBinding,
                        hAlg,
                        &hAik)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(
                                hAik,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                NULL,
                                0,
                                (PULONG)&cbAikPub,
                                0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbAikPub, cbAikPub)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_NT(BCryptExportKey(
                                hAik,
                                NULL,
                                BCRYPT_RSAPUBLIC_BLOB,
                                pbAikPub,
                                cbAikPub,
                                (PULONG)&cbAikPub,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = TpmAttGenerateActivation(
                        hEK,
                        pbIdBinding,
                        cbIdBinding,
                        (nonce) ? nonceDigest : NULL,
                        (nonce) ? sizeof(nonceDigest) : 0,
                        activationSecret,
                        sizeof(activationSecret),
                        NULL,
                        0,
                        &cbActivationBlob)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbActivationBlob, cbActivationBlob)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = TpmAttGenerateActivation(
                        hEK,
                        pbIdBinding,
                        cbIdBinding,
                        (nonce) ? nonceDigest : NULL,
                        (nonce) ? sizeof(nonceDigest) : 0,
                        activationSecret,
                        sizeof(activationSecret),
                        pbActivationBlob,
                        cbActivationBlob,
                        &cbActivationBlob)))
    {
        goto Cleanup;
    }

    // Generate the AIK Cert
    if(FAILED(hr = GetCACertContext(L"MY", &pCaCert)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                            &hProv,
                                            NULL,
                                            0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptImportKey(
                                            hProv,
                                            NULL,
                                            BCRYPT_RSAPUBLIC_BLOB,
                                            NULL,
                                            &hAikPub,
                                            pbAikPub,
                                            cbAikPub,
                                            0))))
    {
        goto Cleanup;
    }
    if(FAILED(hr = IssueCertificate(pCaCert,
                                    (LPWSTR)subject,
                                    hAikPub,
                                    certSerial,
                                    validityPeriod,
                                    NULL,
                                    0,
                                    &cbCertOut,
                                    0)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = AllocateAndZero((PVOID*)&pbCertOut, cbCertOut)))
    {
        goto Cleanup;
    }
    if(FAILED(hr = IssueCertificate(pCaCert,
                                    (LPWSTR)subject,
                                    hAikPub,
                                    certSerial,
                                    validityPeriod,
                                    pbCertOut,
                                    cbCertOut,
                                    &cbCertOut,
                                    0)))
    {
        goto Cleanup;
    }

    // Protect the AIK cert with the activation secret
    if(FAILED(hr = ProtectData(TRUE,
                               activationSecret,
                               sizeof(activationSecret),
                               pbCertOut,
                               cbCertOut)))
    {
        goto Cleanup;
    }

    // Store the activation and cert if required
    if(idBindingFile != NULL)
    {
        if(FAILED(hr = PcpToolWriteFile(
                                activationBlobFile,
                                (PBYTE)&cbActivationBlob,
                                sizeof(cbActivationBlob))))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolAppendFile(
                                activationBlobFile,
                                pbActivationBlob,
                                cbActivationBlob)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolAppendFile(
                                activationBlobFile,
                                (PBYTE)&cbCertOut,
                                sizeof(cbCertOut))))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolAppendFile(
                                activationBlobFile,
                                pbCertOut,
                                cbCertOut)))
        {
            goto Cleanup;
        }
    }

    // Output results
    wprintf(L"<Activation>\n");
    if(FAILED(hr = PcpToolDisplayKey(L"AIK", pbAikPub, cbAikPub, 1)))
    {
        goto Cleanup;
    }
    PcpToolLevelPrefix(1);
    wprintf(L"<ActivationBlob size=\"%u\">\n", cbActivationBlob);
    PcpToolLevelPrefix(2);
    for(UINT32 n = 0; n < cbActivationBlob; n++)
    {
        wprintf(L"%02x", pbActivationBlob[n]);
    }
    wprintf(L"\n");
    PcpToolLevelPrefix(1);
    wprintf(L"</ActivationBlob>\n");
    PcpToolLevelPrefix(1);
    wprintf(L"<AIKCert size=\"%u\">\n", cbCertOut);
    PcpToolLevelPrefix(2);
    for(UINT32 n = 0; n < cbCertOut; n++)
    {
        wprintf(L"%02x", pbCertOut[n]);
    }
    wprintf(L"\n");
    PcpToolLevelPrefix(1);
    wprintf(L"</AIKCert>\n");
    wprintf(L"</Activation>\n");

Cleanup:
    if(pCaCert != NULL)
    {
        CertFreeCertificateContext(pCaCert);
        pCaCert = NULL;
    }
    if(hEK != NULL)
    {
        BCryptDestroyKey(hEK);
        hEK = NULL;
    }
    if(hAik != NULL)
    {
        BCryptDestroyKey(hAik);
        hAik = NULL;
    }
    if(hAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        hAlg = NULL;
    }
    if(hRng != NULL)
    {
        BCryptCloseAlgorithmProvider(hRng, 0);
        hAlg = NULL;
    }
    ZeroAndFree((PVOID*)&pbIdBinding, cbIdBinding);
    ZeroAndFree((PVOID*)&pbEkPub, cbEkPub);
    ZeroAndFree((PVOID*)&pbAikPub, cbAikPub);
    ZeroAndFree((PVOID*)&pbActivationBlob, cbActivationBlob);
    PcpToolCallResult(L"PcpToolIssueAIKCert()", hr);
    return hr;
}

HRESULT
PcpToolPrivacyCaActivate(
    int argc,
    _In_reads_(argc) WCHAR* argv[]
    )
/*++
This function is the last step in what is known as the AIK handshake. The client
will load the AIK into the TPM and perform the activation to retieve the symmetric
key. If the specified EK and AIK reside in the same TPM, it will release
the symmetric key. Then the AIK certififcate is decrypted and registered in the
system.
--*/
{
    HRESULT hr = S_OK;
    LPWSTR certOutName = NULL;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;
    PCWSTR keyName = NULL;
    PCWSTR activationFile = NULL;
    PBYTE pbActivationBlob = NULL;
    UINT32 cbActivationBlob = 0;
    PBYTE pbCertBlob = NULL;
    UINT32 cbCertBlob = 0;
    BYTE activationSecret[0x10] = {0};
    DWORD cbActivationSecret = 0;
    PCCERT_CONTEXT pCert = NULL;
    HCERTSTORE hMyStore = NULL;
    CRYPT_KEY_PROV_INFO keyInfo = {0,
                                   MS_PLATFORM_CRYPTO_PROVIDER,
                                   0,
                                   0,
                                   0,
                                   NULL,
                                   0};

    // Paranoid check
    if(argc < 2)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: AIK name
    if(argc > 2)
    {
        keyName = argv[2];
        keyInfo.pwszContainerName = argv[2];
    }
    else
    {
        wprintf(L"%s %s [key name] [Blob file] {cert file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Mandatory Parameter: Activation and cert blob
    if(argc > 3)
    {
        UINT32 cursor = 0;
        activationFile = argv[3];
        if(FAILED(hr = PcpToolReadFile(activationFile,
                                       cursor,
                                       (PBYTE)&cbActivationBlob,
                                       sizeof(cbActivationBlob))))
        {
            goto Cleanup;
        }
        cursor += sizeof(cbActivationBlob);
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbActivationBlob, cbActivationBlob)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(activationFile,
                                       cursor,
                                       pbActivationBlob,
                                       cbActivationBlob)))
        {
            goto Cleanup;
        }
        cursor += cbActivationBlob;
        if(FAILED(hr = PcpToolReadFile(activationFile,
                                       cursor,
                                       (PBYTE)&cbCertBlob,
                                       sizeof(cbCertBlob))))
        {
            goto Cleanup;
        }
        cursor += sizeof(cbCertBlob);
        if(FAILED(hr = AllocateAndZero((PVOID*)&pbCertBlob, cbCertBlob)))
        {
            goto Cleanup;
        }
        if(FAILED(hr = PcpToolReadFile(activationFile,
                                       cursor,
                                       pbCertBlob,
                                       cbCertBlob)))
        {
            goto Cleanup;
        }
    }
    else
    {
        wprintf(L"%s %s [key name] [Blob file] {cert file}\n",
                argv[0],
                argv[1]);
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    if(argc > 4)
    {
        certOutName = argv[4];
    }

    // Open AIK
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenStorageProvider(
                                &hProv,
                                MS_PLATFORM_CRYPTO_PROVIDER,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptOpenKey(
                                hProv,
                                &hKey,
                                keyName,
                                0,
                                0))))
    {
        goto Cleanup;
    }

    // Perform the activation
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                hKey,
                                NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
                                pbActivationBlob,
                                cbActivationBlob,
                                0))))
    {
        goto Cleanup;
    }

    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
                                hKey,
                                NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY,
                                activationSecret,
                                sizeof(activationSecret),
                                &cbActivationSecret,
                                0))))
    {
        goto Cleanup;
    }

    // Unprotect the AIK cert with the activation secret
    if(FAILED(hr = ProtectData(FALSE,
                               activationSecret,
                               cbActivationSecret,
                               pbCertBlob,
                               cbCertBlob)))
    {
        goto Cleanup;
    }

    // Set the cert on the key
    if(FAILED(hr = HRESULT_FROM_WIN32(NCryptSetProperty(
                                hKey,
                                NCRYPT_CERTIFICATE_PROPERTY,
                                pbCertBlob,
                                cbCertBlob,
                                0))))
    {
        goto Cleanup;
    }

    // Register the Cert
    pCert = CertCreateCertificateContext(
                    X509_ASN_ENCODING |
                    PKCS_7_ASN_ENCODING,
                    pbCertBlob,
                    cbCertBlob);
    if(!pCert)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Link cert to the private key
    if(!CertSetCertificateContextProperty(
                                pCert,
                                CERT_KEY_PROV_INFO_PROP_ID,
                                0,
                                &keyInfo))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Add the cert to the MY store
    hMyStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_W,
                             0,
                             NULL,
                             CERT_SYSTEM_STORE_CURRENT_USER,
                             L"MY");
    if(!hMyStore)
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }
    if(!CertAddCertificateContextToStore(hMyStore,
                                         pCert,
                                         CERT_STORE_ADD_REPLACE_EXISTING,
                                         NULL))
    {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto Cleanup;
    }

    // Store it if required
    if((certOutName != NULL) &&
       (FAILED(hr = PcpToolWriteFile(certOutName, pbCertBlob, cbCertBlob))))
    {
        goto Cleanup;
    }

    wprintf(L"OK.");

Cleanup:
    if(hKey != NULL)
    {
        NCryptFreeObject(hKey);
        hKey = NULL;
    }
    if(hProv != NULL)
    {
        NCryptFreeObject(hProv);
        hProv = NULL;
    }
    ZeroAndFree((PVOID*)&pbActivationBlob, cbActivationBlob);
    PcpToolCallResult(L"PcpToolActivateAIKCert()", hr);
    return hr;
}
