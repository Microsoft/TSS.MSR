/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (c) Microsoft Corporation.  All rights reserved.

Module Name:

    PCPWbcl.cpp

Abstract:

    API surface that offers TCG log parsing functionality.

--*/

#include "stdafx.h"

#define TREE_EVENT_LOG_FORMAT_TCG_1_2   0x00000001
#define TREE_EVENT_LOG_FORMAT_TCG_2     0x00000002

//
// taken from minkernel\boot\environ\lib\misc\tpmfw.c
//
#ifndef MIN_TCG_VERSION_MAJOR
#define MIN_TCG_VERSION_MAJOR (1)
#define MIN_TCG_VERSION_MINOR (2)
#endif // MIN_TCG_VERSION_MAJOR

// the signature for TCG EFI Platform specification version 2.0 is "Spec ID Event03"
char TCG_EfiSpecIdEventStruct_Signature_03[16] = { 0x53, 0x70, 0x65, 0x63,
                                                   0x20, 0x49, 0x44, 0x20,
                                                   0x45, 0x76, 0x65, 0x6e,
                                                   0x74, 0x30, 0x33, 0x00 };

//
// Defines a lookup table to map algorithm IDs to the algorithm ID bitmap.
//
#define WBCL_DIGSET_ALG_ID_MAX  (WBCL_DIGEST_ALG_ID_SHA_2_512 + 1)

static const UINT32 g_WbclAlgotihmIdToBitmapTable[WBCL_DIGSET_ALG_ID_MAX] =
                            { 0, 0, 0, 0,
                                WBCL_DIGEST_ALG_BITMAP_SHA_1,     // WBCL_DIGEST_ALG_ID_SHA_1
                                0, 0, 0, 0, 0, 0,
                                WBCL_DIGEST_ALG_BITMAP_SHA_2_256, // WBCL_DIGEST_ALG_ID_SHA_2_256
                                WBCL_DIGEST_ALG_BITMAP_SHA_2_384, // WBCL_DIGEST_ALG_ID_SHA_2_384
                                WBCL_DIGEST_ALG_BITMAP_SHA_2_512  // WBCL_DIGEST_ALG_ID_SHA_2_512
                            };

//
// Define a maximum number of digests that may be present in a TCG log
// event. This number is the maximum for active PCR banks.
//
#define MAX_NUMBER_OF_DIGESTS   (5)

// define these two types here, so we can cast pointer to them.
// defining the types in the header file generates compile time conflicts

#pragma pack(push,1)

typedef struct _TCG_EfiSpecIdEventAlgorithmSize {
    WBCL_DIGEST_ALG_ID  AlgorithmId;
    UINT16              DigestSize;
} TCG_EfiSpecIdEventAlgorithmSize;

typedef struct _TCG_EfiSpecIdEventStruct {
    UINT8       Signature[16];
    UINT32      PlatformClass;
    UINT8       SpecVersionMinor;
    UINT8       SpecVersionMajor;
    UINT8       SpecErrata;
    UINT8       UintnSize;
    UINT32      NumberOfAlgorithms;
    _Field_size_bytes_(NumberOfAlgorithms * sizeof(TCG_EfiSpecIdEventAlgorithmSize))
        TCG_EfiSpecIdEventAlgorithmSize DigestSizes[ANYSIZE_ARRAY]; // [numberOfAlgorithms]
    UINT8       VendorInfoSize;
    _Field_size_bytes_(VenderInfoSize)
        UINT8       VendorInfo[ANYSIZE_ARRAY]; // [vendorInfoSize]
} TCG_EfiSpecIDEventStruct;

#pragma pack(pop)

#pragma optimize("", off)

UINT32
WbclGetDigestSize(
    _In_ WBCL_Iterator* pWbclIterator,
    _In_ WBCL_DIGEST_ALG_ID algorithmId
    )
/*++

Description:

    Retrieve the size of the digest for a given algorithm ID. The values cannot be
    hard coded, because the log may contain hashes of algorithms that are unknown.
    The log header contains a lookup table that matches all algorithms used in the log
    to their respective digest sizes. Use that table to lookup the digest size for the
    given algorithm.

    For the old log format, the numberOfDigests is 0, so the default value of
    SHA1_DIGEST_SIZE is returned.

Parameters:

    pWbclIterator - pointer to the event log element.

    algorithmId - the algorithm Id queried.

Return value:

    The size of the digest for the given algorithm in bytes. Or zero (0) if algorithm
    is not present in the table.

--*/
{
    UINT32 current;
    UINT16 digestSize = SHA1_DIGEST_SIZE;

    for (current = 0; current < pWbclIterator->numberOfDigests; current++)
    {
        if (((TCG_EfiSpecIdEventAlgorithmSize*)pWbclIterator->digestSizes)[current].AlgorithmId == algorithmId)
        {
            digestSize = ((TCG_EfiSpecIdEventAlgorithmSize*)pWbclIterator->digestSizes)[current].DigestSize;

            goto Cleanup;
        }
    }

Cleanup:
    return digestSize;
}

#pragma optimize("", on)

HRESULT
WbclGetCurrentElementDigestSize(
    _In_ WBCL_Iterator* pWbclIterator,
    _Out_ UINT32* pDigestSize
    )
/*++

Description:

    Retrieve the size of the Digests field of the current element. This might not be fixed,
    as Windows is only storing the SHA256 digest, but not other digests. Parse the Digests
    field and return the sum of the digest sizes.

    Pre: The current element up to the element data size field fits into the log.

Parameters:

    pWbclIterator - the pointer to the current element.

    pDigestSize - The size of the TPML_DIGEST_VALUES structure in the current element or SHA1_DIGEST_SIZE
    if SHA1 log.

Return value:

    S_OK if successful.

--*/
{
    ULONG size = 0;
    UINT32 numberOfDigests = 0;
    UINT32 current;
    PBYTE ptr;
    PBYTE endOfLogPtr = NULL;
    HRESULT hr = S_OK;
    WBCL_DIGEST_ALG_ID algId;
    UINT32 digestSize;
    ULONG tpmtHaSize = 0;

    if (pWbclIterator->logFormat == TREE_EVENT_LOG_FORMAT_TCG_1_2)
    {
        size = SHA1_DIGEST_SIZE;
        goto Cleanup;
    }

    if (pWbclIterator->logFormat == TREE_EVENT_LOG_FORMAT_TCG_2)
    {
        endOfLogPtr = (PBYTE)pWbclIterator->firstElementPtr + pWbclIterator->logSize;

        //
        // ptr to point past PCRIndex and EventType
        //
        ptr = (PBYTE)pWbclIterator->currentElementPtr + 2 * sizeof(UINT32);

        //
        // get number of digests (numberOfDigests) from TPML_DIGEST_VALUES
        //
        numberOfDigests = *(UINT32*)ptr;
        size = sizeof(UINT32); // sizeof(numberOfDigests)
        ptr += sizeof(UINT32);

        //
        // Check untrusted numberOfDigests value. We check against the maximum
        // allowed number of digest and not the numberOfDigests field in the 
        // iterator, because the number of digests in the log may vary. The BIOS
        // is supposed to have as many digests as the numberOfDigests from the
        // iterator, but Windows may log only one digest (or a subset of digests).
        //
        if (numberOfDigests > MAX_NUMBER_OF_DIGESTS)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        for (current = 0; current < numberOfDigests; current++)
        {
            algId = *(WBCL_DIGEST_ALG_ID*)ptr;
            digestSize = WbclGetDigestSize(pWbclIterator, algId);

            //
            // digestSize is untrusted. Use safe addition to add size of algorithm ID
            //
            tpmtHaSize = digestSize + sizeof(WBCL_DIGEST_ALG_ID);

            //
            // advance current ptr by digest size and check if still within log boundaries
            //
            ptr += tpmtHaSize;
            if (ptr > endOfLogPtr)
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }

            //
            // add size of TPMT_HA to total size
            //
            size += tpmtHaSize;
        }
    }

Cleanup:
    if (hr != S_OK)
    {
        size = 0;
    }
    if (pDigestSize != NULL)
    {
        *pDigestSize = size;
    }

    return hr;
}

UINT32
WbclGetCurrentElementDataSize(
    _In_ WBCL_Iterator* pWbclIterator
    )
/*++

Description:

    Returns the size of the event data field.

    Because the log format can have an non-fixed sized Digests field, this function
    adds the size of the event header to the size of the Digests field and returns
    the value of the UINT32 variable stored at that location.

    Pre: The current element fits at least up to the element data size into the log.

Parameters:

    pWbclIterator - pointer to the event log element.

Return value:

    The value stored at the position of the EventSize field.

--*/
{
    PBYTE elementDataSizePtr = NULL;
    UINT32 digestSize = 0;
    HRESULT hr;

    hr = WbclGetCurrentElementDigestSize(pWbclIterator, &digestSize);
    if (hr != S_OK)
    {
        digestSize = 0;
        goto Cleanup;
    }

    elementDataSizePtr = (PBYTE)pWbclIterator->currentElementPtr +
        2 * sizeof(UINT32) + // header
        digestSize; // size of Digests field or SHA1 digest

    digestSize = *(UINT32*)elementDataSizePtr;

Cleanup:
    return digestSize;
}

HRESULT
WbclGetCurrentElementSize(
    _In_ WBCL_Iterator* pWbclIterator,
    _Out_ UINT32* pElementSize
    )
/*++

Description:

    Returns the size of the whole log event.

    This function retrieves the size of the EventData field and add the size of
    the event header, the Digests field, and the EventDataSize field to it.

    Pre: The current element fits at least up to the element data size into the log.

Parameter:

    pWbclIterator - pointer to the event log element.

    pElementSize - pointer to the variable that will receive the element size in bytes.

Return value:

    S_OK if successful.

--*/
{
    HRESULT hr = S_OK;
    UINT32 dataSize;
    UINT32 digestSize = 0;

    hr = WbclGetCurrentElementDigestSize(pWbclIterator, &digestSize);
    if (hr != S_OK)
    {
        goto Cleanup;
    }

    if (pElementSize != NULL)
    {
        dataSize = WbclGetCurrentElementDataSize(pWbclIterator);

        *pElementSize = 2 * sizeof(UINT32) + // header
            digestSize + // size of Digests field or SHA1 digest
            sizeof(UINT32) + // EventDataSize 
            dataSize; // EventData
    }

Cleanup:
    return hr;
}

PBYTE
WbclGetCurrentElementData(
    _In_ WBCL_Iterator* pWbclIterator
    )
/*++

Description:

    Returns a pointer to the EventData field. Because the Digests field can be variable
    in size, this access function calculates the right offsets and returns a pointer
    to the start of the EventData field.

    Pre: The current element fits within the boundaries of the log.

Parameter:

    pWbclIterator - pointer to the event log element.

Return value:

    Pointer to the EventData field or NULL if the EventDataSize is 0.

--*/
{
    PBYTE elementDataPtr = NULL;
    UINT32 digestSize;
    HRESULT hr = S_OK;

    if (WbclGetCurrentElementDataSize(pWbclIterator) == 0)
    {
        goto Cleanup;
    }

    hr = WbclGetCurrentElementDigestSize(pWbclIterator, &digestSize);
    if (hr != S_OK)
    {
        goto Cleanup;
    }

    elementDataPtr = (PBYTE)pWbclIterator->currentElementPtr +
        2 * sizeof(UINT32) + // header
        digestSize + // Digests
        sizeof(UINT32); // sizeof(EventDataSize)

Cleanup:
    return elementDataPtr;
}

PBYTE
WbclGetCurrentElementDigest(
    _In_ WBCL_Iterator* pWbclIterator
    )
/*++

Description:

    Returns a pointer to the digest of the selected hashing algorithm.

    If this is the SHA1 log format, then this function returns a pointer to the Digest
    field.

    If this is the crypto agile format, this function returns a pointer to the digest
    of the selected hashing algorithm (pWbclIterator->hashAlgorithm). The digests are stored
    in a TPML_DIGEST_VALUES structure which consists of a count member, and then <count>
    TPMT_HA structures. The TPMT_HA structure itself consists of a hash algorithm ID
    and the digest. The digest is a byte array. The size of the byte array depends on the
    hashing algorithm.

    Pre: The current element has been verified to be within the bounds of the log.

Parameter:

    pWbclIterator - pointer to the event log element.

Return value:

    Pointer to the digest of the log element.

--*/
{
    UINT32 numberOfDigests;
    WBCL_DIGEST_ALG_ID currentAlgorithm;
    UINT32 currentDigest;
    UINT32 currentDigestSize;
    PBYTE currentDigestPtr = NULL;
    PBYTE endOfLogPtr = NULL;
    HRESULT hr = S_OK;

    //
    // move past PCRIndex and EventType
    //
    currentDigestPtr = (PBYTE)pWbclIterator->currentElementPtr + 2 * sizeof(UINT32);

    if (pWbclIterator->logFormat == TREE_EVENT_LOG_FORMAT_TCG_1_2)
    {
        //
        // For SHA-1 log format, this is it.
        //
        goto Cleanup;
    }

    if (pWbclIterator->logFormat == TREE_EVENT_LOG_FORMAT_TCG_2)
    {
        endOfLogPtr = (PBYTE)pWbclIterator->firstElementPtr + pWbclIterator->logSize;
        numberOfDigests = *(UINT32*)currentDigestPtr;
        currentDigestPtr = (PBYTE)currentDigestPtr + sizeof(UINT32);

        if (numberOfDigests > MAX_NUMBER_OF_DIGESTS)
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }

        for (currentDigest = 0; currentDigest < numberOfDigests; currentDigest++)
        {
            //
            // get current Algorithm ID and move digest pointer past algId
            //
            currentAlgorithm = *(WBCL_DIGEST_ALG_ID*)currentDigestPtr;
            currentDigestPtr = (PBYTE)currentDigestPtr + sizeof(WBCL_DIGEST_ALG_ID);

            //
            // Check if the algorithm matches the hashing algorithm of the log.
            // If so, currentDigestPtr is pointing to the right digest.
            //
            if (currentAlgorithm == pWbclIterator->hashAlgorithm)
            {
                goto Cleanup;
            }

            //
            // Move past the digest with safe operation.
            //
            currentDigestSize = WbclGetDigestSize(pWbclIterator, currentAlgorithm);

            currentDigestPtr += currentDigestSize;
            if (currentDigestPtr > endOfLogPtr)
            {
                hr = E_INVALIDARG;
                goto Cleanup;
            }
        }
    }

    // no matching log format or no matching algorithm found, return NULL
    currentDigestPtr = NULL;

Cleanup:
    //
    // if there was an error, return NULL
    //
    if (hr != S_OK)
    {
        currentDigestPtr = NULL;
    }

    return (PBYTE)currentDigestPtr;
}

//
// public API
//

HRESULT
MyWbclApiInitIterator(
    _In_bytecount_(logSize) PVOID  pLogBuffer,
    _In_                    UINT32 logSize,
    _Out_                   WBCL_Iterator* pWbclIterator
    )
/*++

Description:

    Initialize the WBCL iterator using the provided log file.

    The initialization routine checks if the provided log file contains a header log element,
    which can be used to determine if the log is in a crypto-agile format or the SHA1 specific
    format. If the crypto-agile format is identified, some of the iterator fields are set to
    values from the header element.

Parameters:

    pLogBuffer - pointer to the memory buffer containing the log.

    logSize - the size of pLogBuffer in bytes.

    pWbclIterator - points to an iterator structure that is initialized by this function.

Return value:

    S_OK if everything is fine.

    E_INVALIDARG - pLogBuffer or pWbclIterator are NULL or log is too small

--*/
{
    HRESULT hr = S_OK;
    UINT32  firstElementDataSize = 0;
    UINT32  digestCounter = 0;
    UINT32  supportedAlgorithms = 0;
    UINT32  elementSize = 0;
    TCG_EfiSpecIDEventStruct *pLogDescriptor = NULL;
    UINT32 pcrIndex = 0;
    UINT32 eventType = 0;
    WBCL_DIGEST_ALG_ID algId;

    if (pLogBuffer == NULL ||
        logSize < sizeof(TCG_PCClientPCREventStruct) - sizeof(BYTE) ||
        pWbclIterator == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Start with legacy TCG format.
    pWbclIterator->firstElementPtr = pLogBuffer;
    pWbclIterator->logSize = logSize;
    pWbclIterator->currentElementPtr = pWbclIterator->firstElementPtr;
    pWbclIterator->digestSize = SHA1_DIGEST_SIZE;
    pWbclIterator->logFormat = TREE_EVENT_LOG_FORMAT_TCG_1_2;
    pWbclIterator->numberOfDigests = 0;
    pWbclIterator->digestSizes = NULL;
    pWbclIterator->hashAlgorithm = WBCL_DIGEST_ALG_ID_SHA_1;

    //
    // Using WbclGetCurrentElementSize here works, because the first event is
    // in the old log format with a fixed 20 byte digest and digestSize is 
    // initialized to 20 bytes (SHA1_DIGEST_SIZE) and above check for logSize
    // ensures that at least one event is in the log.
    //
    hr = WbclGetCurrentElementSize(pWbclIterator, &elementSize);
    if (hr != S_OK ||
        logSize < elementSize)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }
    pWbclIterator->currentElementSize = elementSize;

    //
    // Extract information for the first event in the log.
    //
    hr = MyWbclApiGetCurrentElement(pWbclIterator,
                                    &pcrIndex,
                                    &eventType,
                                    NULL,
                                    &firstElementDataSize,
                                    NULL);
    if (hr != S_OK)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        goto Cleanup;
    }

    //
    // Check the very first entry to match the event log descriptor.
    //
    // Note: Use FIELD_OFFSET for minimum size of event data, because the C declaration
    // contains 1 byte for VendorInfo, which is optional.
    //
    if ((pcrIndex == 0) && // pcrIndex
        (eventType == SIPAEV_NO_ACTION) &&
        firstElementDataSize >= FIELD_OFFSET(TCG_EfiSpecIDEventStruct, VendorInfo))
    {
        pLogDescriptor = (TCG_EfiSpecIDEventStruct*)WbclGetCurrentElementData(pWbclIterator);

        if (strcmp((const char*)(pLogDescriptor->Signature),
            TCG_EfiSpecIdEventStruct_Signature_03) == 0)
        {
            //
            // sanity check revision number
            //
            if ((pLogDescriptor->SpecVersionMajor < MIN_TCG_VERSION_MAJOR) ||
                ((pLogDescriptor->SpecVersionMajor == MIN_TCG_VERSION_MAJOR) &&
                    (pLogDescriptor->SpecVersionMinor < MIN_TCG_VERSION_MINOR)))
            {
                hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
                goto Cleanup;
            }

            //
            // sanity check that NumberOfAlgorithms is included in event
            //
            if (firstElementDataSize < FIELD_OFFSET(TCG_EfiSpecIDEventStruct, DigestSizes))
            {
                hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
                goto Cleanup;
            }

            //
            // pLogDescriptor->NumberOfAlgorithms is untrusted. Check against the 
            // maximum value currently defined.
            //
            if (pLogDescriptor->NumberOfAlgorithms > MAX_NUMBER_OF_DIGESTS)
            {
                hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
                goto Cleanup;
            }

            //
            // size sanity check that all digest size fit into event data of first element
            // pLogDescriptor->NumberOfAlgorithms is smaller than MAX_NUMBER_OF_DIGESTS,
            // which is currently 5. It is safe to multiply with the size of 
            // TCG_EfiSpecIdEventAlgorithmSize, which is 4. And adding 20 (5 * 4) to the offset
            // of DigestSizes in TCG_EfiSpecIDEventStruct to it, is safe as well.
            //
            if (firstElementDataSize < FIELD_OFFSET(TCG_EfiSpecIDEventStruct, DigestSizes) +
                pLogDescriptor->NumberOfAlgorithms *
                sizeof(TCG_EfiSpecIdEventAlgorithmSize))
            {
                hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                goto Cleanup;
            }

            for (digestCounter = 0;
            digestCounter < pLogDescriptor->NumberOfAlgorithms;
                digestCounter++)
            {
                algId = pLogDescriptor->DigestSizes[digestCounter].AlgorithmId;
                supportedAlgorithms |= g_WbclAlgotihmIdToBitmapTable[algId];
            }

            pWbclIterator->logFormat = TREE_EVENT_LOG_FORMAT_TCG_2;
            pWbclIterator->numberOfDigests = pLogDescriptor->NumberOfAlgorithms;
            pWbclIterator->digestSizes = &pLogDescriptor->DigestSizes[0];

            //
            // Check for supported algorithm ID in bitmap, based on preference.
            //
            if (supportedAlgorithms & WBCL_DIGEST_ALG_BITMAP_SHA_2_256)
            {
                pWbclIterator->hashAlgorithm = WBCL_DIGEST_ALG_ID_SHA_2_256;
                pWbclIterator->digestSize = SHA256_DIGEST_SIZE;
            }
            else if (supportedAlgorithms & WBCL_DIGEST_ALG_BITMAP_SHA_1)
            {
                pWbclIterator->hashAlgorithm = WBCL_DIGEST_ALG_ID_SHA_1;
                pWbclIterator->digestSize = SHA1_DIGEST_SIZE;
            }
            else
            {
                hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
                goto Cleanup;
            }

            //
            // Move to the first log entry after the descriptor.
            // MyWbclApiMoveToNextElement() does boundary checks.
            //
            hr = MyWbclApiMoveToNextElement(pWbclIterator);
            if (hr != S_OK)
            {
                hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                goto Cleanup;
            }
        }
    }

Cleanup:
    return hr;
}

HRESULT
MyWbclApiGetCurrentElement(
    _In_            WBCL_Iterator* pWbclIterator,
    _Out_           UINT32* pcrIndex,
    _Out_           UINT32* eventType,
    _Outptr_opt_result_bytebuffer_(pWbclIterator->digestSize) BYTE** ppDigest,
    _Out_opt_       UINT32* pcbElementDataSize,
    _Outptr_opt_result_bytebuffer_(*pcbElementDataSize) BYTE** ppbElementData
    )
/*++

Description:

    Retrieve pointers and values to the elements of the current log element.

    The digest and element data will receive pointers into the log. Do NOT
    free the pointers received. These pointer will become invalid when the
    log that has been used to initialize the iterator is freed.

    The digest is retrieved for the algorithm set in pWbclIterator->hashAlgorithm
    and be pWbclIterator->digestSize bytes big.

Parameters:

    pWbclIterator - pointer to the current log element.

    pcrIndex - pointer to variable that will receive the PCR index of the current event.

    eventType - pointer to variable that will receive the event type of the current event.

    ppDigest - provides an optional pointer that will receive the location of the digest of the active hashing algorithm.

    pcbElementDataSize - provides an optional pointer that will receive the size of ppbElementData.

    ppbElementData - provides an optional pointer that will receive the location of the event data.

Return value:

    S_OK if everything is fine.

    E_INVALIDARG - if parameters were invalid.

--*/
{
    HRESULT hr = S_OK;

    if (pWbclIterator->currentElementPtr == NULL ||
        pWbclIterator->currentElementSize == 0 ||
        pcrIndex == NULL ||
        eventType == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    *pcrIndex = *(UINT32*)pWbclIterator->currentElementPtr;
    *eventType = *(((UINT32*)pWbclIterator->currentElementPtr) + 1);

    if (ppDigest != NULL)
    {
        *ppDigest = WbclGetCurrentElementDigest(pWbclIterator);
    }

    if (pcbElementDataSize != NULL)
    {
        *pcbElementDataSize = WbclGetCurrentElementDataSize(pWbclIterator);
    }

    if (ppbElementData != NULL)
    {
        *ppbElementData = WbclGetCurrentElementData(pWbclIterator);
    }

Cleanup:
    return hr;
}

HRESULT
MyWbclApiMoveToNextElement(
    _In_ WBCL_Iterator* pWbclIterator)
/*++

Description:

Parameters:

    pWbclIterator - pointer to the current log element.

Return value:

    S_OK if everything is fine.

    S_FALSE if no more elements in the log

--*/
{
    HRESULT hr = S_OK;
    PBYTE nextElementPtr = NULL;
    PBYTE endOfLogPtr = NULL;
    PBYTE endOfNextElementPtr = NULL;
    UINT32 minimumSize;
    UINT32 elementSize;

    //
    // ensure that repetitive invocations return same result when end of 
    // log is reached
    //
    if (pWbclIterator->currentElementPtr == NULL ||
        pWbclIterator->currentElementSize == 0)
    {
        goto Cleanup;
    }

    //
    // Do safe addition of pointers to avoid wrap around on
    // 32 bit architectures. 
    //
    nextElementPtr = (PBYTE)pWbclIterator->currentElementPtr + pWbclIterator->currentElementSize;
    endOfLogPtr = (PBYTE)pWbclIterator->firstElementPtr + pWbclIterator->logSize;

    //
    // Calculate minimum size of next element.
    // For SHA-1 log this is 3 * sizeof(UINT32) + SHA1 digest size
    // For SHA-2 log this is 4 * sizeof(UINT32) + sizeof(WBCL_DIGEST_ALG_ID) + iterator->digestSize
    //
    minimumSize = 3 * sizeof(UINT32) + SHA1_DIGEST_SIZE;
    if (pWbclIterator->logFormat == TREE_EVENT_LOG_FORMAT_TCG_2)
    {
        minimumSize = 4 * sizeof(UINT32) + sizeof(WBCL_DIGEST_ALG_ID) + pWbclIterator->digestSize;
    }

    //
    // Add the minimum size to the start of the next element.
    // If the minimum size of the next element is not within
    // the boundaries of the log, don't advance.
    //
    endOfNextElementPtr = (PBYTE)nextElementPtr + minimumSize;
    if (endOfNextElementPtr > endOfLogPtr)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    //
    // Advance to next element.
    //
    pWbclIterator->currentElementPtr = (PBYTE)nextElementPtr;
    hr = WbclGetCurrentElementSize(pWbclIterator, &elementSize);
    if (hr != S_OK)
    {
        goto Cleanup;
    }
    pWbclIterator->currentElementSize = elementSize;

    //
    // Extract the correct element size and add to the begin of the element
    // to get the real end of the next element and check if it is
    // in bounds.
    //
    endOfNextElementPtr = (PBYTE)pWbclIterator->currentElementPtr + pWbclIterator->currentElementSize;
    if (endOfNextElementPtr > endOfLogPtr)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    hr = S_OK;

Cleanup:
    if (hr != S_OK)
    {
        pWbclIterator->currentElementPtr = NULL;
        pWbclIterator->currentElementSize = 0;

        hr = S_FALSE;
    }

    return hr;
}
