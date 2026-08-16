using System;
using System.Runtime.Serialization;
using System.Diagnostics.CodeAnalysis;

namespace Tpm2Lib
{
    /// <summary> Table 2 is the list of algorithms to which the TCG has assigned an algorithm
    /// identifier along with its numeric identifier. </summary>
    [DataContract]
    [SpecTypeName("TPM_ALG_ID")]
    public enum TpmAlgId : ushort
    {
        None = 0,

        /// <summary> Should not occur </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ERROR")]
        Error = 0x0000,

        /// <summary> An object type that contains an RSA key </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_FIRST")]
        First = 0x0001,

        /// <summary> An object type that contains an RSA key </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_RSA")]
        Rsa = 0x0001,

        /// <summary> Block cipher with various key sizes (Triple Data Encryption Algorithm,
        /// commonly called Triple Data Encryption Standard) </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_TDES")]
        Tdes = 0x0003,

        /// <summary> Hash algorithm producing a 160-bit digest </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA")]
        Sha = 0x0004,

        /// <summary> Redefinition for documentation consistency </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA1")]
        Sha1 = 0x0004,

        /// <summary> Hash Message Authentication Code (HMAC) algorithm </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_HMAC")]
        Hmac = 0x0005,

        /// <summary> Block cipher with various key sizes </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_AES")]
        Aes = 0x0006,

        /// <summary> Hash-based mask-generation function </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_MGF1")]
        Mgf1 = 0x0007,

        /// <summary> An object type that may use XOR for encryption or an HMAC for signing and
        /// may also refer to a data object that is neither signing nor encrypting </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_KEYEDHASH")]
        Keyedhash = 0x0008,

        /// <summary> Hash-based stream cipher </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_XOR")]
        Xor = 0x000A,

        /// <summary> Hash algorithm producing a 256-bit digest </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA256")]
        Sha256 = 0x000B,

        /// <summary> Hash algorithm producing a 384-bit digest </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA384")]
        Sha384 = 0x000C,

        /// <summary> Hash algorithm producing a 512-bit digest </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA512")]
        Sha512 = 0x000D,

        /// <summary> Indication that no algorithm is selected </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_NULL")]
        Null = 0x0010,

        /// <summary> Hash algorithm producing a 256-bit digest </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SM3_256")]
        Sm3256 = 0x0012,

        /// <summary> Symmetric block cipher with 128 bit key </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SM4")]
        Sm4 = 0x0013,

        /// <summary> A signature algorithm defined in section 8.2 (RSASSA-PKCS1-v1_5) </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_RSASSA")]
        Rsassa = 0x0014,

        /// <summary> A padding algorithm defined in section 7.2 (RSAES-PKCS1-v1_5) </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_RSAES")]
        Rsaes = 0x0015,

        /// <summary> A signature algorithm defined in section 8.1 (RSASSA-PSS) </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_RSAPSS")]
        Rsapss = 0x0016,

        /// <summary> A padding algorithm defined in Section 7.1 (RSAES_OAEP) </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_OAEP")]
        Oaep = 0x0017,

        /// <summary> Signature algorithm using elliptic curve cryptography (ECC) </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECDSA")]
        Ecdsa = 0x0018,

        /// <summary> Secret sharing using ECC Based on context, this can be either One-Pass
        /// Diffie-Hellman, C(1, 1, ECC CDH) defined in 6.2.2.2 or Full Unified Model C(2, 2, ECC
        /// CDH) defined in 6.1.1.2 </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECDH")]
        Ecdh = 0x0019,

        /// <summary> Elliptic-curve based, anonymous signing scheme </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECDAA")]
        Ecdaa = 0x001A,

        /// <summary> Depending on context, either an elliptic-curve-based signature algorithm,
        /// encryption algorithm, or key exchange protocol </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SM2")]
        Sm2 = 0x001B,

        /// <summary> Elliptic-curve based Schnorr signature </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECSCHNORR")]
        Ecschnorr = 0x001C,

        /// <summary> Two-phase elliptic-curve key exchange C(2, 2, ECC MQV) Section 6.1.1.4 </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECMQV")]
        Ecmqv = 0x001D,

        /// <summary> Concatenation key derivation function (approved alternative 1) Section 5.8.1
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_KDF1_SP800_56A")]
        Kdf1Sp80056a = 0x0020,

        /// <summary> Key derivation function KDF2 Section 13.2 </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_KDF2")]
        Kdf2 = 0x0021,

        /// <summary> A key derivation method SP800-108, Section 5.1 KDF in Counter Mode </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_KDF1_SP800_108")]
        Kdf1Sp800108 = 0x0022,

        /// <summary> Prime field ECC </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECC")]
        Ecc = 0x0023,

        /// <summary> The object type for a symmetric block cipher key </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SYMCIPHER")]
        Symcipher = 0x0025,

        /// <summary> Symmetric block cipher with various key sizes </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_CAMELLIA")]
        Camellia = 0x0026,

        /// <summary> Hash algorithm producing a 256-bit digest </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA3_256")]
        Sha3256 = 0x0027,

        /// <summary> Hash algorithm producing a 384-bit digest </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA3_384")]
        Sha3384 = 0x0028,

        /// <summary> Hash algorithm producing a 512-bit digest </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_SHA3_512")]
        Sha3512 = 0x0029,

        [EnumMember]
        [SpecTypeName("TPM_ALG_CMAC")]
        Cmac = 0x003F,

        /// <summary> Counter mode if implemented, all symmetric block ciphers (S type)
        /// implemented shall be capable of using this mode. </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_CTR")]
        Ctr = 0x0040,

        /// <summary> Output Feedback mode if implemented, all symmetric block ciphers (S type)
        /// implemented shall be capable of using this mode. </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_OFB")]
        Ofb = 0x0041,

        /// <summary> Cipher Block Chaining mode if implemented, all symmetric block ciphers (S
        /// type) implemented shall be capable of using this mode. </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_CBC")]
        Cbc = 0x0042,

        /// <summary> Cipher Feedback mode if implemented, all symmetric block ciphers (S type)
        /// implemented shall be capable of using this mode. </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_CFB")]
        Cfb = 0x0043,

        /// <summary> Electronic Codebook mode if implemented, all implemented symmetric block
        /// ciphers (S type) shall be capable of using this mode.
        /// NOTE This mode is not recommended for uses unless the key is frequently rotated such
        /// as in video codecs </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ECB")]
        Ecb = 0x0044,

        [EnumMember]
        [SpecTypeName("TPM_ALG_LAST")]
        Last = 0x0044,

        /// <summary> Phony alg ID to be used for the first union member with no selector </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ANY")]
        Any = 0x7FFF,

        /// <summary> Phony alg ID to be used for the second union member with no selector </summary>
        [EnumMember]
        [SpecTypeName("TPM_ALG_ANY2")]
        Any2 = 0x7FFE
    }

    /// <summary> Table 4 is the list of identifiers for TCG-registered curve ID values for
    /// elliptic curve cryptography. </summary>
    [DataContract]
    [SpecTypeName("TPM_ECC_CURVE")]
    public enum EccCurve : ushort
    {
        [EnumMember]
        [SpecTypeName("TPM_ECC_NONE")]
        None = 0x0000,
        [Obsolete("Use EccCurve.None instead")]
        TpmEccNone = 0x0000,

        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P192")]
        NistP192 = 0x0001,
        [Obsolete("Use EccCurve.NistP192 instead")]
        TpmEccNistP192 = 0x0001,

        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P224")]
        NistP224 = 0x0002,
        [Obsolete("Use EccCurve.NistP224 instead")]
        TpmEccNistP224 = 0x0002,

        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P256")]
        NistP256 = 0x0003,
        [Obsolete("Use EccCurve.NistP256 instead")]
        TpmEccNistP256 = 0x0003,

        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P384")]
        NistP384 = 0x0004,
        [Obsolete("Use EccCurve.NistP384 instead")]
        TpmEccNistP384 = 0x0004,

        [EnumMember]
        [SpecTypeName("TPM_ECC_NIST_P521")]
        NistP521 = 0x0005,
        [Obsolete("Use EccCurve.NistP521 instead")]
        TpmEccNistP521 = 0x0005,

        /// <summary> Curve to support ECDAA </summary>
        [EnumMember]
        [SpecTypeName("TPM_ECC_BN_P256")]
        BnP256 = 0x0010,
        [Obsolete("Use EccCurve.BnP256 instead")]
        TpmEccBnP256 = 0x0010,

        /// <summary> Curve to support ECDAA </summary>
        [EnumMember]
        [SpecTypeName("TPM_ECC_BN_P638")]
        BnP638 = 0x0011,
        [Obsolete("Use EccCurve.BnP638 instead")]
        TpmEccBnP638 = 0x0011,

        [EnumMember]
        [SpecTypeName("TPM_ECC_SM2_P256")]
        Sm2P256 = 0x0020,
        [Obsolete("Use EccCurve.Sm2P256 instead")]
        TpmEccSm2P256 = 0x0020,

        [EnumMember]
        [SpecTypeName("TPM_ECC_TEST_P192")]
        TestP192 = 0x0021,
        [Obsolete("Use EccCurve.TestP192 instead")]
        TpmEccTestP192 = 0x0021
    }

    /// <summary> Table 13 Defines for SHA1 Hash Values </summary>
    [DataContract]
    [SpecTypeName("SHA1")]
    public enum Sha1 : uint
    {
        None = 0,

        /// <summary> Size of digest in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA1_DIGEST_SIZE")]
        DigestSize = 20,

        /// <summary> Size of hash block in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA1_BLOCK_SIZE")]
        BlockSize = 64
    }

    /// <summary> Table 14 Defines for SHA256 Hash Values </summary>
    [DataContract]
    [SpecTypeName("SHA256")]
    public enum Sha256 : uint
    {
        None = 0,

        /// <summary> Size of digest </summary>
        [EnumMember]
        [SpecTypeName("SHA256_DIGEST_SIZE")]
        DigestSize = 32,

        /// <summary> Size of hash block </summary>
        [EnumMember]
        [SpecTypeName("SHA256_BLOCK_SIZE")]
        BlockSize = 64
    }

    /// <summary> Table 15 Defines for SHA384 Hash Values </summary>
    [DataContract]
    [SpecTypeName("SHA384")]
    public enum Sha384 : uint
    {
        None = 0,

        /// <summary> Size of digest in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA384_DIGEST_SIZE")]
        DigestSize = 48,

        /// <summary> Size of hash block in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA384_BLOCK_SIZE")]
        BlockSize = 128
    }

    /// <summary> Table 16 Defines for SHA512 Hash Values </summary>
    [DataContract]
    [SpecTypeName("SHA512")]
    public enum Sha512 : uint
    {
        None = 0,

        /// <summary> Size of digest in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA512_DIGEST_SIZE")]
        DigestSize = 64,

        /// <summary> Size of hash block in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA512_BLOCK_SIZE")]
        BlockSize = 128
    }

    /// <summary> Table 17 Defines for SM3_256 Hash Values </summary>
    [DataContract]
    [SpecTypeName("SM3_256")]
    public enum Sm3256 : uint
    {
        None = 0,

        /// <summary> Size of digest in octets </summary>
        [EnumMember]
        [SpecTypeName("SM3_256_DIGEST_SIZE")]
        DigestSize = 32,

        /// <summary> Size of hash block in octets </summary>
        [EnumMember]
        [SpecTypeName("SM3_256_BLOCK_SIZE")]
        BlockSize = 64
    }

    /// <summary> Table 18 Defines for SHA3_256 Hash Values </summary>
    [DataContract]
    [SpecTypeName("SHA3_256")]
    public enum Sha3256 : uint
    {
        None = 0,

        /// <summary> Size of digest in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA3_256_DIGEST_SIZE")]
        DigestSize = 32,

        /// <summary> Size of hash block in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA3_256_BLOCK_SIZE")]
        BlockSize = 136
    }

    /// <summary> Table 19 Defines for SHA3_384 Hash Values </summary>
    [DataContract]
    [SpecTypeName("SHA3_384")]
    public enum Sha3384 : uint
    {
        None = 0,

        /// <summary> Size of digest in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA3_384_DIGEST_SIZE")]
        DigestSize = 48,

        /// <summary> Size of hash block in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA3_384_BLOCK_SIZE")]
        BlockSize = 104
    }

    /// <summary> Table 20 Defines for SHA3_512 Hash Values </summary>
    [DataContract]
    [SpecTypeName("SHA3_512")]
    public enum Sha3512 : uint
    {
        None = 0,

        /// <summary> Size of digest in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA3_512_DIGEST_SIZE")]
        DigestSize = 64,

        /// <summary> Size of hash block in octets </summary>
        [EnumMember]
        [SpecTypeName("SHA3_512_BLOCK_SIZE")]
        BlockSize = 72
    }

    /// <summary> Table 4 Defines for Logic Values </summary>
    [DataContract]
    [SpecTypeName("Logic")]
    public enum Logic : byte
    {
        None = 0,

        [EnumMember]
        [SpecTypeName("TRUE")]
        True = 1,

        [EnumMember]
        [SpecTypeName("FALSE")]
        False = 0,

        [EnumMember]
        [SpecTypeName("YES")]
        Yes = 1,

        [EnumMember]
        [SpecTypeName("NO")]
        No = 0,

        [EnumMember]
        [SpecTypeName("SET")]
        Set = 1,

        [EnumMember]
        [SpecTypeName("CLEAR")]
        Clear = 0
    }

    /// <summary> These values are readable with TPM2_GetCapability() (see 6.13 for the
    /// format). </summary>
    [DataContract]
    [SpecTypeName("TPM_SPEC")]
    public enum Spec : uint
    {
        None = 0,

        /// <summary> ASCII 2.0 with null terminator </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_FAMILY")]
        Family = 0x322E3000,

        /// <summary> The level number for the specification </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_LEVEL")]
        Level = 0,

        /// <summary> The version number of the spec (001.62 * 100) </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_VERSION")]
        Version = 162,

        /// <summary> The year of the version </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_YEAR")]
        Year = 2019,

        /// <summary> The day of the year (December 26) </summary>
        [EnumMember]
        [SpecTypeName("TPM_SPEC_DAY_OF_YEAR")]
        DayOfYear = 360
    }

    /// <summary> This constant value differentiates TPM-generated structures from non-TPM
    /// structures. </summary>
    [DataContract]
    [SpecTypeName("TPM_GENERATED")]
    public enum Generated : uint
    {
        None = 0,

        /// <summary> 0xFF TCG (FF 54 43 4716) </summary>
        [EnumMember]
        [SpecTypeName("TPM_GENERATED_VALUE")]
        Value = unchecked ((uint)(0xff544347))
    }

    [DataContract]
    [SpecTypeName("TPM_CC")]
    public enum TpmCc : uint
    {
        None = 0,

        /// <summary> Compile variable. May decrease based on implementation. </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_FIRST")]
        First = 0x0000011F,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_UndefineSpaceSpecial")]
        NvUndefineSpaceSpecial = 0x0000011F,

        [EnumMember]
        [SpecTypeName("TPM_CC_EvictControl")]
        EvictControl = 0x00000120,

        [EnumMember]
        [SpecTypeName("TPM_CC_HierarchyControl")]
        HierarchyControl = 0x00000121,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_UndefineSpace")]
        NvUndefineSpace = 0x00000122,

        [EnumMember]
        [SpecTypeName("TPM_CC_ChangeEPS")]
        ChangeEPS = 0x00000124,

        [EnumMember]
        [SpecTypeName("TPM_CC_ChangePPS")]
        ChangePPS = 0x00000125,

        [EnumMember]
        [SpecTypeName("TPM_CC_Clear")]
        Clear = 0x00000126,

        [EnumMember]
        [SpecTypeName("TPM_CC_ClearControl")]
        ClearControl = 0x00000127,

        [EnumMember]
        [SpecTypeName("TPM_CC_ClockSet")]
        ClockSet = 0x00000128,

        [EnumMember]
        [SpecTypeName("TPM_CC_HierarchyChangeAuth")]
        HierarchyChangeAuth = 0x00000129,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_DefineSpace")]
        NvDefineSpace = 0x0000012A,

        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Allocate")]
        PcrAllocate = 0x0000012B,

        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_SetAuthPolicy")]
        PcrSetAuthPolicy = 0x0000012C,

        [EnumMember]
        [SpecTypeName("TPM_CC_PP_Commands")]
        PpCommands = 0x0000012D,

        [EnumMember]
        [SpecTypeName("TPM_CC_SetPrimaryPolicy")]
        SetPrimaryPolicy = 0x0000012E,

        [EnumMember]
        [SpecTypeName("TPM_CC_FieldUpgradeStart")]
        FieldUpgradeStart = 0x0000012F,

        [EnumMember]
        [SpecTypeName("TPM_CC_ClockRateAdjust")]
        ClockRateAdjust = 0x00000130,

        [EnumMember]
        [SpecTypeName("TPM_CC_CreatePrimary")]
        CreatePrimary = 0x00000131,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_GlobalWriteLock")]
        NvGlobalWriteLock = 0x00000132,

        [EnumMember]
        [SpecTypeName("TPM_CC_GetCommandAuditDigest")]
        GetCommandAuditDigest = 0x00000133,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Increment")]
        NvIncrement = 0x00000134,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_SetBits")]
        NvSetBits = 0x00000135,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Extend")]
        NvExtend = 0x00000136,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Write")]
        NvWrite = 0x00000137,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_WriteLock")]
        NvWriteLock = 0x00000138,

        [EnumMember]
        [SpecTypeName("TPM_CC_DictionaryAttackLockReset")]
        DictionaryAttackLockReset = 0x00000139,

        [EnumMember]
        [SpecTypeName("TPM_CC_DictionaryAttackParameters")]
        DictionaryAttackParameters = 0x0000013A,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_ChangeAuth")]
        NvChangeAuth = 0x0000013B,

        /// <summary> PCR </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Event")]
        PcrEvent = 0x0000013C,

        /// <summary> PCR </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Reset")]
        PcrReset = 0x0000013D,

        [EnumMember]
        [SpecTypeName("TPM_CC_SequenceComplete")]
        SequenceComplete = 0x0000013E,

        [EnumMember]
        [SpecTypeName("TPM_CC_SetAlgorithmSet")]
        SetAlgorithmSet = 0x0000013F,

        [EnumMember]
        [SpecTypeName("TPM_CC_SetCommandCodeAuditStatus")]
        SetCommandCodeAuditStatus = 0x00000140,

        [EnumMember]
        [SpecTypeName("TPM_CC_FieldUpgradeData")]
        FieldUpgradeData = 0x00000141,

        [EnumMember]
        [SpecTypeName("TPM_CC_IncrementalSelfTest")]
        IncrementalSelfTest = 0x00000142,

        [EnumMember]
        [SpecTypeName("TPM_CC_SelfTest")]
        SelfTest = 0x00000143,

        [EnumMember]
        [SpecTypeName("TPM_CC_Startup")]
        Startup = 0x00000144,

        [EnumMember]
        [SpecTypeName("TPM_CC_Shutdown")]
        Shutdown = 0x00000145,

        [EnumMember]
        [SpecTypeName("TPM_CC_StirRandom")]
        StirRandom = 0x00000146,

        [EnumMember]
        [SpecTypeName("TPM_CC_ActivateCredential")]
        ActivateCredential = 0x00000147,

        [EnumMember]
        [SpecTypeName("TPM_CC_Certify")]
        Certify = 0x00000148,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyNV")]
        PolicyNV = 0x00000149,

        [EnumMember]
        [SpecTypeName("TPM_CC_CertifyCreation")]
        CertifyCreation = 0x0000014A,

        [EnumMember]
        [SpecTypeName("TPM_CC_Duplicate")]
        Duplicate = 0x0000014B,

        [EnumMember]
        [SpecTypeName("TPM_CC_GetTime")]
        GetTime = 0x0000014C,

        [EnumMember]
        [SpecTypeName("TPM_CC_GetSessionAuditDigest")]
        GetSessionAuditDigest = 0x0000014D,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Read")]
        NvRead = 0x0000014E,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_ReadLock")]
        NvReadLock = 0x0000014F,

        [EnumMember]
        [SpecTypeName("TPM_CC_ObjectChangeAuth")]
        ObjectChangeAuth = 0x00000150,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicySecret")]
        PolicySecret = 0x00000151,

        [EnumMember]
        [SpecTypeName("TPM_CC_Rewrap")]
        Rewrap = 0x00000152,

        [EnumMember]
        [SpecTypeName("TPM_CC_Create")]
        Create = 0x00000153,

        [EnumMember]
        [SpecTypeName("TPM_CC_ECDH_ZGen")]
        EcdhZGen = 0x00000154,

        /// <summary> See NOTE 1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_HMAC")]
        Hmac = 0x00000155,

        /// <summary> See NOTE 1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_MAC")]
        Mac = 0x00000155,

        [EnumMember]
        [SpecTypeName("TPM_CC_Import")]
        Import = 0x00000156,

        [EnumMember]
        [SpecTypeName("TPM_CC_Load")]
        Load = 0x00000157,

        [EnumMember]
        [SpecTypeName("TPM_CC_Quote")]
        Quote = 0x00000158,

        [EnumMember]
        [SpecTypeName("TPM_CC_RSA_Decrypt")]
        RsaDecrypt = 0x00000159,

        /// <summary> See NOTE 1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_HMAC_Start")]
        HmacStart = 0x0000015B,

        /// <summary> See NOTE 1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_MAC_Start")]
        MacStart = 0x0000015B,

        [EnumMember]
        [SpecTypeName("TPM_CC_SequenceUpdate")]
        SequenceUpdate = 0x0000015C,

        [EnumMember]
        [SpecTypeName("TPM_CC_Sign")]
        Sign = 0x0000015D,

        [EnumMember]
        [SpecTypeName("TPM_CC_Unseal")]
        Unseal = 0x0000015E,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicySigned")]
        PolicySigned = 0x00000160,

        /// <summary> Context </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_ContextLoad")]
        ContextLoad = 0x00000161,

        /// <summary> Context </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_ContextSave")]
        ContextSave = 0x00000162,

        [EnumMember]
        [SpecTypeName("TPM_CC_ECDH_KeyGen")]
        EcdhKeyGen = 0x00000163,

        [EnumMember]
        [SpecTypeName("TPM_CC_EncryptDecrypt")]
        EncryptDecrypt = 0x00000164,

        /// <summary> Context </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_FlushContext")]
        FlushContext = 0x00000165,

        [EnumMember]
        [SpecTypeName("TPM_CC_LoadExternal")]
        LoadExternal = 0x00000167,

        [EnumMember]
        [SpecTypeName("TPM_CC_MakeCredential")]
        MakeCredential = 0x00000168,

        /// <summary> NV </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_NV_ReadPublic")]
        NvReadPublic = 0x00000169,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyAuthorize")]
        PolicyAuthorize = 0x0000016A,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyAuthValue")]
        PolicyAuthValue = 0x0000016B,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyCommandCode")]
        PolicyCommandCode = 0x0000016C,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyCounterTimer")]
        PolicyCounterTimer = 0x0000016D,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyCpHash")]
        PolicyCpHash = 0x0000016E,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyLocality")]
        PolicyLocality = 0x0000016F,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyNameHash")]
        PolicyNameHash = 0x00000170,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyOR")]
        PolicyOR = 0x00000171,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyTicket")]
        PolicyTicket = 0x00000172,

        [EnumMember]
        [SpecTypeName("TPM_CC_ReadPublic")]
        ReadPublic = 0x00000173,

        [EnumMember]
        [SpecTypeName("TPM_CC_RSA_Encrypt")]
        RsaEncrypt = 0x00000174,

        [EnumMember]
        [SpecTypeName("TPM_CC_StartAuthSession")]
        StartAuthSession = 0x00000176,

        [EnumMember]
        [SpecTypeName("TPM_CC_VerifySignature")]
        VerifySignature = 0x00000177,

        [EnumMember]
        [SpecTypeName("TPM_CC_ECC_Parameters")]
        EccParameters = 0x00000178,

        [EnumMember]
        [SpecTypeName("TPM_CC_FirmwareRead")]
        FirmwareRead = 0x00000179,

        [EnumMember]
        [SpecTypeName("TPM_CC_GetCapability")]
        GetCapability = 0x0000017A,

        [EnumMember]
        [SpecTypeName("TPM_CC_GetRandom")]
        GetRandom = 0x0000017B,

        [EnumMember]
        [SpecTypeName("TPM_CC_GetTestResult")]
        GetTestResult = 0x0000017C,

        [EnumMember]
        [SpecTypeName("TPM_CC_Hash")]
        Hash = 0x0000017D,

        /// <summary> PCR </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Read")]
        PcrRead = 0x0000017E,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyPCR")]
        PolicyPCR = 0x0000017F,

        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyRestart")]
        PolicyRestart = 0x00000180,

        [EnumMember]
        [SpecTypeName("TPM_CC_ReadClock")]
        ReadClock = 0x00000181,

        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_Extend")]
        PcrExtend = 0x00000182,

        [EnumMember]
        [SpecTypeName("TPM_CC_PCR_SetAuthValue")]
        PcrSetAuthValue = 0x00000183,

        [EnumMember]
        [SpecTypeName("TPM_CC_NV_Certify")]
        NvCertify = 0x00000184,

        [EnumMember]
        [SpecTypeName("TPM_CC_EventSequenceComplete")]
        EventSequenceComplete = 0x00000185,

        [EnumMember]
        [SpecTypeName("TPM_CC_HashSequenceStart")]
        HashSequenceStart = 0x00000186,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyPhysicalPresence")]
        PolicyPhysicalPresence = 0x00000187,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyDuplicationSelect")]
        PolicyDuplicationSelect = 0x00000188,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyGetDigest")]
        PolicyGetDigest = 0x00000189,

        [EnumMember]
        [SpecTypeName("TPM_CC_TestParms")]
        TestParms = 0x0000018A,

        [EnumMember]
        [SpecTypeName("TPM_CC_Commit")]
        Commit = 0x0000018B,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyPassword")]
        PolicyPassword = 0x0000018C,

        [EnumMember]
        [SpecTypeName("TPM_CC_ZGen_2Phase")]
        ZGen2Phase = 0x0000018D,

        [EnumMember]
        [SpecTypeName("TPM_CC_EC_Ephemeral")]
        EcEphemeral = 0x0000018E,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyNvWritten")]
        PolicyNvWritten = 0x0000018F,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyTemplate")]
        PolicyTemplate = 0x00000190,

        [EnumMember]
        [SpecTypeName("TPM_CC_CreateLoaded")]
        CreateLoaded = 0x00000191,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_PolicyAuthorizeNV")]
        PolicyAuthorizeNV = 0x00000192,

        [EnumMember]
        [SpecTypeName("TPM_CC_EncryptDecrypt2")]
        EncryptDecrypt2 = 0x00000193,

        [EnumMember]
        [SpecTypeName("TPM_CC_AC_GetCapability")]
        AcGetCapability = 0x00000194,

        [EnumMember]
        [SpecTypeName("TPM_CC_AC_Send")]
        AcSend = 0x00000195,

        /// <summary> Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_Policy_AC_SendSelect")]
        PolicyAcSendSelect = 0x00000196,

        [EnumMember]
        [SpecTypeName("TPM_CC_CertifyX509")]
        CertifyX509 = 0x00000197,

        [EnumMember]
        [SpecTypeName("TPM_CC_ACT_SetTimeout")]
        ActSetTimeout = 0x00000198,

        [EnumMember]
        [SpecTypeName("TPM_CC_ECC_Encrypt")]
        EccEncrypt = 0x00000199,

        [EnumMember]
        [SpecTypeName("TPM_CC_ECC_Decrypt")]
        EccDecrypt = 0x0000019A,

        /// <summary> Compile variable. May increase based on implementation. </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_LAST")]
        Last = 0x0000019A,

        [EnumMember]
        [SpecTypeName("CC_VEND")]
        CcVend = 0x20000000,

        /// <summary> Used for testing of command dispatch </summary>
        [EnumMember]
        [SpecTypeName("TPM_CC_Vendor_TCG_Test")]
        VendorTcgTest = CcVend+0x0000 // 0x20000000
    }

    /// <summary> Architecturally defined constants </summary>
    [DataContract]
    [SpecTypeName("ImplementationConstants")]
    public enum ImplementationConstants : uint
    {
        None = 0,

        [EnumMember]
        [SpecTypeName("Ossl")]
        Ossl = 1,

        [EnumMember]
        [SpecTypeName("Ltc")]
        Ltc = 2,

        [EnumMember]
        [SpecTypeName("Msbn")]
        Msbn = 3,

        [EnumMember]
        [SpecTypeName("Symcrypt")]
        Symcrypt = 4,

        [EnumMember]
        [SpecTypeName("HASH_COUNT")]
        HashCount = 3,

        [EnumMember]
        [SpecTypeName("MAX_SYM_KEY_BITS")]
        MaxSymKeyBits = 256,

        [EnumMember]
        [SpecTypeName("MAX_SYM_KEY_BYTES")]
        MaxSymKeyBytes = ((MaxSymKeyBits + 7) / 8), // 0x20

        [EnumMember]
        [SpecTypeName("MAX_SYM_BLOCK_SIZE")]
        MaxSymBlockSize = 16,

        [EnumMember]
        [SpecTypeName("MAX_CAP_CC")]
        MaxCapCc = TpmCc.Last, // 0x19A

        [EnumMember]
        [SpecTypeName("MAX_RSA_KEY_BYTES")]
        MaxRsaKeyBytes = 256,

        [EnumMember]
        [SpecTypeName("MAX_AES_KEY_BYTES")]
        MaxAesKeyBytes = 32,

        [EnumMember]
        [SpecTypeName("MAX_ECC_KEY_BYTES")]
        MaxEccKeyBytes = 48,

        [EnumMember]
        [SpecTypeName("LABEL_MAX_BUFFER")]
        LabelMaxBuffer = 32,

        [EnumMember]
        [SpecTypeName("_TPM_CAP_SIZE")]
        _TpmCapSize = sizeof(uint), // 0x4

        [EnumMember]
        [SpecTypeName("MAX_CAP_DATA")]
        MaxCapData = (1024/*MAX_CAP_BUFFER*/-_TpmCapSize-sizeof(uint)), // 0x3F8

        [EnumMember]
        [SpecTypeName("MAX_CAP_ALGS")]
        MaxCapAlgs = (MaxCapData / 0x6/*sizeof(TPMS_ALG_PROPERTY)*/), // 0xA9

        [EnumMember]
        [SpecTypeName("MAX_CAP_HANDLES")]
        MaxCapHandles = (MaxCapData / 0x4/*sizeof(TPM_HANDLE)*/), // 0xFE

        [EnumMember]
        [SpecTypeName("MAX_TPM_PROPERTIES")]
        MaxTpmProperties = (MaxCapData / 0x8/*sizeof(TPMS_TAGGED_PROPERTY)*/), // 0x7F

        [EnumMember]
        [SpecTypeName("MAX_PCR_PROPERTIES")]
        MaxPcrProperties = (MaxCapData / 0x5/*sizeof(TPMS_TAGGED_PCR_SELECT)*/), // 0xCB

        [EnumMember]
        [SpecTypeName("MAX_ECC_CURVES")]
        MaxEccCurves = (MaxCapData / sizeof(EccCurve)), // 0x1FC

        [EnumMember]
        [SpecTypeName("MAX_TAGGED_POLICIES")]
        MaxTaggedPolicies = (MaxCapData / 0x46/*sizeof(TPMS_TAGGED_POLICY)*/), // 0xE

        [EnumMember]
        [SpecTypeName("MAX_AC_CAPABILITIES")]
        MaxAcCapabilities = (MaxCapData / 0x8/*sizeof(TPMS_AC_OUTPUT)*/), // 0x7F

        [EnumMember]
        [SpecTypeName("MAX_ACT_DATA")]
        MaxActData = MaxCapData / 0xC/*sizeof(TPMS_ACT_DATA)*/ // 0x54
    }

    /// <summary> In general, response codes defined in TPM 2.0 Part 2 will be unmarshaling
    /// errors and will have the F (format) bit SET. Codes that are unique to TPM 2.0 Part 3
    /// will have the F bit CLEAR but the V (version) attribute will be SET to indicate that
    /// it is a TPM 2.0 response code. See Response Code Details in TPM 2.0 Part 1. </summary>
    [DataContract]
    [SpecTypeName("TPM_RC")]
    public enum TpmRc : uint
    {
        None = 0,

        [EnumMember]
        [SpecTypeName("TPM_RC_SUCCESS")]
        Success = 0x000,

        /// <summary> Defined for compatibility with TPM 1.2 </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_BAD_TAG")]
        BadTag = 0x01E,

        /// <summary> Set for all format 0 response codes </summary>
        [EnumMember]
        [SpecTypeName("RC_VER1")]
        RcVer1 = 0x100,

        /// <summary> TPM not initialized by TPM2_Startup or already initialized </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_INITIALIZE")]
        Initialize = RcVer1 + 0x000, // 0x100

        /// <summary> Commands not being accepted because of a TPM failure
        /// NOTE This may be returned by TPM2_GetTestResult() as the testResult parameter. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_FAILURE")]
        Failure = RcVer1 + 0x001, // 0x101

        /// <summary> Improper use of a sequence handle </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SEQUENCE")]
        Sequence = RcVer1 + 0x003, // 0x103

        /// <summary> Not currently used </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PRIVATE")]
        Private = RcVer1 + 0x00B, // 0x10B

        /// <summary> Not currently used </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_HMAC")]
        Hmac = RcVer1 + 0x019, // 0x119

        /// <summary> The command is disabled </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_DISABLED")]
        Disabled = RcVer1 + 0x020, // 0x120

        /// <summary> Command failed because audit sequence required exclusivity </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_EXCLUSIVE")]
        Exclusive = RcVer1 + 0x021, // 0x121

        /// <summary> Authorization handle is not correct for command </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_TYPE")]
        AuthType = RcVer1 + 0x024, // 0x124

        /// <summary> Command requires an authorization session for handle and it is not present. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_MISSING")]
        AuthMissing = RcVer1 + 0x025, // 0x125

        /// <summary> Policy failure in math operation or an invalid authPolicy value </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_POLICY")]
        Policy = RcVer1 + 0x026, // 0x126

        /// <summary> PCR check fail </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PCR")]
        Pcr = RcVer1 + 0x027, // 0x127

        /// <summary> PCR have changed since checked. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PCR_CHANGED")]
        PcrChanged = RcVer1 + 0x028, // 0x128

        /// <summary> For all commands other than TPM2_FieldUpgradeData(), this code indicates
        /// that the TPM is in field upgrade mode; for TPM2_FieldUpgradeData(), this code
        /// indicates that the TPM is not in field upgrade mode </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_UPGRADE")]
        Upgrade = RcVer1 + 0x02D, // 0x12D

        /// <summary> Context ID counter is at maximum. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TOO_MANY_CONTEXTS")]
        TooManyContexts = RcVer1 + 0x02E, // 0x12E

        /// <summary> AuthValue or authPolicy is not available for selected entity. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_UNAVAILABLE")]
        AuthUnavailable = RcVer1 + 0x02F, // 0x12F

        /// <summary> A _TPM_Init and Startup(CLEAR) is required before the TPM can resume
        /// operation. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REBOOT")]
        Reboot = RcVer1 + 0x030, // 0x130

        /// <summary> The protection algorithms (hash and symmetric) are not reasonably balanced.
        /// The digest size of the hash must be larger than the key size of the symmetric
        /// algorithm. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_UNBALANCED")]
        Unbalanced = RcVer1 + 0x031, // 0x131

        /// <summary> Command commandSize value is inconsistent with contents of the command
        /// buffer; either the size is not the same as the octets loaded by the hardware interface
        /// layer or the value is not large enough to hold a command header </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_COMMAND_SIZE")]
        CommandSize = RcVer1 + 0x042, // 0x142

        /// <summary> Command code not supported </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_COMMAND_CODE")]
        CommandCode = RcVer1 + 0x043, // 0x143

        /// <summary> The value of authorizationSize is out of range or the number of octets in
        /// the Authorization Area is greater than required </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTHSIZE")]
        Authsize = RcVer1 + 0x044, // 0x144

        /// <summary> Use of an authorization session with a context command or another command
        /// that cannot have an authorization session. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_CONTEXT")]
        AuthContext = RcVer1 + 0x045, // 0x145

        /// <summary> NV offset+size is out of range. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_RANGE")]
        NvRange = RcVer1 + 0x046, // 0x146

        /// <summary> Requested allocation size is larger than allowed. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_SIZE")]
        NvSize = RcVer1 + 0x047, // 0x147

        /// <summary> NV access locked. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_LOCKED")]
        NvLocked = RcVer1 + 0x048, // 0x148

        /// <summary> NV access authorization fails in command actions (this failure does not
        /// affect lockout.action) </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_AUTHORIZATION")]
        NvAuthorization = RcVer1 + 0x049, // 0x149

        /// <summary> An NV Index is used before being initialized or the state saved by
        /// TPM2_Shutdown(STATE) could not be restored </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_UNINITIALIZED")]
        NvUninitialized = RcVer1 + 0x04A, // 0x14A

        /// <summary> Insufficient space for NV allocation </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_SPACE")]
        NvSpace = RcVer1 + 0x04B, // 0x14B

        /// <summary> NV Index or persistent object already defined </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_DEFINED")]
        NvDefined = RcVer1 + 0x04C, // 0x14C

        /// <summary> Context in TPM2_ContextLoad() is not valid </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_BAD_CONTEXT")]
        BadContext = RcVer1 + 0x050, // 0x150

        /// <summary> CpHash value already set or not correct for use </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_CPHASH")]
        Cphash = RcVer1 + 0x051, // 0x151

        /// <summary> Handle for parent is not a valid parent </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PARENT")]
        Parent = RcVer1 + 0x052, // 0x152

        /// <summary> Some function needs testing. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NEEDS_TEST")]
        NeedsTest = RcVer1 + 0x053, // 0x153

        /// <summary> Returned when an internal function cannot process a request due to an
        /// unspecified problem. This code is usually related to invalid parameters that are not
        /// properly filtered by the input unmarshaling code. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NO_RESULT")]
        NoResult = RcVer1 + 0x054, // 0x154

        /// <summary> The sensitive area did not unmarshal correctly after decryption this code is
        /// used in lieu of the other unmarshaling errors so that an attacker cannot determine
        /// where the unmarshaling error occurred </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SENSITIVE")]
        Sensitive = RcVer1 + 0x055, // 0x155

        /// <summary> Largest version 1 code that is not a warning </summary>
        [EnumMember]
        [SpecTypeName("RC_MAX_FM0")]
        RcMaxFm0 = RcVer1 + 0x07F, // 0x17F

        /// <summary> This bit is SET in all format 1 response codes
        /// The codes in this group may have a value added to them to indicate the handle,
        /// session, or parameter to which they apply. </summary>
        [EnumMember]
        [SpecTypeName("RC_FMT1")]
        RcFmt1 = 0x080,

        /// <summary> Asymmetric algorithm not supported or not correct </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_ASYMMETRIC")]
        Asymmetric = RcFmt1 + 0x001, // 0x81

        /// <summary> Inconsistent attributes </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_ATTRIBUTES")]
        Attributes = RcFmt1 + 0x002, // 0x82

        /// <summary> Hash algorithm not supported or not appropriate </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_HASH")]
        Hash = RcFmt1 + 0x003, // 0x83

        /// <summary> Value is out of range or is not correct for the context </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_VALUE")]
        Value = RcFmt1 + 0x004, // 0x84

        /// <summary> Hierarchy is not enabled or is not correct for the use </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_HIERARCHY")]
        Hierarchy = RcFmt1 + 0x005, // 0x85

        /// <summary> Key size is not supported </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_KEY_SIZE")]
        KeySize = RcFmt1 + 0x007, // 0x87

        /// <summary> Mask generation function not supported </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_MGF")]
        Mgf = RcFmt1 + 0x008, // 0x88

        /// <summary> Mode of operation not supported </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_MODE")]
        Mode = RcFmt1 + 0x009, // 0x89

        /// <summary> The type of the value is not appropriate for the use </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TYPE")]
        Type = RcFmt1 + 0x00A, // 0x8A

        /// <summary> The handle is not correct for the use </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_HANDLE")]
        Handle = RcFmt1 + 0x00B, // 0x8B

        /// <summary> Unsupported key derivation function or function not appropriate for use </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_KDF")]
        Kdf = RcFmt1 + 0x00C, // 0x8C

        /// <summary> Value was out of allowed range. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_RANGE")]
        Range = RcFmt1 + 0x00D, // 0x8D

        /// <summary> The authorization HMAC check failed and DA counter incremented </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_AUTH_FAIL")]
        AuthFail = RcFmt1 + 0x00E, // 0x8E

        /// <summary> Invalid nonce size or nonce value mismatch </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NONCE")]
        Nonce = RcFmt1 + 0x00F, // 0x8F

        /// <summary> Authorization requires assertion of PP </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_PP")]
        Pp = RcFmt1 + 0x010, // 0x90

        /// <summary> Unsupported or incompatible scheme </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SCHEME")]
        Scheme = RcFmt1 + 0x012, // 0x92

        /// <summary> Structure is the wrong size </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SIZE")]
        Size = RcFmt1 + 0x015, // 0x95

        /// <summary> Unsupported symmetric algorithm or key size, or not appropriate for instance
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SYMMETRIC")]
        Symmetric = RcFmt1 + 0x016, // 0x96

        /// <summary> Incorrect structure tag </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TAG")]
        Tag = RcFmt1 + 0x017, // 0x97

        /// <summary> Union selector is incorrect </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SELECTOR")]
        Selector = RcFmt1 + 0x018, // 0x98

        /// <summary> The TPM was unable to unmarshal a value because there were not enough octets
        /// in the input buffer </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_INSUFFICIENT")]
        Insufficient = RcFmt1 + 0x01A, // 0x9A

        /// <summary> The signature is not valid </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SIGNATURE")]
        Signature = RcFmt1 + 0x01B, // 0x9B

        /// <summary> Key fields are not compatible with the selected use </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_KEY")]
        Key = RcFmt1 + 0x01C, // 0x9C

        /// <summary> A policy check failed </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_POLICY_FAIL")]
        PolicyFail = RcFmt1 + 0x01D, // 0x9D

        /// <summary> Integrity check failed </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_INTEGRITY")]
        Integrity = RcFmt1 + 0x01F, // 0x9F

        /// <summary> Invalid ticket </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TICKET")]
        Ticket = RcFmt1 + 0x020, // 0xA0

        /// <summary> Reserved bits not set to zero as required </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_RESERVED_BITS")]
        ReservedBits = RcFmt1 + 0x021, // 0xA1

        /// <summary> Authorization failure without DA implications </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_BAD_AUTH")]
        BadAuth = RcFmt1 + 0x022, // 0xA2

        /// <summary> The policy has expired </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_EXPIRED")]
        Expired = RcFmt1 + 0x023, // 0xA3

        /// <summary> The commandCode in the policy is not the commandCode of the command or the
        /// command code in a policy command references a command that is not implemented </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_POLICY_CC")]
        PolicyCc = RcFmt1 + 0x024, // 0xA4

        /// <summary> Public and sensitive portions of an object are not cryptographically bound </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_BINDING")]
        Binding = RcFmt1 + 0x025, // 0xA5

        /// <summary> Curve not supported </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_CURVE")]
        Curve = RcFmt1 + 0x026, // 0xA6

        /// <summary> Point is not on the required curve. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_ECC_POINT")]
        EccPoint = RcFmt1 + 0x027, // 0xA7

        /// <summary> Set for warning response codes </summary>
        [EnumMember]
        [SpecTypeName("RC_WARN")]
        RcWarn = 0x900,

        /// <summary> Gap for context ID is too large </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_CONTEXT_GAP")]
        ContextGap = RcWarn + 0x001, // 0x901

        /// <summary> Out of memory for object contexts </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_OBJECT_MEMORY")]
        ObjectMemory = RcWarn + 0x002, // 0x902

        /// <summary> Out of memory for session contexts </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SESSION_MEMORY")]
        SessionMemory = RcWarn + 0x003, // 0x903

        /// <summary> Out of shared object/session memory or need space for internal operations </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_MEMORY")]
        Memory = RcWarn + 0x004, // 0x904

        /// <summary> Out of session handles a session must be flushed before a new session may be
        /// created </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_SESSION_HANDLES")]
        SessionHandles = RcWarn + 0x005, // 0x905

        /// <summary> Out of object handles the handle space for objects is depleted and a reboot
        /// is required
        /// NOTE 1 This cannot occur on the reference implementation.
        /// NOTE 2 There is no reason why an implementation would implement a design that would
        /// deplete handle space. Platform specifications are encouraged to forbid it. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_OBJECT_HANDLES")]
        ObjectHandles = RcWarn + 0x006, // 0x906

        /// <summary> Bad locality </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_LOCALITY")]
        Locality = RcWarn + 0x007, // 0x907

        /// <summary> The TPM has suspended operation on the command; forward progress was made
        /// and the command may be retried
        /// See TPM 2.0 Part 1, Multi-tasking.
        /// NOTE This cannot occur on the reference implementation. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_YIELDED")]
        Yielded = RcWarn + 0x008, // 0x908

        /// <summary> The command was canceled </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_CANCELED")]
        Canceled = RcWarn + 0x009, // 0x909

        /// <summary> TPM is performing self-tests </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_TESTING")]
        Testing = RcWarn + 0x00A, // 0x90A

        /// <summary> The 1st handle in the handle area references a transient object or session
        /// that is not loaded </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H0")]
        ReferenceH0 = RcWarn + 0x010, // 0x910

        /// <summary> The 2nd handle in the handle area references a transient object or session
        /// that is not loaded </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H1")]
        ReferenceH1 = RcWarn + 0x011, // 0x911

        /// <summary> The 3rd handle in the handle area references a transient object or session
        /// that is not loaded </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H2")]
        ReferenceH2 = RcWarn + 0x012, // 0x912

        /// <summary> The 4th handle in the handle area references a transient object or session
        /// that is not loaded </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H3")]
        ReferenceH3 = RcWarn + 0x013, // 0x913

        /// <summary> The 5th handle in the handle area references a transient object or session
        /// that is not loaded </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H4")]
        ReferenceH4 = RcWarn + 0x014, // 0x914

        /// <summary> The 6th handle in the handle area references a transient object or session
        /// that is not loaded </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H5")]
        ReferenceH5 = RcWarn + 0x015, // 0x915

        /// <summary> The 7th handle in the handle area references a transient object or session
        /// that is not loaded </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_H6")]
        ReferenceH6 = RcWarn + 0x016, // 0x916

        /// <summary> The 1st authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S0")]
        ReferenceS0 = RcWarn + 0x018, // 0x918

        /// <summary> The 2nd authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S1")]
        ReferenceS1 = RcWarn + 0x019, // 0x919

        /// <summary> The 3rd authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S2")]
        ReferenceS2 = RcWarn + 0x01A, // 0x91A

        /// <summary> The 4th authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S3")]
        ReferenceS3 = RcWarn + 0x01B, // 0x91B

        /// <summary> The 5th session handle references a session that is not loaded </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S4")]
        ReferenceS4 = RcWarn + 0x01C, // 0x91C

        /// <summary> The 6th session handle references a session that is not loaded </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S5")]
        ReferenceS5 = RcWarn + 0x01D, // 0x91D

        /// <summary> The 7th authorization session handle references a session that is not loaded
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_REFERENCE_S6")]
        ReferenceS6 = RcWarn + 0x01E, // 0x91E

        /// <summary> The TPM is rate-limiting accesses to prevent wearout of NV </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_RATE")]
        NvRate = RcWarn + 0x020, // 0x920

        /// <summary> Authorizations for objects subject to DA protection are not allowed at this
        /// time because the TPM is in DA lockout mode </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_LOCKOUT")]
        Lockout = RcWarn + 0x021, // 0x921

        /// <summary> The TPM was not able to start the command </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_RETRY")]
        Retry = RcWarn + 0x022, // 0x922

        /// <summary> The command may require writing of NV and NV is not current accessible </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NV_UNAVAILABLE")]
        NvUnavailable = RcWarn + 0x023, // 0x923

        /// <summary> This value is reserved and shall not be returned by the TPM </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_NOT_USED")]
        NotUsed = RcWarn + 0x7F, // 0x97F

        /// <summary> Add to a handle-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_H")]
        H = 0x000,

        /// <summary> Add to a parameter-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_P")]
        P = 0x040,

        /// <summary> Add to a session-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_S")]
        S = 0x800,

        /// <summary> Add to a parameter-, handle-, or session-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_1")]
        _1 = 0x100,

        /// <summary> Add to a parameter-, handle-, or session-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_2")]
        _2 = 0x200,

        /// <summary> Add to a parameter-, handle-, or session-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_3")]
        _3 = 0x300,

        /// <summary> Add to a parameter-, handle-, or session-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_4")]
        _4 = 0x400,

        /// <summary> Add to a parameter-, handle-, or session-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_5")]
        _5 = 0x500,

        /// <summary> Add to a parameter-, handle-, or session-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_6")]
        _6 = 0x600,

        /// <summary> Add to a parameter-, handle-, or session-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_7")]
        _7 = 0x700,

        /// <summary> Add to a parameter-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_8")]
        _8 = 0x800,

        /// <summary> Add to a parameter-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_9")]
        _9 = 0x900,

        /// <summary> Add to a parameter-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_A")]
        A = 0xA00,

        /// <summary> Add to a parameter-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_B")]
        B = 0xB00,

        /// <summary> Add to a parameter-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_C")]
        C = 0xC00,

        /// <summary> Add to a parameter-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_D")]
        D = 0xD00,

        /// <summary> Add to a parameter-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_E")]
        E = 0xE00,

        /// <summary> Add to a parameter-related error </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_F")]
        F = 0xF00,

        /// <summary> Number mask </summary>
        [EnumMember]
        [SpecTypeName("TPM_RC_N_MASK")]
        NMask = 0xF00,

        /// <summary> Response buffer returned by the TPM is too short </summary>
        [EnumMember]
        [SpecTypeName("TSS_TCP_BAD_HANDSHAKE_RESP")]
        TssTcpBadHandshakeResp = 0x40280001,

        /// <summary> Too old TCP server version </summary>
        [EnumMember]
        [SpecTypeName("TSS_TCP_SERVER_TOO_OLD")]
        TssTcpServerTooOld = 0x40280002,

        /// <summary> Bad ack from the TCP end point </summary>
        [EnumMember]
        [SpecTypeName("TSS_TCP_BAD_ACK")]
        TssTcpBadAck = 0x40280003,

        /// <summary> Wrong length of the response buffer returned by the TPM </summary>
        [EnumMember]
        [SpecTypeName("TSS_TCP_BAD_RESP_LEN")]
        TssTcpBadRespLen = 0x40280004,

        /// <summary> TPM2_Startup returned unexpected response code </summary>
        [EnumMember]
        [SpecTypeName("TSS_TCP_UNEXPECTED_STARTUP_RESP")]
        TssTcpUnexpectedStartupResp = 0x40280005,

        /// <summary> Invalid size tag in the TPM response TCP packet </summary>
        [EnumMember]
        [SpecTypeName("TSS_TCP_INVALID_SIZE_TAG")]
        TssTcpInvalidSizeTag = 0x40280006,

        /// <summary> TPM over TCP device is not connected </summary>
        [EnumMember]
        [SpecTypeName("TSS_TCP_DISCONNECTED")]
        TssTcpDisconnected = 0x40280007,

        /// <summary> General TPM command dispatch failure </summary>
        [EnumMember]
        [SpecTypeName("TSS_DISPATCH_FAILED")]
        TssDispatchFailed = 0x40280010,

        /// <summary> Sending data to TPM failed </summary>
        [EnumMember]
        [SpecTypeName("TSS_SEND_OP_FAILED")]
        TssSendOpFailed = 0x40280011,

        /// <summary> Response buffer returned by the TPM is too short </summary>
        [EnumMember]
        [SpecTypeName("TSS_RESP_BUF_TOO_SHORT")]
        TssRespBufTooShort = 0x40280021,

        /// <summary> Invalid tag in the response buffer returned by the TPM </summary>
        [EnumMember]
        [SpecTypeName("TSS_RESP_BUF_INVALID_SESSION_TAG")]
        TssRespBufInvalidSessionTag = 0x40280022,

        /// <summary> Inconsistent TPM response parameters size </summary>
        [EnumMember]
        [SpecTypeName("TSS_RESP_BUF_INVALID_SIZE")]
        TssRespBufInvalidSize = 0x40280023,

        /// <summary> Windows TBS error TPM_E_COMMAND_BLOCKED </summary>
        [EnumMember]
        [SpecTypeName("TBS_COMMAND_BLOCKED")]
        TbsCommandBlocked = 0x80280400,

        /// <summary> Windows TBS error TPM_E_INVALID_HANDLE </summary>
        [EnumMember]
        [SpecTypeName("TBS_INVALID_HANDLE")]
        TbsInvalidHandle = 0x80280401,

        /// <summary> Windows TBS error TPM_E_DUPLICATE_VHANDLE </summary>
        [EnumMember]
        [SpecTypeName("TBS_DUPLICATE_V_HANDLE")]
        TbsDuplicateVHandle = 0x80280402,

        /// <summary> Windows TBS error TPM_E_EMBEDDED_COMMAND_BLOCKED </summary>
        [EnumMember]
        [SpecTypeName("TBS_EMBEDDED_COMMAND_BLOCKED")]
        TbsEmbeddedCommandBlocked = 0x80280403,

        /// <summary> Windows TBS error TPM_E_EMBEDDED_COMMAND_UNSUPPORTED </summary>
        [EnumMember]
        [SpecTypeName("TBS_EMBEDDED_COMMAND_UNSUPPORTED")]
        TbsEmbeddedCommandUnsupported = 0x80280404,

        /// <summary> Windows TBS returned success but empty response buffer </summary>
        [EnumMember]
        [SpecTypeName("TBS_UNKNOWN_ERROR")]
        TbsUnknownError = 0x80284000,

        /// <summary> Windows TBS error TBS_E_INTERNAL_ERROR </summary>
        [EnumMember]
        [SpecTypeName("TBS_INTERNAL_ERROR")]
        TbsInternalError = 0x80284001,

        /// <summary> Windows TBS error TBS_E_BAD_PARAMETER </summary>
        [EnumMember]
        [SpecTypeName("TBS_BAD_PARAMETER")]
        TbsBadParameter = 0x80284002,

        /// <summary> Windows TBS error TBS_E_INVALID_OUTPUT_POINTER </summary>
        [EnumMember]
        [SpecTypeName("TBS_INVALID_OUTPUT_POINTER")]
        TbsInvalidOutputPointer = 0x80284003,

        /// <summary> Windows TBS error TBS_E_INVALID_CONTEXT </summary>
        [EnumMember]
        [SpecTypeName("TBS_INVALID_CONTEXT")]
        TbsInvalidContext = 0x80284004,

        /// <summary> Windows TBS error TBS_E_INSUFFICIENT_BUFFER </summary>
        [EnumMember]
        [SpecTypeName("TBS_INSUFFICIENT_BUFFER")]
        TbsInsufficientBuffer = 0x80284005,

        /// <summary> Windows TBS error TBS_E_IOERROR </summary>
        [EnumMember]
        [SpecTypeName("TBS_IO_ERROR")]
        TbsIoError = 0x80284006,

        /// <summary> Windows TBS error TBS_E_INVALID_CONTEXT_PARAM </summary>
        [EnumMember]
        [SpecTypeName("TBS_INVALID_CONTEXT_PARAM")]
        TbsInvalidContextParam = 0x80284007,

        /// <summary> Windows TBS error TBS_E_SERVICE_NOT_RUNNING </summary>
        [EnumMember]
        [SpecTypeName("TBS_SERVICE_NOT_RUNNING")]
        TbsServiceNotRunning = 0x80284008,

        /// <summary> Windows TBS error TBS_E_TOO_MANY_TBS_CONTEXTS </summary>
        [EnumMember]
        [SpecTypeName("TBS_TOO_MANY_CONTEXTS")]
        TbsTooManyContexts = 0x80284009,

        /// <summary> Windows TBS error TBS_E_TOO_MANY_TBS_RESOURCES </summary>
        [EnumMember]
        [SpecTypeName("TBS_TOO_MANY_RESOURCES")]
        TbsTooManyResources = 0x8028400A,

        /// <summary> Windows TBS error TBS_E_SERVICE_START_PENDING </summary>
        [EnumMember]
        [SpecTypeName("TBS_SERVICE_START_PENDING")]
        TbsServiceStartPending = 0x8028400B,

        /// <summary> Windows TBS error TBS_E_PPI_NOT_SUPPORTED </summary>
        [EnumMember]
        [SpecTypeName("TBS_PPI_NOT_SUPPORTED")]
        TbsPpiNotSupported = 0x8028400C,

        /// <summary> Windows TBS error TBS_E_COMMAND_CANCELED </summary>
        [EnumMember]
        [SpecTypeName("TBS_COMMAND_CANCELED")]
        TbsCommandCanceled = 0x8028400D,

        /// <summary> Windows TBS error TBS_E_BUFFER_TOO_LARGE </summary>
        [EnumMember]
        [SpecTypeName("TBS_BUFFER_TOO_LARGE")]
        TbsBufferTooLarge = 0x8028400E,

        /// <summary> Windows TBS error TBS_E_TPM_NOT_FOUND </summary>
        [EnumMember]
        [SpecTypeName("TBS_TPM_NOT_FOUND")]
        TbsTpmNotFound = 0x8028400F,

        /// <summary> Windows TBS error TBS_E_SERVICE_DISABLED </summary>
        [EnumMember]
        [SpecTypeName("TBS_SERVICE_DISABLED")]
        TbsServiceDisabled = 0x80284010,

        /// <summary> Windows TBS error TBS_E_ACCESS_DENIED </summary>
        [EnumMember]
        [SpecTypeName("TBS_ACCESS_DENIED")]
        TbsAccessDenied = 0x80284012,

        /// <summary> Windows TBS error TBS_E_PPI_FUNCTION_UNSUPPORTED </summary>
        [EnumMember]
        [SpecTypeName("TBS_PPI_FUNCTION_NOT_SUPPORTED")]
        TbsPpiFunctionNotSupported = 0x80284014,

        /// <summary> Windows TBS error TBS_E_OWNERAUTH_NOT_FOUND </summary>
        [EnumMember]
        [SpecTypeName("TBS_OWNER_AUTH_NOT_FOUND")]
        TbsOwnerAuthNotFound = 0x80284015
    }

    /// <summary> A TPM_CLOCK_ADJUST value is used to change the rate at which the TPM
    /// internal oscillator is divided. A change to the divider will change the rate at which
    /// Clock and Time change. </summary>
    [DataContract]
    [SpecTypeName("TPM_CLOCK_ADJUST")]
    public enum ClockAdjust : sbyte
    {
        None = 0,

        /// <summary> Slow the Clock update rate by one coarse adjustment step. </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_COARSE_SLOWER")]
        CoarseSlower = unchecked ((sbyte)(-3)),
        [Obsolete("Use ClockAdjust.CoarseSlower instead")]
        TpmClockCoarseSlower = -3,

        /// <summary> Slow the Clock update rate by one medium adjustment step. </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_MEDIUM_SLOWER")]
        MediumSlower = unchecked ((sbyte)(-2)),
        [Obsolete("Use ClockAdjust.MediumSlower instead")]
        TpmClockMediumSlower = -2,

        /// <summary> Slow the Clock update rate by one fine adjustment step. </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_FINE_SLOWER")]
        FineSlower = unchecked ((sbyte)(-1)),
        [Obsolete("Use ClockAdjust.FineSlower instead")]
        TpmClockFineSlower = -1,

        /// <summary> No change to the Clock update rate. </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_NO_CHANGE")]
        NoChange = 0,
        [Obsolete("Use ClockAdjust.NoChange instead")]
        TpmClockNoChange = 0,

        /// <summary> Speed the Clock update rate by one fine adjustment step. </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_FINE_FASTER")]
        FineFaster = 1,
        [Obsolete("Use ClockAdjust.FineFaster instead")]
        TpmClockFineFaster = 1,

        /// <summary> Speed the Clock update rate by one medium adjustment step. </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_MEDIUM_FASTER")]
        MediumFaster = 2,
        [Obsolete("Use ClockAdjust.MediumFaster instead")]
        TpmClockMediumFaster = 2,

        /// <summary> Speed the Clock update rate by one coarse adjustment step. </summary>
        [EnumMember]
        [SpecTypeName("TPM_CLOCK_COARSE_FASTER")]
        CoarseFaster = 3,
        [Obsolete("Use ClockAdjust.CoarseFaster instead")]
        TpmClockCoarseFaster = 3
    }

    /// <summary> Table 18 Definition of (UINT16) TPM_EO Constants [IN/OUT] </summary>
    [DataContract]
    [SpecTypeName("TPM_EO")]
    public enum Eo : ushort
    {
        None = 0,

        /// <summary> A = B </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_EQ")]
        Eq = 0x0000,

        /// <summary> A B </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_NEQ")]
        Neq = 0x0001,

        /// <summary> A ? B signed </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_SIGNED_GT")]
        SignedGt = 0x0002,

        /// <summary> A ? B unsigned </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_UNSIGNED_GT")]
        UnsignedGt = 0x0003,

        /// <summary> A ? B signed </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_SIGNED_LT")]
        SignedLt = 0x0004,

        /// <summary> A ? B unsigned </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_UNSIGNED_LT")]
        UnsignedLt = 0x0005,

        /// <summary> A B signed </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_SIGNED_GE")]
        SignedGe = 0x0006,

        /// <summary> A B unsigned </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_UNSIGNED_GE")]
        UnsignedGe = 0x0007,

        /// <summary> A B signed </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_SIGNED_LE")]
        SignedLe = 0x0008,

        /// <summary> A B unsigned </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_UNSIGNED_LE")]
        UnsignedLe = 0x0009,

        /// <summary> All bits SET in B are SET in A. ((A?B)=B) </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_BITSET")]
        Bitset = 0x000A,

        /// <summary> All bits SET in B are CLEAR in A. ((A?B)=0) </summary>
        [EnumMember]
        [SpecTypeName("TPM_EO_BITCLEAR")]
        Bitclear = 0x000B
    }

    /// <summary> Structure tags are used to disambiguate structures. They are 16-bit values
    /// with the most significant bit SET so that they do not overlap TPM_ALG_ID values. A
    /// single exception is made for the value associated with TPM_ST_RSP_COMMAND (0x00C4),
    /// which has the same value as the TPM_TAG_RSP_COMMAND tag from earlier versions of this
    /// specification. This value is used when the TPM is compatible with a previous TPM
    /// specification and the TPM cannot determine which family of response code to return
    /// because the command tag is not valid. </summary>
    [DataContract]
    [SpecTypeName("TPM_ST")]
    public enum TpmSt : ushort
    {
        None = 0,

        /// <summary> Tag value for a response; used when there is an error in the tag. This is
        /// also the value returned from a TPM 1.2 when an error occurs. This value is used in
        /// this specification because an error in the command tag may prevent determination of
        /// the family. When this tag is used in the response, the response code will be
        /// TPM_RC_BAD_TAG (0 1E16), which has the same numeric value as the TPM 1.2 response code
        /// for TPM_BADTAG.
        /// NOTE In a previously published version of this specification, TPM_RC_BAD_TAG was
        /// incorrectly assigned a value of 0x030 instead of 30 (0x01e). Some implementations my
        /// return the old value instead of the new value. </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_RSP_COMMAND")]
        RspCommand = 0x00C4,

        /// <summary> No structure type specified </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_NULL")]
        Null = 0X8000,

        /// <summary> Tag value for a command/response for a command defined in this
        /// specification; indicating that the command/response has no attached sessions and no
        /// authorizationSize/parameterSize value is present
        /// If the responseCode from the TPM is not TPM_RC_SUCCESS, then the response tag shall
        /// have this value. </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_NO_SESSIONS")]
        NoSessions = 0x8001,

        /// <summary> Tag value for a command/response for a command defined in this
        /// specification; indicating that the command/response has one or more attached sessions
        /// and the authorizationSize/parameterSize field is present </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_SESSIONS")]
        Sessions = 0x8002,

        /// <summary> Tag for an attestation structure </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_NV")]
        AttestNv = 0x8014,

        /// <summary> Tag for an attestation structure </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_COMMAND_AUDIT")]
        AttestCommandAudit = 0x8015,

        /// <summary> Tag for an attestation structure </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_SESSION_AUDIT")]
        AttestSessionAudit = 0x8016,

        /// <summary> Tag for an attestation structure </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_CERTIFY")]
        AttestCertify = 0x8017,

        /// <summary> Tag for an attestation structure </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_QUOTE")]
        AttestQuote = 0x8018,

        /// <summary> Tag for an attestation structure </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_TIME")]
        AttestTime = 0x8019,

        /// <summary> Tag for an attestation structure </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_CREATION")]
        AttestCreation = 0x801A,

        /// <summary> Tag for an attestation structure </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_ATTEST_NV_DIGEST")]
        AttestNvDigest = 0x801C,

        /// <summary> Tag for a ticket type </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_CREATION")]
        Creation = 0x8021,

        /// <summary> Tag for a ticket type </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_VERIFIED")]
        Verified = 0x8022,

        /// <summary> Tag for a ticket type </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_AUTH_SECRET")]
        AuthSecret = 0x8023,

        /// <summary> Tag for a ticket type </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_HASHCHECK")]
        Hashcheck = 0x8024,

        /// <summary> Tag for a ticket type </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_AUTH_SIGNED")]
        AuthSigned = 0x8025,

        /// <summary> Tag for a structure describing a Field Upgrade Policy </summary>
        [EnumMember]
        [SpecTypeName("TPM_ST_FU_MANIFEST")]
        FuManifest = 0x8029
    }

    /// <summary> These values are used in TPM2_Startup() to indicate the shutdown and startup
    /// mode. The defined startup sequences are: </summary>
    [DataContract]
    [SpecTypeName("TPM_SU")]
    public enum Su : ushort
    {
        None = 0,

        /// <summary> On TPM2_Shutdown(), indicates that the TPM should prepare for loss of power
        /// and save state required for an orderly startup (TPM Reset).
        /// on TPM2_Startup(), indicates that the TPM should perform TPM Reset or TPM Restart </summary>
        [EnumMember]
        [SpecTypeName("TPM_SU_CLEAR")]
        Clear = 0x0000,

        /// <summary> On TPM2_Shutdown(), indicates that the TPM should prepare for loss of power
        /// and save state required for an orderly startup (TPM Restart or TPM Resume)
        /// on TPM2_Startup(), indicates that the TPM should restore the state saved by
        /// TPM2_Shutdown(TPM_SU_STATE) </summary>
        [EnumMember]
        [SpecTypeName("TPM_SU_STATE")]
        State = 0x0001
    }

    /// <summary> This type is used in TPM2_StartAuthSession() to indicate the type of the
    /// session to be created. </summary>
    [DataContract]
    [SpecTypeName("TPM_SE")]
    public enum TpmSe : byte
    {
        None = 0,

        [EnumMember]
        [SpecTypeName("TPM_SE_HMAC")]
        Hmac = 0x00,

        [EnumMember]
        [SpecTypeName("TPM_SE_POLICY")]
        Policy = 0x01,

        /// <summary> The policy session is being used to compute the policyHash and not for
        /// command authorization.
        /// This setting modifies some policy commands and prevents session from being used to
        /// authorize a command. </summary>
        [EnumMember]
        [SpecTypeName("TPM_SE_TRIAL")]
        Trial = 0x03
    }

    /// <summary> The TPM_CAP values are used in TPM2_GetCapability() to select the type of
    /// the value to be returned. The format of the response varies according to the type of
    /// the value. </summary>
    [DataContract]
    [SpecTypeName("TPM_CAP")]
    public enum Cap : uint
    {
        None = 0,

        [EnumMember]
        [SpecTypeName("TPM_CAP_FIRST")]
        First = 0x00000000,

        /// <summary> TPML_ALG_PROPERTY </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_ALGS")]
        Algs = 0x00000000,

        /// <summary> TPML_HANDLE </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_HANDLES")]
        Handles = 0x00000001,

        /// <summary> TPML_CCA </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_COMMANDS")]
        Commands = 0x00000002,

        /// <summary> TPML_CC </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_PP_COMMANDS")]
        PpCommands = 0x00000003,

        /// <summary> TPML_CC </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_AUDIT_COMMANDS")]
        AuditCommands = 0x00000004,

        /// <summary> TPML_PCR_SELECTION </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_PCRS")]
        Pcrs = 0x00000005,

        /// <summary> TPML_TAGGED_TPM_PROPERTY </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_TPM_PROPERTIES")]
        TpmProperties = 0x00000006,

        /// <summary> TPML_TAGGED_PCR_PROPERTY </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_PCR_PROPERTIES")]
        PcrProperties = 0x00000007,

        /// <summary> TPML_ECC_CURVE </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_ECC_CURVES")]
        EccCurves = 0x00000008,

        /// <summary> TPML_TAGGED_POLICY </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_AUTH_POLICIES")]
        AuthPolicies = 0x00000009,

        /// <summary> TPML_ACT_DATA </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_ACT")]
        Act = 0x0000000A,

        [EnumMember]
        [SpecTypeName("TPM_CAP_LAST")]
        Last = 0x0000000A,

        /// <summary> Manufacturer-specific values </summary>
        [EnumMember]
        [SpecTypeName("TPM_CAP_VENDOR_PROPERTY")]
        VendorProperty = 0x00000100
    }

    /// <summary> The TPM_PT constants are used in TPM2_GetCapability(capability =
    /// TPM_CAP_TPM_PROPERTIES) to indicate the property being selected or returned. </summary>
    [DataContract]
    [SpecTypeName("TPM_PT")]
    public enum Pt : uint
    {
        /// <summary> Indicates no property type </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NONE")]
        None = 0x00000000,

        /// <summary> The number of properties in each group.
        /// NOTE The first group with any properties is group 1 (PT_GROUP * 1). Group 0 is
        /// reserved. </summary>
        [EnumMember]
        [SpecTypeName("PT_GROUP")]
        PtGroup = 0x00000100,

        /// <summary> The group of fixed properties returned as TPMS_TAGGED_PROPERTY
        /// The values in this group are only changed due to a firmware change in the TPM. </summary>
        [EnumMember]
        [SpecTypeName("PT_FIXED")]
        PtFixed = PtGroup * 1, // 0x100

        /// <summary> A 4-octet character string containing the TPM Family value (TPM_SPEC_FAMILY)
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_FAMILY_INDICATOR")]
        FamilyIndicator = PtFixed + 0, // 0x100

        /// <summary> The level of the specification
        /// NOTE 1 For this specification, the level is zero.
        /// NOTE 2 The level is on the title page of the specification. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LEVEL")]
        Level = PtFixed + 1, // 0x101

        /// <summary> The specification Revision times 100
        /// EXAMPLE Revision 01.01 would have a value of 101.
        /// NOTE The Revision value is on the title page of the specification. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_REVISION")]
        Revision = PtFixed + 2, // 0x102

        /// <summary> The specification day of year using TCG calendar
        /// EXAMPLE November 15, 2010, has a day of year value of 319 (0000013F16).
        /// NOTE The specification date is on the title page of the specification or errata (see
        /// 6.1). </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_DAY_OF_YEAR")]
        DayOfYear = PtFixed + 3, // 0x103

        /// <summary> The specification year using the CE
        /// EXAMPLE The year 2010 has a value of 000007DA16.
        /// NOTE The specification date is on the title page of the specification or errata (see
        /// 6.1). </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_YEAR")]
        Year = PtFixed + 4, // 0x104

        /// <summary> The vendor ID unique to each TPM manufacturer </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MANUFACTURER")]
        Manufacturer = PtFixed + 5, // 0x105

        /// <summary> The first four characters of the vendor ID string
        /// NOTE When the vendor string is fewer than 16 octets, the additional property values do
        /// not have to be present. A vendor string of 4 octets can be represented in one 32-bit
        /// value and no null terminating character is required. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_STRING_1")]
        VendorString1 = PtFixed + 6, // 0x106

        /// <summary> The second four characters of the vendor ID string </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_STRING_2")]
        VendorString2 = PtFixed + 7, // 0x107

        /// <summary> The third four characters of the vendor ID string </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_STRING_3")]
        VendorString3 = PtFixed + 8, // 0x108

        /// <summary> The fourth four characters of the vendor ID sting </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_STRING_4")]
        VendorString4 = PtFixed + 9, // 0x109

        /// <summary> Vendor-defined value indicating the TPM model </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_TPM_TYPE")]
        VendorTpmType = PtFixed + 10, // 0x10A

        /// <summary> The most-significant 32 bits of a TPM vendor-specific value indicating the
        /// version number of the firmware. See 10.12.2 and 10.12.12. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_FIRMWARE_VERSION_1")]
        FirmwareVersion1 = PtFixed + 11, // 0x10B

        /// <summary> The least-significant 32 bits of a TPM vendor-specific value indicating the
        /// version number of the firmware. See 10.12.2 and 10.12.12. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_FIRMWARE_VERSION_2")]
        FirmwareVersion2 = PtFixed + 12, // 0x10C

        /// <summary> The maximum size of a parameter (typically, a TPM2B_MAX_BUFFER) </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_INPUT_BUFFER")]
        InputBuffer = PtFixed + 13, // 0x10D

        /// <summary> The minimum number of transient objects that can be held in TPM RAM
        /// NOTE This minimum shall be no less than the minimum value required by the
        /// platform-specific specification to which the TPM is built. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_TRANSIENT_MIN")]
        HrTransientMin = PtFixed + 14, // 0x10E

        /// <summary> The minimum number of persistent objects that can be held in TPM NV memory
        /// NOTE This minimum shall be no less than the minimum value required by the
        /// platform-specific specification to which the TPM is built. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_PERSISTENT_MIN")]
        HrPersistentMin = PtFixed + 15, // 0x10F

        /// <summary> The minimum number of authorization sessions that can be held in TPM RAM
        /// NOTE This minimum shall be no less than the minimum value required by the
        /// platform-specific specification to which the TPM is built. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_LOADED_MIN")]
        HrLoadedMin = PtFixed + 16, // 0x110

        /// <summary> The number of authorization sessions that may be active at a time
        /// A session is active when it has a context associated with its handle. The context may
        /// either be in TPM RAM or be context saved.
        /// NOTE This value shall be no less than the minimum value required by the
        /// platform-specific specification to which the TPM is built. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_ACTIVE_SESSIONS_MAX")]
        ActiveSessionsMax = PtFixed + 17, // 0x111

        /// <summary> The number of PCR implemented
        /// NOTE This number is determined by the defined attributes, not the number of PCR that
        /// are populated. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_COUNT")]
        PcrCount = PtFixed + 18, // 0x112

        /// <summary> The minimum number of octets in a TPMS_PCR_SELECT.sizeOfSelect
        /// NOTE This value is not determined by the number of PCR implemented but by the number
        /// of PCR required by the platform-specific specification with which the TPM is compliant
        /// or by the implementer if not adhering to a platform-specific specification. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_SELECT_MIN")]
        PcrSelectMin = PtFixed + 19, // 0x113

        /// <summary> The maximum allowed difference (unsigned) between the contextID values of
        /// two saved session contexts
        /// This value shall be 2n-1, where n is at least 16. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CONTEXT_GAP_MAX")]
        ContextGapMax = PtFixed + 20, // 0x114

        /// <summary> The maximum number of NV Indexes that are allowed to have the TPM_NT_COUNTER
        /// attribute
        /// NOTE 1 It is allowed for this value to be larger than the number of NV Indexes that
        /// can be defined. This would be indicative of a TPM implementation that did not use
        /// different implementation technology for different NV Index types.
        /// NOTE 2 The value zero indicates that there is no fixed maximum. The number of counter
        /// indexes is determined by the available NV memory pool. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_COUNTERS_MAX")]
        NvCountersMax = PtFixed + 22, // 0x116

        /// <summary> The maximum size of an NV Index data area </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_INDEX_MAX")]
        NvIndexMax = PtFixed + 23, // 0x117

        /// <summary> A TPMA_MEMORY indicating the memory management method for the TPM </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MEMORY")]
        Memory = PtFixed + 24, // 0x118

        /// <summary> Interval, in milliseconds, between updates to the copy of
        /// TPMS_CLOCK_INFO.clock in NV </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CLOCK_UPDATE")]
        ClockUpdate = PtFixed + 25, // 0x119

        /// <summary> The algorithm used for the integrity HMAC on saved contexts and for hashing
        /// the fuData of TPM2_FirmwareRead() </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CONTEXT_HASH")]
        ContextHash = PtFixed + 26, // 0x11A

        /// <summary> TPM_ALG_ID, the algorithm used for encryption of saved contexts </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CONTEXT_SYM")]
        ContextSym = PtFixed + 27, // 0x11B

        /// <summary> TPM_KEY_BITS, the size of the key used for encryption of saved contexts </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_CONTEXT_SYM_SIZE")]
        ContextSymSize = PtFixed + 28, // 0x11C

        /// <summary> The modulus - 1 of the count for NV update of an orderly counter
        /// The returned value is MAX_ORDERLY_COUNT.
        /// This will have a value of 2N 1 where 1 N 32
        /// NOTE 1 An orderly counter is an NV Index with an TPM_NT of TPM_NV_COUNTER and
        /// TPMA_NV_ORDERLY SET.
        /// NOTE 2 When the low-order bits of a counter equal this value, an NV write occurs on
        /// the next increment. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_ORDERLY_COUNT")]
        OrderlyCount = PtFixed + 29, // 0x11D

        /// <summary> The maximum value for commandSize in a command </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_COMMAND_SIZE")]
        MaxCommandSize = PtFixed + 30, // 0x11E

        /// <summary> The maximum value for responseSize in a response </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_RESPONSE_SIZE")]
        MaxResponseSize = PtFixed + 31, // 0x11F

        /// <summary> The maximum size of a digest that can be produced by the TPM </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_DIGEST")]
        MaxDigest = PtFixed + 32, // 0x120

        /// <summary> The maximum size of an object context that will be returned by
        /// TPM2_ContextSave </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_OBJECT_CONTEXT")]
        MaxObjectContext = PtFixed + 33, // 0x121

        /// <summary> The maximum size of a session context that will be returned by
        /// TPM2_ContextSave </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_SESSION_CONTEXT")]
        MaxSessionContext = PtFixed + 34, // 0x122

        /// <summary> Platform-specific family (a TPM_PS value)(see Table 25)
        /// NOTE The platform-specific values for the TPM_PT_PS parameters are in the relevant
        /// platform-specific specification. In the reference implementation, all of these values
        /// are 0. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_FAMILY_INDICATOR")]
        PsFamilyIndicator = PtFixed + 35, // 0x123

        /// <summary> The level of the platform-specific specification </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_LEVEL")]
        PsLevel = PtFixed + 36, // 0x124

        /// <summary> A platform specific value </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_REVISION")]
        PsRevision = PtFixed + 37, // 0x125

        /// <summary> The platform-specific TPM specification day of year using TCG calendar
        /// EXAMPLE November 15, 2010, has a day of year value of 319 (0000013F16). </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_DAY_OF_YEAR")]
        PsDayOfYear = PtFixed + 38, // 0x126

        /// <summary> The platform-specific TPM specification year using the CE
        /// EXAMPLE The year 2010 has a value of 000007DA16. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PS_YEAR")]
        PsYear = PtFixed + 39, // 0x127

        /// <summary> The number of split signing operations supported by the TPM </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_SPLIT_MAX")]
        SplitMax = PtFixed + 40, // 0x128

        /// <summary> Total number of commands implemented in the TPM </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_TOTAL_COMMANDS")]
        TotalCommands = PtFixed + 41, // 0x129

        /// <summary> Number of commands from the TPM library that are implemented </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LIBRARY_COMMANDS")]
        LibraryCommands = PtFixed + 42, // 0x12A

        /// <summary> Number of vendor commands that are implemented </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_VENDOR_COMMANDS")]
        VendorCommands = PtFixed + 43, // 0x12B

        /// <summary> The maximum data size in one NV write, NV read, NV extend, or NV certify
        /// command </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_BUFFER_MAX")]
        NvBufferMax = PtFixed + 44, // 0x12C

        /// <summary> A TPMA_MODES value, indicating that the TPM is designed for these modes. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MODES")]
        Modes = PtFixed + 45, // 0x12D

        /// <summary> The maximum size of a TPMS_CAPABILITY_DATA structure returned in
        /// TPM2_GetCapability(). </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_CAP_BUFFER")]
        MaxCapBuffer = PtFixed + 46, // 0x12E

        /// <summary> The group of variable properties returned as TPMS_TAGGED_PROPERTY
        /// The properties in this group change because of a Protected Capability other than a
        /// firmware update. The values are not necessarily persistent across all power
        /// transitions. </summary>
        [EnumMember]
        [SpecTypeName("PT_VAR")]
        PtVar = PtGroup * 2, // 0x200

        /// <summary> TPMA_PERMANENT </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PERMANENT")]
        Permanent = PtVar + 0, // 0x200

        /// <summary> TPMA_STARTUP_CLEAR </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_STARTUP_CLEAR")]
        StartupClear = PtVar + 1, // 0x201

        /// <summary> The number of NV Indexes currently defined </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_NV_INDEX")]
        HrNvIndex = PtVar + 2, // 0x202

        /// <summary> The number of authorization sessions currently loaded into TPM RAM </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_LOADED")]
        HrLoaded = PtVar + 3, // 0x203

        /// <summary> The number of additional authorization sessions, of any type, that could be
        /// loaded into TPM RAM
        /// This value is an estimate. If this value is at least 1, then at least one
        /// authorization session of any type may be loaded. Any command that changes the RAM
        /// memory allocation can make this estimate invalid.
        /// NOTE A valid implementation may return 1 even if more than one authorization session
        /// would fit into RAM. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_LOADED_AVAIL")]
        HrLoadedAvail = PtVar + 4, // 0x204

        /// <summary> The number of active authorization sessions currently being tracked by the TPM
        /// This is the sum of the loaded and saved sessions. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_ACTIVE")]
        HrActive = PtVar + 5, // 0x205

        /// <summary> The number of additional authorization sessions, of any type, that could be created
        /// This value is an estimate. If this value is at least 1, then at least one
        /// authorization session of any type may be created. Any command that changes the RAM
        /// memory allocation can make this estimate invalid.
        /// NOTE A valid implementation may return 1 even if more than one authorization session
        /// could be created. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_ACTIVE_AVAIL")]
        HrActiveAvail = PtVar + 6, // 0x206

        /// <summary> Estimate of the number of additional transient objects that could be loaded
        /// into TPM RAM
        /// This value is an estimate. If this value is at least 1, then at least one object of
        /// any type may be loaded. Any command that changes the memory allocation can make this
        /// estimate invalid.
        /// NOTE A valid implementation may return 1 even if more than one transient object would
        /// fit into RAM. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_TRANSIENT_AVAIL")]
        HrTransientAvail = PtVar + 7, // 0x207

        /// <summary> The number of persistent objects currently loaded into TPM NV memory </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_PERSISTENT")]
        HrPersistent = PtVar + 8, // 0x208

        /// <summary> The number of additional persistent objects that could be loaded into NV memory
        /// This value is an estimate. If this value is at least 1, then at least one object of
        /// any type may be made persistent. Any command that changes the NV memory allocation can
        /// make this estimate invalid.
        /// NOTE A valid implementation may return 1 even if more than one persistent object would
        /// fit into NV memory. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_HR_PERSISTENT_AVAIL")]
        HrPersistentAvail = PtVar + 9, // 0x209

        /// <summary> The number of defined NV Indexes that have NV the TPM_NT_COUNTER attribute </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_COUNTERS")]
        NvCounters = PtVar + 10, // 0x20A

        /// <summary> The number of additional NV Indexes that can be defined with their TPM_NT of
        /// TPM_NV_COUNTER and the TPMA_NV_ORDERLY attribute SET
        /// This value is an estimate. If this value is at least 1, then at least one NV Index may
        /// be created with a TPM_NT of TPM_NV_COUNTER and the TPMA_NV_ORDERLY attributes. Any
        /// command that changes the NV memory allocation can make this estimate invalid.
        /// NOTE A valid implementation may return 1 even if more than one NV counter could be
        /// defined. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_COUNTERS_AVAIL")]
        NvCountersAvail = PtVar + 11, // 0x20B

        /// <summary> Code that limits the algorithms that may be used with the TPM </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_ALGORITHM_SET")]
        AlgorithmSet = PtVar + 12, // 0x20C

        /// <summary> The number of loaded ECC curves </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LOADED_CURVES")]
        LoadedCurves = PtVar + 13, // 0x20D

        /// <summary> The current value of the lockout counter (failedTries) </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LOCKOUT_COUNTER")]
        LockoutCounter = PtVar + 14, // 0x20E

        /// <summary> The number of authorization failures before DA lockout is invoked </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_MAX_AUTH_FAIL")]
        MaxAuthFail = PtVar + 15, // 0x20F

        /// <summary> The number of seconds before the value reported by TPM_PT_LOCKOUT_COUNTER is
        /// decremented </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LOCKOUT_INTERVAL")]
        LockoutInterval = PtVar + 16, // 0x210

        /// <summary> The number of seconds after a lockoutAuth failure before use of lockoutAuth
        /// may be attempted again </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_LOCKOUT_RECOVERY")]
        LockoutRecovery = PtVar + 17, // 0x211

        /// <summary> Number of milliseconds before the TPM will accept another command that will
        /// modify NV
        /// This value is an approximation and may go up or down over time. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_NV_WRITE_RECOVERY")]
        NvWriteRecovery = PtVar + 18, // 0x212

        /// <summary> The high-order 32 bits of the command audit counter </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_AUDIT_COUNTER_0")]
        AuditCounter0 = PtVar + 19, // 0x213

        /// <summary> The low-order 32 bits of the command audit counter </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_AUDIT_COUNTER_1")]
        AuditCounter1 = PtVar + 20 // 0x214
    }

    /// <summary> The TPM_PT_PCR constants are used in TPM2_GetCapability() to indicate the
    /// property being selected or returned. The PCR properties can be read when capability ==
    /// TPM_CAP_PCR_PROPERTIES. If there is no property that corresponds to the value of
    /// property, the next higher value is returned, if it exists. </summary>
    [DataContract]
    [SpecTypeName("TPM_PT_PCR")]
    public enum PtPcr : uint
    {
        None = 0,

        /// <summary> Bottom of the range of TPM_PT_PCR properties </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_FIRST")]
        First = 0x00000000,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR is saved and
        /// restored by TPM_SU_STATE </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_SAVE")]
        Save = 0x00000000,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from
        /// locality 0
        /// This property is only present if a locality other than 0 is implemented. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L0")]
        ExtendL0 = 0x00000001,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by
        /// TPM2_PCR_Reset() from locality 0 </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L0")]
        ResetL0 = 0x00000002,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from
        /// locality 1
        /// This property is only present if locality 1 is implemented. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L1")]
        ExtendL1 = 0x00000003,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by
        /// TPM2_PCR_Reset() from locality 1
        /// This property is only present if locality 1 is implemented. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L1")]
        ResetL1 = 0x00000004,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from
        /// locality 2
        /// This property is only present if localities 1 and 2 are implemented. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L2")]
        ExtendL2 = 0x00000005,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by
        /// TPM2_PCR_Reset() from locality 2
        /// This property is only present if localities 1 and 2 are implemented. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L2")]
        ResetL2 = 0x00000006,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from
        /// locality 3
        /// This property is only present if localities 1, 2, and 3 are implemented. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L3")]
        ExtendL3 = 0x00000007,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by
        /// TPM2_PCR_Reset() from locality 3
        /// This property is only present if localities 1, 2, and 3 are implemented. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L3")]
        ResetL3 = 0x00000008,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be extended from
        /// locality 4
        /// This property is only present if localities 1, 2, 3, and 4 are implemented. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_EXTEND_L4")]
        ExtendL4 = 0x00000009,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR may be reset by
        /// TPM2_PCR_Reset() from locality 4
        /// This property is only present if localities 1, 2, 3, and 4 are implemented. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_RESET_L4")]
        ResetL4 = 0x0000000A,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that modifications to this PCR
        /// (reset or Extend) will not increment the pcrUpdateCounter </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_NO_INCREMENT")]
        NoIncrement = 0x00000011,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR is reset by a D-RTM event
        /// These PCR are reset to -1 on TPM2_Startup() and reset to 0 on a _TPM_Hash_End event
        /// following a _TPM_Hash_Start event. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_DRTM_RESET")]
        DrtmReset = 0x00000012,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled by policy
        /// This property is only present if the TPM supports policy control of a PCR. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_POLICY")]
        Policy = 0x00000013,

        /// <summary> A SET bit in the TPMS_PCR_SELECT indicates that the PCR is controlled by an
        /// authorization value
        /// This property is only present if the TPM supports authorization control of a PCR. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_AUTH")]
        Auth = 0x00000014,

        /// <summary> Top of the range of TPM_PT_PCR properties of the implementation
        /// If the TPM receives a request for a PCR property with a value larger than this, the
        /// TPM will return a zero length list and set the moreData parameter to NO.
        /// NOTE This is an implementation-specific value. The value shown reflects the reference
        /// code implementation. </summary>
        [EnumMember]
        [SpecTypeName("TPM_PT_PCR_LAST")]
        Last = 0x00000014
    }

    /// <summary> The platform values in Table 25 are used for the TPM_PT_PS_FAMILY_INDICATOR.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPM_PS")]
    public enum Ps : uint
    {
        None = 0,

        /// <summary> Not platform specific </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_MAIN")]
        Main = 0x00000000,

        /// <summary> PC Client </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_PC")]
        Pc = 0x00000001,

        /// <summary> PDA (includes all mobile devices that are not specifically cell phones) </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_PDA")]
        Pda = 0x00000002,

        /// <summary> Cell Phone </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_CELL_PHONE")]
        CellPhone = 0x00000003,

        /// <summary> Server WG </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_SERVER")]
        Server = 0x00000004,

        /// <summary> Peripheral WG </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_PERIPHERAL")]
        Peripheral = 0x00000005,

        /// <summary> TSS WG (deprecated) </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_TSS")]
        Tss = 0x00000006,

        /// <summary> Storage WG </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_STORAGE")]
        Storage = 0x00000007,

        /// <summary> Authentication WG </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_AUTHENTICATION")]
        Authentication = 0x00000008,

        /// <summary> Embedded WG </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_EMBEDDED")]
        Embedded = 0x00000009,

        /// <summary> Hardcopy WG </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_HARDCOPY")]
        Hardcopy = 0x0000000A,

        /// <summary> Infrastructure WG (deprecated) </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_INFRASTRUCTURE")]
        Infrastructure = 0x0000000B,

        /// <summary> Virtualization WG </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_VIRTUALIZATION")]
        Virtualization = 0x0000000C,

        /// <summary> Trusted Network Connect WG (deprecated) </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_TNC")]
        Tnc = 0x0000000D,

        /// <summary> Multi-tenant WG (deprecated) </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_MULTI_TENANT")]
        MultiTenant = 0x0000000E,

        /// <summary> Technical Committee (deprecated) </summary>
        [EnumMember]
        [SpecTypeName("TPM_PS_TC")]
        Tc = 0x0000000F
    }

    /// <summary> The 32-bit handle space is divided into 256 regions of equal size with 224
    /// values in each. Each of these ranges represents a handle type. </summary>
    [DataContract]
    [SpecTypeName("TPM_HT")]
    public enum Ht : byte
    {
        None = 0,

        /// <summary> PCR consecutive numbers, starting at 0, that reference the PCR registers
        /// A platform-specific specification will set the minimum number of PCR and an
        /// implementation may have more. </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_PCR")]
        Pcr = 0x00,

        /// <summary> NV Index assigned by the caller </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_NV_INDEX")]
        NvIndex = 0x01,

        /// <summary> HMAC Authorization Session assigned by the TPM when the session is created </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_HMAC_SESSION")]
        HmacSession = 0x02,

        /// <summary> Loaded Authorization Session used only in the context of TPM2_GetCapability
        /// This type references both loaded HMAC and loaded policy authorization sessions. </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_LOADED_SESSION")]
        LoadedSession = 0x02,

        /// <summary> Policy Authorization Session assigned by the TPM when the session is created
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_POLICY_SESSION")]
        PolicySession = 0x03,

        /// <summary> Saved Authorization Session used only in the context of TPM2_GetCapability
        /// This type references saved authorization session contexts for which the TPM is
        /// maintaining tracking information. </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_SAVED_SESSION")]
        SavedSession = 0x03,

        /// <summary> Permanent Values assigned by this specification in Table 28 </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_PERMANENT")]
        Permanent = 0x40,

        /// <summary> Transient Objects assigned by the TPM when an object is loaded into
        /// transient-object memory or when a persistent object is converted to a transient object
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_TRANSIENT")]
        Transient = 0x80,

        /// <summary> Persistent Objects assigned by the TPM when a loaded transient object is
        /// made persistent </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_PERSISTENT")]
        Persistent = 0x81,

        /// <summary> Attached Component handle for an Attached Component. </summary>
        [EnumMember]
        [SpecTypeName("TPM_HT_AC")]
        Ac = 0x90
    }

    /// <summary> Table 28 lists the architecturally defined handles that cannot be changed.
    /// The handles include authorization handles, and special handles. </summary>
    [DataContract]
    [SpecTypeName("TPM_RH")]
    public enum TpmRh : uint
    {
        None = 0,

        [EnumMember]
        [SpecTypeName("TPM_RH_FIRST")]
        First = 0x40000000,

        /// <summary> Not used1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_SRK")]
        Srk = 0x40000000,

        /// <summary> Handle references the Storage Primary Seed (SPS), the ownerAuth, and the
        /// ownerPolicy </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_OWNER")]
        Owner = 0x40000001,

        /// <summary> Not used1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_REVOKE")]
        Revoke = 0x40000002,

        /// <summary> Not used1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_TRANSPORT")]
        Transport = 0x40000003,

        /// <summary> Not used1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_OPERATOR")]
        Operator = 0x40000004,

        /// <summary> Not used1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_ADMIN")]
        Admin = 0x40000005,

        /// <summary> Not used1 </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_EK")]
        Ek = 0x40000006,

        /// <summary> A handle associated with the null hierarchy, an EmptyAuth authValue, and an
        /// Empty Policy authPolicy. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_NULL")]
        Null = 0x40000007,

        /// <summary> Value reserved to the TPM to indicate a handle location that has not been
        /// initialized or assigned </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_UNASSIGNED")]
        Unassigned = 0x40000008,

        /// <summary> Authorization value used to indicate a password authorization session </summary>
        [EnumMember]
        [SpecTypeName("TPM_RS_PW")]
        Pw = 0x40000009,
        [Obsolete("Use TpmRh.Pw instead")]
        TpmRsPw = 0x40000009,

        /// <summary> References the authorization associated with the dictionary attack lockout
        /// reset </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_LOCKOUT")]
        Lockout = 0x4000000A,

        /// <summary> References the Endorsement Primary Seed (EPS), endorsementAuth, and
        /// endorsementPolicy </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_ENDORSEMENT")]
        Endorsement = 0x4000000B,

        /// <summary> References the Platform Primary Seed (PPS), platformAuth, and platformPolicy
        /// </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_PLATFORM")]
        Platform = 0x4000000C,

        /// <summary> For phEnableNV </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_PLATFORM_NV")]
        PlatformNv = 0x4000000D,

        /// <summary> Start of a range of authorization values that are vendor-specific. A TPM may
        /// support any of the values in this range as are needed for vendor-specific purposes.
        /// Disabled if ehEnable is CLEAR.
        /// NOTE Any includes none. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_AUTH_00")]
        Auth00 = 0x40000010,

        /// <summary> End of the range of vendor-specific authorization values. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_AUTH_FF")]
        AuthFf = 0x4000010F,

        /// <summary> Start of the range of authenticated timers </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_ACT_0")]
        Act0 = 0x40000110,

        /// <summary> End of the range of authenticated timers </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_ACT_F")]
        ActF = 0x4000011F,

        /// <summary> The top of the reserved handle area
        /// This is set to allow TPM2_GetCapability() to know where to stop. It may vary as
        /// implementations add to the permanent handle area. </summary>
        [EnumMember]
        [SpecTypeName("TPM_RH_LAST")]
        Last = 0x4000011F
    }

    /// <summary> This table lists the values of the TPM_NT field of a TPMA_NV. See Table 215
    /// for usage. </summary>
    [DataContract]
    [SpecTypeName("TPM_NT")]
    public enum Nt : uint
    {
        None = 0,

        /// <summary> Ordinary contains data that is opaque to the TPM that can only be modified
        /// using TPM2_NV_Write(). </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_ORDINARY")]
        Ordinary = 0x0,

        /// <summary> Counter contains an 8-octet value that is to be used as a counter and can
        /// only be modified with TPM2_NV_Increment() </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_COUNTER")]
        Counter = 0x1,

        /// <summary> Bit Field contains an 8-octet value to be used as a bit field and can only
        /// be modified with TPM2_NV_SetBits(). </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_BITS")]
        Bits = 0x2,

        /// <summary> Extend contains a digest-sized value used like a PCR. The Index can only be
        /// modified using TPM2_NV_Extend(). The extend will use the nameAlg of the Index. </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_EXTEND")]
        Extend = 0x4,

        /// <summary> PIN Fail - contains pinCount that increments on a PIN authorization failure
        /// and a pinLimit </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_PIN_FAIL")]
        PinFail = 0x8,

        /// <summary> PIN Pass - contains pinCount that increments on a PIN authorization success
        /// and a pinLimit </summary>
        [EnumMember]
        [SpecTypeName("TPM_NT_PIN_PASS")]
        PinPass = 0x9
    }

    /// <summary> These constants are used in TPM2_AC_GetCapability() to indicate the first
    /// tagged value returned from an attached component. </summary>
    [DataContract]
    [SpecTypeName("TPM_AT")]
    public enum At : uint
    {
        None = 0,

        /// <summary> In a command, a non-specific request for AC information; in a response,
        /// indicates that outputData is not meaningful </summary>
        [EnumMember]
        [SpecTypeName("TPM_AT_ANY")]
        Any = 0x00000000,

        /// <summary> Indicates a TCG defined, device-specific error </summary>
        [EnumMember]
        [SpecTypeName("TPM_AT_ERROR")]
        Error = 0x00000001,

        /// <summary> Indicates the most significant 32 bits of a pairing value for the AC </summary>
        [EnumMember]
        [SpecTypeName("TPM_AT_PV1")]
        Pv1 = 0x00000002,

        /// <summary> Value added to a TPM_AT to indicate a vendor-specific tag value </summary>
        [EnumMember]
        [SpecTypeName("TPM_AT_VEND")]
        Vend = 0x80000000
    }

    /// <summary> These constants are the TCG-defined error values returned by an AC. </summary>
    [DataContract]
    [SpecTypeName("TPM_AE")]
    public enum Ae : uint
    {
        /// <summary> In a command, a non-specific request for AC information; in a response,
        /// indicates that outputData is not meaningful </summary>
        [EnumMember]
        [SpecTypeName("TPM_AE_NONE")]
        None = 0x00000000
    }

    /// <summary> These values are readable with TPM2_GetCapability(). They are the
    /// TPM_PT_PS_xxx values. </summary>
    [DataContract]
    [SpecTypeName("PLATFORM")]
    public enum Platform : uint
    {
        None = 0,

        [EnumMember]
        [SpecTypeName("PLATFORM_FAMILY")]
        Family = Spec.Family, // 0x322E3000

        [EnumMember]
        [SpecTypeName("PLATFORM_LEVEL")]
        Level = Spec.Level, // 0x0

        [EnumMember]
        [SpecTypeName("PLATFORM_VERSION")]
        Version = Spec.Version, // 0xA2

        [EnumMember]
        [SpecTypeName("PLATFORM_YEAR")]
        Year = Spec.Year, // 0x7E3

        [EnumMember]
        [SpecTypeName("PLATFORM_DAY_OF_YEAR")]
        DayOfYear = Spec.DayOfYear // 0x168
    }

    /// <summary> This table contains a collection of values used in various parts of the
    /// reference code. The values shown are illustrative. </summary>
    [DataContract]
    [SpecTypeName("Implementation")]
    public enum Implementation : uint
    {
        None = 0,

        /// <summary> Temporary define </summary>
        [EnumMember]
        [SpecTypeName("FIELD_UPGRADE_IMPLEMENTED")]
        FieldUpgradeImplemented = Logic.No, // 0x0

        /// <summary> Selection of the library that provides the basic hashing functions. </summary>
        [EnumMember]
        [SpecTypeName("HASH_LIB")]
        HashLib = ImplementationConstants.Ossl, // 0x1

        /// <summary> Selection of the library that provides the low-level symmetric cryptography.
        /// Choices are determined by the vendor (See LibSupport.h for implications). </summary>
        [EnumMember]
        [SpecTypeName("SYM_LIB")]
        SymLib = ImplementationConstants.Ossl, // 0x1

        /// <summary> Selection of the library that provides the big number math including ECC.
        /// Choices are determined by the vendor (See LibSupport.h for implications). </summary>
        [EnumMember]
        [SpecTypeName("MATH_LIB")]
        MathLib = ImplementationConstants.Ossl, // 0x1

        /// <summary> The number of PCR in the TPM </summary>
        [EnumMember]
        [SpecTypeName("IMPLEMENTATION_PCR")]
        ImplementationPcr = 24,

        [EnumMember]
        [SpecTypeName("PCR_SELECT_MAX")]
        PcrSelectMax = ((ImplementationPcr+7)/8), // 0x3

        /// <summary> The number of PCR required by the relevant platform specification </summary>
        [EnumMember]
        [SpecTypeName("PLATFORM_PCR")]
        PlatformPcr = 24,

        [EnumMember]
        [SpecTypeName("PCR_SELECT_MIN")]
        PcrSelectMin = ((PlatformPcr + 7) / 8), // 0x3

        /// <summary> The D-RTM PCR
        /// NOTE This value is not defined when the TPM does not implement D-RTM </summary>
        [EnumMember]
        [SpecTypeName("DRTM_PCR")]
        DrtmPcr = 17,

        /// <summary> The PCR that will receive the H-CRTM value at TPM2_Startup. This value
        /// should not be changed. </summary>
        [EnumMember]
        [SpecTypeName("HCRTM_PCR")]
        HcrtmPcr = 0,

        /// <summary> The number of localities supported by the TPM
        /// This is expected to be either 5 for a PC, or 1 for just about everything else. </summary>
        [EnumMember]
        [SpecTypeName("NUM_LOCALITIES")]
        NumLocalities = 5,

        /// <summary> The maximum number of handles in the handle area
        /// This should be produced by the Part 3 parser but is here for now. </summary>
        [EnumMember]
        [SpecTypeName("MAX_HANDLE_NUM")]
        MaxHandleNum = 3,

        /// <summary> The number of simultaneously active sessions that are supported by the TPM
        /// implementation </summary>
        [EnumMember]
        [SpecTypeName("MAX_ACTIVE_SESSIONS")]
        MaxActiveSessions = 64,

        /// <summary> The number of sessions that the TPM may have in memory </summary>
        [EnumMember]
        [SpecTypeName("MAX_LOADED_SESSIONS")]
        MaxLoadedSessions = 3,

        /// <summary> This is the current maximum value </summary>
        [EnumMember]
        [SpecTypeName("MAX_SESSION_NUM")]
        MaxSessionNum = 3,

        /// <summary> The number of simultaneously loaded objects that are supported by the TPM;
        /// this number does not include the objects that may be placed in NV memory by
        /// TPM2_EvictControl(). </summary>
        [EnumMember]
        [SpecTypeName("MAX_LOADED_OBJECTS")]
        MaxLoadedObjects = 3,

        /// <summary> The minimum number of evict objects supported by the TPM </summary>
        [EnumMember]
        [SpecTypeName("MIN_EVICT_OBJECTS")]
        MinEvictObjects = 2,

        /// <summary> Number of PCR groups that have individual policies </summary>
        [EnumMember]
        [SpecTypeName("NUM_POLICY_PCR_GROUP")]
        NumPolicyPcrGroup = 1,

        /// <summary> Number of PCR groups that have individual authorization values </summary>
        [EnumMember]
        [SpecTypeName("NUM_AUTHVALUE_PCR_GROUP")]
        NumAuthvaluePcrGroup = 1,

        [EnumMember]
        [SpecTypeName("MAX_CONTEXT_SIZE")]
        MaxContextSize = 1264,

        [EnumMember]
        [SpecTypeName("MAX_DIGEST_BUFFER")]
        MaxDigestBuffer = 1024,

        /// <summary> Maximum data size allowed in an NV Index </summary>
        [EnumMember]
        [SpecTypeName("MAX_NV_INDEX_SIZE")]
        MaxNvIndexSize = 2048,

        /// <summary> Maximum data size in one NV read or write command </summary>
        [EnumMember]
        [SpecTypeName("MAX_NV_BUFFER_SIZE")]
        MaxNvBufferSize = 1024,

        /// <summary> Maximum size of a capability buffer </summary>
        [EnumMember]
        [SpecTypeName("MAX_CAP_BUFFER")]
        MaxCapBuffer = 1024,

        /// <summary> Size of NV memory in octets </summary>
        [EnumMember]
        [SpecTypeName("NV_MEMORY_SIZE")]
        NvMemorySize = 16384,

        /// <summary> The TPM will not allocate a non-counter index if it would prevent allocation
        /// of this number of indices. </summary>
        [EnumMember]
        [SpecTypeName("MIN_COUNTER_INDICES")]
        MinCounterIndices = 8,

        [EnumMember]
        [SpecTypeName("NUM_STATIC_PCR")]
        NumStaticPcr = 16,

        /// <summary> Number of algorithms that can be in a list </summary>
        [EnumMember]
        [SpecTypeName("MAX_ALG_LIST_SIZE")]
        MaxAlgListSize = 64,

        /// <summary> Size of the Primary Seed in octets </summary>
        [EnumMember]
        [SpecTypeName("PRIMARY_SEED_SIZE")]
        PrimarySeedSize = 32,

        /// <summary> Context encryption algorithm
        /// Just use the root so that the macros in GpMacros.h will work correctly. </summary>
        [EnumMember]
        [SpecTypeName("CONTEXT_ENCRYPT_ALGORITHM")]
        ContextEncryptAlgorithm = TpmAlgId.Aes, // 0x6

        /// <summary> The update interval expressed as a power of 2 seconds
        /// A value of 12 is 4,096 seconds (~68 minutes). </summary>
        [EnumMember]
        [SpecTypeName("NV_CLOCK_UPDATE_INTERVAL")]
        NvClockUpdateInterval = 12,

        /// <summary> Number of PCR groups that allow policy/auth </summary>
        [EnumMember]
        [SpecTypeName("NUM_POLICY_PCR")]
        NumPolicyPcr = 1,

        /// <summary> Maximum size of a command </summary>
        [EnumMember]
        [SpecTypeName("MAX_COMMAND_SIZE")]
        MaxCommandSize = 4096,

        /// <summary> Maximum size of a response </summary>
        [EnumMember]
        [SpecTypeName("MAX_RESPONSE_SIZE")]
        MaxResponseSize = 4096,

        /// <summary> Number between 1 and 32 inclusive </summary>
        [EnumMember]
        [SpecTypeName("ORDERLY_BITS")]
        OrderlyBits = 8,

        /// <summary> The maximum number of octets that may be in a sealed blob; 128 is the
        /// minimum allowed value </summary>
        [EnumMember]
        [SpecTypeName("MAX_SYM_DATA")]
        MaxSymData = 128,

        [EnumMember]
        [SpecTypeName("MAX_RNG_ENTROPY_SIZE")]
        MaxRngEntropySize = 64,

        /// <summary> Number of bytes used for the RAM index space. If this is not large enough,
        /// it might not be possible to allocate orderly indices. </summary>
        [EnumMember]
        [SpecTypeName("RAM_INDEX_SPACE")]
        RamIndexSpace = 512,

        /// <summary> 216 + 1 </summary>
        [EnumMember]
        [SpecTypeName("RSA_DEFAULT_PUBLIC_EXPONENT")]
        RsaDefaultPublicExponent = 0x00010001,

        /// <summary> Indicates if the TPM_PT_PCR_NO_INCREMENT group is implemented </summary>
        [EnumMember]
        [SpecTypeName("ENABLE_PCR_NO_INCREMENT")]
        EnablePcrNoIncrement = Logic.Yes, // 0x1

        [EnumMember]
        [SpecTypeName("CRT_FORMAT_RSA")]
        CrtFormatRsa = Logic.Yes, // 0x1

        [EnumMember]
        [SpecTypeName("VENDOR_COMMAND_COUNT")]
        VendorCommandCount = 0,

        /// <summary> Maximum size of the vendor-specific buffer </summary>
        [EnumMember]
        [SpecTypeName("MAX_VENDOR_BUFFER_SIZE")]
        MaxVendorBufferSize = 1024,

        /// <summary> L value for a derivation. This is the
        /// maximum number of bits allowed from an instantiation of a KDF-DRBG. This is size is OK
        /// because RSA keys are never derived keys </summary>
        [EnumMember]
        [SpecTypeName("MAX_DERIVATION_BITS")]
        MaxDerivationBits = 8192,

        [EnumMember]
        [SpecTypeName("RSA_MAX_PRIME")]
        RsaMaxPrime = (ImplementationConstants.MaxRsaKeyBytes/2), // 0x80

        [EnumMember]
        [SpecTypeName("RSA_PRIVATE_SIZE")]
        RsaPrivateSize = (RsaMaxPrime * 5), // 0x280

        [EnumMember]
        [SpecTypeName("SIZE_OF_X509_SERIAL_NUMBER")]
        SizeOfX509SerialNumber = 20,

        /// <summary> This is a vendor-specific value so it is in this vendor-speific table. When
        /// this is used, RSA_PRIVATE_SIZE will have been defined </summary>
        [EnumMember]
        [SpecTypeName("PRIVATE_VENDOR_SPECIFIC_BYTES")]
        PrivateVendorSpecificBytes = RsaPrivateSize // 0x280
    }

    /// <summary> The definitions in Table 29 are used to define many of the interface data
    /// types. </summary>
    [DataContract]
    [SpecTypeName("TPM_HC")]
    public enum TpmHc : uint
    {
        None = 0,

        /// <summary> To mask off the HR </summary>
        [EnumMember]
        [SpecTypeName("HR_HANDLE_MASK")]
        HrHandleMask = 0x00FFFFFF,

        /// <summary> To mask off the variable part </summary>
        [EnumMember]
        [SpecTypeName("HR_RANGE_MASK")]
        HrRangeMask = unchecked ((uint)(0xFF000000)),

        [EnumMember]
        [SpecTypeName("HR_SHIFT")]
        HrShift = 24,

        [EnumMember]
        [SpecTypeName("HR_PCR")]
        HrPcr = ((uint)Ht.Pcr << (int)HrShift), // 0x0

        [EnumMember]
        [SpecTypeName("HR_HMAC_SESSION")]
        HrHmacSession = ((uint)Ht.HmacSession << (int)HrShift), // 0x2000000

        [EnumMember]
        [SpecTypeName("HR_POLICY_SESSION")]
        HrPolicySession = ((uint)Ht.PolicySession << (int)HrShift), // 0x3000000

        [EnumMember]
        [SpecTypeName("HR_TRANSIENT")]
        HrTransient = ((uint)Ht.Transient << (int)HrShift), // 0x80000000

        [EnumMember]
        [SpecTypeName("HR_PERSISTENT")]
        HrPersistent = ((uint)Ht.Persistent << (int)HrShift), // 0x81000000

        [EnumMember]
        [SpecTypeName("HR_NV_INDEX")]
        HrNvIndex = ((uint)Ht.NvIndex << (int)HrShift), // 0x1000000

        [EnumMember]
        [SpecTypeName("HR_PERMANENT")]
        HrPermanent = ((uint)Ht.Permanent << (int)HrShift), // 0x40000000

        /// <summary> First PCR </summary>
        [EnumMember]
        [SpecTypeName("PCR_FIRST")]
        PcrFirst = (HrPcr + 0), // 0x0

        /// <summary> Last PCR </summary>
        [EnumMember]
        [SpecTypeName("PCR_LAST")]
        PcrLast = (PcrFirst + Implementation.ImplementationPcr-1), // 0x17

        /// <summary> First HMAC session </summary>
        [EnumMember]
        [SpecTypeName("HMAC_SESSION_FIRST")]
        HmacSessionFirst = (HrHmacSession + 0), // 0x2000000

        /// <summary> Last HMAC session </summary>
        [EnumMember]
        [SpecTypeName("HMAC_SESSION_LAST")]
        HmacSessionLast = (HmacSessionFirst+Implementation.MaxActiveSessions-1), // 0x200003F

        /// <summary> Used in GetCapability </summary>
        [EnumMember]
        [SpecTypeName("LOADED_SESSION_FIRST")]
        LoadedSessionFirst = HmacSessionFirst, // 0x2000000

        /// <summary> Used in GetCapability </summary>
        [EnumMember]
        [SpecTypeName("LOADED_SESSION_LAST")]
        LoadedSessionLast = HmacSessionLast, // 0x200003F

        /// <summary> First policy session </summary>
        [EnumMember]
        [SpecTypeName("POLICY_SESSION_FIRST")]
        PolicySessionFirst = (HrPolicySession + 0), // 0x3000000

        /// <summary> Last policy session </summary>
        [EnumMember]
        [SpecTypeName("POLICY_SESSION_LAST")]
        PolicySessionLast = (PolicySessionFirst + Implementation.MaxActiveSessions-1), // 0x300003F

        /// <summary> First transient object </summary>
        [EnumMember]
        [SpecTypeName("TRANSIENT_FIRST")]
        TransientFirst = (HrTransient + 0), // 0x80000000

        /// <summary> Used in GetCapability </summary>
        [EnumMember]
        [SpecTypeName("ACTIVE_SESSION_FIRST")]
        ActiveSessionFirst = PolicySessionFirst, // 0x3000000

        /// <summary> Used in GetCapability </summary>
        [EnumMember]
        [SpecTypeName("ACTIVE_SESSION_LAST")]
        ActiveSessionLast = PolicySessionLast, // 0x300003F

        /// <summary> Last transient object </summary>
        [EnumMember]
        [SpecTypeName("TRANSIENT_LAST")]
        TransientLast = (TransientFirst+Implementation.MaxLoadedObjects-1), // 0x80000002

        /// <summary> First persistent object </summary>
        [EnumMember]
        [SpecTypeName("PERSISTENT_FIRST")]
        PersistentFirst = (HrPersistent + 0), // 0x81000000

        /// <summary> Last persistent object </summary>
        [EnumMember]
        [SpecTypeName("PERSISTENT_LAST")]
        PersistentLast = (PersistentFirst + 0x00FFFFFF), // 0x81FFFFFF

        /// <summary> First platform persistent object </summary>
        [EnumMember]
        [SpecTypeName("PLATFORM_PERSISTENT")]
        PlatformPersistent = (PersistentFirst + 0x00800000), // 0x81800000

        /// <summary> First allowed NV Index </summary>
        [EnumMember]
        [SpecTypeName("NV_INDEX_FIRST")]
        NvIndexFirst = (HrNvIndex + 0), // 0x1000000

        /// <summary> Last allowed NV Index </summary>
        [EnumMember]
        [SpecTypeName("NV_INDEX_LAST")]
        NvIndexLast = (NvIndexFirst + 0x00FFFFFF), // 0x1FFFFFF

        [EnumMember]
        [SpecTypeName("PERMANENT_FIRST")]
        PermanentFirst = TpmRh.First, // 0x40000000

        [EnumMember]
        [SpecTypeName("PERMANENT_LAST")]
        PermanentLast = TpmRh.Last, // 0x4000011F

        /// <summary> AC aliased NV Index </summary>
        [EnumMember]
        [SpecTypeName("HR_NV_AC")]
        HrNvAc = (((uint)Ht.NvIndex << (int)HrShift) + 0xD00000), // 0x1D00000

        /// <summary> First NV Index aliased to Attached Component </summary>
        [EnumMember]
        [SpecTypeName("NV_AC_FIRST")]
        NvAcFirst = (HrNvAc + 0), // 0x1D00000

        /// <summary> Last NV Index aliased to Attached Component </summary>
        [EnumMember]
        [SpecTypeName("NV_AC_LAST")]
        NvAcLast = (HrNvAc + 0x0000FFFF), // 0x1D0FFFF

        /// <summary> AC Handle </summary>
        [EnumMember]
        [SpecTypeName("HR_AC")]
        HrAc = unchecked ((uint)(((uint)Ht.Ac << (int)HrShift))), // 0x90000000

        /// <summary> First Attached Component </summary>
        [EnumMember]
        [SpecTypeName("AC_FIRST")]
        AcFirst = unchecked ((uint)((HrAc + 0))), // 0x90000000

        /// <summary> Last Attached Component </summary>
        [EnumMember]
        [SpecTypeName("AC_LAST")]
        AcLast = unchecked ((uint)((HrAc + 0x0000FFFF))) // 0x9000FFFF
    }

    /// <summary> This structure defines the attributes of an algorithm. </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_ALGORITHM")]
    public enum AlgorithmAttr : uint
    {
        None = 0,

        /// <summary> SET (1): an asymmetric algorithm with public and private portions
        /// CLEAR (0): not an asymmetric algorithm </summary>
        [EnumMember]
        [SpecTypeName("Asymmetric")]
        Asymmetric = 0x1,

        /// <summary> SET (1): a symmetric block cipher
        /// CLEAR (0): not a symmetric block cipher </summary>
        [EnumMember]
        [SpecTypeName("Symmetric")]
        Symmetric = 0x2,

        /// <summary> SET (1): a hash algorithm
        /// CLEAR (0): not a hash algorithm </summary>
        [EnumMember]
        [SpecTypeName("Hash")]
        Hash = 0x4,

        /// <summary> SET (1): an algorithm that may be used as an object type
        /// CLEAR (0): an algorithm that is not used as an object type </summary>
        [EnumMember]
        [SpecTypeName("Object")]
        Object = 0x8,

        /// <summary> SET (1): a signing algorithm. The setting of asymmetric, symmetric, and hash
        /// will indicate the type of signing algorithm.
        /// CLEAR (0): not a signing algorithm </summary>
        [EnumMember]
        [SpecTypeName("Signing")]
        Signing = 0x100,

        /// <summary> SET (1): an encryption/decryption algorithm. The setting of asymmetric,
        /// symmetric, and hash will indicate the type of encryption/decryption algorithm.
        /// CLEAR (0): not an encryption/decryption algorithm </summary>
        [EnumMember]
        [SpecTypeName("Encrypting")]
        Encrypting = 0x200,

        /// <summary> SET (1): a method such as a key derivative function (KDF)
        /// CLEAR (0): not a method </summary>
        [EnumMember]
        [SpecTypeName("Method")]
        Method = 0x400
    }

    /// <summary> This attribute structure indicates an objects use, its authorization types,
    /// and its relationship to other objects. </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_OBJECT")]
    public enum ObjectAttr : uint
    {
        None = 0,

        /// <summary> SET (1): The hierarchy of the object, as indicated by its Qualified Name,
        /// may not change.
        /// CLEAR (0): The hierarchy of the object may change as a result of this object or an
        /// ancestor key being duplicated for use in another hierarchy.
        /// NOTE fixedTPM does not indicate that key material resides on a single TPM (see
        /// sensitiveDataOrigin). </summary>
        [EnumMember]
        [SpecTypeName("FixedTPM")]
        FixedTPM = 0x2,

        /// <summary> SET (1): Previously saved contexts of this object may not be loaded after
        /// Startup(CLEAR).
        /// CLEAR (0): Saved contexts of this object may be used after a Shutdown(STATE) and
        /// subsequent Startup(). </summary>
        [EnumMember]
        [SpecTypeName("StClear")]
        StClear = 0x4,

        /// <summary> SET (1): The parent of the object may not change.
        /// CLEAR (0): The parent of the object may change as the result of a TPM2_Duplicate() of
        /// the object. </summary>
        [EnumMember]
        [SpecTypeName("FixedParent")]
        FixedParent = 0x10,

        /// <summary> SET (1): Indicates that, when the object was created with TPM2_Create() or
        /// TPM2_CreatePrimary(), the TPM generated all of the sensitive data other than the authValue.
        /// CLEAR (0): A portion of the sensitive data, other than the authValue, was provided by
        /// the caller. </summary>
        [EnumMember]
        [SpecTypeName("SensitiveDataOrigin")]
        SensitiveDataOrigin = 0x20,

        /// <summary> SET (1): Approval of USER role actions with this object may be with an HMAC
        /// session or with a password using the authValue of the object or a policy session.
        /// CLEAR (0): Approval of USER role actions with this object may only be done with a
        /// policy session. </summary>
        [EnumMember]
        [SpecTypeName("UserWithAuth")]
        UserWithAuth = 0x40,

        /// <summary> SET (1): Approval of ADMIN role actions with this object may only be done
        /// with a policy session.
        /// CLEAR (0): Approval of ADMIN role actions with this object may be with an HMAC session
        /// or with a password using the authValue of the object or a policy session. </summary>
        [EnumMember]
        [SpecTypeName("AdminWithPolicy")]
        AdminWithPolicy = 0x80,

        /// <summary> SET (1): The object is not subject to dictionary attack protections.
        /// CLEAR (0): The object is subject to dictionary attack protections. </summary>
        [EnumMember]
        [SpecTypeName("NoDA")]
        NoDA = 0x400,

        /// <summary> SET (1): If the object is duplicated, then symmetricAlg shall not be
        /// TPM_ALG_NULL and newParentHandle shall not be TPM_RH_NULL.
        /// CLEAR (0): The object may be duplicated without an inner wrapper on the private
        /// portion of the object and the new parent may be TPM_RH_NULL. </summary>
        [EnumMember]
        [SpecTypeName("EncryptedDuplication")]
        EncryptedDuplication = 0x800,

        /// <summary> SET (1): Key usage is restricted to manipulate structures of known format;
        /// the parent of this key shall have restricted SET.
        /// CLEAR (0): Key usage is not restricted to use on special formats. </summary>
        [EnumMember]
        [SpecTypeName("Restricted")]
        Restricted = 0x10000,

        /// <summary> SET (1): The private portion of the key may be used to decrypt.
        /// CLEAR (0): The private portion of the key may not be used to decrypt. </summary>
        [EnumMember]
        [SpecTypeName("Decrypt")]
        Decrypt = 0x20000,

        /// <summary> SET (1): For a symmetric cipher object, the private portion of the key may
        /// be used to encrypt. For other objects, the private portion of the key may be used to sign.
        /// CLEAR (0): The private portion of the key may not be used to sign or encrypt. </summary>
        [EnumMember]
        [SpecTypeName("Sign")]
        Sign = 0x40000,

        /// <summary> Alias to the sign value. </summary>
        [EnumMember]
        [SpecTypeName("Encrypt")]
        Encrypt = 0x40000,

        /// <summary> SET (1): An asymmetric key that may not be used to sign with TPM2_Sign()
        /// CLEAR (0): A key that may be used with TPM2_Sign() if sign is SET
        /// NOTE: This attribute only has significance if sign is SET. </summary>
        [EnumMember]
        [SpecTypeName("X509sign")]
        X509sign = 0x80000
    }

    /// <summary> This octet in each session is used to identify the session type, indicate
    /// its relationship to any handles in the command, and indicate its use in parameter
    /// encryption. </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_SESSION")]
    public enum SessionAttr : byte
    {
        None = 0,

        /// <summary> SET (1): In a command, this setting indicates that the session is to remain
        /// active after successful completion of the command. In a response, it indicates that
        /// the session is still active. If SET in the command, this attribute shall be SET in the
        /// response.
        /// CLEAR (0): In a command, this setting indicates that the TPM should close the session
        /// and flush any related context when the command completes successfully. In a response,
        /// it indicates that the session is closed and the context is no longer active.
        /// This attribute has no meaning for a password authorization and the TPM will allow any
        /// setting of the attribute in the command and SET the attribute in the response.
        /// This attribute will only be CLEAR in one response for a logical session. If the
        /// attribute is CLEAR, the context associated with the session is no longer in use and
        /// the space is available. A session created after another session is ended may have the
        /// same handle but logically is not the same session.
        /// This attribute has no effect if the command does not complete successfully. </summary>
        [EnumMember]
        [SpecTypeName("ContinueSession")]
        ContinueSession = 0x1,

        /// <summary> SET (1): In a command, this setting indicates that the command should only
        /// be executed if the session is exclusive at the start of the command. In a response, it
        /// indicates that the session is exclusive. This setting is only allowed if the audit
        /// attribute is SET (TPM_RC_ATTRIBUTES).
        /// CLEAR (0): In a command, indicates that the session need not be exclusive at the start
        /// of the command. In a response, indicates that the session is not exclusive. </summary>
        [EnumMember]
        [SpecTypeName("AuditExclusive")]
        AuditExclusive = 0x2,

        /// <summary> SET (1): In a command, this setting indicates that the audit digest of the
        /// session should be initialized and the exclusive status of the session SET. This
        /// setting is only allowed if the audit attribute is SET (TPM_RC_ATTRIBUTES).
        /// CLEAR (0): In a command, indicates that the audit digest should not be initialized.
        /// This bit is always CLEAR in a response. </summary>
        [EnumMember]
        [SpecTypeName("AuditReset")]
        AuditReset = 0x4,

        /// <summary> SET (1): In a command, this setting indicates that the first parameter in
        /// the command is symmetrically encrypted using the parameter encryption scheme described
        /// in TPM 2.0 Part 1. The TPM will decrypt the parameter after performing any HMAC
        /// computations and before unmarshaling the parameter. In a response, the attribute is
        /// copied from the request but has no effect on the response.
        /// CLEAR (0): Session not used for encryption.
        /// For a password authorization, this attribute will be CLEAR in both the command and response.
        /// This attribute may be SET in a session that is not associated with a command handle.
        /// Such a session is provided for purposes of encrypting a parameter and not for authorization.
        /// This attribute may be SET in combination with any other session attributes. </summary>
        [EnumMember]
        [SpecTypeName("Decrypt")]
        Decrypt = 0x20,

        /// <summary> SET (1): In a command, this setting indicates that the TPM should use this
        /// session to encrypt the first parameter in the response. In a response, it indicates
        /// that the attribute was set in the command and that the TPM used the session to encrypt
        /// the first parameter in the response using the parameter encryption scheme described in
        /// TPM 2.0 Part 1.
        /// CLEAR (0): Session not used for encryption.
        /// For a password authorization, this attribute will be CLEAR in both the command and response.
        /// This attribute may be SET in a session that is not associated with a command handle.
        /// Such a session is provided for purposes of encrypting a parameter and not for
        /// authorization. </summary>
        [EnumMember]
        [SpecTypeName("Encrypt")]
        Encrypt = 0x40,

        /// <summary> SET (1): In a command or response, this setting indicates that the session
        /// is for audit and that auditExclusive and auditReset have meaning. This session may
        /// also be used for authorization, encryption, or decryption. The encrypted and encrypt
        /// fields may be SET or CLEAR.
        /// CLEAR (0): Session is not used for audit.
        /// If SET in the command, then this attribute will be SET in the response. </summary>
        [EnumMember]
        [SpecTypeName("Audit")]
        Audit = 0x80
    }

    /// <summary> In a TPMS_CREATION_DATA structure, this structure is used to indicate the
    /// locality of the command that created the object. No more than one of the locality
    /// attributes shall be set in the creation data. </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_LOCALITY")]
    public enum LocalityAttr : byte
    {
        None = 0,

        [EnumMember]
        [SpecTypeName("LocZero")]
        LocZero = 0x1,
        [Obsolete("Use LocalityAttr.LocZero instead")]
        TpmLocZero = 0x1,

        [EnumMember]
        [SpecTypeName("LocOne")]
        LocOne = 0x2,
        [Obsolete("Use LocalityAttr.LocOne instead")]
        TpmLocOne = 0x2,

        [EnumMember]
        [SpecTypeName("LocTwo")]
        LocTwo = 0x4,
        [Obsolete("Use LocalityAttr.LocTwo instead")]
        TpmLocTwo = 0x4,

        [EnumMember]
        [SpecTypeName("LocThree")]
        LocThree = 0x8,
        [Obsolete("Use LocalityAttr.LocThree instead")]
        TpmLocThree = 0x8,

        [EnumMember]
        [SpecTypeName("LocFour")]
        LocFour = 0x10,
        [Obsolete("Use LocalityAttr.LocFour instead")]
        TpmLocFour = 0x10,

        /// <summary> If any of these bits is set, an extended locality is indicated </summary>
        [EnumMember]
        [SpecTypeName("")]
        ExtendedBitMask = 0xE0,

        [EnumMember]
        [SpecTypeName("")]
        ExtendedBitOffset = 5,

        [EnumMember]
        [SpecTypeName("")]
        ExtendedBitLength = 3,

        [EnumMember]
        [SpecTypeName("")]
        ExtendedBit0 = 0x20,

        [EnumMember]
        [SpecTypeName("")]
        ExtendedBit1 = 0x40,

        [EnumMember]
        [SpecTypeName("")]
        ExtendedBit2 = 0x80
    }

    /// <summary> The attributes in this structure are persistent and are not changed as a
    /// result of _TPM_Init or any TPM2_Startup(). Some of the attributes in this structure
    /// may change as the result of specific Protected Capabilities. This structure may be
    /// read using TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES, property =
    /// TPM_PT_PERMANENT). </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_PERMANENT")]
    public enum PermanentAttr : uint
    {
        None = 0,

        /// <summary> SET (1): TPM2_HierarchyChangeAuth() with ownerAuth has been executed since
        /// the last TPM2_Clear().
        /// CLEAR (0): ownerAuth has not been changed since TPM2_Clear(). </summary>
        [EnumMember]
        [SpecTypeName("OwnerAuthSet")]
        OwnerAuthSet = 0x1,

        /// <summary> SET (1): TPM2_HierarchyChangeAuth() with endorsementAuth has been executed
        /// since the last TPM2_Clear().
        /// CLEAR (0): endorsementAuth has not been changed since TPM2_Clear(). </summary>
        [EnumMember]
        [SpecTypeName("EndorsementAuthSet")]
        EndorsementAuthSet = 0x2,

        /// <summary> SET (1): TPM2_HierarchyChangeAuth() with lockoutAuth has been executed since
        /// the last TPM2_Clear().
        /// CLEAR (0): lockoutAuth has not been changed since TPM2_Clear(). </summary>
        [EnumMember]
        [SpecTypeName("LockoutAuthSet")]
        LockoutAuthSet = 0x4,

        /// <summary> SET (1): TPM2_Clear() is disabled.
        /// CLEAR (0): TPM2_Clear() is enabled.
        /// NOTE See TPM2_ClearControl in TPM 2.0 Part 3 for details on changing this attribute. </summary>
        [EnumMember]
        [SpecTypeName("DisableClear")]
        DisableClear = 0x100,

        /// <summary> SET (1): The TPM is in lockout, when failedTries is equal to maxTries. </summary>
        [EnumMember]
        [SpecTypeName("InLockout")]
        InLockout = 0x200,

        /// <summary> SET (1): The EPS was created by the TPM.
        /// CLEAR (0): The EPS was created outside of the TPM using a manufacturer-specific
        /// process. </summary>
        [EnumMember]
        [SpecTypeName("TpmGeneratedEPS")]
        TpmGeneratedEPS = 0x400
    }

    /// <summary> This structure may be read using TPM2_GetCapability(capability =
    /// TPM_CAP_TPM_PROPERTIES, property = TPM_PT_STARTUP_CLEAR). </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_STARTUP_CLEAR")]
    public enum StartupClearAttr : uint
    {
        None = 0,

        /// <summary> SET (1): The platform hierarchy is enabled and platformAuth or
        /// platformPolicy may be used for authorization.
        /// CLEAR (0): platformAuth and platformPolicy may not be used for authorizations, and
        /// objects in the platform hierarchy, including persistent objects, cannot be used.
        /// NOTE See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing this
        /// attribute. </summary>
        [EnumMember]
        [SpecTypeName("PhEnable")]
        PhEnable = 0x1,

        /// <summary> SET (1): The Storage hierarchy is enabled and ownerAuth or ownerPolicy may
        /// be used for authorization. NV indices defined using owner authorization are accessible.
        /// CLEAR (0): ownerAuth and ownerPolicy may not be used for authorizations, and objects
        /// in the Storage hierarchy, persistent objects, and NV indices defined using owner
        /// authorization cannot be used.
        /// NOTE See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing this
        /// attribute. </summary>
        [EnumMember]
        [SpecTypeName("ShEnable")]
        ShEnable = 0x2,

        /// <summary> SET (1): The EPS hierarchy is enabled and Endorsement Authorization may be
        /// used to authorize commands.
        /// CLEAR (0): Endorsement Authorization may not be used for authorizations, and objects
        /// in the endorsement hierarchy, including persistent objects, cannot be used.
        /// NOTE See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing this
        /// attribute. </summary>
        [EnumMember]
        [SpecTypeName("EhEnable")]
        EhEnable = 0x4,

        /// <summary> SET (1): NV indices that have TPMA_NV_PLATFORMCREATE SET may be read or
        /// written. The platform can create define and undefine indices.
        /// CLEAR (0): NV indices that have TPMA_NV_PLATFORMCREATE SET may not be read or written
        /// (TPM_RC_HANDLE). The platform cannot define (TPM_RC_HIERARCHY) or undefined
        /// (TPM_RC_HANDLE) indices.
        /// NOTE See TPM2_HierarchyControl in TPM 2.0 Part 3 for details on changing this attribute.
        /// NOTE
        /// read refers to these commands: TPM2_NV_Read, TPM2_NV_ReadPublic, TPM_NV_Certify, TPM2_PolicyNV
        /// write refers to these commands: TPM2_NV_Write, TPM2_NV_Increment, TPM2_NV_Extend, TPM2_NV_SetBits
        /// NOTE The TPM must query the index TPMA_NV_PLATFORMCREATE attribute to determine
        /// whether phEnableNV is applicable. Since the TPM will return TPM_RC_HANDLE if the index
        /// does not exist, it also returns this error code if the index is disabled. Otherwise,
        /// the TPM would leak the existence of an index even when disabled. </summary>
        [EnumMember]
        [SpecTypeName("PhEnableNV")]
        PhEnableNV = 0x8,

        /// <summary> SET (1): The TPM received a TPM2_Shutdown() and a matching TPM2_Startup().
        /// CLEAR (0): TPM2_Startup(TPM_SU_CLEAR) was not preceded by a TPM2_Shutdown() of any type.
        /// NOTE A shutdown is orderly if the TPM receives a TPM2_Shutdown() of any type followed
        /// by a TPM2_Startup() of any type. However, the TPM will return an error if
        /// TPM2_Startup(TPM_SU_STATE) was not preceded by TPM2_Shutdown(TPM_SU_STATE). </summary>
        [EnumMember]
        [SpecTypeName("Orderly")]
        Orderly = 0x80000000
    }

    /// <summary> This structure of this attribute is used to report the memory management
    /// method used by the TPM for transient objects and authorization sessions. This
    /// structure may be read using TPM2_GetCapability(capability = TPM_CAP_TPM_PROPERTIES,
    /// property = TPM_PT_MEMORY). </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_MEMORY")]
    public enum MemoryAttr : uint
    {
        None = 0,

        /// <summary> SET (1): indicates that the RAM memory used for authorization session
        /// contexts is shared with the memory used for transient objects
        /// CLEAR (0): indicates that the memory used for authorization sessions is not shared
        /// with memory used for transient objects </summary>
        [EnumMember]
        [SpecTypeName("SharedRAM")]
        SharedRAM = 0x1,

        /// <summary> SET (1): indicates that the NV memory used for persistent objects is shared
        /// with the NV memory used for NV Index values
        /// CLEAR (0): indicates that the persistent objects and NV Index values are allocated
        /// from separate sections of NV </summary>
        [EnumMember]
        [SpecTypeName("SharedNV")]
        SharedNV = 0x2,

        /// <summary> SET (1): indicates that the TPM copies persistent objects to a
        /// transient-object slot in RAM when the persistent object is referenced in a command.
        /// The TRM is required to make sure that an object slot is available.
        /// CLEAR (0): indicates that the TPM does not use transient-object slots when persistent
        /// objects are referenced </summary>
        [EnumMember]
        [SpecTypeName("ObjectCopiedToRam")]
        ObjectCopiedToRam = 0x4
    }

    /// <summary> This structure defines the attributes of a command from a context management
    /// perspective. The fields of the structure indicate to the TPM Resource Manager (TRM)
    /// the number of resources required by a command and how the command affects the TPMs
    /// resources. </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_CC")]
    public enum CcAttr : uint
    {
        None = 0,

        /// <summary> Indicates the command being selected </summary>
        [EnumMember]
        [SpecTypeName("")]
        commandIndexBitMask = 0xFFFF,

        [EnumMember]
        [SpecTypeName("")]
        commandIndexBitOffset = 0,

        [EnumMember]
        [SpecTypeName("")]
        commandIndexBitLength = 16,

        /// <summary> SET (1): indicates that the command may write to NV
        /// CLEAR (0): indicates that the command does not write to NV </summary>
        [EnumMember]
        [SpecTypeName("Nv")]
        Nv = 0x400000,

        /// <summary> SET (1): This command could flush any number of loaded contexts.
        /// CLEAR (0): no additional changes other than indicated by the flushed attribute </summary>
        [EnumMember]
        [SpecTypeName("Extensive")]
        Extensive = 0x800000,

        /// <summary> SET (1): The context associated with any transient handle in the command
        /// will be flushed when this command completes.
        /// CLEAR (0): No context is flushed as a side effect of this command. </summary>
        [EnumMember]
        [SpecTypeName("Flushed")]
        Flushed = 0x1000000,

        /// <summary> Indicates the number of the handles in the handle area for this command </summary>
        [EnumMember]
        [SpecTypeName("")]
        cHandlesBitMask = 0xE000000,

        [EnumMember]
        [SpecTypeName("")]
        cHandlesBitOffset = 25,

        [EnumMember]
        [SpecTypeName("")]
        cHandlesBitLength = 3,

        /// <summary> SET (1): indicates the presence of the handle area in the response </summary>
        [EnumMember]
        [SpecTypeName("RHandle")]
        RHandle = 0x10000000,

        /// <summary> SET (1): indicates that the command is vendor-specific
        /// CLEAR (0): indicates that the command is defined in a version of this specification </summary>
        [EnumMember]
        [SpecTypeName("V")]
        V = 0x20000000,

        /// <summary> Allocated for software; shall be zero </summary>
        [EnumMember]
        [SpecTypeName("")]
        ResBitMask = unchecked ((uint)(0xC0000000)),

        [EnumMember]
        [SpecTypeName("")]
        ResBitOffset = 30,

        [EnumMember]
        [SpecTypeName("")]
        ResBitLength = 2
    }

    /// <summary> This structure of this attribute is used to report that the TPM is designed
    /// for these modes. This structure may be read using TPM2_GetCapability(capability =
    /// TPM_CAP_TPM_PROPERTIES, property = TPM_PT_MODES). </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_MODES")]
    public enum ModesAttr : uint
    {
        None = 0,

        /// <summary> SET (1): indicates that the TPM is designed to comply with all of the FIPS
        /// 140-2 requirements at Level 1 or higher. </summary>
        [EnumMember]
        [SpecTypeName("Fips1402")]
        Fips1402 = 0x1
    }

    /// <summary> These attributes are as specified in clause 4.2.1.3. of RFC 5280 Internet
    /// X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL)
    /// Profile. For TPM2_CertifyX509, when a caller provides a DER encoded Key Usage in
    /// partialCertificate, the TPM will validate that the key to be certified meets the
    /// requirements of Key Usage. </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_X509_KEY_USAGE")]
    public enum X509KeyUsageAttr : uint
    {
        None = 0,

        /// <summary> Attributes.Decrypt SET </summary>
        [EnumMember]
        [SpecTypeName("DecipherOnly")]
        DecipherOnly = 0x800000,

        /// <summary> Attributes.Decrypt SET </summary>
        [EnumMember]
        [SpecTypeName("EncipherOnly")]
        EncipherOnly = 0x1000000,

        /// <summary> Attributes.sign SET </summary>
        [EnumMember]
        [SpecTypeName("CRLSign")]
        CRLSign = 0x2000000,

        /// <summary> Attributes.sign SET </summary>
        [EnumMember]
        [SpecTypeName("KeyCertSign")]
        KeyCertSign = 0x4000000,

        /// <summary> Attributes.Decrypt SET </summary>
        [EnumMember]
        [SpecTypeName("KeyAgreement")]
        KeyAgreement = 0x8000000,

        /// <summary> Attributes.Decrypt SET </summary>
        [EnumMember]
        [SpecTypeName("DataEncipherment")]
        DataEncipherment = 0x10000000,

        /// <summary> Asymmetric key with decrypt and restricted SET key has the attributes of a
        /// parent key </summary>
        [EnumMember]
        [SpecTypeName("KeyEncipherment")]
        KeyEncipherment = 0x20000000,

        /// <summary> FixedTPM SET in Subject Key (objectHandle) </summary>
        [EnumMember]
        [SpecTypeName("Nonrepudiation")]
        Nonrepudiation = 0x40000000,

        /// <summary> Alias to the nonrepudiation value. </summary>
        [EnumMember]
        [SpecTypeName("ContentCommitment")]
        ContentCommitment = 0x40000000,

        /// <summary> Sign SET in Subject Key (objectHandle) </summary>
        [EnumMember]
        [SpecTypeName("DigitalSignature")]
        DigitalSignature = 0x80000000
    }

    /// <summary> This attribute is used to report the ACT state. This attribute may be read
    /// using TPM2_GetCapability(capability = TPM_CAP_ACT, property = TPM_RH_ACT_x where x is
    /// the ACT number (0-F)). The signaled value must be preserved across TPM Resume or if
    /// the TPM has not lost power. The signaled value may be preserved over a power cycle of
    /// a TPM. </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_ACT")]
    public enum ActAttr : uint
    {
        None = 0,

        /// <summary> SET (1): The ACT has signaled
        /// CLEAR (0): The ACT has not signaled </summary>
        [EnumMember]
        [SpecTypeName("Signaled")]
        Signaled = 0x1,

        /// <summary> Preserves the state of signaled, depending on the power cycle </summary>
        [EnumMember]
        [SpecTypeName("PreserveSignaled")]
        PreserveSignaled = 0x2
    }

    /// <summary> A TPM_NV_INDEX is used to reference a defined location in NV memory. The
    /// format of the Index is changed from TPM 1.2 in order to include the Index in the
    /// reserved handle space. Handles in this range use the digest of the public area of the
    /// Index as the Name of the entity in authorization computations </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPM_NV_INDEX")]
    public enum NvIndex : uint
    {
        None = 0,

        /// <summary> The Index of the NV location </summary>
        [EnumMember]
        [SpecTypeName("")]
        indexBitMask = 0xFFFFFF,

        [EnumMember]
        [SpecTypeName("")]
        indexBitOffset = 0,

        [EnumMember]
        [SpecTypeName("")]
        indexBitLength = 24,

        /// <summary> Constant value of TPM_HT_NV_INDEX indicating the NV Index range </summary>
        [EnumMember]
        [SpecTypeName("")]
        RhNvBitMask = unchecked ((uint)(0xFF000000)),

        [EnumMember]
        [SpecTypeName("")]
        RhNvBitOffset = 24,

        [EnumMember]
        [SpecTypeName("")]
        RhNvBitLength = 8
    }

    /// <summary> This structure allows the TPM to keep track of the data and permissions to
    /// manipulate an NV Index. </summary>
    [Flags]
    [DataContract]
    [SpecTypeName("TPMA_NV")]
    public enum NvAttr : uint
    {
        None = 0,

        /// <summary> SET (1): The Index data can be written if Platform Authorization is provided.
        /// CLEAR (0): Writing of the Index data cannot be authorized with Platform Authorization.
        /// </summary>
        [EnumMember]
        [SpecTypeName("Ppwrite")]
        Ppwrite = 0x1,

        /// <summary> SET (1): The Index data can be written if Owner Authorization is provided.
        /// CLEAR (0): Writing of the Index data cannot be authorized with Owner Authorization. </summary>
        [EnumMember]
        [SpecTypeName("Ownerwrite")]
        Ownerwrite = 0x2,

        /// <summary> SET (1): Authorizations to change the Index contents that require USER role
        /// may be provided with an HMAC session or password.
        /// CLEAR (0): Authorizations to change the Index contents that require USER role may not
        /// be provided with an HMAC session or password. </summary>
        [EnumMember]
        [SpecTypeName("Authwrite")]
        Authwrite = 0x4,

        /// <summary> SET (1): Authorizations to change the Index contents that require USER role
        /// may be provided with a policy session.
        /// CLEAR (0): Authorizations to change the Index contents that require USER role may not
        /// be provided with a policy session.
        /// NOTE TPM2_NV_ChangeAuth() always requires that authorization be provided in a policy
        /// session. </summary>
        [EnumMember]
        [SpecTypeName("Policywrite")]
        Policywrite = 0x8,

        /// <summary> Ordinary contains data that is opaque to the TPM that can only be modified
        /// using TPM2_NV_Write(). </summary>
        [EnumMember]
        [SpecTypeName("Ordinary")]
        Ordinary = 0x0,

        /// <summary> Counter contains an 8-octet value that is to be used as a counter and can
        /// only be modified with TPM2_NV_Increment() </summary>
        [EnumMember]
        [SpecTypeName("Counter")]
        Counter = 0x10,

        /// <summary> Bit Field contains an 8-octet value to be used as a bit field and can only
        /// be modified with TPM2_NV_SetBits(). </summary>
        [EnumMember]
        [SpecTypeName("Bits")]
        Bits = 0x20,

        /// <summary> Extend contains a digest-sized value used like a PCR. The Index can only be
        /// modified using TPM2_NV_Extend(). The extend will use the nameAlg of the Index. </summary>
        [EnumMember]
        [SpecTypeName("Extend")]
        Extend = 0x40,

        /// <summary> PIN Fail - contains pinCount that increments on a PIN authorization failure
        /// and a pinLimit </summary>
        [EnumMember]
        [SpecTypeName("PinFail")]
        PinFail = 0x80,

        /// <summary> PIN Pass - contains pinCount that increments on a PIN authorization success
        /// and a pinLimit </summary>
        [EnumMember]
        [SpecTypeName("PinPass")]
        PinPass = 0x90,

        /// <summary> The type of the index.
        /// NOTE A TPM is not required to support all TPM_NT values </summary>
        [EnumMember]
        [SpecTypeName("")]
        TpmNtBitMask = 0xF0,

        [EnumMember]
        [SpecTypeName("")]
        TpmNtBitOffset = 4,

        [EnumMember]
        [SpecTypeName("")]
        TpmNtBitLength = 4,

        /// <summary> SET (1): Index may not be deleted unless the authPolicy is satisfied using
        /// TPM2_NV_UndefineSpaceSpecial().
        /// CLEAR (0): Index may be deleted with proper platform or owner authorization using
        /// TPM2_NV_UndefineSpace().
        /// NOTE An Index with this attribute and a policy that cannot be satisfied (e.g., an
        /// Empty Policy) cannot be deleted. </summary>
        [EnumMember]
        [SpecTypeName("PolicyDelete")]
        PolicyDelete = 0x400,

        /// <summary> SET (1): Index cannot be written.
        /// CLEAR (0): Index can be written. </summary>
        [EnumMember]
        [SpecTypeName("Writelocked")]
        Writelocked = 0x800,

        /// <summary> SET (1): A partial write of the Index data is not allowed. The write size
        /// shall match the defined space size.
        /// CLEAR (0): Partial writes are allowed. This setting is required if the .dataSize of
        /// the Index is larger than NV_MAX_BUFFER_SIZE for the implementation. </summary>
        [EnumMember]
        [SpecTypeName("Writeall")]
        Writeall = 0x1000,

        /// <summary> SET (1): TPM2_NV_WriteLock() may be used to prevent further writes to this location.
        /// CLEAR (0): TPM2_NV_WriteLock() does not block subsequent writes if
        /// TPMA_NV_WRITE_STCLEAR is also CLEAR. </summary>
        [EnumMember]
        [SpecTypeName("Writedefine")]
        Writedefine = 0x2000,

        /// <summary> SET (1): TPM2_NV_WriteLock() may be used to prevent further writes to this
        /// location until the next TPM Reset or TPM Restart.
        /// CLEAR (0): TPM2_NV_WriteLock() does not block subsequent writes if TPMA_NV_WRITEDEFINE
        /// is also CLEAR. </summary>
        [EnumMember]
        [SpecTypeName("WriteStclear")]
        WriteStclear = 0x4000,

        /// <summary> SET (1): If TPM2_NV_GlobalWriteLock() is successful, TPMA_NV_WRITELOCKED is set.
        /// CLEAR (0): TPM2_NV_GlobalWriteLock() has no effect on the writing of the data at this
        /// Index. </summary>
        [EnumMember]
        [SpecTypeName("Globallock")]
        Globallock = 0x8000,

        /// <summary> SET (1): The Index data can be read if Platform Authorization is provided.
        /// CLEAR (0): Reading of the Index data cannot be authorized with Platform Authorization.
        /// </summary>
        [EnumMember]
        [SpecTypeName("Ppread")]
        Ppread = 0x10000,

        /// <summary> SET (1): The Index data can be read if Owner Authorization is provided.
        /// CLEAR (0): Reading of the Index data cannot be authorized with Owner Authorization. </summary>
        [EnumMember]
        [SpecTypeName("Ownerread")]
        Ownerread = 0x20000,

        /// <summary> SET (1): The Index data may be read if the authValue is provided.
        /// CLEAR (0): Reading of the Index data cannot be authorized with the Index authValue. </summary>
        [EnumMember]
        [SpecTypeName("Authread")]
        Authread = 0x40000,

        /// <summary> SET (1): The Index data may be read if the authPolicy is satisfied.
        /// CLEAR (0): Reading of the Index data cannot be authorized with the Index authPolicy. </summary>
        [EnumMember]
        [SpecTypeName("Policyread")]
        Policyread = 0x80000,

        /// <summary> SET (1): Authorization failures of the Index do not affect the DA logic and
        /// authorization of the Index is not blocked when the TPM is in Lockout mode.
        /// CLEAR (0): Authorization failures of the Index will increment the authorization
        /// failure counter and authorizations of this Index are not allowed when the TPM is in
        /// Lockout mode. </summary>
        [EnumMember]
        [SpecTypeName("NoDa")]
        NoDa = 0x2000000,

        /// <summary> SET (1): NV Index state is only required to be saved when the TPM performs
        /// an orderly shutdown (TPM2_Shutdown()).
        /// CLEAR (0): NV Index state is required to be persistent after the command to update the
        /// Index completes successfully (that is, the NV update is synchronous with the update
        /// command). </summary>
        [EnumMember]
        [SpecTypeName("Orderly")]
        Orderly = 0x4000000,

        /// <summary> SET (1): TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM Restart.
        /// CLEAR (0): TPMA_NV_WRITTEN is not changed by TPM Restart.
        /// NOTE This attribute may only be SET if TPM_NT is not TPM_NT_COUNTER. </summary>
        [EnumMember]
        [SpecTypeName("ClearStclear")]
        ClearStclear = 0x8000000,

        /// <summary> SET (1): Reads of the Index are blocked until the next TPM Reset or TPM Restart.
        /// CLEAR (0): Reads of the Index are allowed if proper authorization is provided. </summary>
        [EnumMember]
        [SpecTypeName("Readlocked")]
        Readlocked = 0x10000000,

        /// <summary> SET (1): Index has been written.
        /// CLEAR (0): Index has not been written. </summary>
        [EnumMember]
        [SpecTypeName("Written")]
        Written = 0x20000000,

        /// <summary> SET (1): This Index may be undefined with Platform Authorization but not
        /// with Owner Authorization.
        /// CLEAR (0): This Index may be undefined using Owner Authorization but not with Platform
        /// Authorization.
        /// The TPM will validate that this attribute is SET when the Index is defined using
        /// Platform Authorization and will validate that this attribute is CLEAR when the Index
        /// is defined using Owner Authorization. </summary>
        [EnumMember]
        [SpecTypeName("Platformcreate")]
        Platformcreate = 0x40000000,

        /// <summary> SET (1): TPM2_NV_ReadLock() may be used to SET TPMA_NV_READLOCKED for this Index.
        /// CLEAR (0): TPM2_NV_ReadLock() has no effect on this Index. </summary>
        [EnumMember]
        [SpecTypeName("ReadStclear")]
        ReadStclear = 0x80000000
    }

    /// <summary> Table 119 Definition of TPMU_CAPABILITIES Union [OUT] </summary>
    /// <remarks> One of: AlgPropertyArray, HandleArray, CcaArray, CcArray, PcrSelectionArray,
    /// TaggedTpmPropertyArray, TaggedPcrPropertyArray, EccCurveArray, TaggedPolicyArray,
    /// ActDataArray. </remarks>
    public interface ICapabilitiesUnion
    {
        Cap GetUnionSelector();
    }

    /// <summary> Table 132 Definition of TPMU_ATTEST Union [OUT] </summary>
    /// <remarks> One of: CertifyInfo, CreationInfo, QuoteInfo, CommandAuditInfo,
    /// SessionAuditInfo, TimeAttestInfo, NvCertifyInfo, NvDigestCertifyInfo. </remarks>
    public interface IAttestUnion
    {
        TpmSt GetUnionSelector();
    }

    /// <summary> This union allows additional parameters to be added for a symmetric cipher.
    /// Currently, no additional parameters are required for any of the symmetric algorithms. </summary>
    /// <remarks> One of: TdesSymDetails, AesSymDetails, Sm4SymDetails, CamelliaSymDetails,
    /// AnySymDetails, XorSymDetails, NullSymDetails. </remarks>
    public interface ISymDetailsUnion
    {
        TpmAlgId GetUnionSelector();
    }

    /// <summary> This structure allows a TPM2B_SENSITIVE_CREATE structure to carry either a
    /// TPM2B_SENSITVE_DATA or a TPM2B_DERIVE structure. The contents of the union are
    /// determined by context. When an object is being derived, the derivation values are
    /// present. </summary>
    /// <remarks> One of: byte, TpmDerive. </remarks>
    public interface ISensitiveCreateUnion
    {
        TpmAlgId GetUnionSelector();
    }

    /// <summary> Table 157 Definition of TPMU_SCHEME_KEYEDHASH Union [IN/OUT] </summary>
    /// <remarks> One of: SchemeHmac, SchemeXor, NullSchemeKeyedhash. </remarks>
    public interface ISchemeKeyedhashUnion
    {
        TpmAlgId GetUnionSelector();
    }

    /// <summary> This is the union of all of the signature schemes. </summary>
    /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
    /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
    public interface ISigSchemeUnion
    {
        TpmAlgId GetUnionSelector();
    }

    /// <summary> Table 166 Definition of TPMU_KDF_SCHEME Union [IN/OUT] </summary>
    /// <remarks> One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2,
    /// KdfSchemeKdf1Sp800108, SchemeHash, NullKdfScheme. </remarks>
    public interface IKdfSchemeUnion
    {
        TpmAlgId GetUnionSelector();
    }

    /// <summary> This union of all asymmetric schemes is used in each of the asymmetric
    /// scheme structures. The actual scheme structure is defined by the interface type used
    /// for the selector (TPMI_ALG_ASYM_SCHEME). </summary>
    /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
    /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
    /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
    public interface IAsymSchemeUnion
    {
        TpmAlgId GetUnionSelector();
    }

    /// <summary> A TPMU_SIGNATURE_COMPOSITE is a union of the various signatures that are
    /// supported by a particular TPM implementation. The union allows substitution of any
    /// signature algorithm wherever a signature is required in a structure. </summary>
    /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
    /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
    public interface ISignatureUnion
    {
        TpmAlgId GetUnionSelector();
    }

    /// <summary> This is the union of all values allowed in in the unique field of a
    /// TPMT_PUBLIC. </summary>
    /// <remarks> One of: Tpm2bDigestKeyedhash, Tpm2bDigestSymcipher, Tpm2bPublicKeyRsa,
    /// EccPoint, TpmDerive. </remarks>
    public interface IPublicIdUnion
    {
        TpmAlgId GetUnionSelector();
    }

    /// <summary> Table 199 defines the possible parameter definition structures that may be
    /// contained in the public portion of a key. If the Object can be a parent, the first
    /// field must be a TPMT_SYM_DEF_OBJECT. See 11.1.7. </summary>
    /// <remarks> One of: KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms. </remarks>
    public interface IPublicParmsUnion
    {
        TpmAlgId GetUnionSelector();
    }

    /// <summary> Table 205 Definition of TPMU_SENSITIVE_COMPOSITE Union [IN/OUT] </summary>
    /// <remarks> One of: Tpm2bPrivateKeyRsa, Tpm2bEccParameter, Tpm2bSensitiveData,
    /// Tpm2bSymKey, Tpm2bPrivateVendorSpecific. </remarks>
    public interface ISensitiveCompositeUnion
    {
        TpmAlgId GetUnionSelector();
    }

    public abstract partial class TpmStructureBase
    {
        Type UnionElementFromSelector(Type unionInterface, object selector)
        {
            if (unionInterface == typeof(ICapabilitiesUnion))
            {
                switch ((Cap)selector)
                {
                    case Cap.Algs: return typeof(AlgPropertyArray);
                    case Cap.Handles: return typeof(HandleArray);
                    case Cap.Commands: return typeof(CcaArray);
                    case Cap.PpCommands: return typeof(CcArray);
                    case Cap.AuditCommands: return typeof(CcArray);
                    case Cap.Pcrs: return typeof(PcrSelectionArray);
                    case Cap.TpmProperties: return typeof(TaggedTpmPropertyArray);
                    case Cap.PcrProperties: return typeof(TaggedPcrPropertyArray);
                    case Cap.EccCurves: return typeof(EccCurveArray);
                    case Cap.AuthPolicies: return typeof(TaggedPolicyArray);
                    case Cap.Act: return typeof(ActDataArray);
                }
            }
            else if (unionInterface == typeof(IAttestUnion))
            {
                switch ((TpmSt)selector)
                {
                    case TpmSt.AttestCertify: return typeof(CertifyInfo);
                    case TpmSt.AttestCreation: return typeof(CreationInfo);
                    case TpmSt.AttestQuote: return typeof(QuoteInfo);
                    case TpmSt.AttestCommandAudit: return typeof(CommandAuditInfo);
                    case TpmSt.AttestSessionAudit: return typeof(SessionAuditInfo);
                    case TpmSt.AttestTime: return typeof(TimeAttestInfo);
                    case TpmSt.AttestNv: return typeof(NvCertifyInfo);
                    case TpmSt.AttestNvDigest: return typeof(NvDigestCertifyInfo);
                }
            }
            else if (unionInterface == typeof(ISymDetailsUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Tdes: return typeof(TdesSymDetails);
                    case TpmAlgId.Aes: return typeof(AesSymDetails);
                    case TpmAlgId.Sm4: return typeof(Sm4SymDetails);
                    case TpmAlgId.Camellia: return typeof(CamelliaSymDetails);
                    case TpmAlgId.Any: return typeof(AnySymDetails);
                    case TpmAlgId.Xor: return typeof(XorSymDetails);
                    case TpmAlgId.Null: return typeof(NullSymDetails);
                }
            }
            else if (unionInterface == typeof(ISensitiveCreateUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Any: return typeof(byte);
                    case TpmAlgId.Any2: return typeof(TpmDerive);
                }
            }
            else if (unionInterface == typeof(ISchemeKeyedhashUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Hmac: return typeof(SchemeHmac);
                    case TpmAlgId.Xor: return typeof(SchemeXor);
                    case TpmAlgId.Null: return typeof(NullSchemeKeyedhash);
                }
            }
            else if (unionInterface == typeof(ISigSchemeUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Rsassa: return typeof(SigSchemeRsassa);
                    case TpmAlgId.Rsapss: return typeof(SigSchemeRsapss);
                    case TpmAlgId.Ecdsa: return typeof(SigSchemeEcdsa);
                    case TpmAlgId.Ecdaa: return typeof(SigSchemeEcdaa);
                    case TpmAlgId.Sm2: return typeof(SigSchemeSm2);
                    case TpmAlgId.Ecschnorr: return typeof(SigSchemeEcschnorr);
                    case TpmAlgId.Hmac: return typeof(SchemeHmac);
                    case TpmAlgId.Any: return typeof(SchemeHash);
                    case TpmAlgId.Null: return typeof(NullSigScheme);
                }
            }
            else if (unionInterface == typeof(IKdfSchemeUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Mgf1: return typeof(KdfSchemeMgf1);
                    case TpmAlgId.Kdf1Sp80056a: return typeof(KdfSchemeKdf1Sp80056a);
                    case TpmAlgId.Kdf2: return typeof(KdfSchemeKdf2);
                    case TpmAlgId.Kdf1Sp800108: return typeof(KdfSchemeKdf1Sp800108);
                    case TpmAlgId.Any: return typeof(SchemeHash);
                    case TpmAlgId.Null: return typeof(NullKdfScheme);
                }
            }
            else if (unionInterface == typeof(IAsymSchemeUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Ecdh: return typeof(KeySchemeEcdh);
                    case TpmAlgId.Ecmqv: return typeof(KeySchemeEcmqv);
                    case TpmAlgId.Rsassa: return typeof(SigSchemeRsassa);
                    case TpmAlgId.Rsapss: return typeof(SigSchemeRsapss);
                    case TpmAlgId.Ecdsa: return typeof(SigSchemeEcdsa);
                    case TpmAlgId.Ecdaa: return typeof(SigSchemeEcdaa);
                    case TpmAlgId.Sm2: return typeof(SigSchemeSm2);
                    case TpmAlgId.Ecschnorr: return typeof(SigSchemeEcschnorr);
                    case TpmAlgId.Rsaes: return typeof(EncSchemeRsaes);
                    case TpmAlgId.Oaep: return typeof(EncSchemeOaep);
                    case TpmAlgId.Any: return typeof(SchemeHash);
                    case TpmAlgId.Null: return typeof(NullAsymScheme);
                }
            }
            else if (unionInterface == typeof(ISignatureUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Rsassa: return typeof(SignatureRsassa);
                    case TpmAlgId.Rsapss: return typeof(SignatureRsapss);
                    case TpmAlgId.Ecdsa: return typeof(SignatureEcdsa);
                    case TpmAlgId.Ecdaa: return typeof(SignatureEcdaa);
                    case TpmAlgId.Sm2: return typeof(SignatureSm2);
                    case TpmAlgId.Ecschnorr: return typeof(SignatureEcschnorr);
                    case TpmAlgId.Hmac: return typeof(TpmHash);
                    case TpmAlgId.Any: return typeof(SchemeHash);
                    case TpmAlgId.Null: return typeof(NullSignature);
                }
            }
            else if (unionInterface == typeof(IPublicIdUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Keyedhash: return typeof(Tpm2bDigestKeyedhash);
                    case TpmAlgId.Symcipher: return typeof(Tpm2bDigestSymcipher);
                    case TpmAlgId.Rsa: return typeof(Tpm2bPublicKeyRsa);
                    case TpmAlgId.Ecc: return typeof(EccPoint);
                    case TpmAlgId.Any: return typeof(TpmDerive);
                }
            }
            else if (unionInterface == typeof(IPublicParmsUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Keyedhash: return typeof(KeyedhashParms);
                    case TpmAlgId.Symcipher: return typeof(SymcipherParms);
                    case TpmAlgId.Rsa: return typeof(RsaParms);
                    case TpmAlgId.Ecc: return typeof(EccParms);
                    case TpmAlgId.Any: return typeof(AsymParms);
                }
            }
            else if (unionInterface == typeof(ISensitiveCompositeUnion))
            {
                switch ((TpmAlgId)selector)
                {
                    case TpmAlgId.Rsa: return typeof(Tpm2bPrivateKeyRsa);
                    case TpmAlgId.Ecc: return typeof(Tpm2bEccParameter);
                    case TpmAlgId.Keyedhash: return typeof(Tpm2bSensitiveData);
                    case TpmAlgId.Symcipher: return typeof(Tpm2bSymKey);
                    case TpmAlgId.Any: return typeof(Tpm2bPrivateVendorSpecific);
                }
            }
            else
            {
                throw new Exception("Unknown union interface type " + unionInterface.Name);
            }
            throw new Exception("Unknown selector value" + selector + " for " + unionInterface.Name +  " union");
        }
    }

    /// <summary> Handle of a loaded TPM key or other object [TSS] </summary>
    [DataContract]
    [SpecTypeName("TPM_HANDLE")]
    public partial class TpmHandle: TpmStructureBase
    {
        /// <summary> Handle value </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint handle { get; set; }

        public TpmHandle() { handle = (uint)TpmRh.Null; }

        public TpmHandle(TpmHandle src)
        {
            handle = src.handle;
            Auth = src.Auth;
            if (src.Name != null)
                Name = Globs.CopyData(src.Name);
        }

        /// <param name = "_handle"> Handle value </param>
        public TpmHandle(uint _handle) { handle = _handle; }

        new public TpmHandle Copy() { return CreateCopy<TpmHandle>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Base class for empty union elements.
    /// An empty union element does not contain any data to marshal.
    /// This data structure can be used in place of any other union
    /// initialized with its own empty element. </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_UNION")]
    public partial class NullUnion: TpmStructureBase, ISymDetailsUnion, ISchemeKeyedhashUnion, ISigSchemeUnion, IKdfSchemeUnion, IAsymSchemeUnion, ISignatureUnion
    {
        public NullUnion() {}

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Null; }

        new public NullUnion Copy() { return CreateCopy<NullUnion>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used as a placeholder. In some cases, a union will have a
    /// selector value with no data to unmarshal when that type is selected. Rather than leave
    /// the entry empty, TPMS_EMPTY may be selected. </summary>
    [DataContract]
    [SpecTypeName("TPMS_EMPTY")]
    public partial class Empty: TpmStructureBase, IAsymSchemeUnion
    {
        public Empty() {}

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Rsaes; }

        new public Empty Copy() { return CreateCopy<Empty>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is a return value for a TPM2_GetCapability() that reads the
    /// installed algorithms. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(AlgorithmAttr))]
    [SpecTypeName("TPMS_ALGORITHM_DESCRIPTION")]
    public partial class AlgorithmDescription: TpmStructureBase
    {
        /// <summary> An algorithm </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId alg { get; set; }

        /// <summary> The attributes of the algorithm </summary>
        [MarshalAs(1)]
        [DataMember()]
        public AlgorithmAttr attributes { get; set; }

        public AlgorithmDescription() { alg = TpmAlgId.Null; }

        public AlgorithmDescription(AlgorithmDescription src)
        {
            alg = src.alg;
            attributes = src.attributes;
        }

        /// <param name = "_alg"> An algorithm </param>
        /// <param name = "_attributes"> The attributes of the algorithm </param>
        public AlgorithmDescription(TpmAlgId _alg, AlgorithmAttr _attributes)
        {
            alg = _alg;
            attributes = _attributes;
        }

        new public AlgorithmDescription Copy() { return CreateCopy<AlgorithmDescription>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 80 shows the basic hash-agile structure used in this specification. To
    /// handle hash agility, this structure uses the hashAlg parameter to indicate the
    /// algorithm used to compute the digest and, by implication, the size of the digest. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMT_HA")]
    public partial class TpmHash: TpmStructureBase, ISignatureUnion
    {
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        /// <summary> Hash value </summary>
        [MarshalAs(1, MarshalType.SpecialVariableLengthArray, "hashAlg", 2)]
        [DataMember()]
        public byte[] digest;

        public TpmHash() { hashAlg = TpmAlgId.Null; }

        public TpmHash(TpmHash src)
        {
            hashAlg = src.hashAlg;
            digest = src.digest;
        }

        /// <param name = "_hashAlg"> Selector of the hash contained in the digest that implies the
        ///        size of the digest
        ///        NOTE The leading + on the type indicates that this structure should pass an
        ///        indication to the unmarshaling function for TPMI_ALG_HASH so that TPM_ALG_NULL will
        ///        be allowed if a use of a TPMT_HA allows TPM_ALG_NULL. </param>
        /// <param name = "_digest"> Hash value </param>
        public TpmHash(TpmAlgId _hashAlg, byte[] _digest)
        {
            hashAlg = _hashAlg;
            digest = _digest;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Hmac; }

        new public TpmHash Copy() { return CreateCopy<TpmHash>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used for a sized buffer that cannot be larger than the
    /// largest digest produced by any hash algorithm implemented on the TPM. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DIGEST")]
    public partial class Tpm2bDigest: TpmStructureBase, IPublicIdUnion
    {
        /// <summary> The buffer area that can be no larger than a digest </summary>
        [Range(MaxVal = 0u /*sizeof(TPMU_HA)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bDigest() {}

        public Tpm2bDigest(Tpm2bDigest src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The buffer area that can be no larger than a digest </param>
        public Tpm2bDigest(byte[] _buffer) { buffer = _buffer; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Keyedhash; }

        new public Tpm2bDigest Copy() { return CreateCopy<Tpm2bDigest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used for a data buffer that is required to be no larger
    /// than the size of the Name of an object. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DATA")]
    public partial class Tpm2bData: TpmStructureBase
    {
        [Range(MaxVal = 66u /*sizeof(TPMT_HA)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bData() {}

        public Tpm2bData(Tpm2bData src) { buffer = src.buffer; }

        /// <param name = "_buffer"> TBD </param>
        public Tpm2bData(byte[] _buffer) { buffer = _buffer; }

        new public Tpm2bData Copy() { return CreateCopy<Tpm2bData>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 83 Definition of Types for TPM2B_NONCE </summary>
    [DataContract]
    [SpecTypeName("TPM2B_NONCE")]
    public partial class Tpm2bNonce: Tpm2bDigest
    {
        public Tpm2bNonce() {}

        public Tpm2bNonce(Tpm2bNonce _Tpm2bNonce) : base(_Tpm2bNonce) {}

        /// <param name = "_buffer"> The buffer area that can be no larger than a digest </param>
        public Tpm2bNonce(byte[] _buffer) : base(_buffer) {}

        new public Tpm2bNonce Copy() { return CreateCopy<Tpm2bNonce>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used for an authorization value and limits an authValue to
    /// being no larger than the largest digest produced by a TPM. In order to ensure
    /// consistency within an object, the authValue may be no larger than the size of the
    /// digest produced by the objects nameAlg. This ensures that any TPM that can load the
    /// object will be able to handle the authValue of the object. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_AUTH")]
    public partial class Tpm2bAuth: Tpm2bDigest
    {
        public Tpm2bAuth() {}

        public Tpm2bAuth(Tpm2bAuth _Tpm2bAuth) : base(_Tpm2bAuth) {}

        /// <param name = "_buffer"> The buffer area that can be no larger than a digest </param>
        public Tpm2bAuth(byte[] _buffer) : base(_buffer) {}

        new public Tpm2bAuth Copy() { return CreateCopy<Tpm2bAuth>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This type is a sized buffer that can hold an operand for a comparison with
    /// an NV Index location. The maximum size of the operand is implementation dependent but
    /// a TPM is required to support an operand size that is at least as big as the digest
    /// produced by any of the hash algorithms implemented on the TPM. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_OPERAND")]
    public partial class Tpm2bOperand: Tpm2bDigest
    {
        public Tpm2bOperand() {}

        public Tpm2bOperand(Tpm2bOperand _Tpm2bOperand) : base(_Tpm2bOperand) {}

        /// <param name = "_buffer"> The buffer area that can be no larger than a digest </param>
        public Tpm2bOperand(byte[] _buffer) : base(_buffer) {}

        new public Tpm2bOperand Copy() { return CreateCopy<Tpm2bOperand>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This type is a sized buffer that can hold event data. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_EVENT")]
    public partial class Tpm2bEvent: TpmStructureBase
    {
        /// <summary> The operand </summary>
        [Range(MaxVal = 1024u /*1024*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bEvent() {}

        public Tpm2bEvent(Tpm2bEvent src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The operand </param>
        public Tpm2bEvent(byte[] _buffer) { buffer = _buffer; }

        new public Tpm2bEvent Copy() { return CreateCopy<Tpm2bEvent>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This type is a sized buffer that can hold a maximally sized buffer for
    /// commands that use a large data buffer such as TPM2_Hash(), TPM2_SequenceUpdate(), or
    /// TPM2_FieldUpgradeData(). </summary>
    [DataContract]
    [SpecTypeName("TPM2B_MAX_BUFFER")]
    public partial class Tpm2bMaxBuffer: TpmStructureBase
    {
        /// <summary> The operand </summary>
        [Range(MaxVal = 1024u /*MAX_DIGEST_BUFFER*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bMaxBuffer() {}

        public Tpm2bMaxBuffer(Tpm2bMaxBuffer src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The operand </param>
        public Tpm2bMaxBuffer(byte[] _buffer) { buffer = _buffer; }

        new public Tpm2bMaxBuffer Copy() { return CreateCopy<Tpm2bMaxBuffer>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This type is a sized buffer that can hold a maximally sized buffer for NV
    /// data commands such as TPM2_NV_Read(), TPM2_NV_Write(), and TPM2_NV_Certify(). </summary>
    [DataContract]
    [SpecTypeName("TPM2B_MAX_NV_BUFFER")]
    public partial class Tpm2bMaxNvBuffer: TpmStructureBase
    {
        /// <summary> The operand
        /// NOTE MAX_NV_BUFFER_SIZE is TPM-dependent </summary>
        [Range(MaxVal = 1024u /*MAX_NV_BUFFER_SIZE*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bMaxNvBuffer() {}

        public Tpm2bMaxNvBuffer(Tpm2bMaxNvBuffer src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The operand
        ///        NOTE MAX_NV_BUFFER_SIZE is TPM-dependent </param>
        public Tpm2bMaxNvBuffer(byte[] _buffer) { buffer = _buffer; }

        new public Tpm2bMaxNvBuffer Copy() { return CreateCopy<Tpm2bMaxNvBuffer>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This TPM-dependent structure is used to provide the timeout value for an
    /// authorization. The size shall be 8 or less. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_TIMEOUT")]
    public partial class Tpm2bTimeout: TpmStructureBase
    {
        /// <summary> The timeout value </summary>
        [Range(MaxVal = 8u /*sizeof(UINT64)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bTimeout() {}

        public Tpm2bTimeout(Tpm2bTimeout src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The timeout value </param>
        public Tpm2bTimeout(byte[] _buffer) { buffer = _buffer; }

        new public Tpm2bTimeout Copy() { return CreateCopy<Tpm2bTimeout>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used for passing an initial value for a symmetric block
    /// cipher to or from the TPM. The size is set to be the largest block size of any
    /// implemented symmetric cipher implemented on the TPM. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_IV")]
    public partial class Tpm2bIv: TpmStructureBase
    {
        /// <summary> The IV value </summary>
        [Range(MaxVal = 16u /*MAX_SYM_BLOCK_SIZE*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bIv() {}

        public Tpm2bIv(Tpm2bIv src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The IV value </param>
        public Tpm2bIv(byte[] _buffer) { buffer = _buffer; }

        new public Tpm2bIv Copy() { return CreateCopy<Tpm2bIv>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This buffer holds a Name for any entity type. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_NAME")]
    public partial class Tpm2bName: TpmStructureBase
    {
        /// <summary> The Name structure </summary>
        [Range(MaxVal = 0u /*sizeof(TPMU_NAME)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] name;

        public Tpm2bName() {}

        public Tpm2bName(Tpm2bName src) { name = src.name; }

        /// <param name = "_name"> The Name structure </param>
        public Tpm2bName(byte[] _name) { name = _name; }

        new public Tpm2bName Copy() { return CreateCopy<Tpm2bName>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure provides a standard method of specifying a list of PCR. </summary>
    [DataContract]
    [SpecTypeName("TPMS_PCR_SELECT")]
    public partial class PcrSelect: TpmStructureBase
    {
        /// <summary> The bit map of selected PCR </summary>
        [Range(MinVal = 3u /*PCR_SELECT_MIN*/, MaxVal = 3u /*PCR_SELECT_MAX*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "sizeofSelect", 1)]
        [DataMember()]
        public byte[] pcrSelect;

        public PcrSelect() {}

        public PcrSelect(PcrSelect src) { pcrSelect = src.pcrSelect; }

        /// <param name = "_pcrSelect"> The bit map of selected PCR </param>
        public PcrSelect(byte[] _pcrSelect) { pcrSelect = _pcrSelect; }

        new public PcrSelect Copy() { return CreateCopy<PcrSelect>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 94 Definition of TPMS_PCR_SELECTION Structure </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_PCR_SELECTION")]
    public partial class PcrSelection: TpmStructureBase
    {
        /// <summary> The hash algorithm associated with the selection </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hash { get; set; }

        /// <summary> The bit map of selected PCR </summary>
        [Range(MinVal = 3u /*PCR_SELECT_MIN*/, MaxVal = 3u /*PCR_SELECT_MAX*/)]
        [MarshalAs(1, MarshalType.VariableLengthArray, "sizeofSelect", 1)]
        [DataMember()]
        public byte[] pcrSelect;

        public PcrSelection() { hash = TpmAlgId.Null; }

        public PcrSelection(PcrSelection src)
        {
            hash = src.hash;
            pcrSelect = src.pcrSelect;
        }

        /// <param name = "_hash"> The hash algorithm associated with the selection </param>
        /// <param name = "_pcrSelect"> The bit map of selected PCR </param>
        public PcrSelection(TpmAlgId _hash, byte[] _pcrSelect)
        {
            hash = _hash;
            pcrSelect = _pcrSelect;
        }

        new public PcrSelection Copy() { return CreateCopy<PcrSelection>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This ticket is produced by TPM2_Create() or TPM2_CreatePrimary(). It is used
    /// to bind the creation data to the object to which it applies. The ticket is computed by
    /// </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPMT_TK_CREATION")]
    public partial class TkCreation: TpmStructureBase
    {
        /// <summary> Ticket structure tag </summary>
        [Range(OnlyVal = 32801u /*TPM_ST_CREATION*/)]
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt tag = TpmSt.Creation;

        /// <summary> The hierarchy containing name </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }

        /// <summary> This shall be the HMAC produced using a proof value of hierarchy. </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;

        public TkCreation() { hierarchy = new TpmHandle(); }

        public TkCreation(TkCreation src)
        {
            hierarchy = src.hierarchy;
            digest = src.digest;
        }

        /// <param name = "_hierarchy"> The hierarchy containing name </param>
        /// <param name = "_digest"> This shall be the HMAC produced using a proof value of hierarchy.
        ///        </param>
        public TkCreation(TpmHandle _hierarchy, byte[] _digest)
        {
            hierarchy = _hierarchy;
            digest = _digest;
        }

        new public TkCreation Copy() { return CreateCopy<TkCreation>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This ticket is produced by TPM2_VerifySignature(). This formulation is used
    /// for multiple ticket uses. The ticket provides evidence that the TPM has validated that
    /// a digest was signed by a key with the Name of keyName. The ticket is computed by </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPMT_TK_VERIFIED")]
    public partial class TkVerified: TpmStructureBase
    {
        /// <summary> Ticket structure tag </summary>
        [Range(OnlyVal = 32802u /*TPM_ST_VERIFIED*/)]
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt tag = TpmSt.Verified;

        /// <summary> The hierarchy containing keyName </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }

        /// <summary> This shall be the HMAC produced using a proof value of hierarchy. </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;

        public TkVerified() { hierarchy = new TpmHandle(); }

        public TkVerified(TkVerified src)
        {
            hierarchy = src.hierarchy;
            digest = src.digest;
        }

        /// <param name = "_hierarchy"> The hierarchy containing keyName </param>
        /// <param name = "_digest"> This shall be the HMAC produced using a proof value of hierarchy.
        ///        </param>
        public TkVerified(TpmHandle _hierarchy, byte[] _digest)
        {
            hierarchy = _hierarchy;
            digest = _digest;
        }

        new public TkVerified Copy() { return CreateCopy<TkVerified>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This ticket is produced by TPM2_PolicySigned() and TPM2_PolicySecret() when
    /// the authorization has an expiration time. If nonceTPM was provided in the policy
    /// command, the ticket is computed by </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmSt))]
    [SpecTypeName("TPMT_TK_AUTH")]
    public partial class TkAuth: TpmStructureBase
    {
        /// <summary> Ticket structure tag </summary>
        [Range(Values = new[] {32805u /*TPM_ST_AUTH_SIGNED*/, 32803u /*TPM_ST_AUTH_SECRET*/})]
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt tag { get; set; }

        /// <summary> The hierarchy of the object used to produce the ticket </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }

        /// <summary> This shall be the HMAC produced using a proof value of hierarchy. </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;

        public TkAuth() { hierarchy = new TpmHandle(); }

        public TkAuth(TkAuth src)
        {
            tag = src.tag;
            hierarchy = src.hierarchy;
            digest = src.digest;
        }

        /// <param name = "_tag"> Ticket structure tag </param>
        /// <param name = "_hierarchy"> The hierarchy of the object used to produce the ticket </param>
        /// <param name = "_digest"> This shall be the HMAC produced using a proof value of hierarchy.
        ///        </param>
        public TkAuth(TpmSt _tag, TpmHandle _hierarchy, byte[] _digest)
        {
            tag = _tag;
            hierarchy = _hierarchy;
            digest = _digest;
        }

        new public TkAuth Copy() { return CreateCopy<TkAuth>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This ticket is produced by TPM2_SequenceComplete() or TPM2_Hash() when the
    /// message that was digested did not start with TPM_GENERATED_VALUE. The ticket is
    /// computed by </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("TPMT_TK_HASHCHECK")]
    public partial class TkHashcheck: TpmStructureBase
    {
        /// <summary> Ticket structure tag </summary>
        [Range(OnlyVal = 32804u /*TPM_ST_HASHCHECK*/)]
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt tag = TpmSt.Hashcheck;

        /// <summary> The hierarchy </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }

        /// <summary> This shall be the HMAC produced using a proof value of hierarchy. </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;

        public TkHashcheck() { hierarchy = new TpmHandle(); }

        public TkHashcheck(TkHashcheck src)
        {
            hierarchy = src.hierarchy;
            digest = src.digest;
        }

        /// <param name = "_hierarchy"> The hierarchy </param>
        /// <param name = "_digest"> This shall be the HMAC produced using a proof value of hierarchy.
        ///        </param>
        public TkHashcheck(TpmHandle _hierarchy, byte[] _digest)
        {
            hierarchy = _hierarchy;
            digest = _digest;
        }

        new public TkHashcheck Copy() { return CreateCopy<TkHashcheck>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used to report the properties of an algorithm identifier.
    /// It is returned in response to a TPM2_GetCapability() with capability = TPM_CAP_ALG. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(AlgorithmAttr))]
    [SpecTypeName("TPMS_ALG_PROPERTY")]
    public partial class AlgProperty: TpmStructureBase
    {
        /// <summary> An algorithm identifier </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId alg { get; set; }

        /// <summary> The attributes of the algorithm </summary>
        [MarshalAs(1)]
        [DataMember()]
        public AlgorithmAttr algProperties { get; set; }

        public AlgProperty() { alg = TpmAlgId.Null; }

        public AlgProperty(AlgProperty src)
        {
            alg = src.alg;
            algProperties = src.algProperties;
        }

        /// <param name = "_alg"> An algorithm identifier </param>
        /// <param name = "_algProperties"> The attributes of the algorithm </param>
        public AlgProperty(TpmAlgId _alg, AlgorithmAttr _algProperties)
        {
            alg = _alg;
            algProperties = _algProperties;
        }

        new public AlgProperty Copy() { return CreateCopy<AlgProperty>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used to report the properties that are UINT32 values. It
    /// is returned in response to a TPM2_GetCapability(). </summary>
    [DataContract]
    [KnownType(typeof(Pt))]
    [SpecTypeName("TPMS_TAGGED_PROPERTY")]
    public partial class TaggedProperty: TpmStructureBase
    {
        /// <summary> A property identifier </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Pt property { get; set; }

        /// <summary> The value of the property </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint value { get; set; }

        public TaggedProperty() {}

        public TaggedProperty(TaggedProperty src)
        {
            property = src.property;
            value = src.value;
        }

        /// <param name = "_property"> A property identifier </param>
        /// <param name = "_value"> The value of the property </param>
        public TaggedProperty(Pt _property, uint _value)
        {
            property = _property;
            value = _value;
        }

        new public TaggedProperty Copy() { return CreateCopy<TaggedProperty>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used in TPM2_GetCapability() to return the attributes of
    /// the PCR. </summary>
    [DataContract]
    [KnownType(typeof(PtPcr))]
    [SpecTypeName("TPMS_TAGGED_PCR_SELECT")]
    public partial class TaggedPcrSelect: TpmStructureBase
    {
        /// <summary> The property identifier </summary>
        [MarshalAs(0)]
        [DataMember()]
        public PtPcr tag { get; set; }

        /// <summary> The bit map of PCR with the identified property </summary>
        [Range(MinVal = 3u /*PCR_SELECT_MIN*/, MaxVal = 3u /*PCR_SELECT_MAX*/)]
        [MarshalAs(1, MarshalType.VariableLengthArray, "sizeofSelect", 1)]
        [DataMember()]
        public byte[] pcrSelect;

        public TaggedPcrSelect() {}

        public TaggedPcrSelect(TaggedPcrSelect src)
        {
            tag = src.tag;
            pcrSelect = src.pcrSelect;
        }

        /// <param name = "_tag"> The property identifier </param>
        /// <param name = "_pcrSelect"> The bit map of PCR with the identified property </param>
        public TaggedPcrSelect(PtPcr _tag, byte[] _pcrSelect)
        {
            tag = _tag;
            pcrSelect = _pcrSelect;
        }

        new public TaggedPcrSelect Copy() { return CreateCopy<TaggedPcrSelect>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used in TPM2_GetCapability() to return the policy
    /// associated with a permanent handle. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("TPMS_TAGGED_POLICY")]
    public partial class TaggedPolicy: TpmStructureBase
    {
        /// <summary> A permanent handle </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> The policy algorithm and hash </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHash policyHash { get; set; }

        public TaggedPolicy() { handle = new TpmHandle(); }

        public TaggedPolicy(TaggedPolicy src)
        {
            handle = src.handle;
            policyHash = src.policyHash;
        }

        /// <param name = "_handle"> A permanent handle </param>
        /// <param name = "_policyHash"> The policy algorithm and hash </param>
        public TaggedPolicy(TpmHandle _handle, TpmHash _policyHash)
        {
            handle = _handle;
            policyHash = _policyHash;
        }

        new public TaggedPolicy Copy() { return CreateCopy<TaggedPolicy>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used in TPM2_GetCapability() to return the ACT data. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(ActAttr))]
    [SpecTypeName("TPMS_ACT_DATA")]
    public partial class ActData: TpmStructureBase
    {
        /// <summary> A permanent handle </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> The current timeout of the ACT </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint timeout { get; set; }

        /// <summary> The state of the ACT </summary>
        [MarshalAs(2)]
        [DataMember()]
        public ActAttr attributes { get; set; }

        public ActData() { handle = new TpmHandle(); }

        public ActData(ActData src)
        {
            handle = src.handle;
            timeout = src.timeout;
            attributes = src.attributes;
        }

        /// <param name = "_handle"> A permanent handle </param>
        /// <param name = "_timeout"> The current timeout of the ACT </param>
        /// <param name = "_attributes"> The state of the ACT </param>
        public ActData(TpmHandle _handle, uint _timeout, ActAttr _attributes)
        {
            handle = _handle;
            timeout = _timeout;
            attributes = _attributes;
        }

        new public ActData Copy() { return CreateCopy<ActData>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> A list of command codes may be input to the TPM or returned by the TPM
    /// depending on the command. </summary>
    [DataContract]
    [SpecTypeName("TPML_CC")]
    public partial class CcArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> A list of command codes
        /// The maximum only applies to a command code list in a command. The response size is
        /// limited only by the size of the parameter buffer. </summary>
        [Range(MaxVal = 410u /*MAX_CAP_CC*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TpmCc[] commandCodes;

        public CcArray() {}

        public CcArray(CcArray src) { commandCodes = src.commandCodes; }

        /// <param name = "_commandCodes"> A list of command codes
        ///        The maximum only applies to a command code list in a command. The response size is
        ///        limited only by the size of the parameter buffer. </param>
        public CcArray(TpmCc[] _commandCodes) { commandCodes = _commandCodes; }

        public virtual Cap GetUnionSelector() { return Cap.PpCommands; }

        new public CcArray Copy() { return CreateCopy<CcArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is only used in TPM2_GetCapability(capability = TPM_CAP_COMMANDS).
    /// </summary>
    [DataContract]
    [SpecTypeName("TPML_CCA")]
    public partial class CcaArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> A list of command codes attributes </summary>
        [Range(MaxVal = 410u /*MAX_CAP_CC*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public CcAttr[] commandAttributes;

        public CcaArray() {}

        public CcaArray(CcaArray src) { commandAttributes = src.commandAttributes; }

        /// <param name = "_commandAttributes"> A list of command codes attributes </param>
        public CcaArray(CcAttr[] _commandAttributes) { commandAttributes = _commandAttributes; }

        public virtual Cap GetUnionSelector() { return Cap.Commands; }

        new public CcaArray Copy() { return CreateCopy<CcaArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is returned by TPM2_IncrementalSelfTest(). </summary>
    [DataContract]
    [SpecTypeName("TPML_ALG")]
    public partial class AlgArray: TpmStructureBase
    {
        /// <summary> A list of algorithm IDs
        /// The maximum only applies to an algorithm list in a command. The response size is
        /// limited only by the size of the parameter buffer. </summary>
        [Range(MaxVal = 64u /*MAX_ALG_LIST_SIZE*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TpmAlgId[] algorithms;

        public AlgArray() {}

        public AlgArray(AlgArray src) { algorithms = src.algorithms; }

        /// <param name = "_algorithms"> A list of algorithm IDs
        ///        The maximum only applies to an algorithm list in a command. The response size is
        ///        limited only by the size of the parameter buffer. </param>
        public AlgArray(TpmAlgId[] _algorithms) { algorithms = _algorithms; }

        new public AlgArray Copy() { return CreateCopy<AlgArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used when the TPM returns a list of loaded handles when
    /// the capability in TPM2_GetCapability() is TPM_CAP_HANDLE. </summary>
    [DataContract]
    [SpecTypeName("TPML_HANDLE")]
    public partial class HandleArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> An array of handles </summary>
        [Range(MaxVal = 254u /*MAX_CAP_HANDLES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TpmHandle[] handle;

        public HandleArray() {}

        public HandleArray(HandleArray src) { handle = src.handle; }

        /// <param name = "_handle"> An array of handles </param>
        public HandleArray(TpmHandle[] _handle) { handle = _handle; }

        public virtual Cap GetUnionSelector() { return Cap.Handles; }

        new public HandleArray Copy() { return CreateCopy<HandleArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is used to convey a list of digest values. This type is used in
    /// TPM2_PolicyOR() and in TPM2_PCR_Read(). </summary>
    [DataContract]
    [SpecTypeName("TPML_DIGEST")]
    public partial class DigestArray: TpmStructureBase
    {
        /// <summary> A list of digests
        /// For TPM2_PolicyOR(), all digests will have been computed using the digest of the
        /// policy session. For TPM2_PCR_Read(), each digest will be the size of the digest for
        /// the bank containing the PCR. </summary>
        [Range(MinVal = 2u /*2*/, MaxVal = 8u /*8*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public Tpm2bDigest[] digests;

        public DigestArray() {}

        public DigestArray(DigestArray src) { digests = src.digests; }

        /// <param name = "_digests"> A list of digests
        ///        For TPM2_PolicyOR(), all digests will have been computed using the digest of the
        ///        policy session. For TPM2_PCR_Read(), each digest will be the size of the digest for
        ///        the bank containing the PCR. </param>
        public DigestArray(Tpm2bDigest[] _digests) { digests = _digests; }

        new public DigestArray Copy() { return CreateCopy<DigestArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is used to convey a list of digest values. This type is returned
    /// by TPM2_PCR_Event() and TPM2_EventSequenceComplete() and is an input for
    /// TPM2_PCR_Extend(). </summary>
    [DataContract]
    [SpecTypeName("TPML_DIGEST_VALUES")]
    public partial class DigestValuesArray: TpmStructureBase
    {
        /// <summary> A list of tagged digests </summary>
        [Range(MaxVal = 3u /*HASH_COUNT*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TpmHash[] digests;

        public DigestValuesArray() {}

        public DigestValuesArray(DigestValuesArray src) { digests = src.digests; }

        /// <param name = "_digests"> A list of tagged digests </param>
        public DigestValuesArray(TpmHash[] _digests) { digests = _digests; }

        new public DigestValuesArray Copy() { return CreateCopy<DigestValuesArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is used to indicate the PCR that are included in a selection when
    /// more than one PCR value may be selected. </summary>
    [DataContract]
    [SpecTypeName("TPML_PCR_SELECTION")]
    public partial class PcrSelectionArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> List of selections </summary>
        [Range(MaxVal = 3u /*HASH_COUNT*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelections;

        public PcrSelectionArray() {}

        public PcrSelectionArray(PcrSelectionArray src) { pcrSelections = src.pcrSelections; }

        /// <param name = "_pcrSelections"> List of selections </param>
        public PcrSelectionArray(PcrSelection[] _pcrSelections) { pcrSelections = _pcrSelections; }

        public virtual Cap GetUnionSelector() { return Cap.Pcrs; }

        new public PcrSelectionArray Copy() { return CreateCopy<PcrSelectionArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is used to report on a list of algorithm attributes. It is
    /// returned in a TPM2_GetCapability(). </summary>
    [DataContract]
    [SpecTypeName("TPML_ALG_PROPERTY")]
    public partial class AlgPropertyArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> List of properties </summary>
        [Range(MaxVal = 169u /*MAX_CAP_ALGS*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public AlgProperty[] algProperties;

        public AlgPropertyArray() {}

        public AlgPropertyArray(AlgPropertyArray src) { algProperties = src.algProperties; }

        /// <param name = "_algProperties"> List of properties </param>
        public AlgPropertyArray(AlgProperty[] _algProperties) { algProperties = _algProperties; }

        public virtual Cap GetUnionSelector() { return Cap.Algs; }

        new public AlgPropertyArray Copy() { return CreateCopy<AlgPropertyArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is used to report on a list of properties that are
    /// TPMS_TAGGED_PROPERTY values. It is returned by a TPM2_GetCapability(). </summary>
    [DataContract]
    [SpecTypeName("TPML_TAGGED_TPM_PROPERTY")]
    public partial class TaggedTpmPropertyArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> An array of tagged properties </summary>
        [Range(MaxVal = 127u /*MAX_TPM_PROPERTIES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TaggedProperty[] tpmProperty;

        public TaggedTpmPropertyArray() {}

        public TaggedTpmPropertyArray(TaggedTpmPropertyArray src) { tpmProperty = src.tpmProperty; }

        /// <param name = "_tpmProperty"> An array of tagged properties </param>
        public TaggedTpmPropertyArray(TaggedProperty[] _tpmProperty) { tpmProperty = _tpmProperty; }

        public virtual Cap GetUnionSelector() { return Cap.TpmProperties; }

        new public TaggedTpmPropertyArray Copy() { return CreateCopy<TaggedTpmPropertyArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is used to report on a list of properties that are TPMS_PCR_SELECT
    /// values. It is returned by a TPM2_GetCapability(). </summary>
    [DataContract]
    [SpecTypeName("TPML_TAGGED_PCR_PROPERTY")]
    public partial class TaggedPcrPropertyArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> A tagged PCR selection </summary>
        [Range(MaxVal = 203u /*MAX_PCR_PROPERTIES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TaggedPcrSelect[] pcrProperty;

        public TaggedPcrPropertyArray() {}

        public TaggedPcrPropertyArray(TaggedPcrPropertyArray src) { pcrProperty = src.pcrProperty; }

        /// <param name = "_pcrProperty"> A tagged PCR selection </param>
        public TaggedPcrPropertyArray(TaggedPcrSelect[] _pcrProperty) { pcrProperty = _pcrProperty; }

        public virtual Cap GetUnionSelector() { return Cap.PcrProperties; }

        new public TaggedPcrPropertyArray Copy() { return CreateCopy<TaggedPcrPropertyArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is used to report the ECC curve ID values supported by the TPM. It
    /// is returned by a TPM2_GetCapability(). </summary>
    [DataContract]
    [SpecTypeName("TPML_ECC_CURVE")]
    public partial class EccCurveArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> Array of ECC curve identifiers </summary>
        [Range(MaxVal = 508u /*MAX_ECC_CURVES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public EccCurve[] eccCurves;

        public EccCurveArray() {}

        public EccCurveArray(EccCurveArray src) { eccCurves = src.eccCurves; }

        /// <param name = "_eccCurves"> Array of ECC curve identifiers </param>
        public EccCurveArray(EccCurve[] _eccCurves) { eccCurves = _eccCurves; }

        public virtual Cap GetUnionSelector() { return Cap.EccCurves; }

        new public EccCurveArray Copy() { return CreateCopy<EccCurveArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is used to report the authorization policy values for permanent
    /// handles. This is list may be generated by TPM2_GetCapabiltiy(). A permanent handle
    /// that cannot have a policy is not included in the list. </summary>
    [DataContract]
    [SpecTypeName("TPML_TAGGED_POLICY")]
    public partial class TaggedPolicyArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> Array of tagged policies </summary>
        [Range(MaxVal = 14u /*MAX_TAGGED_POLICIES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public TaggedPolicy[] policies;

        public TaggedPolicyArray() {}

        public TaggedPolicyArray(TaggedPolicyArray src) { policies = src.policies; }

        /// <param name = "_policies"> Array of tagged policies </param>
        public TaggedPolicyArray(TaggedPolicy[] _policies) { policies = _policies; }

        public virtual Cap GetUnionSelector() { return Cap.AuthPolicies; }

        new public TaggedPolicyArray Copy() { return CreateCopy<TaggedPolicyArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is used to report the timeout and state for the ACT. This list may
    /// be generated by TPM2_GetCapabilty(). Only implemented ACT are present in the list </summary>
    [DataContract]
    [SpecTypeName("TPML_ACT_DATA")]
    public partial class ActDataArray: TpmStructureBase, ICapabilitiesUnion
    {
        /// <summary> Array of ACT data </summary>
        [Range(MaxVal = 84u /*MAX_ACT_DATA*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public ActData[] actData;

        public ActDataArray() {}

        public ActDataArray(ActDataArray src) { actData = src.actData; }

        /// <param name = "_actData"> Array of ACT data </param>
        public ActDataArray(ActData[] _actData) { actData = _actData; }

        public virtual Cap GetUnionSelector() { return Cap.Act; }

        new public ActDataArray Copy() { return CreateCopy<ActDataArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This data area is returned in response to a TPM2_GetCapability(). </summary>
    [DataContract]
    [KnownType(typeof(Cap))]
    [KnownType(typeof(ActDataArray))]
    [KnownType(typeof(AlgPropertyArray))]
    [KnownType(typeof(CcArray))]
    [KnownType(typeof(CcaArray))]
    [KnownType(typeof(EccCurveArray))]
    [KnownType(typeof(HandleArray))]
    [KnownType(typeof(PcrSelectionArray))]
    [KnownType(typeof(TaggedPcrPropertyArray))]
    [KnownType(typeof(TaggedPolicyArray))]
    [KnownType(typeof(TaggedTpmPropertyArray))]
    [SpecTypeName("TPMS_CAPABILITY_DATA")]
    public partial class CapabilityData: TpmStructureBase
    {
        /// <summary> The capability </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public Cap capability {
            get { return data.GetUnionSelector(); }
        }

        /// <summary> The capability data </summary>
        /// <remarks> One of: AlgPropertyArray, HandleArray, CcaArray, CcArray, PcrSelectionArray,
        /// TaggedTpmPropertyArray, TaggedPcrPropertyArray, EccCurveArray, TaggedPolicyArray,
        /// ActDataArray. </remarks>
        [MarshalAs(1, MarshalType.Union, "capability")]
        [DataMember()]
        public ICapabilitiesUnion data { get; set; }

        public CapabilityData() {}

        public CapabilityData(CapabilityData src) { data = src.data; }

        /// <param name = "_data"> The capability data
        ///        One of: AlgPropertyArray, HandleArray, CcaArray, CcArray, PcrSelectionArray,
        ///        TaggedTpmPropertyArray, TaggedPcrPropertyArray, EccCurveArray, TaggedPolicyArray,
        ///        ActDataArray. </param>
        public CapabilityData(ICapabilitiesUnion _data) { data = _data; }

        new public CapabilityData Copy() { return CreateCopy<CapabilityData>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used in each of the attestation commands. </summary>
    [DataContract]
    [SpecTypeName("TPMS_CLOCK_INFO")]
    public partial class ClockInfo: TpmStructureBase
    {
        /// <summary> Time value in milliseconds that advances while the TPM is powered
        /// NOTE The interpretation of the time-origin (clock=0) is out of the scope of this
        /// specification, although Coordinated Universal Time (UTC) is expected to be a common
        /// convention. This structure element is used to report on the TPM's Clock value.
        /// This value is reset to zero when the Storage Primary Seed is changed (TPM2_Clear()).
        /// This value may be advanced by TPM2_ClockSet(). </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ulong clock { get; set; }

        /// <summary> Number of occurrences of TPM Reset since the last TPM2_Clear() </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint resetCount { get; set; }

        /// <summary> Number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since
        /// the last TPM Reset or TPM2_Clear(). </summary>
        [MarshalAs(2)]
        [DataMember()]
        public uint restartCount { get; set; }

        /// <summary> No value of Clock greater than the current value of Clock has been
        /// previously reported by the TPM. Set to YES on TPM2_Clear(). </summary>
        [MarshalAs(3)]
        [DataMember()]
        public byte safe { get; set; }

        public ClockInfo() {}

        public ClockInfo(ClockInfo src)
        {
            clock = src.clock;
            resetCount = src.resetCount;
            restartCount = src.restartCount;
            safe = src.safe;
        }

        /// <param name = "_clock"> Time value in milliseconds that advances while the TPM is powered
        ///        NOTE The interpretation of the time-origin (clock=0) is out of the scope of this
        ///        specification, although Coordinated Universal Time (UTC) is expected to be a common
        ///        convention. This structure element is used to report on the TPM's Clock value.
        ///        This value is reset to zero when the Storage Primary Seed is changed (TPM2_Clear()).
        ///        This value may be advanced by TPM2_ClockSet(). </param>
        /// <param name = "_resetCount"> Number of occurrences of TPM Reset since the last
        ///        TPM2_Clear() </param>
        /// <param name = "_restartCount"> Number of times that TPM2_Shutdown() or _TPM_Hash_Start
        ///        have occurred since the last TPM Reset or TPM2_Clear(). </param>
        /// <param name = "_safe"> No value of Clock greater than the current value of Clock has been
        ///        previously reported by the TPM. Set to YES on TPM2_Clear(). </param>
        public ClockInfo(ulong _clock, uint _resetCount, uint _restartCount, byte _safe)
        {
            clock = _clock;
            resetCount = _resetCount;
            restartCount = _restartCount;
            safe = _safe;
        }

        new public ClockInfo Copy() { return CreateCopy<ClockInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used in, e.g., the TPM2_GetTime() attestation and
    /// TPM2_ReadClock(). </summary>
    [DataContract]
    [KnownType(typeof(ClockInfo))]
    [SpecTypeName("TPMS_TIME_INFO")]
    public partial class TimeInfo: TpmStructureBase
    {
        /// <summary> Time in milliseconds since the TIme circuit was last reset
        /// This structure element is used to report on the TPM's Time value. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ulong time { get; set; }

        /// <summary> A structure containing the clock information </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ClockInfo clockInfo { get; set; }

        public TimeInfo() {}

        public TimeInfo(TimeInfo src)
        {
            time = src.time;
            clockInfo = src.clockInfo;
        }

        /// <param name = "_time"> Time in milliseconds since the TIme circuit was last reset
        ///        This structure element is used to report on the TPM's Time value. </param>
        /// <param name = "_clockInfo"> A structure containing the clock information </param>
        public TimeInfo(ulong _time, ClockInfo _clockInfo)
        {
            time = _time;
            clockInfo = _clockInfo;
        }

        new public TimeInfo Copy() { return CreateCopy<TimeInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used when the TPM performs TPM2_GetTime. </summary>
    [DataContract]
    [KnownType(typeof(TimeInfo))]
    [SpecTypeName("TPMS_TIME_ATTEST_INFO")]
    public partial class TimeAttestInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary> The Time, Clock, resetCount, restartCount, and Safe indicator </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TimeInfo time { get; set; }

        /// <summary> A TPM vendor-specific value indicating the version number of the firmware </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ulong firmwareVersion { get; set; }

        public TimeAttestInfo() {}

        public TimeAttestInfo(TimeAttestInfo src)
        {
            time = src.time;
            firmwareVersion = src.firmwareVersion;
        }

        /// <param name = "_time"> The Time, Clock, resetCount, restartCount, and Safe indicator </param>
        /// <param name = "_firmwareVersion"> A TPM vendor-specific value indicating the version
        ///        number of the firmware </param>
        public TimeAttestInfo(TimeInfo _time, ulong _firmwareVersion)
        {
            time = _time;
            firmwareVersion = _firmwareVersion;
        }

        public virtual TpmSt GetUnionSelector() { return TpmSt.AttestTime; }

        new public TimeAttestInfo Copy() { return CreateCopy<TimeAttestInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is the attested data for TPM2_Certify(). </summary>
    [DataContract]
    [SpecTypeName("TPMS_CERTIFY_INFO")]
    public partial class CertifyInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary> Name of the certified object </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;

        /// <summary> Qualified Name of the certified object </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "qualifiedNameSize", 2)]
        [DataMember()]
        public byte[] qualifiedName;

        public CertifyInfo() {}

        public CertifyInfo(CertifyInfo src)
        {
            name = src.name;
            qualifiedName = src.qualifiedName;
        }

        /// <param name = "_name"> Name of the certified object </param>
        /// <param name = "_qualifiedName"> Qualified Name of the certified object </param>
        public CertifyInfo(byte[] _name, byte[] _qualifiedName)
        {
            name = _name;
            qualifiedName = _qualifiedName;
        }

        public virtual TpmSt GetUnionSelector() { return TpmSt.AttestCertify; }

        new public CertifyInfo Copy() { return CreateCopy<CertifyInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is the attested data for TPM2_Quote(). </summary>
    [DataContract]
    [SpecTypeName("TPMS_QUOTE_INFO")]
    public partial class QuoteInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary> Information on algID, PCR selected and digest </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "pcrSelectCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelect;

        /// <summary> Digest of the selected PCR using the hash of the signing key </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrDigestSize", 2)]
        [DataMember()]
        public byte[] pcrDigest;

        public QuoteInfo() {}

        public QuoteInfo(QuoteInfo src)
        {
            pcrSelect = src.pcrSelect;
            pcrDigest = src.pcrDigest;
        }

        /// <param name = "_pcrSelect"> Information on algID, PCR selected and digest </param>
        /// <param name = "_pcrDigest"> Digest of the selected PCR using the hash of the signing key </param>
        public QuoteInfo(PcrSelection[] _pcrSelect, byte[] _pcrDigest)
        {
            pcrSelect = _pcrSelect;
            pcrDigest = _pcrDigest;
        }

        public virtual TpmSt GetUnionSelector() { return TpmSt.AttestQuote; }

        new public QuoteInfo Copy() { return CreateCopy<QuoteInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is the attested data for TPM2_GetCommandAuditDigest(). </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_COMMAND_AUDIT_INFO")]
    public partial class CommandAuditInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary> The monotonic audit counter </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ulong auditCounter { get; set; }

        /// <summary> Hash algorithm used for the command audit </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId digestAlg { get; set; }

        /// <summary> The current value of the audit digest </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "auditDigestSize", 2)]
        [DataMember()]
        public byte[] auditDigest;

        /// <summary> Digest of the command codes being audited using digestAlg </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "commandDigestSize", 2)]
        [DataMember()]
        public byte[] commandDigest;

        public CommandAuditInfo() { digestAlg = TpmAlgId.Null; }

        public CommandAuditInfo(CommandAuditInfo src)
        {
            auditCounter = src.auditCounter;
            digestAlg = src.digestAlg;
            auditDigest = src.auditDigest;
            commandDigest = src.commandDigest;
        }

        /// <param name = "_auditCounter"> The monotonic audit counter </param>
        /// <param name = "_digestAlg"> Hash algorithm used for the command audit </param>
        /// <param name = "_auditDigest"> The current value of the audit digest </param>
        /// <param name = "_commandDigest"> Digest of the command codes being audited using digestAlg </param>
        public CommandAuditInfo(ulong _auditCounter, TpmAlgId _digestAlg, byte[] _auditDigest, byte[] _commandDigest)
        {
            auditCounter = _auditCounter;
            digestAlg = _digestAlg;
            auditDigest = _auditDigest;
            commandDigest = _commandDigest;
        }

        public virtual TpmSt GetUnionSelector() { return TpmSt.AttestCommandAudit; }

        new public CommandAuditInfo Copy() { return CreateCopy<CommandAuditInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is the attested data for TPM2_GetSessionAuditDigest(). </summary>
    [DataContract]
    [SpecTypeName("TPMS_SESSION_AUDIT_INFO")]
    public partial class SessionAuditInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary> Current exclusive status of the session
        /// TRUE if all of the commands recorded in the sessionDigest were executed without any
        /// intervening TPM command that did not use this audit session </summary>
        [MarshalAs(0)]
        [DataMember()]
        public byte exclusiveSession { get; set; }

        /// <summary> The current value of the session audit digest </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "sessionDigestSize", 2)]
        [DataMember()]
        public byte[] sessionDigest;

        public SessionAuditInfo() {}

        public SessionAuditInfo(SessionAuditInfo src)
        {
            exclusiveSession = src.exclusiveSession;
            sessionDigest = src.sessionDigest;
        }

        /// <param name = "_exclusiveSession"> Current exclusive status of the session
        ///        TRUE if all of the commands recorded in the sessionDigest were executed without any
        ///        intervening TPM command that did not use this audit session </param>
        /// <param name = "_sessionDigest"> The current value of the session audit digest </param>
        public SessionAuditInfo(byte _exclusiveSession, byte[] _sessionDigest)
        {
            exclusiveSession = _exclusiveSession;
            sessionDigest = _sessionDigest;
        }

        public virtual TpmSt GetUnionSelector() { return TpmSt.AttestSessionAudit; }

        new public SessionAuditInfo Copy() { return CreateCopy<SessionAuditInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is the attested data for TPM2_CertifyCreation(). </summary>
    [DataContract]
    [SpecTypeName("TPMS_CREATION_INFO")]
    public partial class CreationInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary> Name of the object </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "objectNameSize", 2)]
        [DataMember()]
        public byte[] objectName;

        /// <summary> CreationHash </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "creationHashSize", 2)]
        [DataMember()]
        public byte[] creationHash;

        public CreationInfo() {}

        public CreationInfo(CreationInfo src)
        {
            objectName = src.objectName;
            creationHash = src.creationHash;
        }

        /// <param name = "_objectName"> Name of the object </param>
        /// <param name = "_creationHash"> CreationHash </param>
        public CreationInfo(byte[] _objectName, byte[] _creationHash)
        {
            objectName = _objectName;
            creationHash = _creationHash;
        }

        public virtual TpmSt GetUnionSelector() { return TpmSt.AttestCreation; }

        new public CreationInfo Copy() { return CreateCopy<CreationInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure contains the Name and contents of the selected NV Index that
    /// is certified by TPM2_NV_Certify(). </summary>
    [DataContract]
    [SpecTypeName("TPMS_NV_CERTIFY_INFO")]
    public partial class NvCertifyInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary> Name of the NV Index </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "indexNameSize", 2)]
        [DataMember()]
        public byte[] indexName;

        /// <summary> The offset parameter of TPM2_NV_Certify() </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort offset { get; set; }

        /// <summary> Contents of the NV Index </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "nvContentsSize", 2)]
        [DataMember()]
        public byte[] nvContents;

        public NvCertifyInfo() {}

        public NvCertifyInfo(NvCertifyInfo src)
        {
            indexName = src.indexName;
            offset = src.offset;
            nvContents = src.nvContents;
        }

        /// <param name = "_indexName"> Name of the NV Index </param>
        /// <param name = "_offset"> The offset parameter of TPM2_NV_Certify() </param>
        /// <param name = "_nvContents"> Contents of the NV Index </param>
        public NvCertifyInfo(byte[] _indexName, ushort _offset, byte[] _nvContents)
        {
            indexName = _indexName;
            offset = _offset;
            nvContents = _nvContents;
        }

        public virtual TpmSt GetUnionSelector() { return TpmSt.AttestNv; }

        new public NvCertifyInfo Copy() { return CreateCopy<NvCertifyInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure contains the Name and hash of the contents of the selected NV
    /// Index that is certified by TPM2_NV_Certify(). The data is hashed using hash of the
    /// signing scheme. </summary>
    [DataContract]
    [SpecTypeName("TPMS_NV_DIGEST_CERTIFY_INFO")]
    public partial class NvDigestCertifyInfo: TpmStructureBase, IAttestUnion
    {
        /// <summary> Name of the NV Index </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "indexNameSize", 2)]
        [DataMember()]
        public byte[] indexName;

        /// <summary> Hash of the contents of the index </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nvDigestSize", 2)]
        [DataMember()]
        public byte[] nvDigest;

        public NvDigestCertifyInfo() {}

        public NvDigestCertifyInfo(NvDigestCertifyInfo src)
        {
            indexName = src.indexName;
            nvDigest = src.nvDigest;
        }

        /// <param name = "_indexName"> Name of the NV Index </param>
        /// <param name = "_nvDigest"> Hash of the contents of the index </param>
        public NvDigestCertifyInfo(byte[] _indexName, byte[] _nvDigest)
        {
            indexName = _indexName;
            nvDigest = _nvDigest;
        }

        public virtual TpmSt GetUnionSelector() { return TpmSt.AttestNvDigest; }

        new public NvDigestCertifyInfo Copy() { return CreateCopy<NvDigestCertifyInfo>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used on each TPM-generated signed structure. The signature
    /// is over this structure. </summary>
    [DataContract]
    [KnownType(typeof(Generated))]
    [KnownType(typeof(TpmSt))]
    [KnownType(typeof(CertifyInfo))]
    [KnownType(typeof(ClockInfo))]
    [KnownType(typeof(CommandAuditInfo))]
    [KnownType(typeof(CreationInfo))]
    [KnownType(typeof(NvCertifyInfo))]
    [KnownType(typeof(NvDigestCertifyInfo))]
    [KnownType(typeof(QuoteInfo))]
    [KnownType(typeof(SessionAuditInfo))]
    [KnownType(typeof(TimeAttestInfo))]
    [SpecTypeName("TPMS_ATTEST")]
    public partial class Attest: TpmStructureBase
    {
        /// <summary> The indication that this structure was created by a TPM (always
        /// TPM_GENERATED_VALUE) </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Generated magic { get; set; }

        /// <summary> Type of the attestation structure </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmSt type {
            get { return attested.GetUnionSelector(); }
        }

        /// <summary> Qualified Name of the signing key </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifiedSignerSize", 2)]
        [DataMember()]
        public byte[] qualifiedSigner;

        /// <summary> External information supplied by caller
        /// NOTE A TPM2B_DATA structure provides room for a digest and a method indicator to
        /// indicate the components of the digest. The definition of this method indicator is
        /// outside the scope of this specification. </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "extraDataSize", 2)]
        [DataMember()]
        public byte[] extraData;

        /// <summary> Clock, resetCount, restartCount, and Safe </summary>
        [MarshalAs(4)]
        [DataMember()]
        public ClockInfo clockInfo { get; set; }

        /// <summary> TPM-vendor-specific value identifying the version number of the firmware </summary>
        [MarshalAs(5)]
        [DataMember()]
        public ulong firmwareVersion { get; set; }

        /// <summary> The type-specific attestation information </summary>
        /// <remarks> One of: CertifyInfo, CreationInfo, QuoteInfo, CommandAuditInfo,
        /// SessionAuditInfo, TimeAttestInfo, NvCertifyInfo, NvDigestCertifyInfo. </remarks>
        [MarshalAs(6, MarshalType.Union, "type")]
        [DataMember()]
        public IAttestUnion attested { get; set; }

        public Attest() {}

        public Attest(Attest src)
        {
            magic = src.magic;
            qualifiedSigner = src.qualifiedSigner;
            extraData = src.extraData;
            clockInfo = src.clockInfo;
            firmwareVersion = src.firmwareVersion;
            attested = src.attested;
        }

        /// <param name = "_magic"> The indication that this structure was created by a TPM (always
        ///        TPM_GENERATED_VALUE) </param>
        /// <param name = "_qualifiedSigner"> Qualified Name of the signing key </param>
        /// <param name = "_extraData"> External information supplied by caller
        ///        NOTE A TPM2B_DATA structure provides room for a digest and a method indicator to
        ///        indicate the components of the digest. The definition of this method indicator is
        ///        outside the scope of this specification. </param>
        /// <param name = "_clockInfo"> Clock, resetCount, restartCount, and Safe </param>
        /// <param name = "_firmwareVersion"> TPM-vendor-specific value identifying the version number
        ///        of the firmware </param>
        /// <param name = "_attested"> The type-specific attestation information
        ///        One of: CertifyInfo, CreationInfo, QuoteInfo, CommandAuditInfo, SessionAuditInfo,
        ///        TimeAttestInfo, NvCertifyInfo, NvDigestCertifyInfo. </param>
        public Attest(Generated _magic, byte[] _qualifiedSigner, byte[] _extraData, ClockInfo _clockInfo, ulong _firmwareVersion, IAttestUnion _attested)
        {
            magic = _magic;
            qualifiedSigner = _qualifiedSigner;
            extraData = _extraData;
            clockInfo = _clockInfo;
            firmwareVersion = _firmwareVersion;
            attested = _attested;
        }

        new public Attest Copy() { return CreateCopy<Attest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This sized buffer to contain the signed structure. The attestationData is
    /// the signed portion of the structure. The size parameter is not signed. </summary>
    [DataContract]
    [KnownType(typeof(Attest))]
    [SpecTypeName("TPM2B_ATTEST")]
    public partial class Tpm2bAttest: TpmStructureBase
    {
        /// <summary> The signed structure </summary>
        [Range(MaxVal = 68u /*sizeof(TPMS_ATTEST)*/)]
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public Attest attestationData { get; set; }

        public Tpm2bAttest() {}

        public Tpm2bAttest(Tpm2bAttest src) { attestationData = src.attestationData; }

        /// <param name = "_attestationData"> The signed structure </param>
        public Tpm2bAttest(Attest _attestationData) { attestationData = _attestationData; }

        new public Tpm2bAttest Copy() { return CreateCopy<Tpm2bAttest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is the format used for each of the authorizations in the session area
    /// of a command. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SessionAttr))]
    [SpecTypeName("TPMS_AUTH_COMMAND")]
    public partial class AuthCommand: TpmStructureBase
    {
        /// <summary> The session handle </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sessionHandle { get; set; }

        /// <summary> The session nonce, may be the Empty Buffer </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nonceSize", 2)]
        [DataMember()]
        public byte[] nonce;

        /// <summary> The session attributes </summary>
        [MarshalAs(2)]
        [DataMember()]
        public SessionAttr sessionAttributes { get; set; }

        /// <summary> Either an HMAC, a password, or an EmptyAuth </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "hmacSize", 2)]
        [DataMember()]
        public byte[] hmac;

        public AuthCommand() { sessionHandle = new TpmHandle(); }

        public AuthCommand(AuthCommand src)
        {
            sessionHandle = src.sessionHandle;
            nonce = src.nonce;
            sessionAttributes = src.sessionAttributes;
            hmac = src.hmac;
        }

        /// <param name = "_sessionHandle"> The session handle </param>
        /// <param name = "_nonce"> The session nonce, may be the Empty Buffer </param>
        /// <param name = "_sessionAttributes"> The session attributes </param>
        /// <param name = "_hmac"> Either an HMAC, a password, or an EmptyAuth </param>
        public AuthCommand(TpmHandle _sessionHandle, byte[] _nonce, SessionAttr _sessionAttributes, byte[] _hmac)
        {
            sessionHandle = _sessionHandle;
            nonce = _nonce;
            sessionAttributes = _sessionAttributes;
            hmac = _hmac;
        }

        new public AuthCommand Copy() { return CreateCopy<AuthCommand>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is the format for each of the authorizations in the session area of the
    /// response. If the TPM returns TPM_RC_SUCCESS, then the session area of the response
    /// contains the same number of authorizations as the command and the authorizations are
    /// in the same order. </summary>
    [DataContract]
    [KnownType(typeof(SessionAttr))]
    [SpecTypeName("TPMS_AUTH_RESPONSE")]
    public partial class AuthResponse: TpmStructureBase
    {
        /// <summary> The session nonce, may be the Empty Buffer </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "nonceSize", 2)]
        [DataMember()]
        public byte[] nonce;

        /// <summary> The session attributes </summary>
        [MarshalAs(1)]
        [DataMember()]
        public SessionAttr sessionAttributes { get; set; }

        /// <summary> Either an HMAC or an EmptyAuth </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "hmacSize", 2)]
        [DataMember()]
        public byte[] hmac;

        public AuthResponse() {}

        public AuthResponse(AuthResponse src)
        {
            nonce = src.nonce;
            sessionAttributes = src.sessionAttributes;
            hmac = src.hmac;
        }

        /// <param name = "_nonce"> The session nonce, may be the Empty Buffer </param>
        /// <param name = "_sessionAttributes"> The session attributes </param>
        /// <param name = "_hmac"> Either an HMAC or an EmptyAuth </param>
        public AuthResponse(byte[] _nonce, SessionAttr _sessionAttributes, byte[] _hmac)
        {
            nonce = _nonce;
            sessionAttributes = _sessionAttributes;
            hmac = _hmac;
        }

        new public AuthResponse Copy() { return CreateCopy<AuthResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_TDES for the union TPMU_SYM_DETAILS
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_TDES_SYM_DETAILS")]
    public partial class TdesSymDetails: NullUnion
    {
        public TdesSymDetails() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Tdes; }

        new public TdesSymDetails Copy() { return CreateCopy<TdesSymDetails>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_AES for the union TPMU_SYM_DETAILS </summary>
    [DataContract]
    [SpecTypeName("TPMS_AES_SYM_DETAILS")]
    public partial class AesSymDetails: NullUnion
    {
        public AesSymDetails() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Aes; }

        new public AesSymDetails Copy() { return CreateCopy<AesSymDetails>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_SM4 for the union TPMU_SYM_DETAILS </summary>
    [DataContract]
    [SpecTypeName("TPMS_SM4_SYM_DETAILS")]
    public partial class Sm4SymDetails: NullUnion
    {
        public Sm4SymDetails() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Sm4; }

        new public Sm4SymDetails Copy() { return CreateCopy<Sm4SymDetails>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_CAMELLIA for the union
    /// TPMU_SYM_DETAILS </summary>
    [DataContract]
    [SpecTypeName("TPMS_CAMELLIA_SYM_DETAILS")]
    public partial class CamelliaSymDetails: NullUnion
    {
        public CamelliaSymDetails() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Camellia; }

        new public CamelliaSymDetails Copy() { return CreateCopy<CamelliaSymDetails>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_ANY for the union TPMU_SYM_DETAILS </summary>
    [DataContract]
    [SpecTypeName("TPMS_ANY_SYM_DETAILS")]
    public partial class AnySymDetails: NullUnion
    {
        public AnySymDetails() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Any; }

        new public AnySymDetails Copy() { return CreateCopy<AnySymDetails>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_XOR for the union TPMU_SYM_DETAILS </summary>
    [DataContract]
    [SpecTypeName("TPMS_XOR_SYM_DETAILS")]
    public partial class XorSymDetails: NullUnion
    {
        public XorSymDetails() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Xor; }

        new public XorSymDetails Copy() { return CreateCopy<XorSymDetails>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TPMU_SYM_DETAILS
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SYM_DETAILS")]
    public partial class NullSymDetails: NullUnion
    {
        public NullSymDetails() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Null; }

        new public NullSymDetails Copy() { return CreateCopy<NullSymDetails>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The TPMT_SYM_DEF structure is used to select an algorithm to be used for
    /// parameter encryption in those cases when different symmetric algorithms may be
    /// selected. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMT_SYM_DEF")]
    public partial class SymDef: TpmStructureBase
    {
        /// <summary> Indicates a symmetric algorithm </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId Algorithm { get; set; }

        /// <summary> A supported key size </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort KeyBits { get; set; }

        /// <summary> The mode for the key </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId Mode { get; set; }

        public SymDef()
        {
            Algorithm = TpmAlgId.Null;
            Mode = TpmAlgId.Null;
        }

        public SymDef(SymDef src)
        {
            Algorithm = src.Algorithm;
            KeyBits = src.KeyBits;
            Mode = src.Mode;
        }

        /// <param name = "_Algorithm"> Indicates a symmetric algorithm </param>
        /// <param name = "_KeyBits"> A supported key size </param>
        /// <param name = "_Mode"> The mode for the key </param>
        public SymDef(TpmAlgId _Algorithm, ushort _KeyBits, TpmAlgId _Mode)
        {
            Algorithm = _Algorithm;
            KeyBits = _KeyBits;
            Mode = _Mode;
        }

        new public SymDef Copy() { return CreateCopy<SymDef>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used when different symmetric block cipher (not XOR)
    /// algorithms may be selected. If the Object can be an ordinary parent (not a derivation
    /// parent), this must be the first field in the Object's parameter (see 12.2.3.7) field. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMT_SYM_DEF_OBJECT")]
    public partial class SymDefObject: TpmStructureBase
    {
        /// <summary> Selects a symmetric block cipher
        /// When used in the parameter area of a parent object, this shall be a supported block
        /// cipher and not TPM_ALG_NULL </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId Algorithm { get; set; }

        /// <summary> The key size </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort KeyBits { get; set; }

        /// <summary> Default mode
        /// When used in the parameter area of a parent object, this shall be TPM_ALG_CFB. </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId Mode { get; set; }

        public SymDefObject()
        {
            Algorithm = TpmAlgId.Null;
            Mode = TpmAlgId.Null;
        }

        public SymDefObject(SymDefObject src)
        {
            Algorithm = src.Algorithm;
            KeyBits = src.KeyBits;
            Mode = src.Mode;
        }

        /// <param name = "_Algorithm"> Selects a symmetric block cipher
        ///        When used in the parameter area of a parent object, this shall be a supported block
        ///        cipher and not TPM_ALG_NULL </param>
        /// <param name = "_KeyBits"> The key size </param>
        /// <param name = "_Mode"> Default mode
        ///        When used in the parameter area of a parent object, this shall be TPM_ALG_CFB. </param>
        public SymDefObject(TpmAlgId _Algorithm, ushort _KeyBits, TpmAlgId _Mode)
        {
            Algorithm = _Algorithm;
            KeyBits = _KeyBits;
            Mode = _Mode;
        }

        new public SymDefObject Copy() { return CreateCopy<SymDefObject>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used to hold a symmetric key in the sensitive area of an
    /// asymmetric object. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_SYM_KEY")]
    public partial class Tpm2bSymKey: TpmStructureBase, ISensitiveCompositeUnion
    {
        /// <summary> The key </summary>
        [Range(MaxVal = 32u /*MAX_SYM_KEY_BYTES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bSymKey() {}

        public Tpm2bSymKey(Tpm2bSymKey src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The key </param>
        public Tpm2bSymKey(byte[] _buffer) { buffer = _buffer; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Symcipher; }

        new public Tpm2bSymKey Copy() { return CreateCopy<Tpm2bSymKey>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure contains the parameters for a symmetric block cipher object. </summary>
    [DataContract]
    [KnownType(typeof(SymDefObject))]
    [SpecTypeName("TPMS_SYMCIPHER_PARMS")]
    public partial class SymcipherParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary> A symmetric block cipher </summary>
        [MarshalAs(0)]
        [DataMember()]
        public SymDefObject sym { get; set; }

        public SymcipherParms() {}

        public SymcipherParms(SymcipherParms src) { sym = src.sym; }

        /// <param name = "_sym"> A symmetric block cipher </param>
        public SymcipherParms(SymDefObject _sym) { sym = _sym; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Symcipher; }

        new public SymcipherParms Copy() { return CreateCopy<SymcipherParms>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This buffer holds a label or context value. For interoperability and
    /// backwards compatibility, LABEL_MAX_BUFFER is the minimum of the largest digest on the
    /// device and the largest ECC parameter (MAX_ECC_KEY_BYTES) but no more than 32 bytes. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_LABEL")]
    public partial class Tpm2bLabel: TpmStructureBase
    {
        /// <summary> Symmetric data for a created object or the label and context for a derived
        /// object </summary>
        [Range(MaxVal = 32u /*LABEL_MAX_BUFFER*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bLabel() {}

        public Tpm2bLabel(Tpm2bLabel src) { buffer = src.buffer; }

        /// <param name = "_buffer"> Symmetric data for a created object or the label and context for
        ///        a derived object </param>
        public Tpm2bLabel(byte[] _buffer) { buffer = _buffer; }

        new public Tpm2bLabel Copy() { return CreateCopy<Tpm2bLabel>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure contains the label and context fields for a derived object.
    /// These values are used in the derivation KDF. The values in the unique field of
    /// inPublic area template take precedence over the values in the inSensitive parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_DERIVE")]
    public partial class TpmDerive: TpmStructureBase, ISensitiveCreateUnion, IPublicIdUnion
    {
        [MarshalAs(0, MarshalType.VariableLengthArray, "labelSize", 2)]
        [DataMember()]
        public byte[] label;

        [MarshalAs(1, MarshalType.VariableLengthArray, "contextSize", 2)]
        [DataMember()]
        public byte[] context;

        public TpmDerive() {}

        public TpmDerive(TpmDerive src)
        {
            label = src.label;
            context = src.context;
        }

        /// <param name = "_label"> TBD </param>
        /// <param name = "_context"> TBD </param>
        public TpmDerive(byte[] _label, byte[] _context)
        {
            label = _label;
            context = _context;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Any2; }

        new public TpmDerive Copy() { return CreateCopy<TpmDerive>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 147 Definition of TPM2B_DERIVE Structure </summary>
    [DataContract]
    [KnownType(typeof(TpmDerive))]
    [SpecTypeName("TPM2B_DERIVE")]
    public partial class Tpm2bDerive: TpmStructureBase
    {
        /// <summary> Symmetric data for a created object or the label and context for a derived
        /// object </summary>
        [Range(MaxVal = 4u /*sizeof(TPMS_DERIVE)*/)]
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public TpmDerive buffer { get; set; }

        public Tpm2bDerive() {}

        public Tpm2bDerive(Tpm2bDerive src) { buffer = src.buffer; }

        /// <param name = "_buffer"> Symmetric data for a created object or the label and context for
        ///        a derived object </param>
        public Tpm2bDerive(TpmDerive _buffer) { buffer = _buffer; }

        new public Tpm2bDerive Copy() { return CreateCopy<Tpm2bDerive>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This buffer wraps the TPMU_SENSITIVE_CREATE structure. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_SENSITIVE_DATA")]
    public partial class Tpm2bSensitiveData: TpmStructureBase, ISensitiveCompositeUnion
    {
        /// <summary> Symmetric data for a created object or the label and context for a derived
        /// object </summary>
        [Range(MaxVal = 128u /*sizeof(TPMU_SENSITIVE_CREATE)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bSensitiveData() {}

        public Tpm2bSensitiveData(Tpm2bSensitiveData src) { buffer = src.buffer; }

        /// <param name = "_buffer"> Symmetric data for a created object or the label and context for
        ///        a derived object </param>
        public Tpm2bSensitiveData(byte[] _buffer) { buffer = _buffer; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Keyedhash; }

        new public Tpm2bSensitiveData Copy() { return CreateCopy<Tpm2bSensitiveData>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure defines the values to be placed in the sensitive area of a
    /// created object. This structure is only used within a TPM2B_SENSITIVE_CREATE structure.
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_SENSITIVE_CREATE")]
    public partial class SensitiveCreate: TpmStructureBase
    {
        /// <summary> The USER auth secret value </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "userAuthSize", 2)]
        [DataMember()]
        public byte[] userAuth;

        /// <summary> Data to be sealed, a key, or derivation values </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;

        public SensitiveCreate() {}

        public SensitiveCreate(SensitiveCreate src)
        {
            userAuth = src.userAuth;
            data = src.data;
        }

        /// <param name = "_userAuth"> The USER auth secret value </param>
        /// <param name = "_data"> Data to be sealed, a key, or derivation values </param>
        public SensitiveCreate(byte[] _userAuth, byte[] _data)
        {
            userAuth = _userAuth;
            data = _data;
        }

        new public SensitiveCreate Copy() { return CreateCopy<SensitiveCreate>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure contains the sensitive creation data in a sized buffer. This
    /// structure is defined so that both the userAuth and data values of the
    /// TPMS_SENSITIVE_CREATE may be passed as a single parameter for parameter encryption
    /// purposes. </summary>
    [DataContract]
    [KnownType(typeof(SensitiveCreate))]
    [SpecTypeName("TPM2B_SENSITIVE_CREATE")]
    public partial class Tpm2bSensitiveCreate: TpmStructureBase
    {
        /// <summary> Data to be sealed or a symmetric key value. </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public SensitiveCreate sensitive { get; set; }

        public Tpm2bSensitiveCreate() {}

        public Tpm2bSensitiveCreate(Tpm2bSensitiveCreate src) { sensitive = src.sensitive; }

        /// <param name = "_sensitive"> Data to be sealed or a symmetric key value. </param>
        public Tpm2bSensitiveCreate(SensitiveCreate _sensitive) { sensitive = _sensitive; }

        new public Tpm2bSensitiveCreate Copy() { return CreateCopy<Tpm2bSensitiveCreate>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is the scheme data for schemes that only require a hash to
    /// complete their definition. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SCHEME_HASH")]
    public partial class SchemeHash: TpmStructureBase, ISchemeKeyedhashUnion, ISigSchemeUnion, IKdfSchemeUnion, IAsymSchemeUnion, ISignatureUnion
    {
        /// <summary> The hash algorithm used to digest the message </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        public SchemeHash() { hashAlg = TpmAlgId.Null; }

        public SchemeHash(SchemeHash src) { hashAlg = src.hashAlg; }

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeHash(TpmAlgId _hashAlg) { hashAlg = _hashAlg; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Hmac; }

        new public SchemeHash Copy() { return CreateCopy<SchemeHash>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This definition is for split signing schemes that require a commit count. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SCHEME_ECDAA")]
    public partial class SchemeEcdaa: TpmStructureBase, ISigSchemeUnion, IAsymSchemeUnion
    {
        /// <summary> The hash algorithm used to digest the message </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        /// <summary> The counter value that is used between TPM2_Commit() and the sign operation </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort count { get; set; }

        public SchemeEcdaa() { hashAlg = TpmAlgId.Null; }

        public SchemeEcdaa(SchemeEcdaa src)
        {
            hashAlg = src.hashAlg;
            count = src.count;
        }

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        /// <param name = "_count"> The counter value that is used between TPM2_Commit() and the sign
        ///        operation </param>
        public SchemeEcdaa(TpmAlgId _hashAlg, ushort _count)
        {
            hashAlg = _hashAlg;
            count = _count;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Ecdaa; }

        new public SchemeEcdaa Copy() { return CreateCopy<SchemeEcdaa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 155 Definition of Types for HMAC_SIG_SCHEME </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_HMAC")]
    public partial class SchemeHmac: SchemeHash
    {
        public SchemeHmac() {}

        public SchemeHmac(SchemeHmac _SchemeHmac) : base(_SchemeHmac) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeHmac(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Hmac; }

        new public SchemeHmac Copy() { return CreateCopy<SchemeHmac>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is for the XOR encryption scheme. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SCHEME_XOR")]
    public partial class SchemeXor: TpmStructureBase, ISchemeKeyedhashUnion
    {
        /// <summary> The hash algorithm used to digest the message </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        /// <summary> The key derivation function </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId kdf { get; set; }

        public SchemeXor()
        {
            hashAlg = TpmAlgId.Null;
            kdf = TpmAlgId.Null;
        }

        public SchemeXor(SchemeXor src)
        {
            hashAlg = src.hashAlg;
            kdf = src.kdf;
        }

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        /// <param name = "_kdf"> The key derivation function </param>
        public SchemeXor(TpmAlgId _hashAlg, TpmAlgId _kdf)
        {
            hashAlg = _hashAlg;
            kdf = _kdf;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Xor; }

        new public SchemeXor Copy() { return CreateCopy<SchemeXor>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union
    /// TPMU_SCHEME_KEYEDHASH </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SCHEME_KEYEDHASH")]
    public partial class NullSchemeKeyedhash: NullUnion
    {
        public NullSchemeKeyedhash() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Null; }

        new public NullSchemeKeyedhash Copy() { return CreateCopy<NullSchemeKeyedhash>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used for a hash signing object. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullSchemeKeyedhash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SchemeXor))]
    [SpecTypeName("TPMT_KEYEDHASH_SCHEME")]
    public partial class KeyedhashScheme: TpmStructureBase
    {
        /// <summary> Selects the scheme </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get { return details != null ? details.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The scheme parameters </summary>
        /// <remarks> One of: SchemeHmac, SchemeXor, NullSchemeKeyedhash. </remarks>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public ISchemeKeyedhashUnion details { get; set; }

        public KeyedhashScheme() {}

        public KeyedhashScheme(KeyedhashScheme src) { details = src.details; }

        /// <param name = "_details"> The scheme parameters
        ///        One of: SchemeHmac, SchemeXor, NullSchemeKeyedhash. </param>
        public KeyedhashScheme(ISchemeKeyedhashUnion _details) { details = _details; }

        new public KeyedhashScheme Copy() { return CreateCopy<KeyedhashScheme>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the RSA schemes that only need a hash algorithm as a scheme
    /// parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_RSASSA")]
    public partial class SigSchemeRsassa: SchemeHash
    {
        public SigSchemeRsassa() {}

        public SigSchemeRsassa(SigSchemeRsassa _SigSchemeRsassa) : base(_SigSchemeRsassa) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SigSchemeRsassa(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Rsassa; }

        new public SigSchemeRsassa Copy() { return CreateCopy<SigSchemeRsassa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the RSA schemes that only need a hash algorithm as a scheme
    /// parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_RSAPSS")]
    public partial class SigSchemeRsapss: SchemeHash
    {
        public SigSchemeRsapss() {}

        public SigSchemeRsapss(SigSchemeRsapss _SigSchemeRsapss) : base(_SigSchemeRsapss) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SigSchemeRsapss(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Rsapss; }

        new public SigSchemeRsapss Copy() { return CreateCopy<SigSchemeRsapss>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Most of the ECC signature schemes only require a hash algorithm to complete
    /// the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require
    /// a count value so they are typed to be TPMS_SCHEME_ECDAA. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_ECDSA")]
    public partial class SigSchemeEcdsa: SchemeHash
    {
        public SigSchemeEcdsa() {}

        public SigSchemeEcdsa(SigSchemeEcdsa _SigSchemeEcdsa) : base(_SigSchemeEcdsa) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SigSchemeEcdsa(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Ecdsa; }

        new public SigSchemeEcdsa Copy() { return CreateCopy<SigSchemeEcdsa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Most of the ECC signature schemes only require a hash algorithm to complete
    /// the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require
    /// a count value so they are typed to be TPMS_SCHEME_ECDAA. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_SM2")]
    public partial class SigSchemeSm2: SchemeHash
    {
        public SigSchemeSm2() {}

        public SigSchemeSm2(SigSchemeSm2 _SigSchemeSm2) : base(_SigSchemeSm2) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SigSchemeSm2(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Sm2; }

        new public SigSchemeSm2 Copy() { return CreateCopy<SigSchemeSm2>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Most of the ECC signature schemes only require a hash algorithm to complete
    /// the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require
    /// a count value so they are typed to be TPMS_SCHEME_ECDAA. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_ECSCHNORR")]
    public partial class SigSchemeEcschnorr: SchemeHash
    {
        public SigSchemeEcschnorr() {}

        public SigSchemeEcschnorr(SigSchemeEcschnorr _SigSchemeEcschnorr) : base(_SigSchemeEcschnorr) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SigSchemeEcschnorr(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Ecschnorr; }

        new public SigSchemeEcschnorr Copy() { return CreateCopy<SigSchemeEcschnorr>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Most of the ECC signature schemes only require a hash algorithm to complete
    /// the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require
    /// a count value so they are typed to be TPMS_SCHEME_ECDAA. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIG_SCHEME_ECDAA")]
    public partial class SigSchemeEcdaa: SchemeEcdaa
    {
        public SigSchemeEcdaa() {}

        public SigSchemeEcdaa(SigSchemeEcdaa _SigSchemeEcdaa) : base(_SigSchemeEcdaa) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        /// <param name = "_count"> The counter value that is used between TPM2_Commit() and the sign
        ///        operation </param>
        public SigSchemeEcdaa(TpmAlgId _hashAlg, ushort _count)
            : base(_hashAlg, _count)
        {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Ecdaa; }

        new public SigSchemeEcdaa Copy() { return CreateCopy<SigSchemeEcdaa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TPMU_SIG_SCHEME </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SIG_SCHEME")]
    public partial class NullSigScheme: NullUnion
    {
        public NullSigScheme() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Null; }

        new public NullSigScheme Copy() { return CreateCopy<NullSigScheme>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 162 Definition of TPMT_SIG_SCHEME Structure </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("TPMT_SIG_SCHEME")]
    public partial class SigScheme: TpmStructureBase
    {
        /// <summary> Scheme selector </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get { return details != null ? details.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Scheme parameters </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public ISigSchemeUnion details { get; set; }

        public SigScheme() {}

        public SigScheme(SigScheme src) { details = src.details; }

        /// <param name = "_details"> Scheme parameters
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        public SigScheme(ISigSchemeUnion _details) { details = _details; }

        new public SigScheme Copy() { return CreateCopy<SigScheme>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the RSA encryption schemes that only need a hash algorithm as a
    /// controlling parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_ENC_SCHEME_OAEP")]
    public partial class EncSchemeOaep: SchemeHash
    {
        public EncSchemeOaep() {}

        public EncSchemeOaep(EncSchemeOaep _EncSchemeOaep) : base(_EncSchemeOaep) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public EncSchemeOaep(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Oaep; }

        new public EncSchemeOaep Copy() { return CreateCopy<EncSchemeOaep>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the RSA encryption schemes that only need a hash algorithm as a
    /// controlling parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_ENC_SCHEME_RSAES")]
    public partial class EncSchemeRsaes: Empty
    {
        public EncSchemeRsaes() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Rsaes; }

        new public EncSchemeRsaes Copy() { return CreateCopy<EncSchemeRsaes>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the ECC schemes that only need a hash algorithm as a controlling
    /// parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_KEY_SCHEME_ECDH")]
    public partial class KeySchemeEcdh: SchemeHash
    {
        public KeySchemeEcdh() {}

        public KeySchemeEcdh(KeySchemeEcdh _KeySchemeEcdh) : base(_KeySchemeEcdh) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public KeySchemeEcdh(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Ecdh; }

        new public KeySchemeEcdh Copy() { return CreateCopy<KeySchemeEcdh>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the ECC schemes that only need a hash algorithm as a controlling
    /// parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_KEY_SCHEME_ECMQV")]
    public partial class KeySchemeEcmqv: SchemeHash
    {
        public KeySchemeEcmqv() {}

        public KeySchemeEcmqv(KeySchemeEcmqv _KeySchemeEcmqv) : base(_KeySchemeEcmqv) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public KeySchemeEcmqv(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Ecmqv; }

        new public KeySchemeEcmqv Copy() { return CreateCopy<KeySchemeEcmqv>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These structures are used to define the key derivation for symmetric secret
    /// sharing using asymmetric methods. A secret sharing scheme is required in any
    /// asymmetric key with the decrypt attribute SET. </summary>
    [DataContract]
    [SpecTypeName("TPMS_KDF_SCHEME_MGF1")]
    public partial class KdfSchemeMgf1: SchemeHash
    {
        public KdfSchemeMgf1() {}

        public KdfSchemeMgf1(KdfSchemeMgf1 _KdfSchemeMgf1) : base(_KdfSchemeMgf1) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public KdfSchemeMgf1(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Mgf1; }

        new public KdfSchemeMgf1 Copy() { return CreateCopy<KdfSchemeMgf1>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These structures are used to define the key derivation for symmetric secret
    /// sharing using asymmetric methods. A secret sharing scheme is required in any
    /// asymmetric key with the decrypt attribute SET. </summary>
    [DataContract]
    [SpecTypeName("TPMS_KDF_SCHEME_KDF1_SP800_56A")]
    public partial class KdfSchemeKdf1Sp80056a: SchemeHash
    {
        public KdfSchemeKdf1Sp80056a() {}

        public KdfSchemeKdf1Sp80056a(KdfSchemeKdf1Sp80056a _KdfSchemeKdf1Sp80056a) : base(_KdfSchemeKdf1Sp80056a) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public KdfSchemeKdf1Sp80056a(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Kdf1Sp80056a; }

        new public KdfSchemeKdf1Sp80056a Copy() { return CreateCopy<KdfSchemeKdf1Sp80056a>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These structures are used to define the key derivation for symmetric secret
    /// sharing using asymmetric methods. A secret sharing scheme is required in any
    /// asymmetric key with the decrypt attribute SET. </summary>
    [DataContract]
    [SpecTypeName("TPMS_KDF_SCHEME_KDF2")]
    public partial class KdfSchemeKdf2: SchemeHash
    {
        public KdfSchemeKdf2() {}

        public KdfSchemeKdf2(KdfSchemeKdf2 _KdfSchemeKdf2) : base(_KdfSchemeKdf2) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public KdfSchemeKdf2(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Kdf2; }

        new public KdfSchemeKdf2 Copy() { return CreateCopy<KdfSchemeKdf2>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These structures are used to define the key derivation for symmetric secret
    /// sharing using asymmetric methods. A secret sharing scheme is required in any
    /// asymmetric key with the decrypt attribute SET. </summary>
    [DataContract]
    [SpecTypeName("TPMS_KDF_SCHEME_KDF1_SP800_108")]
    public partial class KdfSchemeKdf1Sp800108: SchemeHash
    {
        public KdfSchemeKdf1Sp800108() {}

        public KdfSchemeKdf1Sp800108(KdfSchemeKdf1Sp800108 _KdfSchemeKdf1Sp800108) : base(_KdfSchemeKdf1Sp800108) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public KdfSchemeKdf1Sp800108(TpmAlgId _hashAlg) : base(_hashAlg) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Kdf1Sp800108; }

        new public KdfSchemeKdf1Sp800108 Copy() { return CreateCopy<KdfSchemeKdf1Sp800108>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TPMU_KDF_SCHEME </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_KDF_SCHEME")]
    public partial class NullKdfScheme: NullUnion
    {
        public NullKdfScheme() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Null; }

        new public NullKdfScheme Copy() { return CreateCopy<NullKdfScheme>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 167 Definition of TPMT_KDF_SCHEME Structure </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(KdfSchemeKdf1Sp800108))]
    [KnownType(typeof(KdfSchemeKdf1Sp80056a))]
    [KnownType(typeof(KdfSchemeKdf2))]
    [KnownType(typeof(KdfSchemeMgf1))]
    [KnownType(typeof(NullKdfScheme))]
    [KnownType(typeof(SchemeHash))]
    [SpecTypeName("TPMT_KDF_SCHEME")]
    public partial class KdfScheme: TpmStructureBase
    {
        /// <summary> Scheme selector </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get { return details != null ? details.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Scheme parameters </summary>
        /// <remarks> One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2,
        /// KdfSchemeKdf1Sp800108, SchemeHash, NullKdfScheme. </remarks>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IKdfSchemeUnion details { get; set; }

        public KdfScheme() {}

        public KdfScheme(KdfScheme src) { details = src.details; }

        /// <param name = "_details"> Scheme parameters
        ///        One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2, KdfSchemeKdf1Sp800108,
        ///        SchemeHash, NullKdfScheme. </param>
        public KdfScheme(IKdfSchemeUnion _details) { details = _details; }

        new public KdfScheme Copy() { return CreateCopy<KdfScheme>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TPMU_ASYM_SCHEME
    /// </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_ASYM_SCHEME")]
    public partial class NullAsymScheme: NullUnion
    {
        public NullAsymScheme() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Null; }

        new public NullAsymScheme Copy() { return CreateCopy<NullAsymScheme>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is defined to allow overlay of all of the schemes for any
    /// asymmetric object. This structure is not sent on the interface. It is defined so that
    /// common functions may operate on any similar scheme structure. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("TPMT_ASYM_SCHEME")]
    public partial class AsymScheme: TpmStructureBase
    {
        /// <summary> Scheme selector </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get { return details != null ? details.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Scheme parameters </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IAsymSchemeUnion details { get; set; }

        public AsymScheme() {}

        public AsymScheme(AsymScheme src) { details = src.details; }

        /// <param name = "_details"> Scheme parameters
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        public AsymScheme(IAsymSchemeUnion _details) { details = _details; }

        new public AsymScheme Copy() { return CreateCopy<AsymScheme>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 172 Definition of {RSA} TPMT_RSA_SCHEME Structure </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("TPMT_RSA_SCHEME")]
    public partial class RsaScheme: TpmStructureBase
    {
        /// <summary> Scheme selector </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get { return details != null ? details.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Scheme parameters </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IAsymSchemeUnion details { get; set; }

        public RsaScheme() {}

        public RsaScheme(RsaScheme src) { details = src.details; }

        /// <param name = "_details"> Scheme parameters
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        public RsaScheme(IAsymSchemeUnion _details) { details = _details; }

        new public RsaScheme Copy() { return CreateCopy<RsaScheme>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 174 Definition of {RSA} TPMT_RSA_DECRYPT Structure </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("TPMT_RSA_DECRYPT")]
    public partial class RsaDecrypt: TpmStructureBase
    {
        /// <summary> Scheme selector </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get { return details != null ? details.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Scheme parameters </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IAsymSchemeUnion details { get; set; }

        public RsaDecrypt() {}

        public RsaDecrypt(RsaDecrypt src) { details = src.details; }

        /// <param name = "_details"> Scheme parameters
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        public RsaDecrypt(IAsymSchemeUnion _details) { details = _details; }

        new public RsaDecrypt Copy() { return CreateCopy<RsaDecrypt>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This sized buffer holds the largest RSA public key supported by the TPM. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_PUBLIC_KEY_RSA")]
    public partial class Tpm2bPublicKeyRsa: TpmStructureBase, IPublicIdUnion
    {
        /// <summary> Value </summary>
        [Range(MaxVal = 256u /*MAX_RSA_KEY_BYTES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bPublicKeyRsa() {}

        public Tpm2bPublicKeyRsa(Tpm2bPublicKeyRsa src) { buffer = src.buffer; }

        /// <param name = "_buffer"> Value </param>
        public Tpm2bPublicKeyRsa(byte[] _buffer) { buffer = _buffer; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Rsa; }

        new public Tpm2bPublicKeyRsa Copy() { return CreateCopy<Tpm2bPublicKeyRsa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This sized buffer holds the largest RSA prime number supported by the TPM. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_PRIVATE_KEY_RSA")]
    public partial class Tpm2bPrivateKeyRsa: TpmStructureBase, ISensitiveCompositeUnion
    {
        [Range(MaxVal = 640u /*RSA_PRIVATE_SIZE*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bPrivateKeyRsa() {}

        public Tpm2bPrivateKeyRsa(Tpm2bPrivateKeyRsa src) { buffer = src.buffer; }

        /// <param name = "_buffer"> TBD </param>
        public Tpm2bPrivateKeyRsa(byte[] _buffer) { buffer = _buffer; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Rsa; }

        new public Tpm2bPrivateKeyRsa Copy() { return CreateCopy<Tpm2bPrivateKeyRsa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This sized buffer holds the largest ECC parameter (coordinate) supported by
    /// the TPM. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_ECC_PARAMETER")]
    public partial class Tpm2bEccParameter: TpmStructureBase, ISensitiveCompositeUnion
    {
        /// <summary> The parameter data </summary>
        [Range(MaxVal = 48u /*MAX_ECC_KEY_BYTES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bEccParameter() {}

        public Tpm2bEccParameter(Tpm2bEccParameter src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The parameter data </param>
        public Tpm2bEccParameter(byte[] _buffer) { buffer = _buffer; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Ecc; }

        new public Tpm2bEccParameter Copy() { return CreateCopy<Tpm2bEccParameter>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure holds two ECC coordinates that, together, make up an ECC
    /// point. </summary>
    [DataContract]
    [SpecTypeName("TPMS_ECC_POINT")]
    public partial class EccPoint: TpmStructureBase, IPublicIdUnion
    {
        /// <summary> X coordinate </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "xSize", 2)]
        [DataMember()]
        public byte[] x;

        /// <summary> Y coordinate </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "ySize", 2)]
        [DataMember()]
        public byte[] y;

        public EccPoint() {}

        public EccPoint(EccPoint src)
        {
            x = src.x;
            y = src.y;
        }

        /// <param name = "_x"> X coordinate </param>
        /// <param name = "_y"> Y coordinate </param>
        public EccPoint(byte[] _x, byte[] _y)
        {
            x = _x;
            y = _y;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Ecc; }

        new public EccPoint Copy() { return CreateCopy<EccPoint>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is defined to allow a point to be a single sized parameter so
    /// that it may be encrypted. </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("TPM2B_ECC_POINT")]
    public partial class Tpm2bEccPoint: TpmStructureBase
    {
        /// <summary> Coordinates </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public EccPoint point { get; set; }

        public Tpm2bEccPoint() {}

        public Tpm2bEccPoint(Tpm2bEccPoint src) { point = src.point; }

        /// <param name = "_point"> Coordinates </param>
        public Tpm2bEccPoint(EccPoint _point) { point = _point; }

        new public Tpm2bEccPoint Copy() { return CreateCopy<Tpm2bEccPoint>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 183 Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("TPMT_ECC_SCHEME")]
    public partial class EccScheme: TpmStructureBase
    {
        /// <summary> Scheme selector </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId scheme {
            get { return details != null ? details.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Scheme parameters </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(1, MarshalType.Union, "scheme")]
        [DataMember()]
        public IAsymSchemeUnion details { get; set; }

        public EccScheme() {}

        public EccScheme(EccScheme src) { details = src.details; }

        /// <param name = "_details"> Scheme parameters
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        public EccScheme(IAsymSchemeUnion _details) { details = _details; }

        new public EccScheme Copy() { return CreateCopy<EccScheme>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used to report on the curve parameters of an ECC curve. It
    /// is returned by TPM2_ECC_Parameters(). </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(EccCurve))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KdfSchemeKdf1Sp800108))]
    [KnownType(typeof(KdfSchemeKdf1Sp80056a))]
    [KnownType(typeof(KdfSchemeKdf2))]
    [KnownType(typeof(KdfSchemeMgf1))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(NullKdfScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("TPMS_ALGORITHM_DETAIL_ECC")]
    public partial class AlgorithmDetailEcc: TpmStructureBase
    {
        /// <summary> Identifier for the curve </summary>
        [MarshalAs(0)]
        [DataMember()]
        public EccCurve curveID { get; set; }

        /// <summary> Size in bits of the key </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort keySize { get; set; }

        /// <summary> Scheme selector </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId kdfScheme {
            get { return kdf != null ? kdf.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> If not TPM_ALG_NULL, the required KDF and hash algorithm used in secret
        /// sharing operations </summary>
        /// <remarks> One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2,
        /// KdfSchemeKdf1Sp800108, SchemeHash, NullKdfScheme. </remarks>
        [MarshalAs(3, MarshalType.Union, "kdfScheme")]
        [DataMember()]
        public IKdfSchemeUnion kdf { get; set; }

        /// <summary> Scheme selector </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId signScheme {
            get { return sign != null ? sign.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> If not TPM_ALG_NULL, this is the mandatory signature scheme that is required
        /// to be used with this curve. </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(5, MarshalType.Union, "signScheme")]
        [DataMember()]
        public IAsymSchemeUnion sign { get; set; }

        /// <summary> Fp (the modulus) </summary>
        [MarshalAs(6, MarshalType.VariableLengthArray, "pSize", 2)]
        [DataMember()]
        public byte[] p;

        /// <summary> Coefficient of the linear term in the curve equation </summary>
        [MarshalAs(7, MarshalType.VariableLengthArray, "aSize", 2)]
        [DataMember()]
        public byte[] a;

        /// <summary> Constant term for curve equation </summary>
        [MarshalAs(8, MarshalType.VariableLengthArray, "bSize", 2)]
        [DataMember()]
        public byte[] b;

        /// <summary> X coordinate of base point G </summary>
        [MarshalAs(9, MarshalType.VariableLengthArray, "gXSize", 2)]
        [DataMember()]
        public byte[] gX;

        /// <summary> Y coordinate of base point G </summary>
        [MarshalAs(10, MarshalType.VariableLengthArray, "gYSize", 2)]
        [DataMember()]
        public byte[] gY;

        /// <summary> Order of G </summary>
        [MarshalAs(11, MarshalType.VariableLengthArray, "nSize", 2)]
        [DataMember()]
        public byte[] n;

        /// <summary> Cofactor (a size of zero indicates a cofactor of 1) </summary>
        [MarshalAs(12, MarshalType.VariableLengthArray, "hSize", 2)]
        [DataMember()]
        public byte[] h;

        public AlgorithmDetailEcc() {}

        public AlgorithmDetailEcc(AlgorithmDetailEcc src)
        {
            curveID = src.curveID;
            keySize = src.keySize;
            kdf = src.kdf;
            sign = src.sign;
            p = src.p;
            a = src.a;
            b = src.b;
            gX = src.gX;
            gY = src.gY;
            n = src.n;
            h = src.h;
        }

        /// <param name = "_curveID"> Identifier for the curve </param>
        /// <param name = "_keySize"> Size in bits of the key </param>
        /// <param name = "_kdf"> If not TPM_ALG_NULL, the required KDF and hash algorithm used in
        ///        secret sharing operations
        ///        One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2, KdfSchemeKdf1Sp800108,
        ///        SchemeHash, NullKdfScheme. </param>
        /// <param name = "_sign"> If not TPM_ALG_NULL, this is the mandatory signature scheme that is
        ///        required to be used with this curve.
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        /// <param name = "_p"> Fp (the modulus) </param>
        /// <param name = "_a"> Coefficient of the linear term in the curve equation </param>
        /// <param name = "_b"> Constant term for curve equation </param>
        /// <param name = "_gX"> X coordinate of base point G </param>
        /// <param name = "_gY"> Y coordinate of base point G </param>
        /// <param name = "_n"> Order of G </param>
        /// <param name = "_h"> Cofactor (a size of zero indicates a cofactor of 1) </param>
        public AlgorithmDetailEcc(EccCurve _curveID, ushort _keySize, IKdfSchemeUnion _kdf, IAsymSchemeUnion _sign, byte[] _p, byte[] _a, byte[] _b, byte[] _gX, byte[] _gY, byte[] _n, byte[] _h)
        {
            curveID = _curveID;
            keySize = _keySize;
            kdf = _kdf;
            sign = _sign;
            p = _p;
            a = _a;
            b = _b;
            gX = _gX;
            gY = _gY;
            n = _n;
            h = _h;
        }

        new public AlgorithmDetailEcc Copy() { return CreateCopy<AlgorithmDetailEcc>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 185 Definition of {RSA} TPMS_SIGNATURE_RSA Structure </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SIGNATURE_RSA")]
    public partial class SignatureRsa: TpmStructureBase, ISignatureUnion
    {
        /// <summary> The hash algorithm used to digest the message
        /// TPM_ALG_NULL is not allowed. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hash { get; set; }

        /// <summary> The signature is the size of a public key. </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "sigSize", 2)]
        [DataMember()]
        public byte[] sig;

        public SignatureRsa() { hash = TpmAlgId.Null; }

        public SignatureRsa(SignatureRsa src)
        {
            hash = src.hash;
            sig = src.sig;
        }

        /// <param name = "_hash"> The hash algorithm used to digest the message
        ///        TPM_ALG_NULL is not allowed. </param>
        /// <param name = "_sig"> The signature is the size of a public key. </param>
        public SignatureRsa(TpmAlgId _hash, byte[] _sig)
        {
            hash = _hash;
            sig = _sig;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Rsassa; }

        new public SignatureRsa Copy() { return CreateCopy<SignatureRsa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 185 Definition of {RSA} TPMS_SIGNATURE_RSA Structure </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_RSASSA")]
    public partial class SignatureRsassa: SignatureRsa
    {
        public SignatureRsassa() {}

        public SignatureRsassa(SignatureRsassa _SignatureRsassa) : base(_SignatureRsassa) {}

        /// <param name = "_hash"> The hash algorithm used to digest the message
        ///        TPM_ALG_NULL is not allowed. </param>
        /// <param name = "_sig"> The signature is the size of a public key. </param>
        public SignatureRsassa(TpmAlgId _hash, byte[] _sig)
            : base(_hash, _sig)
        {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Rsassa; }

        new public SignatureRsassa Copy() { return CreateCopy<SignatureRsassa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 185 Definition of {RSA} TPMS_SIGNATURE_RSA Structure </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_RSAPSS")]
    public partial class SignatureRsapss: SignatureRsa
    {
        public SignatureRsapss() {}

        public SignatureRsapss(SignatureRsapss _SignatureRsapss) : base(_SignatureRsapss) {}

        /// <param name = "_hash"> The hash algorithm used to digest the message
        ///        TPM_ALG_NULL is not allowed. </param>
        /// <param name = "_sig"> The signature is the size of a public key. </param>
        public SignatureRsapss(TpmAlgId _hash, byte[] _sig)
            : base(_hash, _sig)
        {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Rsapss; }

        new public SignatureRsapss Copy() { return CreateCopy<SignatureRsapss>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 187 Definition of {ECC} TPMS_SIGNATURE_ECC Structure </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("TPMS_SIGNATURE_ECC")]
    public partial class SignatureEcc: TpmStructureBase, ISignatureUnion
    {
        /// <summary> The hash algorithm used in the signature process
        /// TPM_ALG_NULL is not allowed. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmAlgId hash { get; set; }

        [MarshalAs(1, MarshalType.VariableLengthArray, "signatureRSize", 2)]
        [DataMember()]
        public byte[] signatureR;

        [MarshalAs(2, MarshalType.VariableLengthArray, "signatureSSize", 2)]
        [DataMember()]
        public byte[] signatureS;

        public SignatureEcc() { hash = TpmAlgId.Null; }

        public SignatureEcc(SignatureEcc src)
        {
            hash = src.hash;
            signatureR = src.signatureR;
            signatureS = src.signatureS;
        }

        /// <param name = "_hash"> The hash algorithm used in the signature process
        ///        TPM_ALG_NULL is not allowed. </param>
        /// <param name = "_signatureR"> TBD </param>
        /// <param name = "_signatureS"> TBD </param>
        public SignatureEcc(TpmAlgId _hash, byte[] _signatureR, byte[] _signatureS)
        {
            hash = _hash;
            signatureR = _signatureR;
            signatureS = _signatureS;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Ecdsa; }

        new public SignatureEcc Copy() { return CreateCopy<SignatureEcc>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 187 Definition of {ECC} TPMS_SIGNATURE_ECC Structure </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_ECDSA")]
    public partial class SignatureEcdsa: SignatureEcc
    {
        public SignatureEcdsa() {}

        public SignatureEcdsa(SignatureEcdsa _SignatureEcdsa) : base(_SignatureEcdsa) {}

        /// <param name = "_hash"> The hash algorithm used in the signature process
        ///        TPM_ALG_NULL is not allowed. </param>
        /// <param name = "_signatureR"> TBD </param>
        /// <param name = "_signatureS"> TBD </param>
        public SignatureEcdsa(TpmAlgId _hash, byte[] _signatureR, byte[] _signatureS)
            : base(_hash, _signatureR, _signatureS)
        {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Ecdsa; }

        new public SignatureEcdsa Copy() { return CreateCopy<SignatureEcdsa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 187 Definition of {ECC} TPMS_SIGNATURE_ECC Structure </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_ECDAA")]
    public partial class SignatureEcdaa: SignatureEcc
    {
        public SignatureEcdaa() {}

        public SignatureEcdaa(SignatureEcdaa _SignatureEcdaa) : base(_SignatureEcdaa) {}

        /// <param name = "_hash"> The hash algorithm used in the signature process
        ///        TPM_ALG_NULL is not allowed. </param>
        /// <param name = "_signatureR"> TBD </param>
        /// <param name = "_signatureS"> TBD </param>
        public SignatureEcdaa(TpmAlgId _hash, byte[] _signatureR, byte[] _signatureS)
            : base(_hash, _signatureR, _signatureS)
        {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Ecdaa; }

        new public SignatureEcdaa Copy() { return CreateCopy<SignatureEcdaa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 187 Definition of {ECC} TPMS_SIGNATURE_ECC Structure </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_SM2")]
    public partial class SignatureSm2: SignatureEcc
    {
        public SignatureSm2() {}

        public SignatureSm2(SignatureSm2 _SignatureSm2) : base(_SignatureSm2) {}

        /// <param name = "_hash"> The hash algorithm used in the signature process
        ///        TPM_ALG_NULL is not allowed. </param>
        /// <param name = "_signatureR"> TBD </param>
        /// <param name = "_signatureS"> TBD </param>
        public SignatureSm2(TpmAlgId _hash, byte[] _signatureR, byte[] _signatureS)
            : base(_hash, _signatureR, _signatureS)
        {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Sm2; }

        new public SignatureSm2 Copy() { return CreateCopy<SignatureSm2>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 187 Definition of {ECC} TPMS_SIGNATURE_ECC Structure </summary>
    [DataContract]
    [SpecTypeName("TPMS_SIGNATURE_ECSCHNORR")]
    public partial class SignatureEcschnorr: SignatureEcc
    {
        public SignatureEcschnorr() {}

        public SignatureEcschnorr(SignatureEcschnorr _SignatureEcschnorr) : base(_SignatureEcschnorr) {}

        /// <param name = "_hash"> The hash algorithm used in the signature process
        ///        TPM_ALG_NULL is not allowed. </param>
        /// <param name = "_signatureR"> TBD </param>
        /// <param name = "_signatureS"> TBD </param>
        public SignatureEcschnorr(TpmAlgId _hash, byte[] _signatureR, byte[] _signatureS)
            : base(_hash, _signatureR, _signatureS)
        {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Ecschnorr; }

        new public SignatureEcschnorr Copy() { return CreateCopy<SignatureEcschnorr>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Custom data structure representing an empty element (i.e. the one with 
    /// no data to marshal) for selector algorithm TPM_ALG_NULL for the union TPMU_SIGNATURE </summary>
    [DataContract]
    [SpecTypeName("TPMS_NULL_SIGNATURE")]
    public partial class NullSignature: NullUnion
    {
        public NullSignature() {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Null; }

        new public NullSignature Copy() { return CreateCopy<NullSignature>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 190 shows the basic algorithm-agile structure when a symmetric or
    /// asymmetric signature is indicated. The sigAlg parameter indicates the algorithm used
    /// for the signature. This structure is output from commands such as the attestation
    /// commands and TPM2_Sign, and is an input to commands such as TPM2_VerifySignature(),
    /// TPM2_PolicySigned(), and TPM2_FieldUpgradeStart(). </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("TPMT_SIGNATURE")]
    public partial class Signature: TpmStructureBase
    {
        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId sigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> This shall be the actual signature information. </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(1, MarshalType.Union, "sigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Signature() {}

        public Signature(Signature src) { signature = src.signature; }

        /// <param name = "_signature"> This shall be the actual signature information.
        ///        One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        ///        SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </param>
        public Signature(ISignatureUnion _signature) { signature = _signature; }

        new public Signature Copy() { return CreateCopy<Signature>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 192 Definition of TPM2B_ENCRYPTED_SECRET Structure </summary>
    [DataContract]
    [SpecTypeName("TPM2B_ENCRYPTED_SECRET")]
    public partial class Tpm2bEncryptedSecret: TpmStructureBase
    {
        /// <summary> Secret </summary>
        [Range(MaxVal = 0u /*sizeof(TPMU_ENCRYPTED_SECRET)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] secret;

        public Tpm2bEncryptedSecret() {}

        public Tpm2bEncryptedSecret(Tpm2bEncryptedSecret src) { secret = src.secret; }

        /// <param name = "_secret"> Secret </param>
        public Tpm2bEncryptedSecret(byte[] _secret) { secret = _secret; }

        new public Tpm2bEncryptedSecret Copy() { return CreateCopy<Tpm2bEncryptedSecret>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure describes the parameters that would appear in the public area
    /// of a KEYEDHASH object. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullSchemeKeyedhash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SchemeXor))]
    [SpecTypeName("TPMS_KEYEDHASH_PARMS")]
    public partial class KeyedhashParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary> Selects the scheme </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId schemeScheme {
            get { return scheme != null ? scheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Indicates the signing method used for a keyedHash signing object. This field
        /// also determines the size of the data field for a data object created with
        /// TPM2_Create() or TPM2_CreatePrimary(). </summary>
        /// <remarks> One of: SchemeHmac, SchemeXor, NullSchemeKeyedhash. </remarks>
        [MarshalAs(1, MarshalType.Union, "schemeScheme")]
        [DataMember()]
        public ISchemeKeyedhashUnion scheme { get; set; }

        public KeyedhashParms() {}

        public KeyedhashParms(KeyedhashParms src) { scheme = src.scheme; }

        /// <param name = "_scheme"> Indicates the signing method used for a keyedHash signing object.
        ///        This field also determines the size of the data field for a data object created
        ///        with TPM2_Create() or TPM2_CreatePrimary().
        ///        One of: SchemeHmac, SchemeXor, NullSchemeKeyedhash. </param>
        public KeyedhashParms(ISchemeKeyedhashUnion _scheme) { scheme = _scheme; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Keyedhash; }

        new public KeyedhashParms Copy() { return CreateCopy<KeyedhashParms>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure contains the common public area parameters for an asymmetric
    /// key. The first two parameters of the parameter definition structures of an asymmetric
    /// key shall have the same two first components. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SymDefObject))]
    [SpecTypeName("TPMS_ASYM_PARMS")]
    public partial class AsymParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary> The companion symmetric algorithm for a restricted decryption key and shall
        /// be set to a supported symmetric algorithm
        /// This field is optional for keys that are not decryption keys and shall be set to
        /// TPM_ALG_NULL if not used. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public SymDefObject symmetric { get; set; }

        /// <summary> Scheme selector </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId schemeScheme {
            get { return scheme != null ? scheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> For a key with the sign attribute SET, a valid signing scheme for the key type
        /// for a key with the decrypt attribute SET, a valid key exchange protocol
        /// for a key with sign and decrypt attributes, shall be TPM_ALG_NULL </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(2, MarshalType.Union, "schemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion scheme { get; set; }

        public AsymParms() {}

        public AsymParms(AsymParms src)
        {
            symmetric = src.symmetric;
            scheme = src.scheme;
        }

        /// <param name = "_symmetric"> The companion symmetric algorithm for a restricted decryption
        ///        key and shall be set to a supported symmetric algorithm
        ///        This field is optional for keys that are not decryption keys and shall be set to
        ///        TPM_ALG_NULL if not used. </param>
        /// <param name = "_scheme"> For a key with the sign attribute SET, a valid signing scheme for
        ///        the key type
        ///        for a key with the decrypt attribute SET, a valid key exchange protocol
        ///        for a key with sign and decrypt attributes, shall be TPM_ALG_NULL
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        public AsymParms(SymDefObject _symmetric, IAsymSchemeUnion _scheme)
        {
            symmetric = _symmetric;
            scheme = _scheme;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Any; }

        new public AsymParms Copy() { return CreateCopy<AsymParms>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> A TPM compatible with this specification and supporting RSA shall support
    /// two primes and an exponent of zero. An exponent of zero indicates that the exponent is
    /// the default of 216 + 1. Support for other values is optional. Use of other exponents
    /// in duplicated keys is not recommended because the resulting keys would not be
    /// interoperable with other TPMs. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SymDefObject))]
    [SpecTypeName("TPMS_RSA_PARMS")]
    public partial class RsaParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary> For a restricted decryption key, shall be set to a supported symmetric
        /// algorithm, key size, and mode.
        /// if the key is not a restricted decryption key, this field shall be set to
        /// TPM_ALG_NULL. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public SymDefObject symmetric { get; set; }

        /// <summary> Scheme selector </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId schemeScheme {
            get { return scheme != null ? scheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Scheme.scheme shall be:
        /// for an unrestricted signing key, either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL
        /// for a restricted signing key, either TPM_ALG_RSAPSS or TPM_ALG_RSASSA
        /// for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP, or TPM_ALG_NULL
        /// unless the object also has the sign attribute
        /// for a restricted decryption key, TPM_ALG_NULL
        /// NOTE When both sign and decrypt are SET, restricted shall be CLEAR and scheme shall be
        /// TPM_ALG_NULL. </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(2, MarshalType.Union, "schemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion scheme { get; set; }

        /// <summary> Number of bits in the public modulus </summary>
        [MarshalAs(3)]
        [DataMember()]
        public ushort keyBits { get; set; }

        /// <summary> The public exponent
        /// A prime number greater than 2. </summary>
        [MarshalAs(4)]
        [DataMember()]
        public uint exponent { get; set; }

        public RsaParms() {}

        public RsaParms(RsaParms src)
        {
            symmetric = src.symmetric;
            scheme = src.scheme;
            keyBits = src.keyBits;
            exponent = src.exponent;
        }

        /// <param name = "_symmetric"> For a restricted decryption key, shall be set to a supported
        ///        symmetric algorithm, key size, and mode.
        ///        if the key is not a restricted decryption key, this field shall be set to
        ///        TPM_ALG_NULL. </param>
        /// <param name = "_scheme"> Scheme.scheme shall be:
        ///        for an unrestricted signing key, either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL
        ///        for a restricted signing key, either TPM_ALG_RSAPSS or TPM_ALG_RSASSA
        ///        for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP, or TPM_ALG_NULL
        ///        unless the object also has the sign attribute
        ///        for a restricted decryption key, TPM_ALG_NULL
        ///        NOTE When both sign and decrypt are SET, restricted shall be CLEAR and scheme shall
        ///        be TPM_ALG_NULL.
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        /// <param name = "_keyBits"> Number of bits in the public modulus </param>
        /// <param name = "_exponent"> The public exponent
        ///        A prime number greater than 2. </param>
        public RsaParms(SymDefObject _symmetric, IAsymSchemeUnion _scheme, ushort _keyBits, uint _exponent)
        {
            symmetric = _symmetric;
            scheme = _scheme;
            keyBits = _keyBits;
            exponent = _exponent;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Rsa; }

        new public RsaParms Copy() { return CreateCopy<RsaParms>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure contains the parameters for prime modulus ECC. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(EccCurve))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KdfSchemeKdf1Sp800108))]
    [KnownType(typeof(KdfSchemeKdf1Sp80056a))]
    [KnownType(typeof(KdfSchemeKdf2))]
    [KnownType(typeof(KdfSchemeMgf1))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(NullKdfScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(SymDefObject))]
    [SpecTypeName("TPMS_ECC_PARMS")]
    public partial class EccParms: TpmStructureBase, IPublicParmsUnion
    {
        /// <summary> For a restricted decryption key, shall be set to a supported symmetric
        /// algorithm, key size. and mode.
        /// if the key is not a restricted decryption key, this field shall be set to
        /// TPM_ALG_NULL. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public SymDefObject symmetric { get; set; }

        /// <summary> Scheme selector </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId schemeScheme {
            get { return scheme != null ? scheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> If the sign attribute of the key is SET, then this shall be a valid signing scheme.
        /// NOTE If the sign parameter in curveID indicates a mandatory scheme, then this field
        /// shall have the same value.
        /// If the decrypt attribute of the key is SET, then this shall be a valid key exchange
        /// scheme or TPM_ALG_NULL.
        /// If the key is a Storage Key, then this field shall be TPM_ALG_NULL. </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(2, MarshalType.Union, "schemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion scheme { get; set; }

        /// <summary> ECC curve ID </summary>
        [MarshalAs(3)]
        [DataMember()]
        public EccCurve curveID { get; set; }

        /// <summary> Scheme selector </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId kdfScheme {
            get { return kdf != null ? kdf.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> An optional key derivation scheme for generating a symmetric key from a Z value
        /// If the kdf parameter associated with curveID is not TPM_ALG_NULL then this is required
        /// to be NULL.
        /// NOTE There are currently no commands where this parameter has effect and, in the
        /// reference code, this field needs to be set to TPM_ALG_NULL. </summary>
        /// <remarks> One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2,
        /// KdfSchemeKdf1Sp800108, SchemeHash, NullKdfScheme. </remarks>
        [MarshalAs(5, MarshalType.Union, "kdfScheme")]
        [DataMember()]
        public IKdfSchemeUnion kdf { get; set; }

        public EccParms() {}

        public EccParms(EccParms src)
        {
            symmetric = src.symmetric;
            scheme = src.scheme;
            curveID = src.curveID;
            kdf = src.kdf;
        }

        /// <param name = "_symmetric"> For a restricted decryption key, shall be set to a supported
        ///        symmetric algorithm, key size. and mode.
        ///        if the key is not a restricted decryption key, this field shall be set to
        ///        TPM_ALG_NULL. </param>
        /// <param name = "_scheme"> If the sign attribute of the key is SET, then this shall be a
        ///        valid signing scheme.
        ///        NOTE If the sign parameter in curveID indicates a mandatory scheme, then this field
        ///        shall have the same value.
        ///        If the decrypt attribute of the key is SET, then this shall be a valid key exchange
        ///        scheme or TPM_ALG_NULL.
        ///        If the key is a Storage Key, then this field shall be TPM_ALG_NULL.
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        /// <param name = "_curveID"> ECC curve ID </param>
        /// <param name = "_kdf"> An optional key derivation scheme for generating a symmetric key
        ///        from a Z value
        ///        If the kdf parameter associated with curveID is not TPM_ALG_NULL then this is
        ///        required to be NULL.
        ///        NOTE There are currently no commands where this parameter has effect and, in the
        ///        reference code, this field needs to be set to TPM_ALG_NULL.
        ///        One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2, KdfSchemeKdf1Sp800108,
        ///        SchemeHash, NullKdfScheme. </param>
        public EccParms(SymDefObject _symmetric, IAsymSchemeUnion _scheme, EccCurve _curveID, IKdfSchemeUnion _kdf)
        {
            symmetric = _symmetric;
            scheme = _scheme;
            curveID = _curveID;
            kdf = _kdf;
        }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Ecc; }

        new public EccParms Copy() { return CreateCopy<EccParms>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used in TPM2_TestParms() to validate that a set of
    /// algorithm parameters is supported by the TPM. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(AsymParms))]
    [KnownType(typeof(EccParms))]
    [KnownType(typeof(KeyedhashParms))]
    [KnownType(typeof(RsaParms))]
    [KnownType(typeof(SymcipherParms))]
    [SpecTypeName("TPMT_PUBLIC_PARMS")]
    public partial class PublicParms: TpmStructureBase
    {
        /// <summary> The algorithm to be tested </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId type {
            get { return parameters.GetUnionSelector(); }
        }

        /// <summary> The algorithm details </summary>
        /// <remarks> One of: KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms. </remarks>
        [MarshalAs(1, MarshalType.Union, "type")]
        [DataMember()]
        public IPublicParmsUnion parameters { get; set; }

        public PublicParms() {}

        public PublicParms(PublicParms src) { parameters = src.parameters; }

        /// <param name = "_parameters"> The algorithm details
        ///        One of: KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms. </param>
        public PublicParms(IPublicParmsUnion _parameters) { parameters = _parameters; }

        new public PublicParms Copy() { return CreateCopy<PublicParms>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Table 201 defines the public area structure. The Name of the object is
    /// nameAlg concatenated with the digest of this structure using nameAlg. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Tpm2bDigestKeyedhash))]
    [KnownType(typeof(Tpm2bDigestSymcipher))]
    [KnownType(typeof(Tpm2bPublicKeyRsa))]
    [KnownType(typeof(ObjectAttr))]
    [KnownType(typeof(AsymParms))]
    [KnownType(typeof(TpmDerive))]
    [KnownType(typeof(EccParms))]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(KeyedhashParms))]
    [KnownType(typeof(RsaParms))]
    [KnownType(typeof(SymcipherParms))]
    [SpecTypeName("TPMT_PUBLIC")]
    public partial class TpmPublic: TpmStructureBase
    {
        /// <summary> Algorithm associated with this object </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId type {
            get { return parameters.GetUnionSelector(); }
        }

        /// <summary> Algorithm used for computing the Name of the object
        /// NOTE The "+" indicates that the instance of a TPMT_PUBLIC may have a "+" to indicate
        /// that the nameAlg may be TPM_ALG_NULL. </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId nameAlg { get; set; }

        /// <summary> Attributes that, along with type, determine the manipulations of this object
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public ObjectAttr objectAttributes { get; set; }

        /// <summary> Optional policy for using this key
        /// The policy is computed using the nameAlg of the object.
        /// NOTE Shall be the Empty Policy if no authorization policy is present. </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "authPolicySize", 2)]
        [DataMember()]
        public byte[] authPolicy;

        /// <summary> The algorithm or structure details </summary>
        /// <remarks> One of: KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms. </remarks>
        [MarshalAs(4, MarshalType.Union, "type")]
        [DataMember()]
        public IPublicParmsUnion parameters { get; set; }

        /// <summary> The unique identifier of the structure
        /// For an asymmetric key, this would be the public key. </summary>
        /// <remarks> One of: Tpm2bDigestKeyedhash, Tpm2bDigestSymcipher, Tpm2bPublicKeyRsa,
        /// EccPoint, TpmDerive. </remarks>
        [MarshalAs(5, MarshalType.Union, "type")]
        [DataMember()]
        public IPublicIdUnion unique { get; set; }

        public TpmPublic() { nameAlg = TpmAlgId.Null; }

        public TpmPublic(TpmPublic src)
        {
            nameAlg = src.nameAlg;
            objectAttributes = src.objectAttributes;
            authPolicy = src.authPolicy;
            parameters = src.parameters;
            unique = src.unique;
        }

        /// <param name = "_nameAlg"> Algorithm used for computing the Name of the object
        ///        NOTE The "+" indicates that the instance of a TPMT_PUBLIC may have a "+" to
        ///        indicate that the nameAlg may be TPM_ALG_NULL. </param>
        /// <param name = "_objectAttributes"> Attributes that, along with type, determine the
        ///        manipulations of this object </param>
        /// <param name = "_authPolicy"> Optional policy for using this key
        ///        The policy is computed using the nameAlg of the object.
        ///        NOTE Shall be the Empty Policy if no authorization policy is present. </param>
        /// <param name = "_parameters"> The algorithm or structure details
        ///        One of: KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms. </param>
        /// <param name = "_unique"> The unique identifier of the structure
        ///        For an asymmetric key, this would be the public key.
        ///        One of: Tpm2bDigestKeyedhash, Tpm2bDigestSymcipher, Tpm2bPublicKeyRsa, EccPoint,
        ///        TpmDerive. </param>
        public TpmPublic(TpmAlgId _nameAlg, ObjectAttr _objectAttributes, byte[] _authPolicy, IPublicParmsUnion _parameters, IPublicIdUnion _unique)
        {
            nameAlg = _nameAlg;
            objectAttributes = _objectAttributes;
            authPolicy = _authPolicy;
            parameters = _parameters;
            unique = _unique;
        }

        new public TpmPublic Copy() { return CreateCopy<TpmPublic>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This sized buffer is used to embed a TPMT_PUBLIC in a load command and in
    /// any response that returns a public area. </summary>
    [DataContract]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("TPM2B_PUBLIC")]
    public partial class Tpm2bPublic: TpmStructureBase
    {
        /// <summary> The public area
        /// NOTE The + indicates that the caller may specify that use of TPM_ALG_NULL is allowed
        /// for nameAlg. </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public TpmPublic publicArea { get; set; }

        public Tpm2bPublic() {}

        public Tpm2bPublic(Tpm2bPublic src) { publicArea = src.publicArea; }

        /// <param name = "_publicArea"> The public area
        ///        NOTE The + indicates that the caller may specify that use of TPM_ALG_NULL is
        ///        allowed for nameAlg. </param>
        public Tpm2bPublic(TpmPublic _publicArea) { publicArea = _publicArea; }

        new public Tpm2bPublic Copy() { return CreateCopy<Tpm2bPublic>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This sized buffer is used to embed a TPMT_TEMPLATE for TPM2_CreateLoaded(). </summary>
    [DataContract]
    [SpecTypeName("TPM2B_TEMPLATE")]
    public partial class Tpm2bTemplate: TpmStructureBase
    {
        /// <summary> The public area </summary>
        [Range(MaxVal = 30u /*sizeof(TPMT_PUBLIC)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bTemplate() {}

        public Tpm2bTemplate(Tpm2bTemplate src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The public area </param>
        public Tpm2bTemplate(byte[] _buffer) { buffer = _buffer; }

        new public Tpm2bTemplate Copy() { return CreateCopy<Tpm2bTemplate>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is defined for coding purposes. For IO to the TPM, the
    /// sensitive portion of the key will be in a canonical form. For an RSA key, this will be
    /// one of the prime factors of the public modulus. After loading, it is typical that
    /// other values will be computed so that computations using the private key will not need
    /// to start with just one prime factor. This structure can be used to store the results
    /// of such vendor-specific calculations. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_PRIVATE_VENDOR_SPECIFIC")]
    public partial class Tpm2bPrivateVendorSpecific: TpmStructureBase, ISensitiveCompositeUnion
    {
        [Range(MaxVal = 640u /*PRIVATE_VENDOR_SPECIFIC_BYTES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bPrivateVendorSpecific() {}

        public Tpm2bPrivateVendorSpecific(Tpm2bPrivateVendorSpecific src) { buffer = src.buffer; }

        /// <param name = "_buffer"> TBD </param>
        public Tpm2bPrivateVendorSpecific(byte[] _buffer) { buffer = _buffer; }

        public virtual TpmAlgId GetUnionSelector() { return TpmAlgId.Any; }

        new public Tpm2bPrivateVendorSpecific Copy() { return CreateCopy<Tpm2bPrivateVendorSpecific>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> AuthValue shall not be larger than the size of the digest produced by the
    /// nameAlg of the object. seedValue shall be the size of the digest produced by the
    /// nameAlg of the object. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Tpm2bEccParameter))]
    [KnownType(typeof(Tpm2bPrivateKeyRsa))]
    [KnownType(typeof(Tpm2bPrivateVendorSpecific))]
    [KnownType(typeof(Tpm2bSensitiveData))]
    [KnownType(typeof(Tpm2bSymKey))]
    [SpecTypeName("TPMT_SENSITIVE")]
    public partial class Sensitive: TpmStructureBase
    {
        /// <summary> Identifier for the sensitive area
        /// This shall be the same as the type parameter of the associated public area. </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId sensitiveType {
            get { return sensitive.GetUnionSelector(); }
        }

        /// <summary> User authorization data
        /// The authValue may be a zero-length string. </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authValueSize", 2)]
        [DataMember()]
        public byte[] authValue;

        /// <summary> For a parent object, the optional protection seed; for other objects, the
        /// obfuscation value </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "seedValueSize", 2)]
        [DataMember()]
        public byte[] seedValue;

        /// <summary> The type-specific private data </summary>
        /// <remarks> One of: Tpm2bPrivateKeyRsa, Tpm2bEccParameter, Tpm2bSensitiveData,
        /// Tpm2bSymKey, Tpm2bPrivateVendorSpecific. </remarks>
        [MarshalAs(3, MarshalType.Union, "sensitiveType")]
        [DataMember()]
        public ISensitiveCompositeUnion sensitive { get; set; }

        public Sensitive() {}

        public Sensitive(Sensitive src)
        {
            authValue = src.authValue;
            seedValue = src.seedValue;
            sensitive = src.sensitive;
        }

        /// <param name = "_authValue"> User authorization data
        ///        The authValue may be a zero-length string. </param>
        /// <param name = "_seedValue"> For a parent object, the optional protection seed; for other
        ///        objects, the obfuscation value </param>
        /// <param name = "_sensitive"> The type-specific private data
        ///        One of: Tpm2bPrivateKeyRsa, Tpm2bEccParameter, Tpm2bSensitiveData, Tpm2bSymKey,
        ///        Tpm2bPrivateVendorSpecific. </param>
        public Sensitive(byte[] _authValue, byte[] _seedValue, ISensitiveCompositeUnion _sensitive)
        {
            authValue = _authValue;
            seedValue = _seedValue;
            sensitive = _sensitive;
        }

        new public Sensitive Copy() { return CreateCopy<Sensitive>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The TPM2B_SENSITIVE structure is used as a parameter in TPM2_LoadExternal().
    /// It is an unencrypted sensitive area but it may be encrypted using parameter
    /// encryption. </summary>
    [DataContract]
    [KnownType(typeof(Sensitive))]
    [SpecTypeName("TPM2B_SENSITIVE")]
    public partial class Tpm2bSensitive: TpmStructureBase
    {
        /// <summary> An unencrypted sensitive area </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public Sensitive sensitiveArea { get; set; }

        public Tpm2bSensitive() {}

        public Tpm2bSensitive(Tpm2bSensitive src) { sensitiveArea = src.sensitiveArea; }

        /// <param name = "_sensitiveArea"> An unencrypted sensitive area </param>
        public Tpm2bSensitive(Sensitive _sensitiveArea) { sensitiveArea = _sensitiveArea; }

        new public Tpm2bSensitive Copy() { return CreateCopy<Tpm2bSensitive>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is defined to size the contents of a TPM2B_PRIVATE. This
    /// structure is not directly marshaled or unmarshaled. </summary>
    [DataContract]
    [KnownType(typeof(Sensitive))]
    [SpecTypeName("_PRIVATE")]
    public partial class _Private: TpmStructureBase
    {
        [MarshalAs(0, MarshalType.VariableLengthArray, "integrityOuterSize", 2)]
        [DataMember()]
        public byte[] integrityOuter;

        /// <summary> Could also be a TPM2B_IV </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "integrityInnerSize", 2)]
        [DataMember()]
        public byte[] integrityInner;

        /// <summary> The sensitive area </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "sensitiveSize", 2)]
        [DataMember()]
        public Sensitive sensitive { get; set; }

        public _Private() {}

        public _Private(_Private src)
        {
            integrityOuter = src.integrityOuter;
            integrityInner = src.integrityInner;
            sensitive = src.sensitive;
        }

        /// <param name = "_integrityOuter"> TBD </param>
        /// <param name = "_integrityInner"> Could also be a TPM2B_IV </param>
        /// <param name = "_sensitive"> The sensitive area </param>
        public _Private(byte[] _integrityOuter, byte[] _integrityInner, Sensitive _sensitive)
        {
            integrityOuter = _integrityOuter;
            integrityInner = _integrityInner;
            sensitive = _sensitive;
        }

        new public _Private Copy() { return CreateCopy<_Private>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The TPM2B_PRIVATE structure is used as a parameter in multiple commands that
    /// create, load, and modify the sensitive area of an object. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_PRIVATE")]
    public partial class TpmPrivate: TpmStructureBase
    {
        /// <summary> An encrypted private area </summary>
        [Range(MaxVal = 1024u /*sizeof(_PRIVATE)*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public TpmPrivate() {}

        public TpmPrivate(TpmPrivate src) { buffer = src.buffer; }

        /// <param name = "_buffer"> An encrypted private area </param>
        public TpmPrivate(byte[] _buffer) { buffer = _buffer; }

        new public TpmPrivate Copy() { return CreateCopy<TpmPrivate>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used for sizing the TPM2B_ID_OBJECT. </summary>
    [DataContract]
    [SpecTypeName("TPMS_ID_OBJECT")]
    public partial class IdObject: TpmStructureBase
    {
        /// <summary> HMAC using the nameAlg of the storage key on the target TPM </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "integrityHMACSize", 2)]
        [DataMember()]
        public byte[] integrityHMAC;

        /// <summary> Credential protector information returned if name matches the referenced object
        /// All of the encIdentity is encrypted, including the size field.
        /// NOTE The TPM is not required to check that the size is not larger than the digest of
        /// the nameAlg. However, if the size is larger, the ID object may not be usable on a TPM
        /// that has no digest larger than produced by nameAlg. </summary>
        [MarshalAs(1, MarshalType.EncryptedVariableLengthArray)]
        [DataMember()]
        public byte[] encIdentity;

        public IdObject() {}

        public IdObject(IdObject src)
        {
            integrityHMAC = src.integrityHMAC;
            encIdentity = src.encIdentity;
        }

        /// <param name = "_integrityHMAC"> HMAC using the nameAlg of the storage key on the target
        ///        TPM </param>
        /// <param name = "_encIdentity"> Credential protector information returned if name matches
        ///        the referenced object
        ///        All of the encIdentity is encrypted, including the size field.
        ///        NOTE The TPM is not required to check that the size is not larger than the digest
        ///        of the nameAlg. However, if the size is larger, the ID object may not be usable on
        ///        a TPM that has no digest larger than produced by nameAlg. </param>
        public IdObject(byte[] _integrityHMAC, byte[] _encIdentity)
        {
            integrityHMAC = _integrityHMAC;
            encIdentity = _encIdentity;
        }

        new public IdObject Copy() { return CreateCopy<IdObject>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is an output from TPM2_MakeCredential() and is an input to
    /// TPM2_ActivateCredential(). </summary>
    [DataContract]
    [KnownType(typeof(IdObject))]
    [SpecTypeName("TPM2B_ID_OBJECT")]
    public partial class Tpm2bIdObject: TpmStructureBase
    {
        /// <summary> An encrypted credential area </summary>
        [Range(MaxVal = 2u /*sizeof(TPMS_ID_OBJECT)*/)]
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public IdObject credential { get; set; }

        public Tpm2bIdObject() {}

        public Tpm2bIdObject(Tpm2bIdObject src) { credential = src.credential; }

        /// <param name = "_credential"> An encrypted credential area </param>
        public Tpm2bIdObject(IdObject _credential) { credential = _credential; }

        new public Tpm2bIdObject Copy() { return CreateCopy<Tpm2bIdObject>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is the data that can be written to and read from a TPM_NT_PIN_PASS or
    /// TPM_NT_PIN_FAIL non-volatile index. pinCount is the most significant octets. pinLimit
    /// is the least significant octets. </summary>
    [DataContract]
    [SpecTypeName("TPMS_NV_PIN_COUNTER_PARAMETERS")]
    public partial class NvPinCounterParameters: TpmStructureBase
    {
        /// <summary> This counter shows the current number of successful authValue authorization
        /// attempts to access a TPM_NT_PIN_PASS index or the current number of unsuccessful
        /// authValue authorization attempts to access a TPM_NT_PIN_FAIL index. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint pinCount { get; set; }

        /// <summary> This threshold is the value of pinCount at which the authValue authorization
        /// of the host TPM_NT_PIN_PASS or TPM_NT_PIN_FAIL index is locked out. </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint pinLimit { get; set; }

        public NvPinCounterParameters() {}

        public NvPinCounterParameters(NvPinCounterParameters src)
        {
            pinCount = src.pinCount;
            pinLimit = src.pinLimit;
        }

        /// <param name = "_pinCount"> This counter shows the current number of successful authValue
        ///        authorization attempts to access a TPM_NT_PIN_PASS index or the current number of
        ///        unsuccessful authValue authorization attempts to access a TPM_NT_PIN_FAIL index. </param>
        /// <param name = "_pinLimit"> This threshold is the value of pinCount at which the authValue
        ///        authorization of the host TPM_NT_PIN_PASS or TPM_NT_PIN_FAIL index is locked out. </param>
        public NvPinCounterParameters(uint _pinCount, uint _pinLimit)
        {
            pinCount = _pinCount;
            pinLimit = _pinLimit;
        }

        new public NvPinCounterParameters Copy() { return CreateCopy<NvPinCounterParameters>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure describes an NV Index. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NvAttr))]
    [SpecTypeName("TPMS_NV_PUBLIC")]
    public partial class NvPublic: TpmStructureBase
    {
        /// <summary> The handle of the data area </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> Hash algorithm used to compute the name of the Index and used for the
        /// authPolicy. For an extend index, the hash algorithm used for the extend. </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId nameAlg { get; set; }

        /// <summary> The Index attributes </summary>
        [MarshalAs(2)]
        [DataMember()]
        public NvAttr attributes { get; set; }

        /// <summary> Optional access policy for the Index
        /// The policy is computed using the nameAlg
        /// NOTE Shall be the Empty Policy if no authorization policy is present. </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "authPolicySize", 2)]
        [DataMember()]
        public byte[] authPolicy;

        /// <summary> The size of the data area
        /// The maximum size is implementation-dependent. The minimum maximum size is
        /// platform-specific. </summary>
        [Range(MaxVal = 2048u /*MAX_NV_INDEX_SIZE*/)]
        [MarshalAs(4)]
        [DataMember()]
        public ushort dataSize { get; set; }

        public NvPublic()
        {
            nvIndex = new TpmHandle();
            nameAlg = TpmAlgId.Null;
        }

        public NvPublic(NvPublic src)
        {
            nvIndex = src.nvIndex;
            nameAlg = src.nameAlg;
            attributes = src.attributes;
            authPolicy = src.authPolicy;
            dataSize = src.dataSize;
        }

        /// <param name = "_nvIndex"> The handle of the data area </param>
        /// <param name = "_nameAlg"> Hash algorithm used to compute the name of the Index and used
        ///        for the authPolicy. For an extend index, the hash algorithm used for the extend. </param>
        /// <param name = "_attributes"> The Index attributes </param>
        /// <param name = "_authPolicy"> Optional access policy for the Index
        ///        The policy is computed using the nameAlg
        ///        NOTE Shall be the Empty Policy if no authorization policy is present. </param>
        /// <param name = "_dataSize"> The size of the data area
        ///        The maximum size is implementation-dependent. The minimum maximum size is
        ///        platform-specific. </param>
        public NvPublic(TpmHandle _nvIndex, TpmAlgId _nameAlg, NvAttr _attributes, byte[] _authPolicy, ushort _dataSize)
        {
            nvIndex = _nvIndex;
            nameAlg = _nameAlg;
            attributes = _attributes;
            authPolicy = _authPolicy;
            dataSize = _dataSize;
        }

        new public NvPublic Copy() { return CreateCopy<NvPublic>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used when a TPMS_NV_PUBLIC is sent on the TPM interface. </summary>
    [DataContract]
    [KnownType(typeof(NvPublic))]
    [SpecTypeName("TPM2B_NV_PUBLIC")]
    public partial class Tpm2bNvPublic: TpmStructureBase
    {
        /// <summary> The public area </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public NvPublic nvPublic { get; set; }

        public Tpm2bNvPublic() {}

        public Tpm2bNvPublic(Tpm2bNvPublic src) { nvPublic = src.nvPublic; }

        /// <param name = "_nvPublic"> The public area </param>
        public Tpm2bNvPublic(NvPublic _nvPublic) { nvPublic = _nvPublic; }

        new public Tpm2bNvPublic Copy() { return CreateCopy<Tpm2bNvPublic>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure holds the object or session context data. When saved, the
    /// full structure is encrypted. </summary>
    [DataContract]
    [SpecTypeName("TPM2B_CONTEXT_SENSITIVE")]
    public partial class Tpm2bContextSensitive: TpmStructureBase
    {
        /// <summary> The sensitive data </summary>
        [Range(MaxVal = 1264u /*MAX_CONTEXT_SIZE*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "size", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2bContextSensitive() {}

        public Tpm2bContextSensitive(Tpm2bContextSensitive src) { buffer = src.buffer; }

        /// <param name = "_buffer"> The sensitive data </param>
        public Tpm2bContextSensitive(byte[] _buffer) { buffer = _buffer; }

        new public Tpm2bContextSensitive Copy() { return CreateCopy<Tpm2bContextSensitive>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure holds the integrity value and the encrypted data for a
    /// context. </summary>
    [DataContract]
    [SpecTypeName("TPMS_CONTEXT_DATA")]
    public partial class ContextData: TpmStructureBase
    {
        /// <summary> The integrity value </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "integritySize", 2)]
        [DataMember()]
        public byte[] integrity;

        /// <summary> The sensitive area </summary>
        [MarshalAs(1, MarshalType.EncryptedVariableLengthArray)]
        [DataMember()]
        public byte[] encrypted;

        public ContextData() {}

        public ContextData(ContextData src)
        {
            integrity = src.integrity;
            encrypted = src.encrypted;
        }

        /// <param name = "_integrity"> The integrity value </param>
        /// <param name = "_encrypted"> The sensitive area </param>
        public ContextData(byte[] _integrity, byte[] _encrypted)
        {
            integrity = _integrity;
            encrypted = _encrypted;
        }

        new public ContextData Copy() { return CreateCopy<ContextData>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used in a TPMS_CONTEXT. </summary>
    [DataContract]
    [KnownType(typeof(ContextData))]
    [SpecTypeName("TPM2B_CONTEXT_DATA")]
    public partial class Tpm2bContextData: TpmStructureBase
    {
        [Range(MaxVal = 2u /*sizeof(TPMS_CONTEXT_DATA)*/)]
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public ContextData buffer { get; set; }

        public Tpm2bContextData() {}

        public Tpm2bContextData(Tpm2bContextData src) { buffer = src.buffer; }

        /// <param name = "_buffer"> TBD </param>
        public Tpm2bContextData(ContextData _buffer) { buffer = _buffer; }

        new public Tpm2bContextData Copy() { return CreateCopy<Tpm2bContextData>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is used in TPM2_ContextLoad() and TPM2_ContextSave(). If the
    /// values of the TPMS_CONTEXT structure in TPM2_ContextLoad() are not the same as the
    /// values when the context was saved (TPM2_ContextSave()), then the TPM shall not load
    /// the context. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(ContextData))]
    [SpecTypeName("TPMS_CONTEXT")]
    public partial class Context: TpmStructureBase
    {
        /// <summary> The sequence number of the context
        /// NOTE Transient object contexts and session contexts used different counters. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ulong sequence { get; set; }

        /// <summary> A handle indicating if the context is a session, object, or sequence object
        /// (see Table 222 Context Handle Values </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle savedHandle { get; set; }

        /// <summary> The hierarchy of the context </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }

        /// <summary> The context data and integrity HMAC </summary>
        [MarshalAs(3, MarshalType.SizedStruct, "contextBlobSize", 2)]
        [DataMember()]
        public ContextData contextBlob { get; set; }

        public Context()
        {
            savedHandle = new TpmHandle();
            hierarchy = new TpmHandle();
        }

        public Context(Context src)
        {
            sequence = src.sequence;
            savedHandle = src.savedHandle;
            hierarchy = src.hierarchy;
            contextBlob = src.contextBlob;
        }

        /// <param name = "_sequence"> The sequence number of the context
        ///        NOTE Transient object contexts and session contexts used different counters. </param>
        /// <param name = "_savedHandle"> A handle indicating if the context is a session, object, or
        ///        sequence object (see Table 222 Context Handle Values </param>
        /// <param name = "_hierarchy"> The hierarchy of the context </param>
        /// <param name = "_contextBlob"> The context data and integrity HMAC </param>
        public Context(ulong _sequence, TpmHandle _savedHandle, TpmHandle _hierarchy, ContextData _contextBlob)
        {
            sequence = _sequence;
            savedHandle = _savedHandle;
            hierarchy = _hierarchy;
            contextBlob = _contextBlob;
        }

        new public Context Copy() { return CreateCopy<Context>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure provides information relating to the creation environment for
    /// the object. The creation data includes the parent Name, parent Qualified Name, and the
    /// digest of selected PCR. These values represent the environment in which the object was
    /// created. Creation data allows a relying party to determine if an object was created
    /// when some appropriate protections were present. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(LocalityAttr))]
    [SpecTypeName("TPMS_CREATION_DATA")]
    public partial class CreationData: TpmStructureBase
    {
        /// <summary> List indicating the PCR included in pcrDigest </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "pcrSelectCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelect;

        /// <summary> Digest of the selected PCR using nameAlg of the object for which this
        /// structure is being created
        /// pcrDigest.size shall be zero if the pcrSelect list is empty. </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrDigestSize", 2)]
        [DataMember()]
        public byte[] pcrDigest;

        /// <summary> The locality at which the object was created </summary>
        [MarshalAs(2)]
        [DataMember()]
        public LocalityAttr locality { get; set; }

        /// <summary> NameAlg of the parent </summary>
        [MarshalAs(3)]
        [DataMember()]
        public TpmAlgId parentNameAlg { get; set; }

        /// <summary> Name of the parent at time of creation
        /// The size will match digest size associated with parentNameAlg unless it is
        /// TPM_ALG_NULL, in which case the size will be 4 and parentName will be the hierarchy
        /// handle. </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "parentNameSize", 2)]
        [DataMember()]
        public byte[] parentName;

        /// <summary> Qualified Name of the parent at the time of creation
        /// Size is the same as parentName. </summary>
        [MarshalAs(5, MarshalType.VariableLengthArray, "parentQualifiedNameSize", 2)]
        [DataMember()]
        public byte[] parentQualifiedName;

        /// <summary> Association with additional information added by the key creator
        /// This will be the contents of the outsideInfo parameter in TPM2_Create() or
        /// TPM2_CreatePrimary(). </summary>
        [MarshalAs(6, MarshalType.VariableLengthArray, "outsideInfoSize", 2)]
        [DataMember()]
        public byte[] outsideInfo;

        public CreationData() { parentNameAlg = TpmAlgId.Null; }

        public CreationData(CreationData src)
        {
            pcrSelect = src.pcrSelect;
            pcrDigest = src.pcrDigest;
            locality = src.locality;
            parentNameAlg = src.parentNameAlg;
            parentName = src.parentName;
            parentQualifiedName = src.parentQualifiedName;
            outsideInfo = src.outsideInfo;
        }

        /// <param name = "_pcrSelect"> List indicating the PCR included in pcrDigest </param>
        /// <param name = "_pcrDigest"> Digest of the selected PCR using nameAlg of the object for
        ///        which this structure is being created
        ///        pcrDigest.size shall be zero if the pcrSelect list is empty. </param>
        /// <param name = "_locality"> The locality at which the object was created </param>
        /// <param name = "_parentNameAlg"> NameAlg of the parent </param>
        /// <param name = "_parentName"> Name of the parent at time of creation
        ///        The size will match digest size associated with parentNameAlg unless it is
        ///        TPM_ALG_NULL, in which case the size will be 4 and parentName will be the hierarchy
        ///        handle. </param>
        /// <param name = "_parentQualifiedName"> Qualified Name of the parent at the time of creation
        ///        Size is the same as parentName. </param>
        /// <param name = "_outsideInfo"> Association with additional information added by the key creator
        ///        This will be the contents of the outsideInfo parameter in TPM2_Create() or
        ///        TPM2_CreatePrimary(). </param>
        public CreationData(PcrSelection[] _pcrSelect, byte[] _pcrDigest, LocalityAttr _locality, TpmAlgId _parentNameAlg, byte[] _parentName, byte[] _parentQualifiedName, byte[] _outsideInfo)
        {
            pcrSelect = _pcrSelect;
            pcrDigest = _pcrDigest;
            locality = _locality;
            parentNameAlg = _parentNameAlg;
            parentName = _parentName;
            parentQualifiedName = _parentQualifiedName;
            outsideInfo = _outsideInfo;
        }

        new public CreationData Copy() { return CreateCopy<CreationData>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This structure is created by TPM2_Create() and TPM2_CreatePrimary(). It is
    /// never entered into the TPM and never has a size of zero. </summary>
    [DataContract]
    [KnownType(typeof(CreationData))]
    [SpecTypeName("TPM2B_CREATION_DATA")]
    public partial class Tpm2bCreationData: TpmStructureBase
    {
        [MarshalAs(0, MarshalType.SizedStruct, "size", 2)]
        [DataMember()]
        public CreationData creationData { get; set; }

        public Tpm2bCreationData() {}

        public Tpm2bCreationData(Tpm2bCreationData src) { creationData = src.creationData; }

        /// <param name = "_creationData"> TBD </param>
        public Tpm2bCreationData(CreationData _creationData) { creationData = _creationData; }

        new public Tpm2bCreationData Copy() { return CreateCopy<Tpm2bCreationData>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> TPMS_AC_OUTPUT is used to return information about an AC. The tag structure
    /// parameter indicates the type of the data value. </summary>
    [DataContract]
    [KnownType(typeof(At))]
    [SpecTypeName("TPMS_AC_OUTPUT")]
    public partial class AcOutput: TpmStructureBase
    {
        /// <summary> Tag indicating the contents of data </summary>
        [MarshalAs(0)]
        [DataMember()]
        public At tag { get; set; }

        /// <summary> The data returned from the AC </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint data { get; set; }

        public AcOutput() {}

        public AcOutput(AcOutput src)
        {
            tag = src.tag;
            data = src.data;
        }

        /// <param name = "_tag"> Tag indicating the contents of data </param>
        /// <param name = "_data"> The data returned from the AC </param>
        public AcOutput(At _tag, uint _data)
        {
            tag = _tag;
            data = _data;
        }

        new public AcOutput Copy() { return CreateCopy<AcOutput>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This list is only used in TPM2_AC_GetCapability(). </summary>
    [DataContract]
    [SpecTypeName("TPML_AC_CAPABILITIES")]
    public partial class AcCapabilitiesArray: TpmStructureBase
    {
        /// <summary> A list of AC values </summary>
        [Range(MaxVal = 127u /*MAX_AC_CAPABILITIES*/)]
        [MarshalAs(0, MarshalType.VariableLengthArray, "count", 4)]
        [DataMember()]
        public AcOutput[] acCapabilities;

        public AcCapabilitiesArray() {}

        public AcCapabilitiesArray(AcCapabilitiesArray src) { acCapabilities = src.acCapabilities; }

        /// <param name = "_acCapabilities"> A list of AC values </param>
        public AcCapabilitiesArray(AcOutput[] _acCapabilities) { acCapabilities = _acCapabilities; }

        new public AcCapabilitiesArray Copy() { return CreateCopy<AcCapabilitiesArray>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> TPM2_Startup() is always preceded by _TPM_Init, which is the physical
    /// indication that TPM initialization is necessary because of a system-wide reset.
    /// TPM2_Startup() is only valid after _TPM_Init. Additional TPM2_Startup() commands are
    /// not allowed after it has completed successfully. If a TPM requires TPM2_Startup() and
    /// another command is received, or if the TPM receives TPM2_Startup() when it is not
    /// required, the TPM shall return TPM_RC_INITIALIZE. </summary>
    [DataContract]
    [KnownType(typeof(Su))]
    [SpecTypeName("Startup_In")]
    public partial class Tpm2StartupRequest: TpmStructureBase
    {
        /// <summary> TPM_SU_CLEAR or TPM_SU_STATE </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Su startupType { get; set; }

        public Tpm2StartupRequest() {}

        /// <param name = "_startupType"> TPM_SU_CLEAR or TPM_SU_STATE </param>
        public Tpm2StartupRequest(Su _startupType) { startupType = _startupType; }

        new public Tpm2StartupRequest Copy() { return CreateCopy<Tpm2StartupRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to prepare the TPM for a power cycle. The shutdownType
    /// parameter indicates how the subsequent TPM2_Startup() will be processed. </summary>
    [DataContract]
    [KnownType(typeof(Su))]
    [SpecTypeName("Shutdown_In")]
    public partial class Tpm2ShutdownRequest: TpmStructureBase
    {
        /// <summary> TPM_SU_CLEAR or TPM_SU_STATE </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Su shutdownType { get; set; }

        public Tpm2ShutdownRequest() {}

        /// <param name = "_shutdownType"> TPM_SU_CLEAR or TPM_SU_STATE </param>
        public Tpm2ShutdownRequest(Su _shutdownType) { shutdownType = _shutdownType; }

        new public Tpm2ShutdownRequest Copy() { return CreateCopy<Tpm2ShutdownRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command causes the TPM to perform a test of its capabilities. If the
    /// fullTest is YES, the TPM will test all functions. If fullTest = NO, the TPM will only
    /// test those functions that have not previously been tested. </summary>
    [DataContract]
    [SpecTypeName("SelfTest_In")]
    public partial class Tpm2SelfTestRequest: TpmStructureBase
    {
        /// <summary> YES if full test to be performed
        /// NO if only test of untested functions required </summary>
        [MarshalAs(0)]
        [DataMember()]
        public byte fullTest { get; set; }

        public Tpm2SelfTestRequest() {}

        /// <param name = "_fullTest"> YES if full test to be performed
        ///        NO if only test of untested functions required </param>
        public Tpm2SelfTestRequest(byte _fullTest) { fullTest = _fullTest; }

        new public Tpm2SelfTestRequest Copy() { return CreateCopy<Tpm2SelfTestRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command causes the TPM to perform a test of the selected algorithms. </summary>
    [DataContract]
    [SpecTypeName("IncrementalSelfTest_In")]
    public partial class Tpm2IncrementalSelfTestRequest: TpmStructureBase
    {
        /// <summary> List of algorithms that should be tested </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "toTestCount", 4)]
        [DataMember()]
        public TpmAlgId[] toTest;

        public Tpm2IncrementalSelfTestRequest() {}

        /// <param name = "_toTest"> List of algorithms that should be tested </param>
        public Tpm2IncrementalSelfTestRequest(TpmAlgId[] _toTest) { toTest = _toTest; }

        new public Tpm2IncrementalSelfTestRequest Copy() { return CreateCopy<Tpm2IncrementalSelfTestRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command causes the TPM to perform a test of the selected algorithms. </summary>
    [DataContract]
    [SpecTypeName("IncrementalSelfTest_Out")]
    public partial class Tpm2IncrementalSelfTestResponse: TpmStructureBase
    {
        /// <summary> List of algorithms that need testing </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "toDoListCount", 4)]
        [DataMember()]
        public TpmAlgId[] toDoList;

        public Tpm2IncrementalSelfTestResponse() {}

        public Tpm2IncrementalSelfTestResponse(Tpm2IncrementalSelfTestResponse src) { toDoList = src.toDoList; }

        new public Tpm2IncrementalSelfTestResponse Copy() { return CreateCopy<Tpm2IncrementalSelfTestResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns manufacturer-specific information regarding the results
    /// of a self-test and an indication of the test status. </summary>
    [DataContract]
    [SpecTypeName("GetTestResult_In")]
    public partial class Tpm2GetTestResultRequest: TpmStructureBase
    {
        public Tpm2GetTestResultRequest() {}

        new public Tpm2GetTestResultRequest Copy() { return CreateCopy<Tpm2GetTestResultRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns manufacturer-specific information regarding the results
    /// of a self-test and an indication of the test status. </summary>
    [DataContract]
    [KnownType(typeof(TpmRc))]
    [SpecTypeName("GetTestResult_Out")]
    public partial class Tpm2GetTestResultResponse: TpmStructureBase
    {
        /// <summary> Test result data
        /// contains manufacturer-specific information </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outDataSize", 2)]
        [DataMember()]
        public byte[] outData;

        [MarshalAs(1)]
        [DataMember()]
        public TpmRc testResult { get; set; }

        public Tpm2GetTestResultResponse() {}

        public Tpm2GetTestResultResponse(Tpm2GetTestResultResponse src)
        {
            outData = src.outData;
            testResult = src.testResult;
        }

        new public Tpm2GetTestResultResponse Copy() { return CreateCopy<Tpm2GetTestResultResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to start an authorization session using alternative
    /// methods of establishing the session key (sessionKey). The session key is then used to
    /// derive values used for authorization and for encrypting parameters. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmSe))]
    [KnownType(typeof(SymDef))]
    [SpecTypeName("StartAuthSession_In")]
    public partial class Tpm2StartAuthSessionRequest: TpmStructureBase
    {
        /// <summary> Handle of a loaded decrypt key used to encrypt salt
        /// may be TPM_RH_NULL
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle tpmKey { get; set; }

        /// <summary> Entity providing the authValue
        /// may be TPM_RH_NULL
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle bind { get; set; }

        /// <summary> Initial nonceCaller, sets nonceTPM size for the session
        /// shall be at least 16 octets </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "nonceCallerSize", 2)]
        [DataMember()]
        public byte[] nonceCaller;

        /// <summary> Value encrypted according to the type of tpmKey
        /// If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer. </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "encryptedSaltSize", 2)]
        [DataMember()]
        public byte[] encryptedSalt;

        /// <summary> Indicates the type of the session; simple HMAC or policy (including a trial
        /// policy) </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TpmSe sessionType { get; set; }

        /// <summary> The algorithm and key size for parameter encryption
        /// may select TPM_ALG_NULL </summary>
        [MarshalAs(5)]
        [DataMember()]
        public SymDef symmetric { get; set; }

        /// <summary> Hash algorithm to use for the session
        /// Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL </summary>
        [MarshalAs(6)]
        [DataMember()]
        public TpmAlgId authHash { get; set; }

        public Tpm2StartAuthSessionRequest()
        {
            tpmKey = new TpmHandle();
            bind = new TpmHandle();
            authHash = TpmAlgId.Null;
        }

        /// <param name = "_tpmKey"> Handle of a loaded decrypt key used to encrypt salt
        ///        may be TPM_RH_NULL
        ///        Auth Index: None </param>
        /// <param name = "_bind"> Entity providing the authValue
        ///        may be TPM_RH_NULL
        ///        Auth Index: None </param>
        /// <param name = "_nonceCaller"> Initial nonceCaller, sets nonceTPM size for the session
        ///        shall be at least 16 octets </param>
        /// <param name = "_encryptedSalt"> Value encrypted according to the type of tpmKey
        ///        If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer. </param>
        /// <param name = "_sessionType"> Indicates the type of the session; simple HMAC or policy
        ///        (including a trial policy) </param>
        /// <param name = "_symmetric"> The algorithm and key size for parameter encryption
        ///        may select TPM_ALG_NULL </param>
        /// <param name = "_authHash"> Hash algorithm to use for the session
        ///        Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL </param>
        public Tpm2StartAuthSessionRequest(TpmHandle _tpmKey, TpmHandle _bind, byte[] _nonceCaller, byte[] _encryptedSalt, TpmSe _sessionType, SymDef _symmetric, TpmAlgId _authHash)
        {
            tpmKey = _tpmKey;
            bind = _bind;
            nonceCaller = _nonceCaller;
            encryptedSalt = _encryptedSalt;
            sessionType = _sessionType;
            symmetric = _symmetric;
            authHash = _authHash;
        }

        new public Tpm2StartAuthSessionRequest Copy() { return CreateCopy<Tpm2StartAuthSessionRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to start an authorization session using alternative
    /// methods of establishing the session key (sessionKey). The session key is then used to
    /// derive values used for authorization and for encrypting parameters. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("StartAuthSession_Out")]
    public partial class Tpm2StartAuthSessionResponse: TpmStructureBase
    {
        /// <summary> Handle for the newly created session </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> The initial nonce from the TPM, used in the computation of the sessionKey </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nonceTPMSize", 2)]
        [DataMember()]
        public byte[] nonceTPM;

        public Tpm2StartAuthSessionResponse() { handle = new TpmHandle(); }

        public Tpm2StartAuthSessionResponse(Tpm2StartAuthSessionResponse src)
        {
            handle = src.handle;
            nonceTPM = src.nonceTPM;
        }

        new public Tpm2StartAuthSessionResponse Copy() { return CreateCopy<Tpm2StartAuthSessionResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows a policy authorization session to be returned to its
    /// initial state. This command is used after the TPM returns TPM_RC_PCR_CHANGED. That
    /// response code indicates that a policy will fail because the PCR have changed after
    /// TPM2_PolicyPCR() was executed. Restarting the session allows the authorizations to be
    /// replayed because the session restarts with the same nonceTPM. If the PCR are valid for
    /// the policy, the policy may then succeed. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyRestart_In")]
    public partial class Tpm2PolicyRestartRequest: TpmStructureBase
    {
        /// <summary> The handle for the policy session </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sessionHandle { get; set; }

        public Tpm2PolicyRestartRequest() { sessionHandle = new TpmHandle(); }

        /// <param name = "_sessionHandle"> The handle for the policy session </param>
        public Tpm2PolicyRestartRequest(TpmHandle _sessionHandle) { sessionHandle = _sessionHandle; }

        new public Tpm2PolicyRestartRequest Copy() { return CreateCopy<Tpm2PolicyRestartRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to create an object that can be loaded into a TPM using
    /// TPM2_Load(). If the command completes successfully, the TPM will create the new object
    /// and return the objects creation data (creationData), its public area (outPublic), and
    /// its encrypted sensitive area (outPrivate). Preservation of the returned data is the
    /// responsibility of the caller. The object will need to be loaded (TPM2_Load()) before
    /// it may be used. The only difference between the inPublic TPMT_PUBLIC template and the
    /// outPublic TPMT_PUBLIC object is in the unique field. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SensitiveCreate))]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("Create_In")]
    public partial class Tpm2CreateRequest: TpmStructureBase
    {
        /// <summary> Handle of parent for new object
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }

        /// <summary> The sensitive data </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inSensitiveSize", 2)]
        [DataMember()]
        public SensitiveCreate inSensitive { get; set; }

        /// <summary> The public template </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "inPublicSize", 2)]
        [DataMember()]
        public TpmPublic inPublic { get; set; }

        /// <summary> Data that will be included in the creation data for this object to provide
        /// permanent, verifiable linkage between this object and some object owner data </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "outsideInfoSize", 2)]
        [DataMember()]
        public byte[] outsideInfo;

        /// <summary> PCR that will be used in creation data </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "creationPCRCount", 4)]
        [DataMember()]
        public PcrSelection[] creationPCR;

        public Tpm2CreateRequest() { parentHandle = new TpmHandle(); }

        /// <param name = "_parentHandle"> Handle of parent for new object
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_inSensitive"> The sensitive data </param>
        /// <param name = "_inPublic"> The public template </param>
        /// <param name = "_outsideInfo"> Data that will be included in the creation data for this
        ///        object to provide permanent, verifiable linkage between this object and some object
        ///        owner data </param>
        /// <param name = "_creationPCR"> PCR that will be used in creation data </param>
        public Tpm2CreateRequest(TpmHandle _parentHandle, SensitiveCreate _inSensitive, TpmPublic _inPublic, byte[] _outsideInfo, PcrSelection[] _creationPCR)
        {
            parentHandle = _parentHandle;
            inSensitive = _inSensitive;
            inPublic = _inPublic;
            outsideInfo = _outsideInfo;
            creationPCR = _creationPCR;
        }

        new public Tpm2CreateRequest Copy() { return CreateCopy<Tpm2CreateRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to create an object that can be loaded into a TPM using
    /// TPM2_Load(). If the command completes successfully, the TPM will create the new object
    /// and return the objects creation data (creationData), its public area (outPublic), and
    /// its encrypted sensitive area (outPrivate). Preservation of the returned data is the
    /// responsibility of the caller. The object will need to be loaded (TPM2_Load()) before
    /// it may be used. The only difference between the inPublic TPMT_PUBLIC template and the
    /// outPublic TPMT_PUBLIC object is in the unique field. </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [KnownType(typeof(CreationData))]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(TkCreation))]
    [SpecTypeName("Create_Out")]
    public partial class Tpm2CreateResponse: TpmStructureBase
    {
        /// <summary> The private portion of the object </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPrivate outPrivate { get; set; }

        /// <summary> The public portion of the created object </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "outPublicSize", 2)]
        [DataMember()]
        public TpmPublic outPublic { get; set; }

        /// <summary> Contains a TPMS_CREATION_DATA </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "creationDataSize", 2)]
        [DataMember()]
        public CreationData creationData { get; set; }

        /// <summary> Digest of creationData using nameAlg of outPublic </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "creationHashSize", 2)]
        [DataMember()]
        public byte[] creationHash;

        /// <summary> Ticket used by TPM2_CertifyCreation() to validate that the creation data was
        /// produced by the TPM </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TkCreation creationTicket { get; set; }

        public Tpm2CreateResponse() {}

        public Tpm2CreateResponse(Tpm2CreateResponse src)
        {
            outPrivate = src.outPrivate;
            outPublic = src.outPublic;
            creationData = src.creationData;
            creationHash = src.creationHash;
            creationTicket = src.creationTicket;
        }

        new public Tpm2CreateResponse Copy() { return CreateCopy<Tpm2CreateResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to load objects into the TPM. This command is used when
    /// both a TPM2B_PUBLIC and TPM2B_PRIVATE are to be loaded. If only a TPM2B_PUBLIC is to
    /// be loaded, the TPM2_LoadExternal command is used. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPrivate))]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("Load_In")]
    public partial class Tpm2LoadRequest: TpmStructureBase
    {
        /// <summary> TPM handle of parent key; shall not be a reserved handle
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }

        /// <summary> The private portion of the object </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmPrivate inPrivate { get; set; }

        /// <summary> The public portion of the object </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "inPublicSize", 2)]
        [DataMember()]
        public TpmPublic inPublic { get; set; }

        public Tpm2LoadRequest() { parentHandle = new TpmHandle(); }

        /// <param name = "_parentHandle"> TPM handle of parent key; shall not be a reserved handle
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_inPrivate"> The private portion of the object </param>
        /// <param name = "_inPublic"> The public portion of the object </param>
        public Tpm2LoadRequest(TpmHandle _parentHandle, TpmPrivate _inPrivate, TpmPublic _inPublic)
        {
            parentHandle = _parentHandle;
            inPrivate = _inPrivate;
            inPublic = _inPublic;
        }

        new public Tpm2LoadRequest Copy() { return CreateCopy<Tpm2LoadRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to load objects into the TPM. This command is used when
    /// both a TPM2B_PUBLIC and TPM2B_PRIVATE are to be loaded. If only a TPM2B_PUBLIC is to
    /// be loaded, the TPM2_LoadExternal command is used. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("Load_Out")]
    public partial class Tpm2LoadResponse: TpmStructureBase
    {
        /// <summary> Handle of type TPM_HT_TRANSIENT for the loaded object </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> Name of the loaded object </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;

        public Tpm2LoadResponse() { handle = new TpmHandle(); }

        public Tpm2LoadResponse(Tpm2LoadResponse src)
        {
            handle = src.handle;
            name = src.name;
        }

        new public Tpm2LoadResponse Copy() { return CreateCopy<Tpm2LoadResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to load an object that is not a Protected Object into
    /// the TPM. The command allows loading of a public area or both a public and sensitive
    /// area. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(Sensitive))]
    [SpecTypeName("LoadExternal_In")]
    public partial class Tpm2LoadExternalRequest: TpmStructureBase
    {
        /// <summary> The sensitive portion of the object (optional) </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "inPrivateSize", 2)]
        [DataMember()]
        public Sensitive inPrivate { get; set; }

        /// <summary> The public portion of the object </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inPublicSize", 2)]
        [DataMember()]
        public TpmPublic inPublic { get; set; }

        /// <summary> Hierarchy with which the object area is associated </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }

        public Tpm2LoadExternalRequest() { hierarchy = new TpmHandle(); }

        /// <param name = "_inPrivate"> The sensitive portion of the object (optional) </param>
        /// <param name = "_inPublic"> The public portion of the object </param>
        /// <param name = "_hierarchy"> Hierarchy with which the object area is associated </param>
        public Tpm2LoadExternalRequest(Sensitive _inPrivate, TpmPublic _inPublic, TpmHandle _hierarchy)
        {
            inPrivate = _inPrivate;
            inPublic = _inPublic;
            hierarchy = _hierarchy;
        }

        new public Tpm2LoadExternalRequest Copy() { return CreateCopy<Tpm2LoadExternalRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to load an object that is not a Protected Object into
    /// the TPM. The command allows loading of a public area or both a public and sensitive
    /// area. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("LoadExternal_Out")]
    public partial class Tpm2LoadExternalResponse: TpmStructureBase
    {
        /// <summary> Handle of type TPM_HT_TRANSIENT for the loaded object </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> Name of the loaded object </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;

        public Tpm2LoadExternalResponse() { handle = new TpmHandle(); }

        public Tpm2LoadExternalResponse(Tpm2LoadExternalResponse src)
        {
            handle = src.handle;
            name = src.name;
        }

        new public Tpm2LoadExternalResponse Copy() { return CreateCopy<Tpm2LoadExternalResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows access to the public area of a loaded object. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ReadPublic_In")]
    public partial class Tpm2ReadPublicRequest: TpmStructureBase
    {
        /// <summary> TPM handle of an object
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }

        public Tpm2ReadPublicRequest() { objectHandle = new TpmHandle(); }

        /// <param name = "_objectHandle"> TPM handle of an object
        ///        Auth Index: None </param>
        public Tpm2ReadPublicRequest(TpmHandle _objectHandle) { objectHandle = _objectHandle; }

        new public Tpm2ReadPublicRequest Copy() { return CreateCopy<Tpm2ReadPublicRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows access to the public area of a loaded object. </summary>
    [DataContract]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("ReadPublic_Out")]
    public partial class Tpm2ReadPublicResponse: TpmStructureBase
    {
        /// <summary> Structure containing the public area of an object </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "outPublicSize", 2)]
        [DataMember()]
        public TpmPublic outPublic { get; set; }

        /// <summary> Name of the object </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;

        /// <summary> The Qualified Name of the object </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifiedNameSize", 2)]
        [DataMember()]
        public byte[] qualifiedName;

        public Tpm2ReadPublicResponse() {}

        public Tpm2ReadPublicResponse(Tpm2ReadPublicResponse src)
        {
            outPublic = src.outPublic;
            name = src.name;
            qualifiedName = src.qualifiedName;
        }

        new public Tpm2ReadPublicResponse Copy() { return CreateCopy<Tpm2ReadPublicResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command enables the association of a credential with an object in a way
    /// that ensures that the TPM has validated the parameters of the credentialed object. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(IdObject))]
    [SpecTypeName("ActivateCredential_In")]
    public partial class Tpm2ActivateCredentialRequest: TpmStructureBase
    {
        /// <summary> Handle of the object associated with certificate in credentialBlob
        /// Auth Index: 1
        /// Auth Role: ADMIN </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle activateHandle { get; set; }

        /// <summary> Loaded key used to decrypt the TPMS_SENSITIVE in credentialBlob
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> The credential </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "credentialBlobSize", 2)]
        [DataMember()]
        public IdObject credentialBlob { get; set; }

        /// <summary> KeyHandle algorithm-dependent encrypted seed that protects credentialBlob </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "secretSize", 2)]
        [DataMember()]
        public byte[] secret;

        public Tpm2ActivateCredentialRequest()
        {
            activateHandle = new TpmHandle();
            keyHandle = new TpmHandle();
        }

        /// <param name = "_activateHandle"> Handle of the object associated with certificate in credentialBlob
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "_keyHandle"> Loaded key used to decrypt the TPMS_SENSITIVE in credentialBlob
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "_credentialBlob"> The credential </param>
        /// <param name = "_secret"> KeyHandle algorithm-dependent encrypted seed that protects
        ///        credentialBlob </param>
        public Tpm2ActivateCredentialRequest(TpmHandle _activateHandle, TpmHandle _keyHandle, IdObject _credentialBlob, byte[] _secret)
        {
            activateHandle = _activateHandle;
            keyHandle = _keyHandle;
            credentialBlob = _credentialBlob;
            secret = _secret;
        }

        new public Tpm2ActivateCredentialRequest Copy() { return CreateCopy<Tpm2ActivateCredentialRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command enables the association of a credential with an object in a way
    /// that ensures that the TPM has validated the parameters of the credentialed object. </summary>
    [DataContract]
    [SpecTypeName("ActivateCredential_Out")]
    public partial class Tpm2ActivateCredentialResponse: TpmStructureBase
    {
        /// <summary> The decrypted certificate information
        /// the data should be no larger than the size of the digest of the nameAlg associated
        /// with keyHandle </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "certInfoSize", 2)]
        [DataMember()]
        public byte[] certInfo;

        public Tpm2ActivateCredentialResponse() {}

        public Tpm2ActivateCredentialResponse(Tpm2ActivateCredentialResponse src) { certInfo = src.certInfo; }

        new public Tpm2ActivateCredentialResponse Copy() { return CreateCopy<Tpm2ActivateCredentialResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows the TPM to perform the actions required of a Certificate
    /// Authority (CA) in creating a TPM2B_ID_OBJECT containing an activation credential. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("MakeCredential_In")]
    public partial class Tpm2MakeCredentialRequest: TpmStructureBase
    {
        /// <summary> Loaded public area, used to encrypt the sensitive area containing the
        /// credential key
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> The credential information </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "credentialSize", 2)]
        [DataMember()]
        public byte[] credential;

        /// <summary> Name of the object to which the credential applies </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "objectNameSize", 2)]
        [DataMember()]
        public byte[] objectName;

        public Tpm2MakeCredentialRequest() { handle = new TpmHandle(); }

        /// <param name = "_handle"> Loaded public area, used to encrypt the sensitive area containing
        ///        the credential key
        ///        Auth Index: None </param>
        /// <param name = "_credential"> The credential information </param>
        /// <param name = "_objectName"> Name of the object to which the credential applies </param>
        public Tpm2MakeCredentialRequest(TpmHandle _handle, byte[] _credential, byte[] _objectName)
        {
            handle = _handle;
            credential = _credential;
            objectName = _objectName;
        }

        new public Tpm2MakeCredentialRequest Copy() { return CreateCopy<Tpm2MakeCredentialRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows the TPM to perform the actions required of a Certificate
    /// Authority (CA) in creating a TPM2B_ID_OBJECT containing an activation credential. </summary>
    [DataContract]
    [KnownType(typeof(IdObject))]
    [SpecTypeName("MakeCredential_Out")]
    public partial class Tpm2MakeCredentialResponse: TpmStructureBase
    {
        /// <summary> The credential </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "credentialBlobSize", 2)]
        [DataMember()]
        public IdObject credentialBlob { get; set; }

        /// <summary> Handle algorithm-dependent data that wraps the key that encrypts
        /// credentialBlob </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "secretSize", 2)]
        [DataMember()]
        public byte[] secret;

        public Tpm2MakeCredentialResponse() {}

        public Tpm2MakeCredentialResponse(Tpm2MakeCredentialResponse src)
        {
            credentialBlob = src.credentialBlob;
            secret = src.secret;
        }

        new public Tpm2MakeCredentialResponse Copy() { return CreateCopy<Tpm2MakeCredentialResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the data in a loaded Sealed Data Object. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("Unseal_In")]
    public partial class Tpm2UnsealRequest: TpmStructureBase
    {
        /// <summary> Handle of a loaded data object
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle itemHandle { get; set; }

        public Tpm2UnsealRequest() { itemHandle = new TpmHandle(); }

        /// <param name = "_itemHandle"> Handle of a loaded data object
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        public Tpm2UnsealRequest(TpmHandle _itemHandle) { itemHandle = _itemHandle; }

        new public Tpm2UnsealRequest Copy() { return CreateCopy<Tpm2UnsealRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the data in a loaded Sealed Data Object. </summary>
    [DataContract]
    [SpecTypeName("Unseal_Out")]
    public partial class Tpm2UnsealResponse: TpmStructureBase
    {
        /// <summary> Unsealed data
        /// Size of outData is limited to be no more than 128 octets. </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outDataSize", 2)]
        [DataMember()]
        public byte[] outData;

        public Tpm2UnsealResponse() {}

        public Tpm2UnsealResponse(Tpm2UnsealResponse src) { outData = src.outData; }

        new public Tpm2UnsealResponse Copy() { return CreateCopy<Tpm2UnsealResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to change the authorization secret for a TPM-resident
    /// object. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ObjectChangeAuth_In")]
    public partial class Tpm2ObjectChangeAuthRequest: TpmStructureBase
    {
        /// <summary> Handle of the object
        /// Auth Index: 1
        /// Auth Role: ADMIN </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }

        /// <summary> Handle of the parent
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }

        /// <summary> New authorization value </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "newAuthSize", 2)]
        [DataMember()]
        public byte[] newAuth;

        public Tpm2ObjectChangeAuthRequest()
        {
            objectHandle = new TpmHandle();
            parentHandle = new TpmHandle();
        }

        /// <param name = "_objectHandle"> Handle of the object
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "_parentHandle"> Handle of the parent
        ///        Auth Index: None </param>
        /// <param name = "_newAuth"> New authorization value </param>
        public Tpm2ObjectChangeAuthRequest(TpmHandle _objectHandle, TpmHandle _parentHandle, byte[] _newAuth)
        {
            objectHandle = _objectHandle;
            parentHandle = _parentHandle;
            newAuth = _newAuth;
        }

        new public Tpm2ObjectChangeAuthRequest Copy() { return CreateCopy<Tpm2ObjectChangeAuthRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to change the authorization secret for a TPM-resident
    /// object. </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("ObjectChangeAuth_Out")]
    public partial class Tpm2ObjectChangeAuthResponse: TpmStructureBase
    {
        /// <summary> Private area containing the new authorization value </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPrivate outPrivate { get; set; }

        public Tpm2ObjectChangeAuthResponse() {}

        public Tpm2ObjectChangeAuthResponse(Tpm2ObjectChangeAuthResponse src) { outPrivate = src.outPrivate; }

        new public Tpm2ObjectChangeAuthResponse Copy() { return CreateCopy<Tpm2ObjectChangeAuthResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command creates an object and loads it in the TPM. This command allows
    /// creation of any type of object (Primary, Ordinary, or Derived) depending on the type
    /// of parentHandle. If parentHandle references a Primary Seed, then a Primary Object is
    /// created; if parentHandle references a Storage Parent, then an Ordinary Object is
    /// created; and if parentHandle references a Derivation Parent, then a Derived Object is
    /// generated. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SensitiveCreate))]
    [SpecTypeName("CreateLoaded_In")]
    public partial class Tpm2CreateLoadedRequest: TpmStructureBase
    {
        /// <summary> Handle of a transient storage key, a persistent storage key,
        /// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }

        /// <summary> The sensitive data, see TPM 2.0 Part 1 Sensitive Values </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inSensitiveSize", 2)]
        [DataMember()]
        public SensitiveCreate inSensitive { get; set; }

        /// <summary> The public template </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "inPublicSize", 2)]
        [DataMember()]
        public byte[] inPublic;

        public Tpm2CreateLoadedRequest() { parentHandle = new TpmHandle(); }

        /// <param name = "_parentHandle"> Handle of a transient storage key, a persistent storage
        ///        key, TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_inSensitive"> The sensitive data, see TPM 2.0 Part 1 Sensitive Values </param>
        /// <param name = "_inPublic"> The public template </param>
        public Tpm2CreateLoadedRequest(TpmHandle _parentHandle, SensitiveCreate _inSensitive, byte[] _inPublic)
        {
            parentHandle = _parentHandle;
            inSensitive = _inSensitive;
            inPublic = _inPublic;
        }

        new public Tpm2CreateLoadedRequest Copy() { return CreateCopy<Tpm2CreateLoadedRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command creates an object and loads it in the TPM. This command allows
    /// creation of any type of object (Primary, Ordinary, or Derived) depending on the type
    /// of parentHandle. If parentHandle references a Primary Seed, then a Primary Object is
    /// created; if parentHandle references a Storage Parent, then an Ordinary Object is
    /// created; and if parentHandle references a Derivation Parent, then a Derived Object is
    /// generated. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPrivate))]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("CreateLoaded_Out")]
    public partial class Tpm2CreateLoadedResponse: TpmStructureBase
    {
        /// <summary> Handle of type TPM_HT_TRANSIENT for created object </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> The sensitive area of the object (optional) </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmPrivate outPrivate { get; set; }

        /// <summary> The public portion of the created object </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "outPublicSize", 2)]
        [DataMember()]
        public TpmPublic outPublic { get; set; }

        /// <summary> The name of the created object </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;

        public Tpm2CreateLoadedResponse() { handle = new TpmHandle(); }

        public Tpm2CreateLoadedResponse(Tpm2CreateLoadedResponse src)
        {
            handle = src.handle;
            outPrivate = src.outPrivate;
            outPublic = src.outPublic;
            name = src.name;
        }

        new public Tpm2CreateLoadedResponse Copy() { return CreateCopy<Tpm2CreateLoadedResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command duplicates a loaded object so that it may be used in a
    /// different hierarchy. The new parent key for the duplicate may be on the same or
    /// different TPM or TPM_RH_NULL. Only the public area of newParentHandle is required to
    /// be loaded. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SymDefObject))]
    [SpecTypeName("Duplicate_In")]
    public partial class Tpm2DuplicateRequest: TpmStructureBase
    {
        /// <summary> Loaded object to duplicate
        /// Auth Index: 1
        /// Auth Role: DUP </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }

        /// <summary> Shall reference the public area of an asymmetric key
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle newParentHandle { get; set; }

        /// <summary> Optional symmetric encryption key
        /// The size for this key is set to zero when the TPM is to generate the key. This
        /// parameter may be encrypted. </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "encryptionKeyInSize", 2)]
        [DataMember()]
        public byte[] encryptionKeyIn;

        /// <summary> Definition for the symmetric algorithm to be used for the inner wrapper
        /// may be TPM_ALG_NULL if no inner wrapper is applied </summary>
        [MarshalAs(3)]
        [DataMember()]
        public SymDefObject symmetricAlg { get; set; }

        public Tpm2DuplicateRequest()
        {
            objectHandle = new TpmHandle();
            newParentHandle = new TpmHandle();
        }

        /// <param name = "_objectHandle"> Loaded object to duplicate
        ///        Auth Index: 1
        ///        Auth Role: DUP </param>
        /// <param name = "_newParentHandle"> Shall reference the public area of an asymmetric key
        ///        Auth Index: None </param>
        /// <param name = "_encryptionKeyIn"> Optional symmetric encryption key
        ///        The size for this key is set to zero when the TPM is to generate the key. This
        ///        parameter may be encrypted. </param>
        /// <param name = "_symmetricAlg"> Definition for the symmetric algorithm to be used for the
        ///        inner wrapper
        ///        may be TPM_ALG_NULL if no inner wrapper is applied </param>
        public Tpm2DuplicateRequest(TpmHandle _objectHandle, TpmHandle _newParentHandle, byte[] _encryptionKeyIn, SymDefObject _symmetricAlg)
        {
            objectHandle = _objectHandle;
            newParentHandle = _newParentHandle;
            encryptionKeyIn = _encryptionKeyIn;
            symmetricAlg = _symmetricAlg;
        }

        new public Tpm2DuplicateRequest Copy() { return CreateCopy<Tpm2DuplicateRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command duplicates a loaded object so that it may be used in a
    /// different hierarchy. The new parent key for the duplicate may be on the same or
    /// different TPM or TPM_RH_NULL. Only the public area of newParentHandle is required to
    /// be loaded. </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("Duplicate_Out")]
    public partial class Tpm2DuplicateResponse: TpmStructureBase
    {
        /// <summary> If the caller provided an encryption key or if symmetricAlg was
        /// TPM_ALG_NULL, then this will be the Empty Buffer; otherwise, it shall contain the
        /// TPM-generated, symmetric encryption key for the inner wrapper. </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "encryptionKeyOutSize", 2)]
        [DataMember()]
        public byte[] encryptionKeyOut;

        /// <summary> Private area that may be encrypted by encryptionKeyIn; and may be doubly
        /// encrypted </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmPrivate duplicate { get; set; }

        /// <summary> Seed protected by the asymmetric algorithms of new parent (NP) </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "outSymSeedSize", 2)]
        [DataMember()]
        public byte[] outSymSeed;

        public Tpm2DuplicateResponse() {}

        public Tpm2DuplicateResponse(Tpm2DuplicateResponse src)
        {
            encryptionKeyOut = src.encryptionKeyOut;
            duplicate = src.duplicate;
            outSymSeed = src.outSymSeed;
        }

        new public Tpm2DuplicateResponse Copy() { return CreateCopy<Tpm2DuplicateResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows the TPM to serve in the role as a Duplication Authority.
    /// If proper authorization for use of the oldParent is provided, then an HMAC key and a
    /// symmetric key are recovered from inSymSeed and used to integrity check and decrypt
    /// inDuplicate. A new protection seed value is generated according to the methods
    /// appropriate for newParent and the blob is re-encrypted and a new integrity value is
    /// computed. The re-encrypted blob is returned in outDuplicate and the symmetric key
    /// returned in outSymKey. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("Rewrap_In")]
    public partial class Tpm2RewrapRequest: TpmStructureBase
    {
        /// <summary> Parent of object
        /// Auth Index: 1
        /// Auth Role: User </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle oldParent { get; set; }

        /// <summary> New parent of the object
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle newParent { get; set; }

        /// <summary> An object encrypted using symmetric key derived from inSymSeed </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmPrivate inDuplicate { get; set; }

        /// <summary> The Name of the object being rewrapped </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;

        /// <summary> The seed for the symmetric key and HMAC key
        /// needs oldParent private key to recover the seed and generate the symmetric key </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "inSymSeedSize", 2)]
        [DataMember()]
        public byte[] inSymSeed;

        public Tpm2RewrapRequest()
        {
            oldParent = new TpmHandle();
            newParent = new TpmHandle();
        }

        /// <param name = "_oldParent"> Parent of object
        ///        Auth Index: 1
        ///        Auth Role: User </param>
        /// <param name = "_newParent"> New parent of the object
        ///        Auth Index: None </param>
        /// <param name = "_inDuplicate"> An object encrypted using symmetric key derived from
        ///        inSymSeed </param>
        /// <param name = "_name"> The Name of the object being rewrapped </param>
        /// <param name = "_inSymSeed"> The seed for the symmetric key and HMAC key
        ///        needs oldParent private key to recover the seed and generate the symmetric key </param>
        public Tpm2RewrapRequest(TpmHandle _oldParent, TpmHandle _newParent, TpmPrivate _inDuplicate, byte[] _name, byte[] _inSymSeed)
        {
            oldParent = _oldParent;
            newParent = _newParent;
            inDuplicate = _inDuplicate;
            name = _name;
            inSymSeed = _inSymSeed;
        }

        new public Tpm2RewrapRequest Copy() { return CreateCopy<Tpm2RewrapRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows the TPM to serve in the role as a Duplication Authority.
    /// If proper authorization for use of the oldParent is provided, then an HMAC key and a
    /// symmetric key are recovered from inSymSeed and used to integrity check and decrypt
    /// inDuplicate. A new protection seed value is generated according to the methods
    /// appropriate for newParent and the blob is re-encrypted and a new integrity value is
    /// computed. The re-encrypted blob is returned in outDuplicate and the symmetric key
    /// returned in outSymKey. </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("Rewrap_Out")]
    public partial class Tpm2RewrapResponse: TpmStructureBase
    {
        /// <summary> An object encrypted using symmetric key derived from outSymSeed </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPrivate outDuplicate { get; set; }

        /// <summary> Seed for a symmetric key protected by newParent asymmetric key </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "outSymSeedSize", 2)]
        [DataMember()]
        public byte[] outSymSeed;

        public Tpm2RewrapResponse() {}

        public Tpm2RewrapResponse(Tpm2RewrapResponse src)
        {
            outDuplicate = src.outDuplicate;
            outSymSeed = src.outSymSeed;
        }

        new public Tpm2RewrapResponse Copy() { return CreateCopy<Tpm2RewrapResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows an object to be encrypted using the symmetric encryption
    /// values of a Storage Key. After encryption, the object may be loaded and used in the
    /// new hierarchy. The imported object (duplicate) may be singly encrypted, multiply
    /// encrypted, or unencrypted. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TpmPrivate))]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(SymDefObject))]
    [SpecTypeName("Import_In")]
    public partial class Tpm2ImportRequest: TpmStructureBase
    {
        /// <summary> The handle of the new parent for the object
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle parentHandle { get; set; }

        /// <summary> The optional symmetric encryption key used as the inner wrapper for duplicate
        /// If symmetricAlg is TPM_ALG_NULL, then this parameter shall be the Empty Buffer. </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "encryptionKeySize", 2)]
        [DataMember()]
        public byte[] encryptionKey;

        /// <summary> The public area of the object to be imported
        /// This is provided so that the integrity value for duplicate and the object attributes
        /// can be checked.
        /// NOTE Even if the integrity value of the object is not checked on input, the object
        /// Name is required to create the integrity value for the imported object. </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "objectPublicSize", 2)]
        [DataMember()]
        public TpmPublic objectPublic { get; set; }

        /// <summary> The symmetrically encrypted duplicate object that may contain an inner
        /// symmetric wrapper </summary>
        [MarshalAs(3)]
        [DataMember()]
        public TpmPrivate duplicate { get; set; }

        /// <summary> The seed for the symmetric key and HMAC key
        /// inSymSeed is encrypted/encoded using the algorithms of newParent. </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "inSymSeedSize", 2)]
        [DataMember()]
        public byte[] inSymSeed;

        /// <summary> Definition for the symmetric algorithm to use for the inner wrapper
        /// If this algorithm is TPM_ALG_NULL, no inner wrapper is present and encryptionKey shall
        /// be the Empty Buffer. </summary>
        [MarshalAs(5)]
        [DataMember()]
        public SymDefObject symmetricAlg { get; set; }

        public Tpm2ImportRequest() { parentHandle = new TpmHandle(); }

        /// <param name = "_parentHandle"> The handle of the new parent for the object
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_encryptionKey"> The optional symmetric encryption key used as the inner
        ///        wrapper for duplicate
        ///        If symmetricAlg is TPM_ALG_NULL, then this parameter shall be the Empty Buffer. </param>
        /// <param name = "_objectPublic"> The public area of the object to be imported
        ///        This is provided so that the integrity value for duplicate and the object
        ///        attributes can be checked.
        ///        NOTE Even if the integrity value of the object is not checked on input, the object
        ///        Name is required to create the integrity value for the imported object. </param>
        /// <param name = "_duplicate"> The symmetrically encrypted duplicate object that may contain
        ///        an inner symmetric wrapper </param>
        /// <param name = "_inSymSeed"> The seed for the symmetric key and HMAC key
        ///        inSymSeed is encrypted/encoded using the algorithms of newParent. </param>
        /// <param name = "_symmetricAlg"> Definition for the symmetric algorithm to use for the inner
        ///        wrapper
        ///        If this algorithm is TPM_ALG_NULL, no inner wrapper is present and encryptionKey
        ///        shall be the Empty Buffer. </param>
        public Tpm2ImportRequest(TpmHandle _parentHandle, byte[] _encryptionKey, TpmPublic _objectPublic, TpmPrivate _duplicate, byte[] _inSymSeed, SymDefObject _symmetricAlg)
        {
            parentHandle = _parentHandle;
            encryptionKey = _encryptionKey;
            objectPublic = _objectPublic;
            duplicate = _duplicate;
            inSymSeed = _inSymSeed;
            symmetricAlg = _symmetricAlg;
        }

        new public Tpm2ImportRequest Copy() { return CreateCopy<Tpm2ImportRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows an object to be encrypted using the symmetric encryption
    /// values of a Storage Key. After encryption, the object may be loaded and used in the
    /// new hierarchy. The imported object (duplicate) may be singly encrypted, multiply
    /// encrypted, or unencrypted. </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [SpecTypeName("Import_Out")]
    public partial class Tpm2ImportResponse: TpmStructureBase
    {
        /// <summary> The sensitive area encrypted with the symmetric key of parentHandle </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPrivate outPrivate { get; set; }

        public Tpm2ImportResponse() {}

        public Tpm2ImportResponse(Tpm2ImportResponse src) { outPrivate = src.outPrivate; }

        new public Tpm2ImportResponse Copy() { return CreateCopy<Tpm2ImportResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs RSA encryption using the indicated padding scheme
    /// according to IETF RFC 8017. If the scheme of keyHandle is TPM_ALG_NULL, then the
    /// caller may use inScheme to specify the padding scheme. If scheme of keyHandle is not
    /// TPM_ALG_NULL, then inScheme shall either be TPM_ALG_NULL or be the same as scheme
    /// (TPM_RC_SCHEME). </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("RSA_Encrypt_In")]
    public partial class Tpm2RsaEncryptRequest: TpmStructureBase
    {
        /// <summary> Reference to public portion of RSA key to use for encryption
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> Message to be encrypted
        /// NOTE 1 The data type was chosen because it limits the overall size of the input to no
        /// greater than the size of the largest RSA public key. This may be larger than allowed
        /// for keyHandle. </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "messageSize", 2)]
        [DataMember()]
        public byte[] message;

        /// <summary> Scheme selector </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The padding scheme to use if scheme associated with keyHandle is
        /// TPM_ALG_NULL </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(3, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion inScheme { get; set; }

        /// <summary> Optional label L to be associated with the message
        /// Size of the buffer is zero if no label is present
        /// NOTE 2 See description of label above. </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "labelSize", 2)]
        [DataMember()]
        public byte[] label;

        public Tpm2RsaEncryptRequest() { keyHandle = new TpmHandle(); }

        /// <param name = "_keyHandle"> Reference to public portion of RSA key to use for encryption
        ///        Auth Index: None </param>
        /// <param name = "_message"> Message to be encrypted
        ///        NOTE 1 The data type was chosen because it limits the overall size of the input to
        ///        no greater than the size of the largest RSA public key. This may be larger than
        ///        allowed for keyHandle. </param>
        /// <param name = "_inScheme"> The padding scheme to use if scheme associated with keyHandle
        ///        is TPM_ALG_NULL
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        /// <param name = "_label"> Optional label L to be associated with the message
        ///        Size of the buffer is zero if no label is present
        ///        NOTE 2 See description of label above. </param>
        public Tpm2RsaEncryptRequest(TpmHandle _keyHandle, byte[] _message, IAsymSchemeUnion _inScheme, byte[] _label)
        {
            keyHandle = _keyHandle;
            message = _message;
            inScheme = _inScheme;
            label = _label;
        }

        new public Tpm2RsaEncryptRequest Copy() { return CreateCopy<Tpm2RsaEncryptRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs RSA encryption using the indicated padding scheme
    /// according to IETF RFC 8017. If the scheme of keyHandle is TPM_ALG_NULL, then the
    /// caller may use inScheme to specify the padding scheme. If scheme of keyHandle is not
    /// TPM_ALG_NULL, then inScheme shall either be TPM_ALG_NULL or be the same as scheme
    /// (TPM_RC_SCHEME). </summary>
    [DataContract]
    [SpecTypeName("RSA_Encrypt_Out")]
    public partial class Tpm2RsaEncryptResponse: TpmStructureBase
    {
        /// <summary> Encrypted output </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outDataSize", 2)]
        [DataMember()]
        public byte[] outData;

        public Tpm2RsaEncryptResponse() {}

        public Tpm2RsaEncryptResponse(Tpm2RsaEncryptResponse src) { outData = src.outData; }

        new public Tpm2RsaEncryptResponse Copy() { return CreateCopy<Tpm2RsaEncryptResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs RSA decryption using the indicated padding scheme
    /// according to IETF RFC 8017 ((PKCS#1). </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(EncSchemeOaep))]
    [KnownType(typeof(EncSchemeRsaes))]
    [KnownType(typeof(KeySchemeEcdh))]
    [KnownType(typeof(KeySchemeEcmqv))]
    [KnownType(typeof(NullAsymScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("RSA_Decrypt_In")]
    public partial class Tpm2RsaDecryptRequest: TpmStructureBase
    {
        /// <summary> RSA key to use for decryption
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> Cipher text to be decrypted
        /// NOTE An encrypted RSA data block is the size of the public modulus. </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "cipherTextSize", 2)]
        [DataMember()]
        public byte[] cipherText;

        /// <summary> Scheme selector </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The padding scheme to use if scheme associated with keyHandle is
        /// TPM_ALG_NULL </summary>
        /// <remarks> One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        /// SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        /// EncSchemeOaep, SchemeHash, NullAsymScheme. </remarks>
        [MarshalAs(3, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public IAsymSchemeUnion inScheme { get; set; }

        /// <summary> Label whose association with the message is to be verified </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "labelSize", 2)]
        [DataMember()]
        public byte[] label;

        public Tpm2RsaDecryptRequest() { keyHandle = new TpmHandle(); }

        /// <param name = "_keyHandle"> RSA key to use for decryption
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_cipherText"> Cipher text to be decrypted
        ///        NOTE An encrypted RSA data block is the size of the public modulus. </param>
        /// <param name = "_inScheme"> The padding scheme to use if scheme associated with keyHandle
        ///        is TPM_ALG_NULL
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        /// <param name = "_label"> Label whose association with the message is to be verified </param>
        public Tpm2RsaDecryptRequest(TpmHandle _keyHandle, byte[] _cipherText, IAsymSchemeUnion _inScheme, byte[] _label)
        {
            keyHandle = _keyHandle;
            cipherText = _cipherText;
            inScheme = _inScheme;
            label = _label;
        }

        new public Tpm2RsaDecryptRequest Copy() { return CreateCopy<Tpm2RsaDecryptRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs RSA decryption using the indicated padding scheme
    /// according to IETF RFC 8017 ((PKCS#1). </summary>
    [DataContract]
    [SpecTypeName("RSA_Decrypt_Out")]
    public partial class Tpm2RsaDecryptResponse: TpmStructureBase
    {
        /// <summary> Decrypted output </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "messageSize", 2)]
        [DataMember()]
        public byte[] message;

        public Tpm2RsaDecryptResponse() {}

        public Tpm2RsaDecryptResponse(Tpm2RsaDecryptResponse src) { message = src.message; }

        new public Tpm2RsaDecryptResponse Copy() { return CreateCopy<Tpm2RsaDecryptResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command uses the TPM to generate an ephemeral key pair (de, Qe where Qe
    /// [de]G). It uses the private ephemeral key and a loaded public key (QS) to compute the
    /// shared secret value (P [hde]QS). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ECDH_KeyGen_In")]
    public partial class Tpm2EcdhKeyGenRequest: TpmStructureBase
    {
        /// <summary> Handle of a loaded ECC key public area.
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        public Tpm2EcdhKeyGenRequest() { keyHandle = new TpmHandle(); }

        /// <param name = "_keyHandle"> Handle of a loaded ECC key public area.
        ///        Auth Index: None </param>
        public Tpm2EcdhKeyGenRequest(TpmHandle _keyHandle) { keyHandle = _keyHandle; }

        new public Tpm2EcdhKeyGenRequest Copy() { return CreateCopy<Tpm2EcdhKeyGenRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command uses the TPM to generate an ephemeral key pair (de, Qe where Qe
    /// [de]G). It uses the private ephemeral key and a loaded public key (QS) to compute the
    /// shared secret value (P [hde]QS). </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("ECDH_KeyGen_Out")]
    public partial class Tpm2EcdhKeyGenResponse: TpmStructureBase
    {
        /// <summary> Results of P h[de]Qs </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "zPointSize", 2)]
        [DataMember()]
        public EccPoint zPoint { get; set; }

        /// <summary> Generated ephemeral public point (Qe) </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "pubPointSize", 2)]
        [DataMember()]
        public EccPoint pubPoint { get; set; }

        public Tpm2EcdhKeyGenResponse() {}

        public Tpm2EcdhKeyGenResponse(Tpm2EcdhKeyGenResponse src)
        {
            zPoint = src.zPoint;
            pubPoint = src.pubPoint;
        }

        new public Tpm2EcdhKeyGenResponse Copy() { return CreateCopy<Tpm2EcdhKeyGenResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command uses the TPM to recover the Z value from a public point (QB)
    /// and a private key (ds). It will perform the multiplication of the provided inPoint
    /// (QB) with the private key (ds) and return the coordinates of the resultant point (Z =
    /// (xZ , yZ) [hds]QB; where h is the cofactor of the curve). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("ECDH_ZGen_In")]
    public partial class Tpm2EcdhZGenRequest: TpmStructureBase
    {
        /// <summary> Handle of a loaded ECC key
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> A public key </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inPointSize", 2)]
        [DataMember()]
        public EccPoint inPoint { get; set; }

        public Tpm2EcdhZGenRequest() { keyHandle = new TpmHandle(); }

        /// <param name = "_keyHandle"> Handle of a loaded ECC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_inPoint"> A public key </param>
        public Tpm2EcdhZGenRequest(TpmHandle _keyHandle, EccPoint _inPoint)
        {
            keyHandle = _keyHandle;
            inPoint = _inPoint;
        }

        new public Tpm2EcdhZGenRequest Copy() { return CreateCopy<Tpm2EcdhZGenRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command uses the TPM to recover the Z value from a public point (QB)
    /// and a private key (ds). It will perform the multiplication of the provided inPoint
    /// (QB) with the private key (ds) and return the coordinates of the resultant point (Z =
    /// (xZ , yZ) [hds]QB; where h is the cofactor of the curve). </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("ECDH_ZGen_Out")]
    public partial class Tpm2EcdhZGenResponse: TpmStructureBase
    {
        /// <summary> X and Y coordinates of the product of the multiplication Z = (xZ , yZ)
        /// [hdS]QB </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "outPointSize", 2)]
        [DataMember()]
        public EccPoint outPoint { get; set; }

        public Tpm2EcdhZGenResponse() {}

        public Tpm2EcdhZGenResponse(Tpm2EcdhZGenResponse src) { outPoint = src.outPoint; }

        new public Tpm2EcdhZGenResponse Copy() { return CreateCopy<Tpm2EcdhZGenResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the parameters of an ECC curve identified by its
    /// TCG-assigned curveID. </summary>
    [DataContract]
    [KnownType(typeof(EccCurve))]
    [SpecTypeName("ECC_Parameters_In")]
    public partial class Tpm2EccParametersRequest: TpmStructureBase
    {
        /// <summary> Parameter set selector </summary>
        [MarshalAs(0)]
        [DataMember()]
        public EccCurve curveID { get; set; }

        public Tpm2EccParametersRequest() {}

        /// <param name = "_curveID"> Parameter set selector </param>
        public Tpm2EccParametersRequest(EccCurve _curveID) { curveID = _curveID; }

        new public Tpm2EccParametersRequest Copy() { return CreateCopy<Tpm2EccParametersRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the parameters of an ECC curve identified by its
    /// TCG-assigned curveID. </summary>
    [DataContract]
    [KnownType(typeof(AlgorithmDetailEcc))]
    [SpecTypeName("ECC_Parameters_Out")]
    public partial class Tpm2EccParametersResponse: TpmStructureBase
    {
        /// <summary> ECC parameters for the selected curve </summary>
        [MarshalAs(0)]
        [DataMember()]
        public AlgorithmDetailEcc parameters { get; set; }

        public Tpm2EccParametersResponse() {}

        public Tpm2EccParametersResponse(Tpm2EccParametersResponse src) { parameters = src.parameters; }

        new public Tpm2EccParametersResponse Copy() { return CreateCopy<Tpm2EccParametersResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command supports two-phase key exchange protocols. The command is used
    /// in combination with TPM2_EC_Ephemeral(). TPM2_EC_Ephemeral() generates an ephemeral
    /// key and returns the public point of that ephemeral key along with a numeric value that
    /// allows the TPM to regenerate the associated private key. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("ZGen_2Phase_In")]
    public partial class Tpm2ZGen2PhaseRequest: TpmStructureBase
    {
        /// <summary> Handle of an unrestricted decryption key ECC
        /// The private key referenced by this handle is used as dS,A
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyA { get; set; }

        /// <summary> Other partys static public key (Qs,B = (Xs,B, Ys,B)) </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inQsBSize", 2)]
        [DataMember()]
        public EccPoint inQsB { get; set; }

        /// <summary> Other party's ephemeral public key (Qe,B = (Xe,B, Ye,B)) </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "inQeBSize", 2)]
        [DataMember()]
        public EccPoint inQeB { get; set; }

        /// <summary> The key exchange scheme </summary>
        [MarshalAs(3)]
        [DataMember()]
        public TpmAlgId inScheme { get; set; }

        /// <summary> Value returned by TPM2_EC_Ephemeral() </summary>
        [MarshalAs(4)]
        [DataMember()]
        public ushort counter { get; set; }

        public Tpm2ZGen2PhaseRequest()
        {
            keyA = new TpmHandle();
            inScheme = TpmAlgId.Null;
        }

        /// <param name = "_keyA"> Handle of an unrestricted decryption key ECC
        ///        The private key referenced by this handle is used as dS,A
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_inQsB"> Other partys static public key (Qs,B = (Xs,B, Ys,B)) </param>
        /// <param name = "_inQeB"> Other party's ephemeral public key (Qe,B = (Xe,B, Ye,B)) </param>
        /// <param name = "_inScheme"> The key exchange scheme </param>
        /// <param name = "_counter"> Value returned by TPM2_EC_Ephemeral() </param>
        public Tpm2ZGen2PhaseRequest(TpmHandle _keyA, EccPoint _inQsB, EccPoint _inQeB, TpmAlgId _inScheme, ushort _counter)
        {
            keyA = _keyA;
            inQsB = _inQsB;
            inQeB = _inQeB;
            inScheme = _inScheme;
            counter = _counter;
        }

        new public Tpm2ZGen2PhaseRequest Copy() { return CreateCopy<Tpm2ZGen2PhaseRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command supports two-phase key exchange protocols. The command is used
    /// in combination with TPM2_EC_Ephemeral(). TPM2_EC_Ephemeral() generates an ephemeral
    /// key and returns the public point of that ephemeral key along with a numeric value that
    /// allows the TPM to regenerate the associated private key. </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("ZGen_2Phase_Out")]
    public partial class Tpm2ZGen2PhaseResponse: TpmStructureBase
    {
        /// <summary> X and Y coordinates of the computed value (scheme dependent) </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "outZ1Size", 2)]
        [DataMember()]
        public EccPoint outZ1 { get; set; }

        /// <summary> X and Y coordinates of the second computed value (scheme dependent) </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "outZ2Size", 2)]
        [DataMember()]
        public EccPoint outZ2 { get; set; }

        public Tpm2ZGen2PhaseResponse() {}

        public Tpm2ZGen2PhaseResponse(Tpm2ZGen2PhaseResponse src)
        {
            outZ1 = src.outZ1;
            outZ2 = src.outZ2;
        }

        new public Tpm2ZGen2PhaseResponse Copy() { return CreateCopy<Tpm2ZGen2PhaseResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs ECC encryption as described in Part 1, Annex D. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(KdfSchemeKdf1Sp800108))]
    [KnownType(typeof(KdfSchemeKdf1Sp80056a))]
    [KnownType(typeof(KdfSchemeKdf2))]
    [KnownType(typeof(KdfSchemeMgf1))]
    [KnownType(typeof(NullKdfScheme))]
    [KnownType(typeof(SchemeHash))]
    [SpecTypeName("ECC_Encrypt_In")]
    public partial class Tpm2EccEncryptRequest: TpmStructureBase
    {
        /// <summary> Reference to public portion of ECC key to use for encryption
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> Plaintext to be encrypted </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "plainTextSize", 2)]
        [DataMember()]
        public byte[] plainText;

        /// <summary> Scheme selector </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The KDF to use if scheme associated with keyHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2,
        /// KdfSchemeKdf1Sp800108, SchemeHash, NullKdfScheme. </remarks>
        [MarshalAs(3, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public IKdfSchemeUnion inScheme { get; set; }

        public Tpm2EccEncryptRequest() { keyHandle = new TpmHandle(); }

        /// <param name = "_keyHandle"> Reference to public portion of ECC key to use for encryption
        ///        Auth Index: None </param>
        /// <param name = "_plainText"> Plaintext to be encrypted </param>
        /// <param name = "_inScheme"> The KDF to use if scheme associated with keyHandle is TPM_ALG_NULL
        ///        One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2, KdfSchemeKdf1Sp800108,
        ///        SchemeHash, NullKdfScheme. </param>
        public Tpm2EccEncryptRequest(TpmHandle _keyHandle, byte[] _plainText, IKdfSchemeUnion _inScheme)
        {
            keyHandle = _keyHandle;
            plainText = _plainText;
            inScheme = _inScheme;
        }

        new public Tpm2EccEncryptRequest Copy() { return CreateCopy<Tpm2EccEncryptRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs ECC encryption as described in Part 1, Annex D. </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("ECC_Encrypt_Out")]
    public partial class Tpm2EccEncryptResponse: TpmStructureBase
    {
        /// <summary> The public ephemeral key used for ECDH </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "C1Size", 2)]
        [DataMember()]
        public EccPoint C1 { get; set; }

        /// <summary> The data block produced by the XOR process </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "C2Size", 2)]
        [DataMember()]
        public byte[] C2;

        /// <summary> The integrity value </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "C3Size", 2)]
        [DataMember()]
        public byte[] C3;

        public Tpm2EccEncryptResponse() {}

        public Tpm2EccEncryptResponse(Tpm2EccEncryptResponse src)
        {
            C1 = src.C1;
            C2 = src.C2;
            C3 = src.C3;
        }

        new public Tpm2EccEncryptResponse Copy() { return CreateCopy<Tpm2EccEncryptResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs ECC decryption. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(KdfSchemeKdf1Sp800108))]
    [KnownType(typeof(KdfSchemeKdf1Sp80056a))]
    [KnownType(typeof(KdfSchemeKdf2))]
    [KnownType(typeof(KdfSchemeMgf1))]
    [KnownType(typeof(NullKdfScheme))]
    [KnownType(typeof(SchemeHash))]
    [SpecTypeName("ECC_Decrypt_In")]
    public partial class Tpm2EccDecryptRequest: TpmStructureBase
    {
        /// <summary> ECC key to use for decryption
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> The public ephemeral key used for ECDH </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "C1Size", 2)]
        [DataMember()]
        public EccPoint C1 { get; set; }

        /// <summary> The data block produced by the XOR process </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "C2Size", 2)]
        [DataMember()]
        public byte[] C2;

        /// <summary> The integrity value </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "C3Size", 2)]
        [DataMember()]
        public byte[] C3;

        /// <summary> Scheme selector </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The KDF to use if scheme associated with keyHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2,
        /// KdfSchemeKdf1Sp800108, SchemeHash, NullKdfScheme. </remarks>
        [MarshalAs(5, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public IKdfSchemeUnion inScheme { get; set; }

        public Tpm2EccDecryptRequest() { keyHandle = new TpmHandle(); }

        /// <param name = "_keyHandle"> ECC key to use for decryption
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_C1"> The public ephemeral key used for ECDH </param>
        /// <param name = "_C2"> The data block produced by the XOR process </param>
        /// <param name = "_C3"> The integrity value </param>
        /// <param name = "_inScheme"> The KDF to use if scheme associated with keyHandle is TPM_ALG_NULL
        ///        One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2, KdfSchemeKdf1Sp800108,
        ///        SchemeHash, NullKdfScheme. </param>
        public Tpm2EccDecryptRequest(TpmHandle _keyHandle, EccPoint _C1, byte[] _C2, byte[] _C3, IKdfSchemeUnion _inScheme)
        {
            keyHandle = _keyHandle;
            C1 = _C1;
            C2 = _C2;
            C3 = _C3;
            inScheme = _inScheme;
        }

        new public Tpm2EccDecryptRequest Copy() { return CreateCopy<Tpm2EccDecryptRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs ECC decryption. </summary>
    [DataContract]
    [SpecTypeName("ECC_Decrypt_Out")]
    public partial class Tpm2EccDecryptResponse: TpmStructureBase
    {
        /// <summary> Decrypted output </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "plainTextSize", 2)]
        [DataMember()]
        public byte[] plainText;

        public Tpm2EccDecryptResponse() {}

        public Tpm2EccDecryptResponse(Tpm2EccDecryptResponse src) { plainText = src.plainText; }

        new public Tpm2EccDecryptResponse Copy() { return CreateCopy<Tpm2EccDecryptResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> NOTE 1 This command is deprecated, and TPM2_EncryptDecrypt2() is preferred.
    /// This should be reflected in platform-specific specifications. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("EncryptDecrypt_In")]
    public partial class Tpm2EncryptDecryptRequest: TpmStructureBase
    {
        /// <summary> The symmetric key used for the operation
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> If YES, then the operation is decryption; if NO, the operation is encryption
        /// </summary>
        [MarshalAs(1)]
        [DataMember()]
        public byte decrypt { get; set; }

        /// <summary> Symmetric encryption/decryption mode
        /// this field shall match the default mode of the key or be TPM_ALG_NULL. </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId mode { get; set; }

        /// <summary> An initial value as required by the algorithm </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "ivInSize", 2)]
        [DataMember()]
        public byte[] ivIn;

        /// <summary> The data to be encrypted/decrypted </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "inDataSize", 2)]
        [DataMember()]
        public byte[] inData;

        public Tpm2EncryptDecryptRequest()
        {
            keyHandle = new TpmHandle();
            mode = TpmAlgId.Null;
        }

        /// <param name = "_keyHandle"> The symmetric key used for the operation
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_decrypt"> If YES, then the operation is decryption; if NO, the operation
        ///        is encryption </param>
        /// <param name = "_mode"> Symmetric encryption/decryption mode
        ///        this field shall match the default mode of the key or be TPM_ALG_NULL. </param>
        /// <param name = "_ivIn"> An initial value as required by the algorithm </param>
        /// <param name = "_inData"> The data to be encrypted/decrypted </param>
        public Tpm2EncryptDecryptRequest(TpmHandle _keyHandle, byte _decrypt, TpmAlgId _mode, byte[] _ivIn, byte[] _inData)
        {
            keyHandle = _keyHandle;
            decrypt = _decrypt;
            mode = _mode;
            ivIn = _ivIn;
            inData = _inData;
        }

        new public Tpm2EncryptDecryptRequest Copy() { return CreateCopy<Tpm2EncryptDecryptRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> NOTE 1 This command is deprecated, and TPM2_EncryptDecrypt2() is preferred.
    /// This should be reflected in platform-specific specifications. </summary>
    [DataContract]
    [SpecTypeName("EncryptDecrypt_Out")]
    public partial class Tpm2EncryptDecryptResponse: TpmStructureBase
    {
        /// <summary> Encrypted or decrypted output </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outDataSize", 2)]
        [DataMember()]
        public byte[] outData;

        /// <summary> Chaining value to use for IV in next round </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "ivOutSize", 2)]
        [DataMember()]
        public byte[] ivOut;

        public Tpm2EncryptDecryptResponse() {}

        public Tpm2EncryptDecryptResponse(Tpm2EncryptDecryptResponse src)
        {
            outData = src.outData;
            ivOut = src.ivOut;
        }

        new public Tpm2EncryptDecryptResponse Copy() { return CreateCopy<Tpm2EncryptDecryptResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is identical to TPM2_EncryptDecrypt(), except that the inData
    /// parameter is the first parameter. This permits inData to be parameter encrypted. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("EncryptDecrypt2_In")]
    public partial class Tpm2EncryptDecrypt2Request: TpmStructureBase
    {
        /// <summary> The symmetric key used for the operation
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> The data to be encrypted/decrypted </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "inDataSize", 2)]
        [DataMember()]
        public byte[] inData;

        /// <summary> If YES, then the operation is decryption; if NO, the operation is encryption
        /// </summary>
        [MarshalAs(2)]
        [DataMember()]
        public byte decrypt { get; set; }

        /// <summary> Symmetric mode
        /// this field shall match the default mode of the key or be TPM_ALG_NULL. </summary>
        [MarshalAs(3)]
        [DataMember()]
        public TpmAlgId mode { get; set; }

        /// <summary> An initial value as required by the algorithm </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "ivInSize", 2)]
        [DataMember()]
        public byte[] ivIn;

        public Tpm2EncryptDecrypt2Request()
        {
            keyHandle = new TpmHandle();
            mode = TpmAlgId.Null;
        }

        /// <param name = "_keyHandle"> The symmetric key used for the operation
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_inData"> The data to be encrypted/decrypted </param>
        /// <param name = "_decrypt"> If YES, then the operation is decryption; if NO, the operation
        ///        is encryption </param>
        /// <param name = "_mode"> Symmetric mode
        ///        this field shall match the default mode of the key or be TPM_ALG_NULL. </param>
        /// <param name = "_ivIn"> An initial value as required by the algorithm </param>
        public Tpm2EncryptDecrypt2Request(TpmHandle _keyHandle, byte[] _inData, byte _decrypt, TpmAlgId _mode, byte[] _ivIn)
        {
            keyHandle = _keyHandle;
            inData = _inData;
            decrypt = _decrypt;
            mode = _mode;
            ivIn = _ivIn;
        }

        new public Tpm2EncryptDecrypt2Request Copy() { return CreateCopy<Tpm2EncryptDecrypt2Request>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is identical to TPM2_EncryptDecrypt(), except that the inData
    /// parameter is the first parameter. This permits inData to be parameter encrypted. </summary>
    [DataContract]
    [SpecTypeName("EncryptDecrypt2_Out")]
    public partial class Tpm2EncryptDecrypt2Response: TpmStructureBase
    {
        /// <summary> Encrypted or decrypted output </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outDataSize", 2)]
        [DataMember()]
        public byte[] outData;

        /// <summary> Chaining value to use for IV in next round </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "ivOutSize", 2)]
        [DataMember()]
        public byte[] ivOut;

        public Tpm2EncryptDecrypt2Response() {}

        public Tpm2EncryptDecrypt2Response(Tpm2EncryptDecrypt2Response src)
        {
            outData = src.outData;
            ivOut = src.ivOut;
        }

        new public Tpm2EncryptDecrypt2Response Copy() { return CreateCopy<Tpm2EncryptDecrypt2Response>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs a hash operation on a data buffer and returns the
    /// results. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("Hash_In")]
    public partial class Tpm2HashRequest: TpmStructureBase
    {
        /// <summary> Data to be hashed </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;

        /// <summary> Algorithm for the hash being computed shall not be TPM_ALG_NULL </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        /// <summary> Hierarchy to use for the ticket (TPM_RH_NULL allowed) </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }

        public Tpm2HashRequest()
        {
            hashAlg = TpmAlgId.Null;
            hierarchy = new TpmHandle();
        }

        /// <param name = "_data"> Data to be hashed </param>
        /// <param name = "_hashAlg"> Algorithm for the hash being computed shall not be TPM_ALG_NULL </param>
        /// <param name = "_hierarchy"> Hierarchy to use for the ticket (TPM_RH_NULL allowed) </param>
        public Tpm2HashRequest(byte[] _data, TpmAlgId _hashAlg, TpmHandle _hierarchy)
        {
            data = _data;
            hashAlg = _hashAlg;
            hierarchy = _hierarchy;
        }

        new public Tpm2HashRequest Copy() { return CreateCopy<Tpm2HashRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs a hash operation on a data buffer and returns the
    /// results. </summary>
    [DataContract]
    [KnownType(typeof(TkHashcheck))]
    [SpecTypeName("Hash_Out")]
    public partial class Tpm2HashResponse: TpmStructureBase
    {
        /// <summary> Results </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outHashSize", 2)]
        [DataMember()]
        public byte[] outHash;

        /// <summary> Ticket indicating that the sequence of octets used to compute outDigest did
        /// not start with TPM_GENERATED_VALUE
        /// will be a NULL ticket if the digest may not be signed with a restricted key </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TkHashcheck validation { get; set; }

        public Tpm2HashResponse() {}

        public Tpm2HashResponse(Tpm2HashResponse src)
        {
            outHash = src.outHash;
            validation = src.validation;
        }

        new public Tpm2HashResponse Copy() { return CreateCopy<Tpm2HashResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs an HMAC on the supplied data using the indicated hash
    /// algorithm. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("HMAC_In")]
    public partial class Tpm2HmacRequest: TpmStructureBase
    {
        /// <summary> Handle for the symmetric signing key providing the HMAC key
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> HMAC data </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "bufferSize", 2)]
        [DataMember()]
        public byte[] buffer;

        /// <summary> Algorithm to use for HMAC </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        public Tpm2HmacRequest()
        {
            handle = new TpmHandle();
            hashAlg = TpmAlgId.Null;
        }

        /// <param name = "_handle"> Handle for the symmetric signing key providing the HMAC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_buffer"> HMAC data </param>
        /// <param name = "_hashAlg"> Algorithm to use for HMAC </param>
        public Tpm2HmacRequest(TpmHandle _handle, byte[] _buffer, TpmAlgId _hashAlg)
        {
            handle = _handle;
            buffer = _buffer;
            hashAlg = _hashAlg;
        }

        new public Tpm2HmacRequest Copy() { return CreateCopy<Tpm2HmacRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs an HMAC on the supplied data using the indicated hash
    /// algorithm. </summary>
    [DataContract]
    [SpecTypeName("HMAC_Out")]
    public partial class Tpm2HmacResponse: TpmStructureBase
    {
        /// <summary> The returned HMAC in a sized buffer </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outHMACSize", 2)]
        [DataMember()]
        public byte[] outHMAC;

        public Tpm2HmacResponse() {}

        public Tpm2HmacResponse(Tpm2HmacResponse src) { outHMAC = src.outHMAC; }

        new public Tpm2HmacResponse Copy() { return CreateCopy<Tpm2HmacResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs an HMAC or a block cipher MAC on the supplied data
    /// using the indicated algorithm. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("MAC_In")]
    public partial class Tpm2MacRequest: TpmStructureBase
    {
        /// <summary> Handle for the symmetric signing key providing the MAC key
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> MAC data </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "bufferSize", 2)]
        [DataMember()]
        public byte[] buffer;

        /// <summary> Algorithm to use for MAC </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId inScheme { get; set; }

        public Tpm2MacRequest()
        {
            handle = new TpmHandle();
            inScheme = TpmAlgId.Null;
        }

        /// <param name = "_handle"> Handle for the symmetric signing key providing the MAC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_buffer"> MAC data </param>
        /// <param name = "_inScheme"> Algorithm to use for MAC </param>
        public Tpm2MacRequest(TpmHandle _handle, byte[] _buffer, TpmAlgId _inScheme)
        {
            handle = _handle;
            buffer = _buffer;
            inScheme = _inScheme;
        }

        new public Tpm2MacRequest Copy() { return CreateCopy<Tpm2MacRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command performs an HMAC or a block cipher MAC on the supplied data
    /// using the indicated algorithm. </summary>
    [DataContract]
    [SpecTypeName("MAC_Out")]
    public partial class Tpm2MacResponse: TpmStructureBase
    {
        /// <summary> The returned MAC in a sized buffer </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outMACSize", 2)]
        [DataMember()]
        public byte[] outMAC;

        public Tpm2MacResponse() {}

        public Tpm2MacResponse(Tpm2MacResponse src) { outMAC = src.outMAC; }

        new public Tpm2MacResponse Copy() { return CreateCopy<Tpm2MacResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the next bytesRequested octets from the random number
    /// generator (RNG). </summary>
    [DataContract]
    [SpecTypeName("GetRandom_In")]
    public partial class Tpm2GetRandomRequest: TpmStructureBase
    {
        /// <summary> Number of octets to return </summary>
        [MarshalAs(0)]
        [DataMember()]
        public ushort bytesRequested { get; set; }

        public Tpm2GetRandomRequest() {}

        /// <param name = "_bytesRequested"> Number of octets to return </param>
        public Tpm2GetRandomRequest(ushort _bytesRequested) { bytesRequested = _bytesRequested; }

        new public Tpm2GetRandomRequest Copy() { return CreateCopy<Tpm2GetRandomRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the next bytesRequested octets from the random number
    /// generator (RNG). </summary>
    [DataContract]
    [SpecTypeName("GetRandom_Out")]
    public partial class Tpm2GetRandomResponse: TpmStructureBase
    {
        /// <summary> The random octets </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "randomBytesSize", 2)]
        [DataMember()]
        public byte[] randomBytes;

        public Tpm2GetRandomResponse() {}

        public Tpm2GetRandomResponse(Tpm2GetRandomResponse src) { randomBytes = src.randomBytes; }

        new public Tpm2GetRandomResponse Copy() { return CreateCopy<Tpm2GetRandomResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to add "additional information" to the RNG state. </summary>
    [DataContract]
    [SpecTypeName("StirRandom_In")]
    public partial class Tpm2StirRandomRequest: TpmStructureBase
    {
        /// <summary> Additional information </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "inDataSize", 2)]
        [DataMember()]
        public byte[] inData;

        public Tpm2StirRandomRequest() {}

        /// <param name = "_inData"> Additional information </param>
        public Tpm2StirRandomRequest(byte[] _inData) { inData = _inData; }

        new public Tpm2StirRandomRequest Copy() { return CreateCopy<Tpm2StirRandomRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command starts an HMAC sequence. The TPM will create and initialize an
    /// HMAC sequence structure, assign a handle to the sequence, and set the authValue of the
    /// sequence object to the value in auth. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("HMAC_Start_In")]
    public partial class Tpm2HmacStartRequest: TpmStructureBase
    {
        /// <summary> Handle of an HMAC key
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> Authorization value for subsequent use of the sequence </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;

        /// <summary> The hash algorithm to use for the HMAC </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        public Tpm2HmacStartRequest()
        {
            handle = new TpmHandle();
            hashAlg = TpmAlgId.Null;
        }

        /// <param name = "_handle"> Handle of an HMAC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_auth"> Authorization value for subsequent use of the sequence </param>
        /// <param name = "_hashAlg"> The hash algorithm to use for the HMAC </param>
        public Tpm2HmacStartRequest(TpmHandle _handle, byte[] _auth, TpmAlgId _hashAlg)
        {
            handle = _handle;
            auth = _auth;
            hashAlg = _hashAlg;
        }

        new public Tpm2HmacStartRequest Copy() { return CreateCopy<Tpm2HmacStartRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command starts an HMAC sequence. The TPM will create and initialize an
    /// HMAC sequence structure, assign a handle to the sequence, and set the authValue of the
    /// sequence object to the value in auth. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("HMAC_Start_Out")]
    public partial class Tpm2HmacStartResponse: TpmStructureBase
    {
        /// <summary> A handle to reference the sequence </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        public Tpm2HmacStartResponse() { handle = new TpmHandle(); }

        public Tpm2HmacStartResponse(Tpm2HmacStartResponse src) { handle = src.handle; }

        new public Tpm2HmacStartResponse Copy() { return CreateCopy<Tpm2HmacStartResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command starts a MAC sequence. The TPM will create and initialize a MAC
    /// sequence structure, assign a handle to the sequence, and set the authValue of the
    /// sequence object to the value in auth. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("MAC_Start_In")]
    public partial class Tpm2MacStartRequest: TpmStructureBase
    {
        /// <summary> Handle of a MAC key
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> Authorization value for subsequent use of the sequence </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;

        /// <summary> The algorithm to use for the MAC </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId inScheme { get; set; }

        public Tpm2MacStartRequest()
        {
            handle = new TpmHandle();
            inScheme = TpmAlgId.Null;
        }

        /// <param name = "_handle"> Handle of a MAC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_auth"> Authorization value for subsequent use of the sequence </param>
        /// <param name = "_inScheme"> The algorithm to use for the MAC </param>
        public Tpm2MacStartRequest(TpmHandle _handle, byte[] _auth, TpmAlgId _inScheme)
        {
            handle = _handle;
            auth = _auth;
            inScheme = _inScheme;
        }

        new public Tpm2MacStartRequest Copy() { return CreateCopy<Tpm2MacStartRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command starts a MAC sequence. The TPM will create and initialize a MAC
    /// sequence structure, assign a handle to the sequence, and set the authValue of the
    /// sequence object to the value in auth. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("MAC_Start_Out")]
    public partial class Tpm2MacStartResponse: TpmStructureBase
    {
        /// <summary> A handle to reference the sequence </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        public Tpm2MacStartResponse() { handle = new TpmHandle(); }

        public Tpm2MacStartResponse(Tpm2MacStartResponse src) { handle = src.handle; }

        new public Tpm2MacStartResponse Copy() { return CreateCopy<Tpm2MacStartResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command starts a hash or an Event Sequence. If hashAlg is an
    /// implemented hash, then a hash sequence is started. If hashAlg is TPM_ALG_NULL, then an
    /// Event Sequence is started. If hashAlg is neither an implemented algorithm nor
    /// TPM_ALG_NULL, then the TPM shall return TPM_RC_HASH. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [SpecTypeName("HashSequenceStart_In")]
    public partial class Tpm2HashSequenceStartRequest: TpmStructureBase
    {
        /// <summary> Authorization value for subsequent use of the sequence </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;

        /// <summary> The hash algorithm to use for the hash sequence
        /// An Event Sequence starts if this is TPM_ALG_NULL. </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        public Tpm2HashSequenceStartRequest() { hashAlg = TpmAlgId.Null; }

        /// <param name = "_auth"> Authorization value for subsequent use of the sequence </param>
        /// <param name = "_hashAlg"> The hash algorithm to use for the hash sequence
        ///        An Event Sequence starts if this is TPM_ALG_NULL. </param>
        public Tpm2HashSequenceStartRequest(byte[] _auth, TpmAlgId _hashAlg)
        {
            auth = _auth;
            hashAlg = _hashAlg;
        }

        new public Tpm2HashSequenceStartRequest Copy() { return CreateCopy<Tpm2HashSequenceStartRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command starts a hash or an Event Sequence. If hashAlg is an
    /// implemented hash, then a hash sequence is started. If hashAlg is TPM_ALG_NULL, then an
    /// Event Sequence is started. If hashAlg is neither an implemented algorithm nor
    /// TPM_ALG_NULL, then the TPM shall return TPM_RC_HASH. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("HashSequenceStart_Out")]
    public partial class Tpm2HashSequenceStartResponse: TpmStructureBase
    {
        /// <summary> A handle to reference the sequence </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        public Tpm2HashSequenceStartResponse() { handle = new TpmHandle(); }

        public Tpm2HashSequenceStartResponse(Tpm2HashSequenceStartResponse src) { handle = src.handle; }

        new public Tpm2HashSequenceStartResponse Copy() { return CreateCopy<Tpm2HashSequenceStartResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to add data to a hash or HMAC sequence. The amount of
    /// data in buffer may be any size up to the limits of the TPM. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("SequenceUpdate_In")]
    public partial class Tpm2SequenceUpdateRequest: TpmStructureBase
    {
        /// <summary> Handle for the sequence object
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sequenceHandle { get; set; }

        /// <summary> Data to be added to hash </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "bufferSize", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2SequenceUpdateRequest() { sequenceHandle = new TpmHandle(); }

        /// <param name = "_sequenceHandle"> Handle for the sequence object
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_buffer"> Data to be added to hash </param>
        public Tpm2SequenceUpdateRequest(TpmHandle _sequenceHandle, byte[] _buffer)
        {
            sequenceHandle = _sequenceHandle;
            buffer = _buffer;
        }

        new public Tpm2SequenceUpdateRequest Copy() { return CreateCopy<Tpm2SequenceUpdateRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command adds the last part of data, if any, to a hash/HMAC sequence and
    /// returns the result. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("SequenceComplete_In")]
    public partial class Tpm2SequenceCompleteRequest: TpmStructureBase
    {
        /// <summary> Authorization for the sequence
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sequenceHandle { get; set; }

        /// <summary> Data to be added to the hash/HMAC </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "bufferSize", 2)]
        [DataMember()]
        public byte[] buffer;

        /// <summary> Hierarchy of the ticket for a hash </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle hierarchy { get; set; }

        public Tpm2SequenceCompleteRequest()
        {
            sequenceHandle = new TpmHandle();
            hierarchy = new TpmHandle();
        }

        /// <param name = "_sequenceHandle"> Authorization for the sequence
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_buffer"> Data to be added to the hash/HMAC </param>
        /// <param name = "_hierarchy"> Hierarchy of the ticket for a hash </param>
        public Tpm2SequenceCompleteRequest(TpmHandle _sequenceHandle, byte[] _buffer, TpmHandle _hierarchy)
        {
            sequenceHandle = _sequenceHandle;
            buffer = _buffer;
            hierarchy = _hierarchy;
        }

        new public Tpm2SequenceCompleteRequest Copy() { return CreateCopy<Tpm2SequenceCompleteRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command adds the last part of data, if any, to a hash/HMAC sequence and
    /// returns the result. </summary>
    [DataContract]
    [KnownType(typeof(TkHashcheck))]
    [SpecTypeName("SequenceComplete_Out")]
    public partial class Tpm2SequenceCompleteResponse: TpmStructureBase
    {
        /// <summary> The returned HMAC or digest in a sized buffer </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "resultSize", 2)]
        [DataMember()]
        public byte[] result;

        /// <summary> Ticket indicating that the sequence of octets used to compute outDigest did
        /// not start with TPM_GENERATED_VALUE
        /// This is a NULL Ticket when the sequence is HMAC. </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TkHashcheck validation { get; set; }

        public Tpm2SequenceCompleteResponse() {}

        public Tpm2SequenceCompleteResponse(Tpm2SequenceCompleteResponse src)
        {
            result = src.result;
            validation = src.validation;
        }

        new public Tpm2SequenceCompleteResponse Copy() { return CreateCopy<Tpm2SequenceCompleteResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command adds the last part of data, if any, to an Event Sequence and
    /// returns the result in a digest list. If pcrHandle references a PCR and not
    /// TPM_RH_NULL, then the returned digest list is processed in the same manner as the
    /// digest list input parameter to TPM2_PCR_Extend(). That is, if a bank contains a PCR
    /// associated with pcrHandle, it is extended with the associated digest value from the
    /// list. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("EventSequenceComplete_In")]
    public partial class Tpm2EventSequenceCompleteRequest: TpmStructureBase
    {
        /// <summary> PCR to be extended with the Event data
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }

        /// <summary> Authorization for the sequence
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle sequenceHandle { get; set; }

        /// <summary> Data to be added to the Event </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "bufferSize", 2)]
        [DataMember()]
        public byte[] buffer;

        public Tpm2EventSequenceCompleteRequest()
        {
            pcrHandle = new TpmHandle();
            sequenceHandle = new TpmHandle();
        }

        /// <param name = "_pcrHandle"> PCR to be extended with the Event data
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_sequenceHandle"> Authorization for the sequence
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "_buffer"> Data to be added to the Event </param>
        public Tpm2EventSequenceCompleteRequest(TpmHandle _pcrHandle, TpmHandle _sequenceHandle, byte[] _buffer)
        {
            pcrHandle = _pcrHandle;
            sequenceHandle = _sequenceHandle;
            buffer = _buffer;
        }

        new public Tpm2EventSequenceCompleteRequest Copy() { return CreateCopy<Tpm2EventSequenceCompleteRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command adds the last part of data, if any, to an Event Sequence and
    /// returns the result in a digest list. If pcrHandle references a PCR and not
    /// TPM_RH_NULL, then the returned digest list is processed in the same manner as the
    /// digest list input parameter to TPM2_PCR_Extend(). That is, if a bank contains a PCR
    /// associated with pcrHandle, it is extended with the associated digest value from the
    /// list. </summary>
    [DataContract]
    [SpecTypeName("EventSequenceComplete_Out")]
    public partial class Tpm2EventSequenceCompleteResponse: TpmStructureBase
    {
        /// <summary> List of digests computed for the PCR </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "resultsCount", 4)]
        [DataMember()]
        public TpmHash[] results;

        public Tpm2EventSequenceCompleteResponse() {}

        public Tpm2EventSequenceCompleteResponse(Tpm2EventSequenceCompleteResponse src) { results = src.results; }

        new public Tpm2EventSequenceCompleteResponse Copy() { return CreateCopy<Tpm2EventSequenceCompleteResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to prove that an object with a specific Name
    /// is loaded in the TPM. By certifying that the object is loaded, the TPM warrants that a
    /// public area with a given Name is self-consistent and associated with a valid sensitive
    /// area. If a relying party has a public area that has the same Name as a Name certified
    /// with this command, then the values in that public area are correct. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("Certify_In")]
    public partial class Tpm2CertifyRequest: TpmStructureBase
    {
        /// <summary> Handle of the object to be certified
        /// Auth Index: 1
        /// Auth Role: ADMIN </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }

        /// <summary> Handle of the key used to sign the attestation structure
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }

        /// <summary> User provided qualifying data </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;

        /// <summary> Scheme selector </summary>
        [MarshalAs(3, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(4, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }

        public Tpm2CertifyRequest()
        {
            objectHandle = new TpmHandle();
            signHandle = new TpmHandle();
        }

        /// <param name = "_objectHandle"> Handle of the object to be certified
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "_signHandle"> Handle of the key used to sign the attestation structure
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "_qualifyingData"> User provided qualifying data </param>
        /// <param name = "_inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        public Tpm2CertifyRequest(TpmHandle _objectHandle, TpmHandle _signHandle, byte[] _qualifyingData, ISigSchemeUnion _inScheme)
        {
            objectHandle = _objectHandle;
            signHandle = _signHandle;
            qualifyingData = _qualifyingData;
            inScheme = _inScheme;
        }

        new public Tpm2CertifyRequest Copy() { return CreateCopy<Tpm2CertifyRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to prove that an object with a specific Name
    /// is loaded in the TPM. By certifying that the object is loaded, the TPM warrants that a
    /// public area with a given Name is self-consistent and associated with a valid sensitive
    /// area. If a relying party has a public area that has the same Name as a Name certified
    /// with this command, then the values in that public area are correct. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Attest))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("Certify_Out")]
    public partial class Tpm2CertifyResponse: TpmStructureBase
    {
        /// <summary> The structure that was signed </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "certifyInfoSize", 2)]
        [DataMember()]
        public Attest certifyInfo { get; set; }

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The asymmetric signature over certifyInfo using the key referenced by
        /// signHandle </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2CertifyResponse() {}

        public Tpm2CertifyResponse(Tpm2CertifyResponse src)
        {
            certifyInfo = src.certifyInfo;
            signature = src.signature;
        }

        new public Tpm2CertifyResponse Copy() { return CreateCopy<Tpm2CertifyResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to prove the association between an object and its
    /// creation data. The TPM will validate that the ticket was produced by the TPM and that
    /// the ticket validates the association between a loaded public area and the provided
    /// hash of the creation data (creationHash). </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(TkCreation))]
    [SpecTypeName("CertifyCreation_In")]
    public partial class Tpm2CertifyCreationRequest: TpmStructureBase
    {
        /// <summary> Handle of the key that will sign the attestation block
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }

        /// <summary> The object associated with the creation data
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }

        /// <summary> User-provided qualifying data </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;

        /// <summary> Hash of the creation data produced by TPM2_Create() or TPM2_CreatePrimary() </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "creationHashSize", 2)]
        [DataMember()]
        public byte[] creationHash;

        /// <summary> Scheme selector </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(5, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }

        /// <summary> Ticket produced by TPM2_Create() or TPM2_CreatePrimary() </summary>
        [MarshalAs(6)]
        [DataMember()]
        public TkCreation creationTicket { get; set; }

        public Tpm2CertifyCreationRequest()
        {
            signHandle = new TpmHandle();
            objectHandle = new TpmHandle();
        }

        /// <param name = "_signHandle"> Handle of the key that will sign the attestation block
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_objectHandle"> The object associated with the creation data
        ///        Auth Index: None </param>
        /// <param name = "_qualifyingData"> User-provided qualifying data </param>
        /// <param name = "_creationHash"> Hash of the creation data produced by TPM2_Create() or
        ///        TPM2_CreatePrimary() </param>
        /// <param name = "_inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "_creationTicket"> Ticket produced by TPM2_Create() or TPM2_CreatePrimary() </param>
        public Tpm2CertifyCreationRequest(TpmHandle _signHandle, TpmHandle _objectHandle, byte[] _qualifyingData, byte[] _creationHash, ISigSchemeUnion _inScheme, TkCreation _creationTicket)
        {
            signHandle = _signHandle;
            objectHandle = _objectHandle;
            qualifyingData = _qualifyingData;
            creationHash = _creationHash;
            inScheme = _inScheme;
            creationTicket = _creationTicket;
        }

        new public Tpm2CertifyCreationRequest Copy() { return CreateCopy<Tpm2CertifyCreationRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to prove the association between an object and its
    /// creation data. The TPM will validate that the ticket was produced by the TPM and that
    /// the ticket validates the association between a loaded public area and the provided
    /// hash of the creation data (creationHash). </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Attest))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("CertifyCreation_Out")]
    public partial class Tpm2CertifyCreationResponse: TpmStructureBase
    {
        /// <summary> The structure that was signed </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "certifyInfoSize", 2)]
        [DataMember()]
        public Attest certifyInfo { get; set; }

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The signature over certifyInfo </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2CertifyCreationResponse() {}

        public Tpm2CertifyCreationResponse(Tpm2CertifyCreationResponse src)
        {
            certifyInfo = src.certifyInfo;
            signature = src.signature;
        }

        new public Tpm2CertifyCreationResponse Copy() { return CreateCopy<Tpm2CertifyCreationResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to quote PCR values. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("Quote_In")]
    public partial class Tpm2QuoteRequest: TpmStructureBase
    {
        /// <summary> Handle of key that will perform signature
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }

        /// <summary> Data supplied by the caller </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;

        /// <summary> Scheme selector </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(3, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }

        /// <summary> PCR set to quote </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "PCRselectCount", 4)]
        [DataMember()]
        public PcrSelection[] PCRselect;

        public Tpm2QuoteRequest() { signHandle = new TpmHandle(); }

        /// <param name = "_signHandle"> Handle of key that will perform signature
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_qualifyingData"> Data supplied by the caller </param>
        /// <param name = "_inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "_PCRselect"> PCR set to quote </param>
        public Tpm2QuoteRequest(TpmHandle _signHandle, byte[] _qualifyingData, ISigSchemeUnion _inScheme, PcrSelection[] _PCRselect)
        {
            signHandle = _signHandle;
            qualifyingData = _qualifyingData;
            inScheme = _inScheme;
            PCRselect = _PCRselect;
        }

        new public Tpm2QuoteRequest Copy() { return CreateCopy<Tpm2QuoteRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to quote PCR values. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Attest))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("Quote_Out")]
    public partial class Tpm2QuoteResponse: TpmStructureBase
    {
        /// <summary> The quoted information </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "quotedSize", 2)]
        [DataMember()]
        public Attest quoted { get; set; }

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The signature over quoted </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2QuoteResponse() {}

        public Tpm2QuoteResponse(Tpm2QuoteResponse src)
        {
            quoted = src.quoted;
            signature = src.signature;
        }

        new public Tpm2QuoteResponse Copy() { return CreateCopy<Tpm2QuoteResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns a digital signature of the audit session digest. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("GetSessionAuditDigest_In")]
    public partial class Tpm2GetSessionAuditDigestRequest: TpmStructureBase
    {
        /// <summary> Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle privacyAdminHandle { get; set; }

        /// <summary> Handle of the signing key
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }

        /// <summary> Handle of the audit session
        /// Auth Index: None </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle sessionHandle { get; set; }

        /// <summary> User-provided qualifying data may be zero-length </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;

        /// <summary> Scheme selector </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(5, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }

        public Tpm2GetSessionAuditDigestRequest()
        {
            privacyAdminHandle = new TpmHandle();
            signHandle = new TpmHandle();
            sessionHandle = new TpmHandle();
        }

        /// <param name = "_privacyAdminHandle"> Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_signHandle"> Handle of the signing key
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "_sessionHandle"> Handle of the audit session
        ///        Auth Index: None </param>
        /// <param name = "_qualifyingData"> User-provided qualifying data may be zero-length </param>
        /// <param name = "_inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        public Tpm2GetSessionAuditDigestRequest(TpmHandle _privacyAdminHandle, TpmHandle _signHandle, TpmHandle _sessionHandle, byte[] _qualifyingData, ISigSchemeUnion _inScheme)
        {
            privacyAdminHandle = _privacyAdminHandle;
            signHandle = _signHandle;
            sessionHandle = _sessionHandle;
            qualifyingData = _qualifyingData;
            inScheme = _inScheme;
        }

        new public Tpm2GetSessionAuditDigestRequest Copy() { return CreateCopy<Tpm2GetSessionAuditDigestRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns a digital signature of the audit session digest. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Attest))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("GetSessionAuditDigest_Out")]
    public partial class Tpm2GetSessionAuditDigestResponse: TpmStructureBase
    {
        /// <summary> The audit information that was signed </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "auditInfoSize", 2)]
        [DataMember()]
        public Attest auditInfo { get; set; }

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The signature over auditInfo </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2GetSessionAuditDigestResponse() {}

        public Tpm2GetSessionAuditDigestResponse(Tpm2GetSessionAuditDigestResponse src)
        {
            auditInfo = src.auditInfo;
            signature = src.signature;
        }

        new public Tpm2GetSessionAuditDigestResponse Copy() { return CreateCopy<Tpm2GetSessionAuditDigestResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the current value of the command audit digest, a digest
    /// of the commands being audited, and the audit hash algorithm. These values are placed
    /// in an attestation structure and signed with the key referenced by signHandle. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("GetCommandAuditDigest_In")]
    public partial class Tpm2GetCommandAuditDigestRequest: TpmStructureBase
    {
        /// <summary> Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle privacyHandle { get; set; }

        /// <summary> The handle of the signing key
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }

        /// <summary> Other data to associate with this audit digest </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;

        /// <summary> Scheme selector </summary>
        [MarshalAs(3, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(4, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }

        public Tpm2GetCommandAuditDigestRequest()
        {
            privacyHandle = new TpmHandle();
            signHandle = new TpmHandle();
        }

        /// <param name = "_privacyHandle"> Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_signHandle"> The handle of the signing key
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "_qualifyingData"> Other data to associate with this audit digest </param>
        /// <param name = "_inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        public Tpm2GetCommandAuditDigestRequest(TpmHandle _privacyHandle, TpmHandle _signHandle, byte[] _qualifyingData, ISigSchemeUnion _inScheme)
        {
            privacyHandle = _privacyHandle;
            signHandle = _signHandle;
            qualifyingData = _qualifyingData;
            inScheme = _inScheme;
        }

        new public Tpm2GetCommandAuditDigestRequest Copy() { return CreateCopy<Tpm2GetCommandAuditDigestRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the current value of the command audit digest, a digest
    /// of the commands being audited, and the audit hash algorithm. These values are placed
    /// in an attestation structure and signed with the key referenced by signHandle. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Attest))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("GetCommandAuditDigest_Out")]
    public partial class Tpm2GetCommandAuditDigestResponse: TpmStructureBase
    {
        /// <summary> The auditInfo that was signed </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "auditInfoSize", 2)]
        [DataMember()]
        public Attest auditInfo { get; set; }

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The signature over auditInfo </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2GetCommandAuditDigestResponse() {}

        public Tpm2GetCommandAuditDigestResponse(Tpm2GetCommandAuditDigestResponse src)
        {
            auditInfo = src.auditInfo;
            signature = src.signature;
        }

        new public Tpm2GetCommandAuditDigestResponse Copy() { return CreateCopy<Tpm2GetCommandAuditDigestResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the current values of Time and Clock. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("GetTime_In")]
    public partial class Tpm2GetTimeRequest: TpmStructureBase
    {
        /// <summary> Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle privacyAdminHandle { get; set; }

        /// <summary> The keyHandle identifier of a loaded key that can perform digital signatures
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }

        /// <summary> Data to tick stamp </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;

        /// <summary> Scheme selector </summary>
        [MarshalAs(3, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(4, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }

        public Tpm2GetTimeRequest()
        {
            privacyAdminHandle = new TpmHandle();
            signHandle = new TpmHandle();
        }

        /// <param name = "_privacyAdminHandle"> Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_signHandle"> The keyHandle identifier of a loaded key that can perform
        ///        digital signatures
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "_qualifyingData"> Data to tick stamp </param>
        /// <param name = "_inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        public Tpm2GetTimeRequest(TpmHandle _privacyAdminHandle, TpmHandle _signHandle, byte[] _qualifyingData, ISigSchemeUnion _inScheme)
        {
            privacyAdminHandle = _privacyAdminHandle;
            signHandle = _signHandle;
            qualifyingData = _qualifyingData;
            inScheme = _inScheme;
        }

        new public Tpm2GetTimeRequest Copy() { return CreateCopy<Tpm2GetTimeRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the current values of Time and Clock. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Attest))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("GetTime_Out")]
    public partial class Tpm2GetTimeResponse: TpmStructureBase
    {
        /// <summary> Standard TPM-generated attestation block </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "timeInfoSize", 2)]
        [DataMember()]
        public Attest timeInfo { get; set; }

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The signature over timeInfo </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2GetTimeResponse() {}

        public Tpm2GetTimeResponse(Tpm2GetTimeResponse src)
        {
            timeInfo = src.timeInfo;
            signature = src.signature;
        }

        new public Tpm2GetTimeResponse Copy() { return CreateCopy<Tpm2GetTimeResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to generate an X.509 certificate that proves
    /// an object with a specific public key and attributes is loaded in the TPM. In contrast
    /// to TPM2_Certify, which uses a TCG-defined data structure to convey attestation
    /// information, TPM2_CertifyX509 encodes the attestation information in a DER-encoded
    /// X.509 certificate that is compliant with RFC5280 Internet X.509 Public Key
    /// Infrastructure Certificate and Certificate Revocation List (CRL) Profile. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("CertifyX509_In")]
    public partial class Tpm2CertifyX509Request: TpmStructureBase
    {
        /// <summary> Handle of the object to be certified
        /// Auth Index: 1
        /// Auth Role: ADMIN </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }

        /// <summary> Handle of the key used to sign the attestation structure
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }

        /// <summary> Shall be an Empty Buffer </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "reservedSize", 2)]
        [DataMember()]
        public byte[] reserved;

        /// <summary> Scheme selector </summary>
        [MarshalAs(3, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(4, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }

        /// <summary> A DER encoded partial certificate </summary>
        [MarshalAs(5, MarshalType.VariableLengthArray, "partialCertificateSize", 2)]
        [DataMember()]
        public byte[] partialCertificate;

        public Tpm2CertifyX509Request()
        {
            objectHandle = new TpmHandle();
            signHandle = new TpmHandle();
        }

        /// <param name = "_objectHandle"> Handle of the object to be certified
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "_signHandle"> Handle of the key used to sign the attestation structure
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "_reserved"> Shall be an Empty Buffer </param>
        /// <param name = "_inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "_partialCertificate"> A DER encoded partial certificate </param>
        public Tpm2CertifyX509Request(TpmHandle _objectHandle, TpmHandle _signHandle, byte[] _reserved, ISigSchemeUnion _inScheme, byte[] _partialCertificate)
        {
            objectHandle = _objectHandle;
            signHandle = _signHandle;
            reserved = _reserved;
            inScheme = _inScheme;
            partialCertificate = _partialCertificate;
        }

        new public Tpm2CertifyX509Request Copy() { return CreateCopy<Tpm2CertifyX509Request>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to generate an X.509 certificate that proves
    /// an object with a specific public key and attributes is loaded in the TPM. In contrast
    /// to TPM2_Certify, which uses a TCG-defined data structure to convey attestation
    /// information, TPM2_CertifyX509 encodes the attestation information in a DER-encoded
    /// X.509 certificate that is compliant with RFC5280 Internet X.509 Public Key
    /// Infrastructure Certificate and Certificate Revocation List (CRL) Profile. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("CertifyX509_Out")]
    public partial class Tpm2CertifyX509Response: TpmStructureBase
    {
        /// <summary> A DER encoded SEQUENCE containing the DER encoded fields added to
        /// partialCertificate to make it a complete RFC5280 TBSCertificate. </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "addedToCertificateSize", 2)]
        [DataMember()]
        public byte[] addedToCertificate;

        /// <summary> The digest that was signed </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "tbsDigestSize", 2)]
        [DataMember()]
        public byte[] tbsDigest;

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The signature over tbsDigest </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(3, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2CertifyX509Response() {}

        public Tpm2CertifyX509Response(Tpm2CertifyX509Response src)
        {
            addedToCertificate = src.addedToCertificate;
            tbsDigest = src.tbsDigest;
            signature = src.signature;
        }

        new public Tpm2CertifyX509Response Copy() { return CreateCopy<Tpm2CertifyX509Response>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> TPM2_Commit() performs the first part of an ECC anonymous signing operation.
    /// The TPM will perform the point multiplications on the provided points and return
    /// intermediate signing values. The signHandle parameter shall refer to an ECC key and
    /// the signing scheme must be anonymous (TPM_RC_SCHEME). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("Commit_In")]
    public partial class Tpm2CommitRequest: TpmStructureBase
    {
        /// <summary> Handle of the key that will be used in the signing operation
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }

        /// <summary> A point (M) on the curve used by signHandle </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "P1Size", 2)]
        [DataMember()]
        public EccPoint P1 { get; set; }

        /// <summary> Octet array used to derive x-coordinate of a base point </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "s2Size", 2)]
        [DataMember()]
        public byte[] s2;

        /// <summary> Y coordinate of the point associated with s2 </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "y2Size", 2)]
        [DataMember()]
        public byte[] y2;

        public Tpm2CommitRequest() { signHandle = new TpmHandle(); }

        /// <param name = "_signHandle"> Handle of the key that will be used in the signing operation
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_P1"> A point (M) on the curve used by signHandle </param>
        /// <param name = "_s2"> Octet array used to derive x-coordinate of a base point </param>
        /// <param name = "_y2"> Y coordinate of the point associated with s2 </param>
        public Tpm2CommitRequest(TpmHandle _signHandle, EccPoint _P1, byte[] _s2, byte[] _y2)
        {
            signHandle = _signHandle;
            P1 = _P1;
            s2 = _s2;
            y2 = _y2;
        }

        new public Tpm2CommitRequest Copy() { return CreateCopy<Tpm2CommitRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> TPM2_Commit() performs the first part of an ECC anonymous signing operation.
    /// The TPM will perform the point multiplications on the provided points and return
    /// intermediate signing values. The signHandle parameter shall refer to an ECC key and
    /// the signing scheme must be anonymous (TPM_RC_SCHEME). </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("Commit_Out")]
    public partial class Tpm2CommitResponse: TpmStructureBase
    {
        /// <summary> ECC point K [ds](x2, y2) </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "KSize", 2)]
        [DataMember()]
        public EccPoint K { get; set; }

        /// <summary> ECC point L [r](x2, y2) </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "LSize", 2)]
        [DataMember()]
        public EccPoint L { get; set; }

        /// <summary> ECC point E [r]P1 </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "ESize", 2)]
        [DataMember()]
        public EccPoint E { get; set; }

        /// <summary> Least-significant 16 bits of commitCount </summary>
        [MarshalAs(3)]
        [DataMember()]
        public ushort counter { get; set; }

        public Tpm2CommitResponse() {}

        public Tpm2CommitResponse(Tpm2CommitResponse src)
        {
            K = src.K;
            L = src.L;
            E = src.E;
            counter = src.counter;
        }

        new public Tpm2CommitResponse Copy() { return CreateCopy<Tpm2CommitResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> TPM2_EC_Ephemeral() creates an ephemeral key for use in a two-phase key
    /// exchange protocol. </summary>
    [DataContract]
    [KnownType(typeof(EccCurve))]
    [SpecTypeName("EC_Ephemeral_In")]
    public partial class Tpm2EcEphemeralRequest: TpmStructureBase
    {
        /// <summary> The curve for the computed ephemeral point </summary>
        [MarshalAs(0)]
        [DataMember()]
        public EccCurve curveID { get; set; }

        public Tpm2EcEphemeralRequest() {}

        /// <param name = "_curveID"> The curve for the computed ephemeral point </param>
        public Tpm2EcEphemeralRequest(EccCurve _curveID) { curveID = _curveID; }

        new public Tpm2EcEphemeralRequest Copy() { return CreateCopy<Tpm2EcEphemeralRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> TPM2_EC_Ephemeral() creates an ephemeral key for use in a two-phase key
    /// exchange protocol. </summary>
    [DataContract]
    [KnownType(typeof(EccPoint))]
    [SpecTypeName("EC_Ephemeral_Out")]
    public partial class Tpm2EcEphemeralResponse: TpmStructureBase
    {
        /// <summary> Ephemeral public key Q [r]G </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "QSize", 2)]
        [DataMember()]
        public EccPoint Q { get; set; }

        /// <summary> Least-significant 16 bits of commitCount </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ushort counter { get; set; }

        public Tpm2EcEphemeralResponse() {}

        public Tpm2EcEphemeralResponse(Tpm2EcEphemeralResponse src)
        {
            Q = src.Q;
            counter = src.counter;
        }

        new public Tpm2EcEphemeralResponse Copy() { return CreateCopy<Tpm2EcEphemeralResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command uses loaded keys to validate a signature on a message with the
    /// message digest passed to the TPM. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("VerifySignature_In")]
    public partial class Tpm2VerifySignatureRequest: TpmStructureBase
    {
        /// <summary> Handle of public key that will be used in the validation
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> Digest of the signed message </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signature to be tested </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(3, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2VerifySignatureRequest() { keyHandle = new TpmHandle(); }

        /// <param name = "_keyHandle"> Handle of public key that will be used in the validation
        ///        Auth Index: None </param>
        /// <param name = "_digest"> Digest of the signed message </param>
        /// <param name = "_signature"> Signature to be tested
        ///        One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        ///        SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </param>
        public Tpm2VerifySignatureRequest(TpmHandle _keyHandle, byte[] _digest, ISignatureUnion _signature)
        {
            keyHandle = _keyHandle;
            digest = _digest;
            signature = _signature;
        }

        new public Tpm2VerifySignatureRequest Copy() { return CreateCopy<Tpm2VerifySignatureRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command uses loaded keys to validate a signature on a message with the
    /// message digest passed to the TPM. </summary>
    [DataContract]
    [KnownType(typeof(TkVerified))]
    [SpecTypeName("VerifySignature_Out")]
    public partial class Tpm2VerifySignatureResponse: TpmStructureBase
    {
        [MarshalAs(0)]
        [DataMember()]
        public TkVerified validation { get; set; }

        public Tpm2VerifySignatureResponse() {}

        public Tpm2VerifySignatureResponse(Tpm2VerifySignatureResponse src) { validation = src.validation; }

        new public Tpm2VerifySignatureResponse Copy() { return CreateCopy<Tpm2VerifySignatureResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command causes the TPM to sign an externally provided hash with the
    /// specified symmetric or asymmetric signing key. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [KnownType(typeof(TkHashcheck))]
    [SpecTypeName("Sign_In")]
    public partial class Tpm2SignRequest: TpmStructureBase
    {
        /// <summary> Handle of key that will perform signing
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> Digest to be signed </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "digestSize", 2)]
        [DataMember()]
        public byte[] digest;

        /// <summary> Scheme selector </summary>
        [MarshalAs(2, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signing scheme to use if the scheme for keyHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(3, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }

        /// <summary> Proof that digest was created by the TPM
        /// If keyHandle is not a restricted signing key, then this may be a NULL Ticket with tag
        /// = TPM_ST_CHECKHASH. </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TkHashcheck validation { get; set; }

        public Tpm2SignRequest() { keyHandle = new TpmHandle(); }

        /// <param name = "_keyHandle"> Handle of key that will perform signing
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_digest"> Digest to be signed </param>
        /// <param name = "_inScheme"> Signing scheme to use if the scheme for keyHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "_validation"> Proof that digest was created by the TPM
        ///        If keyHandle is not a restricted signing key, then this may be a NULL Ticket with
        ///        tag = TPM_ST_CHECKHASH. </param>
        public Tpm2SignRequest(TpmHandle _keyHandle, byte[] _digest, ISigSchemeUnion _inScheme, TkHashcheck _validation)
        {
            keyHandle = _keyHandle;
            digest = _digest;
            inScheme = _inScheme;
            validation = _validation;
        }

        new public Tpm2SignRequest Copy() { return CreateCopy<Tpm2SignRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command causes the TPM to sign an externally provided hash with the
    /// specified symmetric or asymmetric signing key. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("Sign_Out")]
    public partial class Tpm2SignResponse: TpmStructureBase
    {
        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The signature </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(1, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2SignResponse() {}

        public Tpm2SignResponse(Tpm2SignResponse src) { signature = src.signature; }

        new public Tpm2SignResponse Copy() { return CreateCopy<Tpm2SignResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command may be used by the Privacy Administrator or platform to change
    /// the audit status of a command or to set the hash algorithm used for the audit digest,
    /// but not both at the same time. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("SetCommandCodeAuditStatus_In")]
    public partial class Tpm2SetCommandCodeAuditStatusRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }

        /// <summary> Hash algorithm for the audit digest; if TPM_ALG_NULL, then the hash is not
        /// changed </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmAlgId auditAlg { get; set; }

        /// <summary> List of commands that will be added to those that will be audited </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "setListCount", 4)]
        [DataMember()]
        public TpmCc[] setList;

        /// <summary> List of commands that will no longer be audited </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "clearListCount", 4)]
        [DataMember()]
        public TpmCc[] clearList;

        public Tpm2SetCommandCodeAuditStatusRequest()
        {
            auth = new TpmHandle();
            auditAlg = TpmAlgId.Null;
        }

        /// <param name = "_auth"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_auditAlg"> Hash algorithm for the audit digest; if TPM_ALG_NULL, then the
        ///        hash is not changed </param>
        /// <param name = "_setList"> List of commands that will be added to those that will be
        ///        audited </param>
        /// <param name = "_clearList"> List of commands that will no longer be audited </param>
        public Tpm2SetCommandCodeAuditStatusRequest(TpmHandle _auth, TpmAlgId _auditAlg, TpmCc[] _setList, TpmCc[] _clearList)
        {
            auth = _auth;
            auditAlg = _auditAlg;
            setList = _setList;
            clearList = _clearList;
        }

        new public Tpm2SetCommandCodeAuditStatusRequest Copy() { return CreateCopy<Tpm2SetCommandCodeAuditStatusRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to cause an update to the indicated PCR. The digests
    /// parameter contains one or more tagged digest values identified by an algorithm ID. For
    /// each digest, the PCR associated with pcrHandle is Extended into the bank identified by
    /// the tag (hashAlg). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PCR_Extend_In")]
    public partial class Tpm2PcrExtendRequest: TpmStructureBase
    {
        /// <summary> Handle of the PCR
        /// Auth Handle: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }

        /// <summary> List of tagged digest values to be extended </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "digestsCount", 4)]
        [DataMember()]
        public TpmHash[] digests;

        public Tpm2PcrExtendRequest() { pcrHandle = new TpmHandle(); }

        /// <param name = "_pcrHandle"> Handle of the PCR
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "_digests"> List of tagged digest values to be extended </param>
        public Tpm2PcrExtendRequest(TpmHandle _pcrHandle, TpmHash[] _digests)
        {
            pcrHandle = _pcrHandle;
            digests = _digests;
        }

        new public Tpm2PcrExtendRequest Copy() { return CreateCopy<Tpm2PcrExtendRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to cause an update to the indicated PCR. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PCR_Event_In")]
    public partial class Tpm2PcrEventRequest: TpmStructureBase
    {
        /// <summary> Handle of the PCR
        /// Auth Handle: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }

        /// <summary> Event data in sized buffer </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "eventDataSize", 2)]
        [DataMember()]
        public byte[] eventData;

        public Tpm2PcrEventRequest() { pcrHandle = new TpmHandle(); }

        /// <param name = "_pcrHandle"> Handle of the PCR
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "_eventData"> Event data in sized buffer </param>
        public Tpm2PcrEventRequest(TpmHandle _pcrHandle, byte[] _eventData)
        {
            pcrHandle = _pcrHandle;
            eventData = _eventData;
        }

        new public Tpm2PcrEventRequest Copy() { return CreateCopy<Tpm2PcrEventRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to cause an update to the indicated PCR. </summary>
    [DataContract]
    [SpecTypeName("PCR_Event_Out")]
    public partial class Tpm2PcrEventResponse: TpmStructureBase
    {
        [MarshalAs(0, MarshalType.VariableLengthArray, "digestsCount", 4)]
        [DataMember()]
        public TpmHash[] digests;

        public Tpm2PcrEventResponse() {}

        public Tpm2PcrEventResponse(Tpm2PcrEventResponse src) { digests = src.digests; }

        new public Tpm2PcrEventResponse Copy() { return CreateCopy<Tpm2PcrEventResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the values of all PCR specified in pcrSelectionIn. </summary>
    [DataContract]
    [SpecTypeName("PCR_Read_In")]
    public partial class Tpm2PcrReadRequest: TpmStructureBase
    {
        /// <summary> The selection of PCR to read </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "pcrSelectionInCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelectionIn;

        public Tpm2PcrReadRequest() {}

        /// <param name = "_pcrSelectionIn"> The selection of PCR to read </param>
        public Tpm2PcrReadRequest(PcrSelection[] _pcrSelectionIn) { pcrSelectionIn = _pcrSelectionIn; }

        new public Tpm2PcrReadRequest Copy() { return CreateCopy<Tpm2PcrReadRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the values of all PCR specified in pcrSelectionIn. </summary>
    [DataContract]
    [SpecTypeName("PCR_Read_Out")]
    public partial class Tpm2PcrReadResponse: TpmStructureBase
    {
        /// <summary> The current value of the PCR update counter </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint pcrUpdateCounter { get; set; }

        /// <summary> The PCR in the returned list </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrSelectionOutCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrSelectionOut;

        /// <summary> The contents of the PCR indicated in pcrSelectOut-? pcrSelection[] as tagged
        /// digests </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "pcrValuesCount", 4)]
        [DataMember()]
        public Tpm2bDigest[] pcrValues;

        public Tpm2PcrReadResponse() {}

        public Tpm2PcrReadResponse(Tpm2PcrReadResponse src)
        {
            pcrUpdateCounter = src.pcrUpdateCounter;
            pcrSelectionOut = src.pcrSelectionOut;
            pcrValues = src.pcrValues;
        }

        new public Tpm2PcrReadResponse Copy() { return CreateCopy<Tpm2PcrReadResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to set the desired PCR allocation of PCR and
    /// algorithms. This command requires Platform Authorization. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PCR_Allocate_In")]
    public partial class Tpm2PcrAllocateRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The requested allocation </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrAllocationCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrAllocation;

        public Tpm2PcrAllocateRequest() { authHandle = new TpmHandle(); }

        /// <param name = "_authHandle"> TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_pcrAllocation"> The requested allocation </param>
        public Tpm2PcrAllocateRequest(TpmHandle _authHandle, PcrSelection[] _pcrAllocation)
        {
            authHandle = _authHandle;
            pcrAllocation = _pcrAllocation;
        }

        new public Tpm2PcrAllocateRequest Copy() { return CreateCopy<Tpm2PcrAllocateRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to set the desired PCR allocation of PCR and
    /// algorithms. This command requires Platform Authorization. </summary>
    [DataContract]
    [SpecTypeName("PCR_Allocate_Out")]
    public partial class Tpm2PcrAllocateResponse: TpmStructureBase
    {
        /// <summary> YES if the allocation succeeded </summary>
        [MarshalAs(0)]
        [DataMember()]
        public byte allocationSuccess { get; set; }

        /// <summary> Maximum number of PCR that may be in a bank </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint maxPCR { get; set; }

        /// <summary> Number of octets required to satisfy the request </summary>
        [MarshalAs(2)]
        [DataMember()]
        public uint sizeNeeded { get; set; }

        /// <summary> Number of octets available. Computed before the allocation. </summary>
        [MarshalAs(3)]
        [DataMember()]
        public uint sizeAvailable { get; set; }

        public Tpm2PcrAllocateResponse() {}

        public Tpm2PcrAllocateResponse(Tpm2PcrAllocateResponse src)
        {
            allocationSuccess = src.allocationSuccess;
            maxPCR = src.maxPCR;
            sizeNeeded = src.sizeNeeded;
            sizeAvailable = src.sizeAvailable;
        }

        new public Tpm2PcrAllocateResponse Copy() { return CreateCopy<Tpm2PcrAllocateResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to associate a policy with a PCR or group of PCR. The
    /// policy determines the conditions under which a PCR may be extended or reset. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PCR_SetAuthPolicy_In")]
    public partial class Tpm2PcrSetAuthPolicyRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The desired authPolicy </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authPolicySize", 2)]
        [DataMember()]
        public byte[] authPolicy;

        /// <summary> The hash algorithm of the policy </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        /// <summary> The PCR for which the policy is to be set </summary>
        [MarshalAs(3)]
        [DataMember()]
        public TpmHandle pcrNum { get; set; }

        public Tpm2PcrSetAuthPolicyRequest()
        {
            authHandle = new TpmHandle();
            hashAlg = TpmAlgId.Null;
            pcrNum = new TpmHandle();
        }

        /// <param name = "_authHandle"> TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_authPolicy"> The desired authPolicy </param>
        /// <param name = "_hashAlg"> The hash algorithm of the policy </param>
        /// <param name = "_pcrNum"> The PCR for which the policy is to be set </param>
        public Tpm2PcrSetAuthPolicyRequest(TpmHandle _authHandle, byte[] _authPolicy, TpmAlgId _hashAlg, TpmHandle _pcrNum)
        {
            authHandle = _authHandle;
            authPolicy = _authPolicy;
            hashAlg = _hashAlg;
            pcrNum = _pcrNum;
        }

        new public Tpm2PcrSetAuthPolicyRequest Copy() { return CreateCopy<Tpm2PcrSetAuthPolicyRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command changes the authValue of a PCR or group of PCR. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PCR_SetAuthValue_In")]
    public partial class Tpm2PcrSetAuthValueRequest: TpmStructureBase
    {
        /// <summary> Handle for a PCR that may have an authorization value set
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }

        /// <summary> The desired authorization value </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;

        public Tpm2PcrSetAuthValueRequest() { pcrHandle = new TpmHandle(); }

        /// <param name = "_pcrHandle"> Handle for a PCR that may have an authorization value set
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_auth"> The desired authorization value </param>
        public Tpm2PcrSetAuthValueRequest(TpmHandle _pcrHandle, byte[] _auth)
        {
            pcrHandle = _pcrHandle;
            auth = _auth;
        }

        new public Tpm2PcrSetAuthValueRequest Copy() { return CreateCopy<Tpm2PcrSetAuthValueRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> If the attribute of a PCR allows the PCR to be reset and proper
    /// authorization is provided, then this command may be used to set the PCR in all banks
    /// to zero. The attributes of the PCR may restrict the locality that can perform the
    /// reset operation. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PCR_Reset_In")]
    public partial class Tpm2PcrResetRequest: TpmStructureBase
    {
        /// <summary> The PCR to reset
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle pcrHandle { get; set; }

        public Tpm2PcrResetRequest() { pcrHandle = new TpmHandle(); }

        /// <param name = "_pcrHandle"> The PCR to reset
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        public Tpm2PcrResetRequest(TpmHandle _pcrHandle) { pcrHandle = _pcrHandle; }

        new public Tpm2PcrResetRequest Copy() { return CreateCopy<Tpm2PcrResetRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command includes a signed authorization in a policy. The command ties
    /// the policy to a signing key by including the Name of the signing key in the
    /// policyDigest </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("PolicySigned_In")]
    public partial class Tpm2PolicySignedRequest: TpmStructureBase
    {
        /// <summary> Handle for a key that will validate the signature
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authObject { get; set; }

        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The policy nonce for the session
        /// This can be the Empty Buffer. </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "nonceTPMSize", 2)]
        [DataMember()]
        public byte[] nonceTPM;

        /// <summary> Digest of the command parameters to which this authorization is limited
        /// This is not the cpHash for this command but the cpHash for the command to which this
        /// policy session will be applied. If it is not limited, the parameter will be the Empty
        /// Buffer. </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "cpHashASize", 2)]
        [DataMember()]
        public byte[] cpHashA;

        /// <summary> A reference to a policy relating to the authorization may be the Empty Buffer
        /// Size is limited to be no larger than the nonce size supported on the TPM. </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "policyRefSize", 2)]
        [DataMember()]
        public byte[] policyRef;

        /// <summary> Time when authorization will expire, measured in seconds from the time that
        /// nonceTPM was generated
        /// If expiration is non-negative, a NULL Ticket is returned. See 23.2.5. </summary>
        [MarshalAs(5)]
        [DataMember()]
        public int expiration { get; set; }

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(6, MarshalType.UnionSelector)]
        public TpmAlgId authSigAlg {
            get { return auth != null ? auth.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signed authorization (not optional) </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(7, MarshalType.Union, "authSigAlg")]
        [DataMember()]
        public ISignatureUnion auth { get; set; }

        public Tpm2PolicySignedRequest()
        {
            authObject = new TpmHandle();
            policySession = new TpmHandle();
        }

        /// <param name = "_authObject"> Handle for a key that will validate the signature
        ///        Auth Index: None </param>
        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_nonceTPM"> The policy nonce for the session
        ///        This can be the Empty Buffer. </param>
        /// <param name = "_cpHashA"> Digest of the command parameters to which this authorization is limited
        ///        This is not the cpHash for this command but the cpHash for the command to which
        ///        this policy session will be applied. If it is not limited, the parameter will be
        ///        the Empty Buffer. </param>
        /// <param name = "_policyRef"> A reference to a policy relating to the authorization may be
        ///        the Empty Buffer
        ///        Size is limited to be no larger than the nonce size supported on the TPM. </param>
        /// <param name = "_expiration"> Time when authorization will expire, measured in seconds from
        ///        the time that nonceTPM was generated
        ///        If expiration is non-negative, a NULL Ticket is returned. See 23.2.5. </param>
        /// <param name = "_auth"> Signed authorization (not optional)
        ///        One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        ///        SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </param>
        public Tpm2PolicySignedRequest(TpmHandle _authObject, TpmHandle _policySession, byte[] _nonceTPM, byte[] _cpHashA, byte[] _policyRef, int _expiration, ISignatureUnion _auth)
        {
            authObject = _authObject;
            policySession = _policySession;
            nonceTPM = _nonceTPM;
            cpHashA = _cpHashA;
            policyRef = _policyRef;
            expiration = _expiration;
            auth = _auth;
        }

        new public Tpm2PolicySignedRequest Copy() { return CreateCopy<Tpm2PolicySignedRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command includes a signed authorization in a policy. The command ties
    /// the policy to a signing key by including the Name of the signing key in the
    /// policyDigest </summary>
    [DataContract]
    [KnownType(typeof(TkAuth))]
    [SpecTypeName("PolicySigned_Out")]
    public partial class Tpm2PolicySignedResponse: TpmStructureBase
    {
        /// <summary> Implementation-specific time value, used to indicate to the TPM when the
        /// ticket expires
        /// NOTE If policyTicket is a NULL Ticket, then this shall be the Empty Buffer. </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "timeoutSize", 2)]
        [DataMember()]
        public byte[] timeout;

        /// <summary> Produced if the command succeeds and expiration in the command was non-zero;
        /// this ticket will use the TPMT_ST_AUTH_SIGNED structure tag. See 23.2.5 </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TkAuth policyTicket { get; set; }

        public Tpm2PolicySignedResponse() {}

        public Tpm2PolicySignedResponse(Tpm2PolicySignedResponse src)
        {
            timeout = src.timeout;
            policyTicket = src.policyTicket;
        }

        new public Tpm2PolicySignedResponse Copy() { return CreateCopy<Tpm2PolicySignedResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command includes a secret-based authorization to a policy. The caller
    /// proves knowledge of the secret value using an authorization session using the
    /// authValue associated with authHandle. A password session, an HMAC session, or a policy
    /// session containing TPM2_PolicyAuthValue() or TPM2_PolicyPassword() will satisfy this
    /// requirement. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicySecret_In")]
    public partial class Tpm2PolicySecretRequest: TpmStructureBase
    {
        /// <summary> Handle for an entity providing the authorization
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The policy nonce for the session
        /// This can be the Empty Buffer. </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "nonceTPMSize", 2)]
        [DataMember()]
        public byte[] nonceTPM;

        /// <summary> Digest of the command parameters to which this authorization is limited
        /// This not the cpHash for this command but the cpHash for the command to which this
        /// policy session will be applied. If it is not limited, the parameter will be the Empty
        /// Buffer. </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "cpHashASize", 2)]
        [DataMember()]
        public byte[] cpHashA;

        /// <summary> A reference to a policy relating to the authorization may be the Empty Buffer
        /// Size is limited to be no larger than the nonce size supported on the TPM. </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "policyRefSize", 2)]
        [DataMember()]
        public byte[] policyRef;

        /// <summary> Time when authorization will expire, measured in seconds from the time that
        /// nonceTPM was generated
        /// If expiration is non-negative, a NULL Ticket is returned. See 23.2.5. </summary>
        [MarshalAs(5)]
        [DataMember()]
        public int expiration { get; set; }

        public Tpm2PolicySecretRequest()
        {
            authHandle = new TpmHandle();
            policySession = new TpmHandle();
        }

        /// <param name = "_authHandle"> Handle for an entity providing the authorization
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_nonceTPM"> The policy nonce for the session
        ///        This can be the Empty Buffer. </param>
        /// <param name = "_cpHashA"> Digest of the command parameters to which this authorization is limited
        ///        This not the cpHash for this command but the cpHash for the command to which this
        ///        policy session will be applied. If it is not limited, the parameter will be the
        ///        Empty Buffer. </param>
        /// <param name = "_policyRef"> A reference to a policy relating to the authorization may be
        ///        the Empty Buffer
        ///        Size is limited to be no larger than the nonce size supported on the TPM. </param>
        /// <param name = "_expiration"> Time when authorization will expire, measured in seconds from
        ///        the time that nonceTPM was generated
        ///        If expiration is non-negative, a NULL Ticket is returned. See 23.2.5. </param>
        public Tpm2PolicySecretRequest(TpmHandle _authHandle, TpmHandle _policySession, byte[] _nonceTPM, byte[] _cpHashA, byte[] _policyRef, int _expiration)
        {
            authHandle = _authHandle;
            policySession = _policySession;
            nonceTPM = _nonceTPM;
            cpHashA = _cpHashA;
            policyRef = _policyRef;
            expiration = _expiration;
        }

        new public Tpm2PolicySecretRequest Copy() { return CreateCopy<Tpm2PolicySecretRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command includes a secret-based authorization to a policy. The caller
    /// proves knowledge of the secret value using an authorization session using the
    /// authValue associated with authHandle. A password session, an HMAC session, or a policy
    /// session containing TPM2_PolicyAuthValue() or TPM2_PolicyPassword() will satisfy this
    /// requirement. </summary>
    [DataContract]
    [KnownType(typeof(TkAuth))]
    [SpecTypeName("PolicySecret_Out")]
    public partial class Tpm2PolicySecretResponse: TpmStructureBase
    {
        /// <summary> Implementation-specific time value used to indicate to the TPM when the
        /// ticket expires </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "timeoutSize", 2)]
        [DataMember()]
        public byte[] timeout;

        /// <summary> Produced if the command succeeds and expiration in the command was non-zero
        /// ( See 23.2.5). This ticket will use the TPMT_ST_AUTH_SECRET structure tag </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TkAuth policyTicket { get; set; }

        public Tpm2PolicySecretResponse() {}

        public Tpm2PolicySecretResponse(Tpm2PolicySecretResponse src)
        {
            timeout = src.timeout;
            policyTicket = src.policyTicket;
        }

        new public Tpm2PolicySecretResponse Copy() { return CreateCopy<Tpm2PolicySecretResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is similar to TPM2_PolicySigned() except that it takes a ticket
    /// instead of a signed authorization. The ticket represents a validated authorization
    /// that had an expiration time associated with it. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TkAuth))]
    [SpecTypeName("PolicyTicket_In")]
    public partial class Tpm2PolicyTicketRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> Time when authorization will expire
        /// The contents are TPM specific. This shall be the value returned when ticket was
        /// produced. </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "timeoutSize", 2)]
        [DataMember()]
        public byte[] timeout;

        /// <summary> Digest of the command parameters to which this authorization is limited
        /// If it is not limited, the parameter will be the Empty Buffer. </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "cpHashASize", 2)]
        [DataMember()]
        public byte[] cpHashA;

        /// <summary> Reference to a qualifier for the policy may be the Empty Buffer </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "policyRefSize", 2)]
        [DataMember()]
        public byte[] policyRef;

        /// <summary> Name of the object that provided the authorization </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "authNameSize", 2)]
        [DataMember()]
        public byte[] authName;

        /// <summary> An authorization ticket returned by the TPM in response to a
        /// TPM2_PolicySigned() or TPM2_PolicySecret() </summary>
        [MarshalAs(5)]
        [DataMember()]
        public TkAuth ticket { get; set; }

        public Tpm2PolicyTicketRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_timeout"> Time when authorization will expire
        ///        The contents are TPM specific. This shall be the value returned when ticket was
        ///        produced. </param>
        /// <param name = "_cpHashA"> Digest of the command parameters to which this authorization is limited
        ///        If it is not limited, the parameter will be the Empty Buffer. </param>
        /// <param name = "_policyRef"> Reference to a qualifier for the policy may be the Empty
        ///        Buffer </param>
        /// <param name = "_authName"> Name of the object that provided the authorization </param>
        /// <param name = "_ticket"> An authorization ticket returned by the TPM in response to a
        ///        TPM2_PolicySigned() or TPM2_PolicySecret() </param>
        public Tpm2PolicyTicketRequest(TpmHandle _policySession, byte[] _timeout, byte[] _cpHashA, byte[] _policyRef, byte[] _authName, TkAuth _ticket)
        {
            policySession = _policySession;
            timeout = _timeout;
            cpHashA = _cpHashA;
            policyRef = _policyRef;
            authName = _authName;
            ticket = _ticket;
        }

        new public Tpm2PolicyTicketRequest Copy() { return CreateCopy<Tpm2PolicyTicketRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows options in authorizations without requiring that the TPM
    /// evaluate all of the options. If a policy may be satisfied by different sets of
    /// conditions, the TPM need only evaluate one set that satisfies the policy. This command
    /// will indicate that one of the required sets of conditions has been satisfied. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyOR_In")]
    public partial class Tpm2PolicyORRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The list of hashes to check for a match </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pHashListCount", 4)]
        [DataMember()]
        public Tpm2bDigest[] pHashList;

        public Tpm2PolicyORRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_pHashList"> The list of hashes to check for a match </param>
        public Tpm2PolicyORRequest(TpmHandle _policySession, Tpm2bDigest[] _pHashList)
        {
            policySession = _policySession;
            pHashList = _pHashList;
        }

        new public Tpm2PolicyORRequest Copy() { return CreateCopy<Tpm2PolicyORRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to cause conditional gating of a policy based on PCR.
    /// This command together with TPM2_PolicyOR() allows one group of authorizations to occur
    /// when PCR are in one state and a different set of authorizations when the PCR are in a
    /// different state. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyPCR_In")]
    public partial class Tpm2PolicyPCRRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> Expected digest value of the selected PCR using the hash algorithm of the
        /// session; may be zero length </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "pcrDigestSize", 2)]
        [DataMember()]
        public byte[] pcrDigest;

        /// <summary> The PCR to include in the check digest </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "pcrsCount", 4)]
        [DataMember()]
        public PcrSelection[] pcrs;

        public Tpm2PolicyPCRRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_pcrDigest"> Expected digest value of the selected PCR using the hash
        ///        algorithm of the session; may be zero length </param>
        /// <param name = "_pcrs"> The PCR to include in the check digest </param>
        public Tpm2PolicyPCRRequest(TpmHandle _policySession, byte[] _pcrDigest, PcrSelection[] _pcrs)
        {
            policySession = _policySession;
            pcrDigest = _pcrDigest;
            pcrs = _pcrs;
        }

        new public Tpm2PolicyPCRRequest Copy() { return CreateCopy<Tpm2PolicyPCRRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command indicates that the authorization will be limited to a specific
    /// locality. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(LocalityAttr))]
    [SpecTypeName("PolicyLocality_In")]
    public partial class Tpm2PolicyLocalityRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The allowed localities for the policy </summary>
        [MarshalAs(1)]
        [DataMember()]
        public LocalityAttr locality { get; set; }

        public Tpm2PolicyLocalityRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_locality"> The allowed localities for the policy </param>
        public Tpm2PolicyLocalityRequest(TpmHandle _policySession, LocalityAttr _locality)
        {
            policySession = _policySession;
            locality = _locality;
        }

        new public Tpm2PolicyLocalityRequest Copy() { return CreateCopy<Tpm2PolicyLocalityRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to cause conditional gating of a policy based on the
    /// contents of an NV Index. It is an immediate assertion. The NV index is validated
    /// during the TPM2_PolicyNV() command, not when the session is used for authorization. </summary>
    [DataContract]
    [KnownType(typeof(Eo))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyNV_In")]
    public partial class Tpm2PolicyNVRequest: TpmStructureBase
    {
        /// <summary> Handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The NV Index of the area to read
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The second operand </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "operandBSize", 2)]
        [DataMember()]
        public byte[] operandB;

        /// <summary> The octet offset in the NV Index for the start of operand A </summary>
        [MarshalAs(4)]
        [DataMember()]
        public ushort offset { get; set; }

        /// <summary> The comparison to make </summary>
        [MarshalAs(5)]
        [DataMember()]
        public Eo operation { get; set; }

        public Tpm2PolicyNVRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
            policySession = new TpmHandle();
        }

        /// <param name = "_authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> The NV Index of the area to read
        ///        Auth Index: None </param>
        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_operandB"> The second operand </param>
        /// <param name = "_offset"> The octet offset in the NV Index for the start of operand A </param>
        /// <param name = "_operation"> The comparison to make </param>
        public Tpm2PolicyNVRequest(TpmHandle _authHandle, TpmHandle _nvIndex, TpmHandle _policySession, byte[] _operandB, ushort _offset, Eo _operation)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
            policySession = _policySession;
            operandB = _operandB;
            offset = _offset;
            operation = _operation;
        }

        new public Tpm2PolicyNVRequest Copy() { return CreateCopy<Tpm2PolicyNVRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to cause conditional gating of a policy based on the
    /// contents of the TPMS_TIME_INFO structure. </summary>
    [DataContract]
    [KnownType(typeof(Eo))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyCounterTimer_In")]
    public partial class Tpm2PolicyCounterTimerRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The second operand </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "operandBSize", 2)]
        [DataMember()]
        public byte[] operandB;

        /// <summary> The octet offset in the TPMS_TIME_INFO structure for the start of operand A </summary>
        [MarshalAs(2)]
        [DataMember()]
        public ushort offset { get; set; }

        /// <summary> The comparison to make </summary>
        [MarshalAs(3)]
        [DataMember()]
        public Eo operation { get; set; }

        public Tpm2PolicyCounterTimerRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_operandB"> The second operand </param>
        /// <param name = "_offset"> The octet offset in the TPMS_TIME_INFO structure for the start of
        ///        operand A </param>
        /// <param name = "_operation"> The comparison to make </param>
        public Tpm2PolicyCounterTimerRequest(TpmHandle _policySession, byte[] _operandB, ushort _offset, Eo _operation)
        {
            policySession = _policySession;
            operandB = _operandB;
            offset = _offset;
            operation = _operation;
        }

        new public Tpm2PolicyCounterTimerRequest Copy() { return CreateCopy<Tpm2PolicyCounterTimerRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command indicates that the authorization will be limited to a specific
    /// command code. </summary>
    [DataContract]
    [KnownType(typeof(TpmCc))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyCommandCode_In")]
    public partial class Tpm2PolicyCommandCodeRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The allowed commandCode </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmCc code { get; set; }

        public Tpm2PolicyCommandCodeRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_code"> The allowed commandCode </param>
        public Tpm2PolicyCommandCodeRequest(TpmHandle _policySession, TpmCc _code)
        {
            policySession = _policySession;
            code = _code;
        }

        new public Tpm2PolicyCommandCodeRequest Copy() { return CreateCopy<Tpm2PolicyCommandCodeRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command indicates that physical presence will need to be asserted at
    /// the time the authorization is performed. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyPhysicalPresence_In")]
    public partial class Tpm2PolicyPhysicalPresenceRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        public Tpm2PolicyPhysicalPresenceRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        public Tpm2PolicyPhysicalPresenceRequest(TpmHandle _policySession) { policySession = _policySession; }

        new public Tpm2PolicyPhysicalPresenceRequest Copy() { return CreateCopy<Tpm2PolicyPhysicalPresenceRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to allow a policy to be bound to a specific command and
    /// command parameters. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyCpHash_In")]
    public partial class Tpm2PolicyCpHashRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The cpHash added to the policy </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "cpHashASize", 2)]
        [DataMember()]
        public byte[] cpHashA;

        public Tpm2PolicyCpHashRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_cpHashA"> The cpHash added to the policy </param>
        public Tpm2PolicyCpHashRequest(TpmHandle _policySession, byte[] _cpHashA)
        {
            policySession = _policySession;
            cpHashA = _cpHashA;
        }

        new public Tpm2PolicyCpHashRequest Copy() { return CreateCopy<Tpm2PolicyCpHashRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows a policy to be bound to a specific set of TPM entities
    /// without being bound to the parameters of the command. This is most useful for commands
    /// such as TPM2_Duplicate() and for TPM2_PCR_Event() when the referenced PCR requires a
    /// policy. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyNameHash_In")]
    public partial class Tpm2PolicyNameHashRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The digest to be added to the policy </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nameHashSize", 2)]
        [DataMember()]
        public byte[] nameHash;

        public Tpm2PolicyNameHashRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_nameHash"> The digest to be added to the policy </param>
        public Tpm2PolicyNameHashRequest(TpmHandle _policySession, byte[] _nameHash)
        {
            policySession = _policySession;
            nameHash = _nameHash;
        }

        new public Tpm2PolicyNameHashRequest Copy() { return CreateCopy<Tpm2PolicyNameHashRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows qualification of duplication to allow duplication to a
    /// selected new parent. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyDuplicationSelect_In")]
    public partial class Tpm2PolicyDuplicationSelectRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The Name of the object to be duplicated </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "objectNameSize", 2)]
        [DataMember()]
        public byte[] objectName;

        /// <summary> The Name of the new parent </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "newParentNameSize", 2)]
        [DataMember()]
        public byte[] newParentName;

        /// <summary> If YES, the objectName will be included in the value in
        /// policySessionpolicyDigest </summary>
        [MarshalAs(3)]
        [DataMember()]
        public byte includeObject { get; set; }

        public Tpm2PolicyDuplicationSelectRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_objectName"> The Name of the object to be duplicated </param>
        /// <param name = "_newParentName"> The Name of the new parent </param>
        /// <param name = "_includeObject"> If YES, the objectName will be included in the value in
        ///        policySessionpolicyDigest </param>
        public Tpm2PolicyDuplicationSelectRequest(TpmHandle _policySession, byte[] _objectName, byte[] _newParentName, byte _includeObject)
        {
            policySession = _policySession;
            objectName = _objectName;
            newParentName = _newParentName;
            includeObject = _includeObject;
        }

        new public Tpm2PolicyDuplicationSelectRequest Copy() { return CreateCopy<Tpm2PolicyDuplicationSelectRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows policies to change. If a policy were static, then it
    /// would be difficult to add users to a policy. This command lets a policy authority sign
    /// a new policy so that it may be used in an existing policy. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(TkVerified))]
    [SpecTypeName("PolicyAuthorize_In")]
    public partial class Tpm2PolicyAuthorizeRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> Digest of the policy being approved </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "approvedPolicySize", 2)]
        [DataMember()]
        public byte[] approvedPolicy;

        /// <summary> A policy qualifier </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "policyRefSize", 2)]
        [DataMember()]
        public byte[] policyRef;

        /// <summary> Name of a key that can sign a policy addition </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "keySignSize", 2)]
        [DataMember()]
        public byte[] keySign;

        /// <summary> Ticket validating that approvedPolicy and policyRef were signed by keySign </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TkVerified checkTicket { get; set; }

        public Tpm2PolicyAuthorizeRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_approvedPolicy"> Digest of the policy being approved </param>
        /// <param name = "_policyRef"> A policy qualifier </param>
        /// <param name = "_keySign"> Name of a key that can sign a policy addition </param>
        /// <param name = "_checkTicket"> Ticket validating that approvedPolicy and policyRef were
        ///        signed by keySign </param>
        public Tpm2PolicyAuthorizeRequest(TpmHandle _policySession, byte[] _approvedPolicy, byte[] _policyRef, byte[] _keySign, TkVerified _checkTicket)
        {
            policySession = _policySession;
            approvedPolicy = _approvedPolicy;
            policyRef = _policyRef;
            keySign = _keySign;
            checkTicket = _checkTicket;
        }

        new public Tpm2PolicyAuthorizeRequest Copy() { return CreateCopy<Tpm2PolicyAuthorizeRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows a policy to be bound to the authorization value of the
    /// authorized entity. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyAuthValue_In")]
    public partial class Tpm2PolicyAuthValueRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        public Tpm2PolicyAuthValueRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        public Tpm2PolicyAuthValueRequest(TpmHandle _policySession) { policySession = _policySession; }

        new public Tpm2PolicyAuthValueRequest Copy() { return CreateCopy<Tpm2PolicyAuthValueRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows a policy to be bound to the authorization value of the
    /// authorized object. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyPassword_In")]
    public partial class Tpm2PolicyPasswordRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        public Tpm2PolicyPasswordRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        public Tpm2PolicyPasswordRequest(TpmHandle _policySession) { policySession = _policySession; }

        new public Tpm2PolicyPasswordRequest Copy() { return CreateCopy<Tpm2PolicyPasswordRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the current policyDigest of the session. This command
    /// allows the TPM to be used to perform the actions required to pre-compute the
    /// authPolicy for an object. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyGetDigest_In")]
    public partial class Tpm2PolicyGetDigestRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        public Tpm2PolicyGetDigestRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session
        ///        Auth Index: None </param>
        public Tpm2PolicyGetDigestRequest(TpmHandle _policySession) { policySession = _policySession; }

        new public Tpm2PolicyGetDigestRequest Copy() { return CreateCopy<Tpm2PolicyGetDigestRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns the current policyDigest of the session. This command
    /// allows the TPM to be used to perform the actions required to pre-compute the
    /// authPolicy for an object. </summary>
    [DataContract]
    [SpecTypeName("PolicyGetDigest_Out")]
    public partial class Tpm2PolicyGetDigestResponse: TpmStructureBase
    {
        /// <summary> The current value of the policySessionpolicyDigest </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "policyDigestSize", 2)]
        [DataMember()]
        public byte[] policyDigest;

        public Tpm2PolicyGetDigestResponse() {}

        public Tpm2PolicyGetDigestResponse(Tpm2PolicyGetDigestResponse src) { policyDigest = src.policyDigest; }

        new public Tpm2PolicyGetDigestResponse Copy() { return CreateCopy<Tpm2PolicyGetDigestResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows a policy to be bound to the TPMA_NV_WRITTEN attributes.
    /// This is a deferred assertion. Values are stored in the policy session context and
    /// checked when the policy is used for authorization. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyNvWritten_In")]
    public partial class Tpm2PolicyNvWrittenRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> YES if NV Index is required to have been written
        /// NO if NV Index is required not to have been written </summary>
        [MarshalAs(1)]
        [DataMember()]
        public byte writtenSet { get; set; }

        public Tpm2PolicyNvWrittenRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_writtenSet"> YES if NV Index is required to have been written
        ///        NO if NV Index is required not to have been written </param>
        public Tpm2PolicyNvWrittenRequest(TpmHandle _policySession, byte _writtenSet)
        {
            policySession = _policySession;
            writtenSet = _writtenSet;
        }

        new public Tpm2PolicyNvWrittenRequest Copy() { return CreateCopy<Tpm2PolicyNvWrittenRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows a policy to be bound to a specific creation template.
    /// This is most useful for an object creation command such as TPM2_Create(),
    /// TPM2_CreatePrimary(), or TPM2_CreateLoaded(). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyTemplate_In")]
    public partial class Tpm2PolicyTemplateRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The digest to be added to the policy </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "templateHashSize", 2)]
        [DataMember()]
        public byte[] templateHash;

        public Tpm2PolicyTemplateRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_templateHash"> The digest to be added to the policy </param>
        public Tpm2PolicyTemplateRequest(TpmHandle _policySession, byte[] _templateHash)
        {
            policySession = _policySession;
            templateHash = _templateHash;
        }

        new public Tpm2PolicyTemplateRequest Copy() { return CreateCopy<Tpm2PolicyTemplateRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command provides a capability that is the equivalent of a revocable
    /// policy. With TPM2_PolicyAuthorize(), the authorization ticket never expires, so the
    /// authorization may not be withdrawn. With this command, the approved policy is kept in
    /// an NV Index location so that the policy may be changed as needed to render the old
    /// policy unusable. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PolicyAuthorizeNV_In")]
    public partial class Tpm2PolicyAuthorizeNVRequest: TpmStructureBase
    {
        /// <summary> Handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The NV Index of the area to read
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        public Tpm2PolicyAuthorizeNVRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
            policySession = new TpmHandle();
        }

        /// <param name = "_authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> The NV Index of the area to read
        ///        Auth Index: None </param>
        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        public Tpm2PolicyAuthorizeNVRequest(TpmHandle _authHandle, TpmHandle _nvIndex, TpmHandle _policySession)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
            policySession = _policySession;
        }

        new public Tpm2PolicyAuthorizeNVRequest Copy() { return CreateCopy<Tpm2PolicyAuthorizeNVRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to create a Primary Object under one of the Primary
    /// Seeds or a Temporary Object under TPM_RH_NULL. The command uses a TPM2B_PUBLIC as a
    /// template for the object to be created. The size of the unique field shall not be
    /// checked for consistency with the other object parameters. The command will create and
    /// load a Primary Object. The sensitive area is not returned. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SensitiveCreate))]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("CreatePrimary_In")]
    public partial class Tpm2CreatePrimaryRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle primaryHandle { get; set; }

        /// <summary> The sensitive data, see TPM 2.0 Part 1 Sensitive Values </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "inSensitiveSize", 2)]
        [DataMember()]
        public SensitiveCreate inSensitive { get; set; }

        /// <summary> The public template </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "inPublicSize", 2)]
        [DataMember()]
        public TpmPublic inPublic { get; set; }

        /// <summary> Data that will be included in the creation data for this object to provide
        /// permanent, verifiable linkage between this object and some object owner data </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "outsideInfoSize", 2)]
        [DataMember()]
        public byte[] outsideInfo;

        /// <summary> PCR that will be used in creation data </summary>
        [MarshalAs(4, MarshalType.VariableLengthArray, "creationPCRCount", 4)]
        [DataMember()]
        public PcrSelection[] creationPCR;

        public Tpm2CreatePrimaryRequest() { primaryHandle = new TpmHandle(); }

        /// <param name = "_primaryHandle"> TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or
        ///        TPM_RH_NULL
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_inSensitive"> The sensitive data, see TPM 2.0 Part 1 Sensitive Values </param>
        /// <param name = "_inPublic"> The public template </param>
        /// <param name = "_outsideInfo"> Data that will be included in the creation data for this
        ///        object to provide permanent, verifiable linkage between this object and some object
        ///        owner data </param>
        /// <param name = "_creationPCR"> PCR that will be used in creation data </param>
        public Tpm2CreatePrimaryRequest(TpmHandle _primaryHandle, SensitiveCreate _inSensitive, TpmPublic _inPublic, byte[] _outsideInfo, PcrSelection[] _creationPCR)
        {
            primaryHandle = _primaryHandle;
            inSensitive = _inSensitive;
            inPublic = _inPublic;
            outsideInfo = _outsideInfo;
            creationPCR = _creationPCR;
        }

        new public Tpm2CreatePrimaryRequest Copy() { return CreateCopy<Tpm2CreatePrimaryRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to create a Primary Object under one of the Primary
    /// Seeds or a Temporary Object under TPM_RH_NULL. The command uses a TPM2B_PUBLIC as a
    /// template for the object to be created. The size of the unique field shall not be
    /// checked for consistency with the other object parameters. The command will create and
    /// load a Primary Object. The sensitive area is not returned. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(CreationData))]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(TkCreation))]
    [SpecTypeName("CreatePrimary_Out")]
    public partial class Tpm2CreatePrimaryResponse: TpmStructureBase
    {
        /// <summary> Handle of type TPM_HT_TRANSIENT for created Primary Object </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> The public portion of the created object </summary>
        [MarshalAs(1, MarshalType.SizedStruct, "outPublicSize", 2)]
        [DataMember()]
        public TpmPublic outPublic { get; set; }

        /// <summary> Contains a TPMT_CREATION_DATA </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "creationDataSize", 2)]
        [DataMember()]
        public CreationData creationData { get; set; }

        /// <summary> Digest of creationData using nameAlg of outPublic </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "creationHashSize", 2)]
        [DataMember()]
        public byte[] creationHash;

        /// <summary> Ticket used by TPM2_CertifyCreation() to validate that the creation data was
        /// produced by the TPM </summary>
        [MarshalAs(4)]
        [DataMember()]
        public TkCreation creationTicket { get; set; }

        /// <summary> The name of the created object </summary>
        [MarshalAs(5, MarshalType.VariableLengthArray, "nameSize", 2)]
        [DataMember()]
        public byte[] name;

        public Tpm2CreatePrimaryResponse() { handle = new TpmHandle(); }

        public Tpm2CreatePrimaryResponse(Tpm2CreatePrimaryResponse src)
        {
            handle = src.handle;
            outPublic = src.outPublic;
            creationData = src.creationData;
            creationHash = src.creationHash;
            creationTicket = src.creationTicket;
            name = src.name;
        }

        new public Tpm2CreatePrimaryResponse Copy() { return CreateCopy<Tpm2CreatePrimaryResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command enables and disables use of a hierarchy and its associated NV
    /// storage. The command allows phEnable, phEnableNV, shEnable, and ehEnable to be changed
    /// when the proper authorization is provided. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("HierarchyControl_In")]
    public partial class Tpm2HierarchyControlRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The enable being modified
        /// TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, or TPM_RH_PLATFORM_NV </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle enable { get; set; }

        /// <summary> YES if the enable should be SET, NO if the enable should be CLEAR </summary>
        [MarshalAs(2)]
        [DataMember()]
        public byte state { get; set; }

        public Tpm2HierarchyControlRequest()
        {
            authHandle = new TpmHandle();
            enable = new TpmHandle();
        }

        /// <param name = "_authHandle"> TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_enable"> The enable being modified
        ///        TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, or TPM_RH_PLATFORM_NV </param>
        /// <param name = "_state"> YES if the enable should be SET, NO if the enable should be CLEAR </param>
        public Tpm2HierarchyControlRequest(TpmHandle _authHandle, TpmHandle _enable, byte _state)
        {
            authHandle = _authHandle;
            enable = _enable;
            state = _state;
        }

        new public Tpm2HierarchyControlRequest Copy() { return CreateCopy<Tpm2HierarchyControlRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows setting of the authorization policy for the lockout
    /// (lockoutPolicy), the platform hierarchy (platformPolicy), the storage hierarchy
    /// (ownerPolicy), and the endorsement hierarchy (endorsementPolicy). On TPMs implementing
    /// Authenticated Countdown Timers (ACT), this command may also be used to set the
    /// authorization policy for an ACT. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("SetPrimaryPolicy_In")]
    public partial class Tpm2SetPrimaryPolicyRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPMI_RH_ACT or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> An authorization policy digest; may be the Empty Buffer
        /// If hashAlg is TPM_ALG_NULL, then this shall be an Empty Buffer. </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authPolicySize", 2)]
        [DataMember()]
        public byte[] authPolicy;

        /// <summary> The hash algorithm to use for the policy
        /// If the authPolicy is an Empty Buffer, then this field shall be TPM_ALG_NULL. </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmAlgId hashAlg { get; set; }

        public Tpm2SetPrimaryPolicyRequest()
        {
            authHandle = new TpmHandle();
            hashAlg = TpmAlgId.Null;
        }

        /// <param name = "_authHandle"> TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPMI_RH_ACT
        ///        or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_authPolicy"> An authorization policy digest; may be the Empty Buffer
        ///        If hashAlg is TPM_ALG_NULL, then this shall be an Empty Buffer. </param>
        /// <param name = "_hashAlg"> The hash algorithm to use for the policy
        ///        If the authPolicy is an Empty Buffer, then this field shall be TPM_ALG_NULL. </param>
        public Tpm2SetPrimaryPolicyRequest(TpmHandle _authHandle, byte[] _authPolicy, TpmAlgId _hashAlg)
        {
            authHandle = _authHandle;
            authPolicy = _authPolicy;
            hashAlg = _hashAlg;
        }

        new public Tpm2SetPrimaryPolicyRequest Copy() { return CreateCopy<Tpm2SetPrimaryPolicyRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This replaces the current platform primary seed (PPS) with a value from the
    /// RNG and sets platformPolicy to the default initialization value (the Empty Buffer). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ChangePPS_In")]
    public partial class Tpm2ChangePPSRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        public Tpm2ChangePPSRequest() { authHandle = new TpmHandle(); }

        /// <param name = "_authHandle"> TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        public Tpm2ChangePPSRequest(TpmHandle _authHandle) { authHandle = _authHandle; }

        new public Tpm2ChangePPSRequest Copy() { return CreateCopy<Tpm2ChangePPSRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This replaces the current endorsement primary seed (EPS) with a value from
    /// the RNG and sets the Endorsement hierarchy controls to their default initialization
    /// values: ehEnable is SET, endorsementAuth and endorsementPolicy are both set to the
    /// Empty Buffer. It will flush any resident objects (transient or persistent) in the
    /// Endorsement hierarchy and not allow objects in the hierarchy associated with the
    /// previous EPS to be loaded. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ChangeEPS_In")]
    public partial class Tpm2ChangeEPSRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        public Tpm2ChangeEPSRequest() { authHandle = new TpmHandle(); }

        /// <param name = "_authHandle"> TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        public Tpm2ChangeEPSRequest(TpmHandle _authHandle) { authHandle = _authHandle; }

        new public Tpm2ChangeEPSRequest Copy() { return CreateCopy<Tpm2ChangeEPSRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command removes all TPM context associated with a specific Owner. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("Clear_In")]
    public partial class Tpm2ClearRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        public Tpm2ClearRequest() { authHandle = new TpmHandle(); }

        /// <param name = "_authHandle"> TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        public Tpm2ClearRequest(TpmHandle _authHandle) { authHandle = _authHandle; }

        new public Tpm2ClearRequest Copy() { return CreateCopy<Tpm2ClearRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> TPM2_ClearControl() disables and enables the execution of TPM2_Clear(). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ClearControl_In")]
    public partial class Tpm2ClearControlRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }

        /// <summary> YES if the disableOwnerClear flag is to be SET, NO if the flag is to be
        /// CLEAR. </summary>
        [MarshalAs(1)]
        [DataMember()]
        public byte disable { get; set; }

        public Tpm2ClearControlRequest() { auth = new TpmHandle(); }

        /// <param name = "_auth"> TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "_disable"> YES if the disableOwnerClear flag is to be SET, NO if the flag
        ///        is to be CLEAR. </param>
        public Tpm2ClearControlRequest(TpmHandle _auth, byte _disable)
        {
            auth = _auth;
            disable = _disable;
        }

        new public Tpm2ClearControlRequest Copy() { return CreateCopy<Tpm2ClearControlRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows the authorization secret for a hierarchy or lockout to
    /// be changed using the current authorization value as the command authorization. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("HierarchyChangeAuth_In")]
    public partial class Tpm2HierarchyChangeAuthRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> New authorization value </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "newAuthSize", 2)]
        [DataMember()]
        public byte[] newAuth;

        public Tpm2HierarchyChangeAuthRequest() { authHandle = new TpmHandle(); }

        /// <param name = "_authHandle"> TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_newAuth"> New authorization value </param>
        public Tpm2HierarchyChangeAuthRequest(TpmHandle _authHandle, byte[] _newAuth)
        {
            authHandle = _authHandle;
            newAuth = _newAuth;
        }

        new public Tpm2HierarchyChangeAuthRequest Copy() { return CreateCopy<Tpm2HierarchyChangeAuthRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command cancels the effect of a TPM lockout due to a number of
    /// successive authorization failures. If this command is properly authorized, the lockout
    /// counter is set to zero. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("DictionaryAttackLockReset_In")]
    public partial class Tpm2DictionaryAttackLockResetRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_LOCKOUT
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle lockHandle { get; set; }

        public Tpm2DictionaryAttackLockResetRequest() { lockHandle = new TpmHandle(); }

        /// <param name = "_lockHandle"> TPM_RH_LOCKOUT
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        public Tpm2DictionaryAttackLockResetRequest(TpmHandle _lockHandle) { lockHandle = _lockHandle; }

        new public Tpm2DictionaryAttackLockResetRequest Copy() { return CreateCopy<Tpm2DictionaryAttackLockResetRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command changes the lockout parameters. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("DictionaryAttackParameters_In")]
    public partial class Tpm2DictionaryAttackParametersRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_LOCKOUT
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle lockHandle { get; set; }

        /// <summary> Count of authorization failures before the lockout is imposed </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint newMaxTries { get; set; }

        /// <summary> Time in seconds before the authorization failure count is automatically decremented
        /// A value of zero indicates that DA protection is disabled. </summary>
        [MarshalAs(2)]
        [DataMember()]
        public uint newRecoveryTime { get; set; }

        /// <summary> Time in seconds after a lockoutAuth failure before use of lockoutAuth is allowed
        /// A value of zero indicates that a reboot is required. </summary>
        [MarshalAs(3)]
        [DataMember()]
        public uint lockoutRecovery { get; set; }

        public Tpm2DictionaryAttackParametersRequest() { lockHandle = new TpmHandle(); }

        /// <param name = "_lockHandle"> TPM_RH_LOCKOUT
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_newMaxTries"> Count of authorization failures before the lockout is
        ///        imposed </param>
        /// <param name = "_newRecoveryTime"> Time in seconds before the authorization failure count
        ///        is automatically decremented
        ///        A value of zero indicates that DA protection is disabled. </param>
        /// <param name = "_lockoutRecovery"> Time in seconds after a lockoutAuth failure before use
        ///        of lockoutAuth is allowed
        ///        A value of zero indicates that a reboot is required. </param>
        public Tpm2DictionaryAttackParametersRequest(TpmHandle _lockHandle, uint _newMaxTries, uint _newRecoveryTime, uint _lockoutRecovery)
        {
            lockHandle = _lockHandle;
            newMaxTries = _newMaxTries;
            newRecoveryTime = _newRecoveryTime;
            lockoutRecovery = _lockoutRecovery;
        }

        new public Tpm2DictionaryAttackParametersRequest Copy() { return CreateCopy<Tpm2DictionaryAttackParametersRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to determine which commands require assertion of
    /// Physical Presence (PP) in addition to platformAuth/platformPolicy. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("PP_Commands_In")]
    public partial class Tpm2PpCommandsRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_PLATFORM+PP
        /// Auth Index: 1
        /// Auth Role: USER + Physical Presence </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }

        /// <summary> List of commands to be added to those that will require that Physical
        /// Presence be asserted </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "setListCount", 4)]
        [DataMember()]
        public TpmCc[] setList;

        /// <summary> List of commands that will no longer require that Physical Presence be
        /// asserted </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "clearListCount", 4)]
        [DataMember()]
        public TpmCc[] clearList;

        public Tpm2PpCommandsRequest() { auth = new TpmHandle(); }

        /// <param name = "_auth"> TPM_RH_PLATFORM+PP
        ///        Auth Index: 1
        ///        Auth Role: USER + Physical Presence </param>
        /// <param name = "_setList"> List of commands to be added to those that will require that
        ///        Physical Presence be asserted </param>
        /// <param name = "_clearList"> List of commands that will no longer require that Physical
        ///        Presence be asserted </param>
        public Tpm2PpCommandsRequest(TpmHandle _auth, TpmCc[] _setList, TpmCc[] _clearList)
        {
            auth = _auth;
            setList = _setList;
            clearList = _clearList;
        }

        new public Tpm2PpCommandsRequest Copy() { return CreateCopy<Tpm2PpCommandsRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows the platform to change the set of algorithms that are
    /// used by the TPM. The algorithmSet setting is a vendor-dependent value. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("SetAlgorithmSet_In")]
    public partial class Tpm2SetAlgorithmSetRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_PLATFORM
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> A TPM vendor-dependent value indicating the algorithm set selection </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint algorithmSet { get; set; }

        public Tpm2SetAlgorithmSetRequest() { authHandle = new TpmHandle(); }

        /// <param name = "_authHandle"> TPM_RH_PLATFORM
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_algorithmSet"> A TPM vendor-dependent value indicating the algorithm set
        ///        selection </param>
        public Tpm2SetAlgorithmSetRequest(TpmHandle _authHandle, uint _algorithmSet)
        {
            authHandle = _authHandle;
            algorithmSet = _algorithmSet;
        }

        new public Tpm2SetAlgorithmSetRequest Copy() { return CreateCopy<Tpm2SetAlgorithmSetRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command uses platformPolicy and a TPM Vendor Authorization Key to
    /// authorize a Field Upgrade Manifest. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("FieldUpgradeStart_In")]
    public partial class Tpm2FieldUpgradeStartRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_PLATFORM+{PP}
        /// Auth Index:1
        /// Auth Role: ADMIN </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authorization { get; set; }

        /// <summary> Handle of a public area that contains the TPM Vendor Authorization Key that
        /// will be used to validate manifestSignature
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle keyHandle { get; set; }

        /// <summary> Digest of the first block in the field upgrade sequence </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "fuDigestSize", 2)]
        [DataMember()]
        public byte[] fuDigest;

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(3, MarshalType.UnionSelector)]
        public TpmAlgId manifestSignatureSigAlg {
            get { return manifestSignature != null ? manifestSignature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signature over fuDigest using the key associated with keyHandle (not
        /// optional) </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(4, MarshalType.Union, "manifestSignatureSigAlg")]
        [DataMember()]
        public ISignatureUnion manifestSignature { get; set; }

        public Tpm2FieldUpgradeStartRequest()
        {
            authorization = new TpmHandle();
            keyHandle = new TpmHandle();
        }

        /// <param name = "_authorization"> TPM_RH_PLATFORM+{PP}
        ///        Auth Index:1
        ///        Auth Role: ADMIN </param>
        /// <param name = "_keyHandle"> Handle of a public area that contains the TPM Vendor
        ///        Authorization Key that will be used to validate manifestSignature
        ///        Auth Index: None </param>
        /// <param name = "_fuDigest"> Digest of the first block in the field upgrade sequence </param>
        /// <param name = "_manifestSignature"> Signature over fuDigest using the key associated with
        ///        keyHandle (not optional)
        ///        One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        ///        SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </param>
        public Tpm2FieldUpgradeStartRequest(TpmHandle _authorization, TpmHandle _keyHandle, byte[] _fuDigest, ISignatureUnion _manifestSignature)
        {
            authorization = _authorization;
            keyHandle = _keyHandle;
            fuDigest = _fuDigest;
            manifestSignature = _manifestSignature;
        }

        new public Tpm2FieldUpgradeStartRequest Copy() { return CreateCopy<Tpm2FieldUpgradeStartRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command will take the actual field upgrade image to be installed on the
    /// TPM. The exact format of fuData is vendor-specific. This command is only possible
    /// following a successful TPM2_FieldUpgradeStart(). If the TPM has not received a
    /// properly authorized TPM2_FieldUpgradeStart(), then the TPM shall return
    /// TPM_RC_FIELDUPGRADE. </summary>
    [DataContract]
    [SpecTypeName("FieldUpgradeData_In")]
    public partial class Tpm2FieldUpgradeDataRequest: TpmStructureBase
    {
        /// <summary> Field upgrade image data </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "fuDataSize", 2)]
        [DataMember()]
        public byte[] fuData;

        public Tpm2FieldUpgradeDataRequest() {}

        /// <param name = "_fuData"> Field upgrade image data </param>
        public Tpm2FieldUpgradeDataRequest(byte[] _fuData) { fuData = _fuData; }

        new public Tpm2FieldUpgradeDataRequest Copy() { return CreateCopy<Tpm2FieldUpgradeDataRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command will take the actual field upgrade image to be installed on the
    /// TPM. The exact format of fuData is vendor-specific. This command is only possible
    /// following a successful TPM2_FieldUpgradeStart(). If the TPM has not received a
    /// properly authorized TPM2_FieldUpgradeStart(), then the TPM shall return
    /// TPM_RC_FIELDUPGRADE. </summary>
    [DataContract]
    [KnownType(typeof(TpmHash))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("FieldUpgradeData_Out")]
    public partial class Tpm2FieldUpgradeDataResponse: TpmStructureBase
    {
        /// <summary> Tagged digest of the next block
        /// TPM_ALG_NULL if field update is complete </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHash nextDigest { get; set; }

        /// <summary> Tagged digest of the first block of the sequence </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHash firstDigest { get; set; }

        public Tpm2FieldUpgradeDataResponse() {}

        public Tpm2FieldUpgradeDataResponse(Tpm2FieldUpgradeDataResponse src)
        {
            nextDigest = src.nextDigest;
            firstDigest = src.firstDigest;
        }

        new public Tpm2FieldUpgradeDataResponse Copy() { return CreateCopy<Tpm2FieldUpgradeDataResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to read a copy of the current firmware installed in the
    /// TPM. </summary>
    [DataContract]
    [SpecTypeName("FirmwareRead_In")]
    public partial class Tpm2FirmwareReadRequest: TpmStructureBase
    {
        /// <summary> The number of previous calls to this command in this sequence
        /// set to 0 on the first call </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint sequenceNumber { get; set; }

        public Tpm2FirmwareReadRequest() {}

        /// <param name = "_sequenceNumber"> The number of previous calls to this command in this sequence
        ///        set to 0 on the first call </param>
        public Tpm2FirmwareReadRequest(uint _sequenceNumber) { sequenceNumber = _sequenceNumber; }

        new public Tpm2FirmwareReadRequest Copy() { return CreateCopy<Tpm2FirmwareReadRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to read a copy of the current firmware installed in the
    /// TPM. </summary>
    [DataContract]
    [SpecTypeName("FirmwareRead_Out")]
    public partial class Tpm2FirmwareReadResponse: TpmStructureBase
    {
        /// <summary> Field upgrade image data </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "fuDataSize", 2)]
        [DataMember()]
        public byte[] fuData;

        public Tpm2FirmwareReadResponse() {}

        public Tpm2FirmwareReadResponse(Tpm2FirmwareReadResponse src) { fuData = src.fuData; }

        new public Tpm2FirmwareReadResponse Copy() { return CreateCopy<Tpm2FirmwareReadResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command saves a session context, object context, or sequence object
    /// context outside the TPM. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ContextSave_In")]
    public partial class Tpm2ContextSaveRequest: TpmStructureBase
    {
        /// <summary> Handle of the resource to save
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle saveHandle { get; set; }

        public Tpm2ContextSaveRequest() { saveHandle = new TpmHandle(); }

        /// <param name = "_saveHandle"> Handle of the resource to save
        ///        Auth Index: None </param>
        public Tpm2ContextSaveRequest(TpmHandle _saveHandle) { saveHandle = _saveHandle; }

        new public Tpm2ContextSaveRequest Copy() { return CreateCopy<Tpm2ContextSaveRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command saves a session context, object context, or sequence object
    /// context outside the TPM. </summary>
    [DataContract]
    [KnownType(typeof(Context))]
    [SpecTypeName("ContextSave_Out")]
    public partial class Tpm2ContextSaveResponse: TpmStructureBase
    {
        [MarshalAs(0)]
        [DataMember()]
        public Context context { get; set; }

        public Tpm2ContextSaveResponse() {}

        public Tpm2ContextSaveResponse(Tpm2ContextSaveResponse src) { context = src.context; }

        new public Tpm2ContextSaveResponse Copy() { return CreateCopy<Tpm2ContextSaveResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to reload a context that has been saved by
    /// TPM2_ContextSave(). </summary>
    [DataContract]
    [KnownType(typeof(Context))]
    [SpecTypeName("ContextLoad_In")]
    public partial class Tpm2ContextLoadRequest: TpmStructureBase
    {
        /// <summary> The context blob </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Context context { get; set; }

        public Tpm2ContextLoadRequest() {}

        /// <param name = "_context"> The context blob </param>
        public Tpm2ContextLoadRequest(Context _context) { context = _context; }

        new public Tpm2ContextLoadRequest Copy() { return CreateCopy<Tpm2ContextLoadRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to reload a context that has been saved by
    /// TPM2_ContextSave(). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ContextLoad_Out")]
    public partial class Tpm2ContextLoadResponse: TpmStructureBase
    {
        /// <summary> The handle assigned to the resource after it has been successfully loaded </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        public Tpm2ContextLoadResponse() { handle = new TpmHandle(); }

        public Tpm2ContextLoadResponse(Tpm2ContextLoadResponse src) { handle = src.handle; }

        new public Tpm2ContextLoadResponse Copy() { return CreateCopy<Tpm2ContextLoadResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command causes all context associated with a loaded object, sequence
    /// object, or session to be removed from TPM memory. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("FlushContext_In")]
    public partial class Tpm2FlushContextRequest: TpmStructureBase
    {
        /// <summary> The handle of the item to flush
        /// NOTE This is a use of a handle as a parameter. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle flushHandle { get; set; }

        public Tpm2FlushContextRequest() { flushHandle = new TpmHandle(); }

        /// <param name = "_flushHandle"> The handle of the item to flush
        ///        NOTE This is a use of a handle as a parameter. </param>
        public Tpm2FlushContextRequest(TpmHandle _flushHandle) { flushHandle = _flushHandle; }

        new public Tpm2FlushContextRequest Copy() { return CreateCopy<Tpm2FlushContextRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows certain Transient Objects to be made persistent or a
    /// persistent object to be evicted. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("EvictControl_In")]
    public partial class Tpm2EvictControlRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }

        /// <summary> The handle of a loaded object
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle objectHandle { get; set; }

        /// <summary> If objectHandle is a transient object handle, then this is the persistent
        /// handle for the object
        /// if objectHandle is a persistent object handle, then it shall be the same value as
        /// persistentHandle </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle persistentHandle { get; set; }

        public Tpm2EvictControlRequest()
        {
            auth = new TpmHandle();
            objectHandle = new TpmHandle();
            persistentHandle = new TpmHandle();
        }

        /// <param name = "_auth"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "_objectHandle"> The handle of a loaded object
        ///        Auth Index: None </param>
        /// <param name = "_persistentHandle"> If objectHandle is a transient object handle, then this
        ///        is the persistent handle for the object
        ///        if objectHandle is a persistent object handle, then it shall be the same value as
        ///        persistentHandle </param>
        public Tpm2EvictControlRequest(TpmHandle _auth, TpmHandle _objectHandle, TpmHandle _persistentHandle)
        {
            auth = _auth;
            objectHandle = _objectHandle;
            persistentHandle = _persistentHandle;
        }

        new public Tpm2EvictControlRequest Copy() { return CreateCopy<Tpm2EvictControlRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command reads the current TPMS_TIME_INFO structure that contains the
    /// current setting of Time, Clock, resetCount, and restartCount. </summary>
    [DataContract]
    [SpecTypeName("ReadClock_In")]
    public partial class Tpm2ReadClockRequest: TpmStructureBase
    {
        public Tpm2ReadClockRequest() {}

        new public Tpm2ReadClockRequest Copy() { return CreateCopy<Tpm2ReadClockRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command reads the current TPMS_TIME_INFO structure that contains the
    /// current setting of Time, Clock, resetCount, and restartCount. </summary>
    [DataContract]
    [KnownType(typeof(TimeInfo))]
    [SpecTypeName("ReadClock_Out")]
    public partial class Tpm2ReadClockResponse: TpmStructureBase
    {
        [MarshalAs(0)]
        [DataMember()]
        public TimeInfo currentTime { get; set; }

        public Tpm2ReadClockResponse() {}

        public Tpm2ReadClockResponse(Tpm2ReadClockResponse src) { currentTime = src.currentTime; }

        new public Tpm2ReadClockResponse Copy() { return CreateCopy<Tpm2ReadClockResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to advance the value of the TPMs Clock. The command
    /// will fail if newTime is less than the current value of Clock or if the new time is
    /// greater than FFFF00000000000016. If both of these checks succeed, Clock is set to
    /// newTime. If either of these checks fails, the TPM shall return TPM_RC_VALUE and make
    /// no change to Clock. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ClockSet_In")]
    public partial class Tpm2ClockSetRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }

        /// <summary> New Clock setting in milliseconds </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ulong newTime { get; set; }

        public Tpm2ClockSetRequest() { auth = new TpmHandle(); }

        /// <param name = "_auth"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "_newTime"> New Clock setting in milliseconds </param>
        public Tpm2ClockSetRequest(TpmHandle _auth, ulong _newTime)
        {
            auth = _auth;
            newTime = _newTime;
        }

        new public Tpm2ClockSetRequest Copy() { return CreateCopy<Tpm2ClockSetRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command adjusts the rate of advance of Clock and Time to provide a
    /// better approximation to real time. </summary>
    [DataContract]
    [KnownType(typeof(ClockAdjust))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ClockRateAdjust_In")]
    public partial class Tpm2ClockRateAdjustRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Handle: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle auth { get; set; }

        /// <summary> Adjustment to current Clock update rate </summary>
        [MarshalAs(1)]
        [DataMember()]
        public ClockAdjust rateAdjust { get; set; }

        public Tpm2ClockRateAdjustRequest() { auth = new TpmHandle(); }

        /// <param name = "_auth"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "_rateAdjust"> Adjustment to current Clock update rate </param>
        public Tpm2ClockRateAdjustRequest(TpmHandle _auth, ClockAdjust _rateAdjust)
        {
            auth = _auth;
            rateAdjust = _rateAdjust;
        }

        new public Tpm2ClockRateAdjustRequest Copy() { return CreateCopy<Tpm2ClockRateAdjustRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns various information regarding the TPM and its current
    /// state. </summary>
    [DataContract]
    [KnownType(typeof(Cap))]
    [SpecTypeName("GetCapability_In")]
    public partial class Tpm2GetCapabilityRequest: TpmStructureBase
    {
        /// <summary> Group selection; determines the format of the response </summary>
        [MarshalAs(0)]
        [DataMember()]
        public Cap capability { get; set; }

        /// <summary> Further definition of information </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint property { get; set; }

        /// <summary> Number of properties of the indicated type to return </summary>
        [MarshalAs(2)]
        [DataMember()]
        public uint propertyCount { get; set; }

        public Tpm2GetCapabilityRequest() {}

        /// <param name = "_capability"> Group selection; determines the format of the response </param>
        /// <param name = "_property"> Further definition of information </param>
        /// <param name = "_propertyCount"> Number of properties of the indicated type to return </param>
        public Tpm2GetCapabilityRequest(Cap _capability, uint _property, uint _propertyCount)
        {
            capability = _capability;
            property = _property;
            propertyCount = _propertyCount;
        }

        new public Tpm2GetCapabilityRequest Copy() { return CreateCopy<Tpm2GetCapabilityRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command returns various information regarding the TPM and its current
    /// state. </summary>
    [DataContract]
    [KnownType(typeof(Cap))]
    [KnownType(typeof(ActDataArray))]
    [KnownType(typeof(AlgPropertyArray))]
    [KnownType(typeof(CcArray))]
    [KnownType(typeof(CcaArray))]
    [KnownType(typeof(EccCurveArray))]
    [KnownType(typeof(HandleArray))]
    [KnownType(typeof(PcrSelectionArray))]
    [KnownType(typeof(TaggedPcrPropertyArray))]
    [KnownType(typeof(TaggedPolicyArray))]
    [KnownType(typeof(TaggedTpmPropertyArray))]
    [SpecTypeName("GetCapability_Out")]
    public partial class Tpm2GetCapabilityResponse: TpmStructureBase
    {
        /// <summary> Flag to indicate if there are more values of this type </summary>
        [MarshalAs(0)]
        [DataMember()]
        public byte moreData { get; set; }

        /// <summary> The capability </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public Cap capabilityDataCapability {
            get { return capabilityData.GetUnionSelector(); }
        }

        /// <summary> The capability data </summary>
        /// <remarks> One of: AlgPropertyArray, HandleArray, CcaArray, CcArray, PcrSelectionArray,
        /// TaggedTpmPropertyArray, TaggedPcrPropertyArray, EccCurveArray, TaggedPolicyArray,
        /// ActDataArray. </remarks>
        [MarshalAs(2, MarshalType.Union, "capabilityDataCapability")]
        [DataMember()]
        public ICapabilitiesUnion capabilityData { get; set; }

        public Tpm2GetCapabilityResponse() {}

        public Tpm2GetCapabilityResponse(Tpm2GetCapabilityResponse src)
        {
            moreData = src.moreData;
            capabilityData = src.capabilityData;
        }

        new public Tpm2GetCapabilityResponse Copy() { return CreateCopy<Tpm2GetCapabilityResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to check to see if specific combinations of algorithm
    /// parameters are supported. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(AsymParms))]
    [KnownType(typeof(EccParms))]
    [KnownType(typeof(KeyedhashParms))]
    [KnownType(typeof(RsaParms))]
    [KnownType(typeof(SymcipherParms))]
    [SpecTypeName("TestParms_In")]
    public partial class Tpm2TestParmsRequest: TpmStructureBase
    {
        /// <summary> The algorithm to be tested </summary>
        [MarshalAs(0, MarshalType.UnionSelector)]
        public TpmAlgId parametersType {
            get { return parameters.GetUnionSelector(); }
        }

        /// <summary> Algorithm parameters to be validated </summary>
        /// <remarks> One of: KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms. </remarks>
        [MarshalAs(1, MarshalType.Union, "parametersType")]
        [DataMember()]
        public IPublicParmsUnion parameters { get; set; }

        public Tpm2TestParmsRequest() {}

        /// <param name = "_parameters"> Algorithm parameters to be validated
        ///        One of: KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms. </param>
        public Tpm2TestParmsRequest(IPublicParmsUnion _parameters) { parameters = _parameters; }

        new public Tpm2TestParmsRequest Copy() { return CreateCopy<Tpm2TestParmsRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command defines the attributes of an NV Index and causes the TPM to
    /// reserve space to hold the data associated with the NV Index. If a definition already
    /// exists at the NV Index, the TPM will return TPM_RC_NV_DEFINED. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NvPublic))]
    [SpecTypeName("NV_DefineSpace_In")]
    public partial class Tpm2NvDefineSpaceRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The authorization value </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;

        /// <summary> The public parameters of the NV area </summary>
        [MarshalAs(2, MarshalType.SizedStruct, "publicInfoSize", 2)]
        [DataMember()]
        public NvPublic publicInfo { get; set; }

        public Tpm2NvDefineSpaceRequest() { authHandle = new TpmHandle(); }

        /// <param name = "_authHandle"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_auth"> The authorization value </param>
        /// <param name = "_publicInfo"> The public parameters of the NV area </param>
        public Tpm2NvDefineSpaceRequest(TpmHandle _authHandle, byte[] _auth, NvPublic _publicInfo)
        {
            authHandle = _authHandle;
            auth = _auth;
            publicInfo = _publicInfo;
        }

        new public Tpm2NvDefineSpaceRequest Copy() { return CreateCopy<Tpm2NvDefineSpaceRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command removes an Index from the TPM. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_UndefineSpace_In")]
    public partial class Tpm2NvUndefineSpaceRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The NV Index to remove from NV space
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        public Tpm2NvUndefineSpaceRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }

        /// <param name = "_authHandle"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> The NV Index to remove from NV space
        ///        Auth Index: None </param>
        public Tpm2NvUndefineSpaceRequest(TpmHandle _authHandle, TpmHandle _nvIndex)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
        }

        new public Tpm2NvUndefineSpaceRequest Copy() { return CreateCopy<Tpm2NvUndefineSpaceRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows removal of a platform-created NV Index that has
    /// TPMA_NV_POLICY_DELETE SET. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_UndefineSpaceSpecial_In")]
    public partial class Tpm2NvUndefineSpaceSpecialRequest: TpmStructureBase
    {
        /// <summary> Index to be deleted
        /// Auth Index: 1
        /// Auth Role: ADMIN </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> TPM_RH_PLATFORM + {PP}
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle platform { get; set; }

        public Tpm2NvUndefineSpaceSpecialRequest()
        {
            nvIndex = new TpmHandle();
            platform = new TpmHandle();
        }

        /// <param name = "_nvIndex"> Index to be deleted
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "_platform"> TPM_RH_PLATFORM + {PP}
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        public Tpm2NvUndefineSpaceSpecialRequest(TpmHandle _nvIndex, TpmHandle _platform)
        {
            nvIndex = _nvIndex;
            platform = _platform;
        }

        new public Tpm2NvUndefineSpaceSpecialRequest Copy() { return CreateCopy<Tpm2NvUndefineSpaceSpecialRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to read the public area and Name of an NV Index. The
    /// public area of an Index is not privacy-sensitive and no authorization is required to
    /// read this data. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_ReadPublic_In")]
    public partial class Tpm2NvReadPublicRequest: TpmStructureBase
    {
        /// <summary> The NV Index
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        public Tpm2NvReadPublicRequest() { nvIndex = new TpmHandle(); }

        /// <param name = "_nvIndex"> The NV Index
        ///        Auth Index: None </param>
        public Tpm2NvReadPublicRequest(TpmHandle _nvIndex) { nvIndex = _nvIndex; }

        new public Tpm2NvReadPublicRequest Copy() { return CreateCopy<Tpm2NvReadPublicRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to read the public area and Name of an NV Index. The
    /// public area of an Index is not privacy-sensitive and no authorization is required to
    /// read this data. </summary>
    [DataContract]
    [KnownType(typeof(NvPublic))]
    [SpecTypeName("NV_ReadPublic_Out")]
    public partial class Tpm2NvReadPublicResponse: TpmStructureBase
    {
        /// <summary> The public area of the NV Index </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "nvPublicSize", 2)]
        [DataMember()]
        public NvPublic nvPublic { get; set; }

        /// <summary> The Name of the nvIndex </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nvNameSize", 2)]
        [DataMember()]
        public byte[] nvName;

        public Tpm2NvReadPublicResponse() {}

        public Tpm2NvReadPublicResponse(Tpm2NvReadPublicResponse src)
        {
            nvPublic = src.nvPublic;
            nvName = src.nvName;
        }

        new public Tpm2NvReadPublicResponse Copy() { return CreateCopy<Tpm2NvReadPublicResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command writes a value to an area in NV memory that was previously
    /// defined by TPM2_NV_DefineSpace(). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_Write_In")]
    public partial class Tpm2NvWriteRequest: TpmStructureBase
    {
        /// <summary> Handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The NV Index of the area to write
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> The data to write </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;

        /// <summary> The octet offset into the NV Area </summary>
        [MarshalAs(3)]
        [DataMember()]
        public ushort offset { get; set; }

        public Tpm2NvWriteRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }

        /// <param name = "_authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> The NV Index of the area to write
        ///        Auth Index: None </param>
        /// <param name = "_data"> The data to write </param>
        /// <param name = "_offset"> The octet offset into the NV Area </param>
        public Tpm2NvWriteRequest(TpmHandle _authHandle, TpmHandle _nvIndex, byte[] _data, ushort _offset)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
            data = _data;
            offset = _offset;
        }

        new public Tpm2NvWriteRequest Copy() { return CreateCopy<Tpm2NvWriteRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to increment the value in an NV Index that has the
    /// TPM_NT_COUNTER attribute. The data value of the NV Index is incremented by one. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_Increment_In")]
    public partial class Tpm2NvIncrementRequest: TpmStructureBase
    {
        /// <summary> Handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The NV Index to increment
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        public Tpm2NvIncrementRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }

        /// <param name = "_authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> The NV Index to increment
        ///        Auth Index: None </param>
        public Tpm2NvIncrementRequest(TpmHandle _authHandle, TpmHandle _nvIndex)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
        }

        new public Tpm2NvIncrementRequest Copy() { return CreateCopy<Tpm2NvIncrementRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command extends a value to an area in NV memory that was previously
    /// defined by TPM2_NV_DefineSpace. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_Extend_In")]
    public partial class Tpm2NvExtendRequest: TpmStructureBase
    {
        /// <summary> Handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The NV Index to extend
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> The data to extend </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;

        public Tpm2NvExtendRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }

        /// <param name = "_authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> The NV Index to extend
        ///        Auth Index: None </param>
        /// <param name = "_data"> The data to extend </param>
        public Tpm2NvExtendRequest(TpmHandle _authHandle, TpmHandle _nvIndex, byte[] _data)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
            data = _data;
        }

        new public Tpm2NvExtendRequest Copy() { return CreateCopy<Tpm2NvExtendRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to SET bits in an NV Index that was created as a bit
    /// field. Any number of bits from 0 to 64 may be SET. The contents of bits are ORed with
    /// the current contents of the NV Index. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_SetBits_In")]
    public partial class Tpm2NvSetBitsRequest: TpmStructureBase
    {
        /// <summary> Handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> NV Index of the area in which the bit is to be set
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> The data to OR with the current contents </summary>
        [MarshalAs(2)]
        [DataMember()]
        public ulong bits { get; set; }

        public Tpm2NvSetBitsRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }

        /// <param name = "_authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> NV Index of the area in which the bit is to be set
        ///        Auth Index: None </param>
        /// <param name = "_bits"> The data to OR with the current contents </param>
        public Tpm2NvSetBitsRequest(TpmHandle _authHandle, TpmHandle _nvIndex, ulong _bits)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
            bits = _bits;
        }

        new public Tpm2NvSetBitsRequest Copy() { return CreateCopy<Tpm2NvSetBitsRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> If the TPMA_NV_WRITEDEFINE or TPMA_NV_WRITE_STCLEAR attributes of an NV
    /// location are SET, then this command may be used to inhibit further writes of the NV
    /// Index. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_WriteLock_In")]
    public partial class Tpm2NvWriteLockRequest: TpmStructureBase
    {
        /// <summary> Handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The NV Index of the area to lock
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        public Tpm2NvWriteLockRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }

        /// <param name = "_authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> The NV Index of the area to lock
        ///        Auth Index: None </param>
        public Tpm2NvWriteLockRequest(TpmHandle _authHandle, TpmHandle _nvIndex)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
        }

        new public Tpm2NvWriteLockRequest Copy() { return CreateCopy<Tpm2NvWriteLockRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The command will SET TPMA_NV_WRITELOCKED for all indexes that have their
    /// TPMA_NV_GLOBALLOCK attribute SET. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_GlobalWriteLock_In")]
    public partial class Tpm2NvGlobalWriteLockRequest: TpmStructureBase
    {
        /// <summary> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        public Tpm2NvGlobalWriteLockRequest() { authHandle = new TpmHandle(); }

        /// <param name = "_authHandle"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        public Tpm2NvGlobalWriteLockRequest(TpmHandle _authHandle) { authHandle = _authHandle; }

        new public Tpm2NvGlobalWriteLockRequest Copy() { return CreateCopy<Tpm2NvGlobalWriteLockRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command reads a value from an area in NV memory previously defined by
    /// TPM2_NV_DefineSpace(). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_Read_In")]
    public partial class Tpm2NvReadRequest: TpmStructureBase
    {
        /// <summary> The handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The NV Index to be read
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> Number of octets to read </summary>
        [MarshalAs(2)]
        [DataMember()]
        public ushort size { get; set; }

        /// <summary> Octet offset into the NV area
        /// This value shall be less than or equal to the size of the nvIndex data. </summary>
        [MarshalAs(3)]
        [DataMember()]
        public ushort offset { get; set; }

        public Tpm2NvReadRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }

        /// <param name = "_authHandle"> The handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> The NV Index to be read
        ///        Auth Index: None </param>
        /// <param name = "_size"> Number of octets to read </param>
        /// <param name = "_offset"> Octet offset into the NV area
        ///        This value shall be less than or equal to the size of the nvIndex data. </param>
        public Tpm2NvReadRequest(TpmHandle _authHandle, TpmHandle _nvIndex, ushort _size, ushort _offset)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
            size = _size;
            offset = _offset;
        }

        new public Tpm2NvReadRequest Copy() { return CreateCopy<Tpm2NvReadRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command reads a value from an area in NV memory previously defined by
    /// TPM2_NV_DefineSpace(). </summary>
    [DataContract]
    [SpecTypeName("NV_Read_Out")]
    public partial class Tpm2NvReadResponse: TpmStructureBase
    {
        /// <summary> The data read </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "dataSize", 2)]
        [DataMember()]
        public byte[] data;

        public Tpm2NvReadResponse() {}

        public Tpm2NvReadResponse(Tpm2NvReadResponse src) { data = src.data; }

        new public Tpm2NvReadResponse Copy() { return CreateCopy<Tpm2NvReadResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> If TPMA_NV_READ_STCLEAR is SET in an Index, then this command may be used to
    /// prevent further reads of the NV Index until the next TPM2_Startup (TPM_SU_CLEAR). </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_ReadLock_In")]
    public partial class Tpm2NvReadLockRequest: TpmStructureBase
    {
        /// <summary> The handle indicating the source of the authorization value
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> The NV Index to be locked
        /// Auth Index: None </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        public Tpm2NvReadLockRequest()
        {
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }

        /// <param name = "_authHandle"> The handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> The NV Index to be locked
        ///        Auth Index: None </param>
        public Tpm2NvReadLockRequest(TpmHandle _authHandle, TpmHandle _nvIndex)
        {
            authHandle = _authHandle;
            nvIndex = _nvIndex;
        }

        new public Tpm2NvReadLockRequest Copy() { return CreateCopy<Tpm2NvReadLockRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows the authorization secret for an NV Index to be changed. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("NV_ChangeAuth_In")]
    public partial class Tpm2NvChangeAuthRequest: TpmStructureBase
    {
        /// <summary> Handle of the entity
        /// Auth Index: 1
        /// Auth Role: ADMIN </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> New authorization value </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "newAuthSize", 2)]
        [DataMember()]
        public byte[] newAuth;

        public Tpm2NvChangeAuthRequest() { nvIndex = new TpmHandle(); }

        /// <param name = "_nvIndex"> Handle of the entity
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "_newAuth"> New authorization value </param>
        public Tpm2NvChangeAuthRequest(TpmHandle _nvIndex, byte[] _newAuth)
        {
            nvIndex = _nvIndex;
            newAuth = _newAuth;
        }

        new public Tpm2NvChangeAuthRequest Copy() { return CreateCopy<Tpm2NvChangeAuthRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to certify the contents of an NV Index or
    /// portion of an NV Index. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(NullSigScheme))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SchemeHmac))]
    [KnownType(typeof(SigSchemeEcdaa))]
    [KnownType(typeof(SigSchemeEcdsa))]
    [KnownType(typeof(SigSchemeEcschnorr))]
    [KnownType(typeof(SigSchemeRsapss))]
    [KnownType(typeof(SigSchemeRsassa))]
    [KnownType(typeof(SigSchemeSm2))]
    [SpecTypeName("NV_Certify_In")]
    public partial class Tpm2NvCertifyRequest: TpmStructureBase
    {
        /// <summary> Handle of the key used to sign the attestation structure
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle signHandle { get; set; }

        /// <summary> Handle indicating the source of the authorization value for the NV Index
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> Index for the area to be certified
        /// Auth Index: None </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle nvIndex { get; set; }

        /// <summary> User-provided qualifying data </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "qualifyingDataSize", 2)]
        [DataMember()]
        public byte[] qualifyingData;

        /// <summary> Scheme selector </summary>
        [MarshalAs(4, MarshalType.UnionSelector)]
        public TpmAlgId inSchemeScheme {
            get { return inScheme != null ? inScheme.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL </summary>
        /// <remarks> One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        /// SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </remarks>
        [MarshalAs(5, MarshalType.Union, "inSchemeScheme")]
        [DataMember()]
        public ISigSchemeUnion inScheme { get; set; }

        /// <summary> Number of octets to certify </summary>
        [MarshalAs(6)]
        [DataMember()]
        public ushort size { get; set; }

        /// <summary> Octet offset into the NV area
        /// This value shall be less than or equal to the size of the nvIndex data. </summary>
        [MarshalAs(7)]
        [DataMember()]
        public ushort offset { get; set; }

        public Tpm2NvCertifyRequest()
        {
            signHandle = new TpmHandle();
            authHandle = new TpmHandle();
            nvIndex = new TpmHandle();
        }

        /// <param name = "_signHandle"> Handle of the key used to sign the attestation structure
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_authHandle"> Handle indicating the source of the authorization value for
        ///        the NV Index
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "_nvIndex"> Index for the area to be certified
        ///        Auth Index: None </param>
        /// <param name = "_qualifyingData"> User-provided qualifying data </param>
        /// <param name = "_inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "_size"> Number of octets to certify </param>
        /// <param name = "_offset"> Octet offset into the NV area
        ///        This value shall be less than or equal to the size of the nvIndex data. </param>
        public Tpm2NvCertifyRequest(TpmHandle _signHandle, TpmHandle _authHandle, TpmHandle _nvIndex, byte[] _qualifyingData, ISigSchemeUnion _inScheme, ushort _size, ushort _offset)
        {
            signHandle = _signHandle;
            authHandle = _authHandle;
            nvIndex = _nvIndex;
            qualifyingData = _qualifyingData;
            inScheme = _inScheme;
            size = _size;
            offset = _offset;
        }

        new public Tpm2NvCertifyRequest Copy() { return CreateCopy<Tpm2NvCertifyRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to certify the contents of an NV Index or
    /// portion of an NV Index. </summary>
    [DataContract]
    [KnownType(typeof(TpmAlgId))]
    [KnownType(typeof(Attest))]
    [KnownType(typeof(NullSignature))]
    [KnownType(typeof(SchemeHash))]
    [KnownType(typeof(SignatureEcdaa))]
    [KnownType(typeof(SignatureEcdsa))]
    [KnownType(typeof(SignatureEcschnorr))]
    [KnownType(typeof(SignatureRsapss))]
    [KnownType(typeof(SignatureRsassa))]
    [KnownType(typeof(SignatureSm2))]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("NV_Certify_Out")]
    public partial class Tpm2NvCertifyResponse: TpmStructureBase
    {
        /// <summary> The structure that was signed </summary>
        [MarshalAs(0, MarshalType.SizedStruct, "certifyInfoSize", 2)]
        [DataMember()]
        public Attest certifyInfo { get; set; }

        /// <summary> Selector of the algorithm used to construct the signature </summary>
        [MarshalAs(1, MarshalType.UnionSelector)]
        public TpmAlgId signatureSigAlg {
            get { return signature != null ? signature.GetUnionSelector() : TpmAlgId.Null; }
        }

        /// <summary> The asymmetric signature over certifyInfo using the key referenced by
        /// signHandle </summary>
        /// <remarks> One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        /// SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </remarks>
        [MarshalAs(2, MarshalType.Union, "signatureSigAlg")]
        [DataMember()]
        public ISignatureUnion signature { get; set; }

        public Tpm2NvCertifyResponse() {}

        public Tpm2NvCertifyResponse(Tpm2NvCertifyResponse src)
        {
            certifyInfo = src.certifyInfo;
            signature = src.signature;
        }

        new public Tpm2NvCertifyResponse Copy() { return CreateCopy<Tpm2NvCertifyResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to obtain information about an Attached
    /// Component referenced by an AC handle. </summary>
    [DataContract]
    [KnownType(typeof(At))]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("AC_GetCapability_In")]
    public partial class Tpm2AcGetCapabilityRequest: TpmStructureBase
    {
        /// <summary> Handle indicating the Attached Component
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle ac { get; set; }

        /// <summary> Starting info type </summary>
        [MarshalAs(1)]
        [DataMember()]
        public At capability { get; set; }

        /// <summary> Maximum number of values to return </summary>
        [MarshalAs(2)]
        [DataMember()]
        public uint count { get; set; }

        public Tpm2AcGetCapabilityRequest() { ac = new TpmHandle(); }

        /// <param name = "_ac"> Handle indicating the Attached Component
        ///        Auth Index: None </param>
        /// <param name = "_capability"> Starting info type </param>
        /// <param name = "_count"> Maximum number of values to return </param>
        public Tpm2AcGetCapabilityRequest(TpmHandle _ac, At _capability, uint _count)
        {
            ac = _ac;
            capability = _capability;
            count = _count;
        }

        new public Tpm2AcGetCapabilityRequest Copy() { return CreateCopy<Tpm2AcGetCapabilityRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to obtain information about an Attached
    /// Component referenced by an AC handle. </summary>
    [DataContract]
    [SpecTypeName("AC_GetCapability_Out")]
    public partial class Tpm2AcGetCapabilityResponse: TpmStructureBase
    {
        /// <summary> Flag to indicate whether there are more values </summary>
        [MarshalAs(0)]
        [DataMember()]
        public byte moreData { get; set; }

        /// <summary> List of capabilities </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "capabilitiesDataCount", 4)]
        [DataMember()]
        public AcOutput[] capabilitiesData;

        public Tpm2AcGetCapabilityResponse() {}

        public Tpm2AcGetCapabilityResponse(Tpm2AcGetCapabilityResponse src)
        {
            moreData = src.moreData;
            capabilitiesData = src.capabilitiesData;
        }

        new public Tpm2AcGetCapabilityResponse Copy() { return CreateCopy<Tpm2AcGetCapabilityResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to send (copy) a loaded object from the TPM
    /// to an Attached Component. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("AC_Send_In")]
    public partial class Tpm2AcSendRequest: TpmStructureBase
    {
        /// <summary> Handle of the object being sent to ac
        /// Auth Index: 1
        /// Auth Role: DUP </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle sendObject { get; set; }

        /// <summary> The handle indicating the source of the authorization value
        /// Auth Index: 2
        /// Auth Role: USER </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHandle authHandle { get; set; }

        /// <summary> Handle indicating the Attached Component to which the object will be sent
        /// Auth Index: None </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmHandle ac { get; set; }

        /// <summary> Optional non sensitive information related to the object </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "acDataInSize", 2)]
        [DataMember()]
        public byte[] acDataIn;

        public Tpm2AcSendRequest()
        {
            sendObject = new TpmHandle();
            authHandle = new TpmHandle();
            ac = new TpmHandle();
        }

        /// <param name = "_sendObject"> Handle of the object being sent to ac
        ///        Auth Index: 1
        ///        Auth Role: DUP </param>
        /// <param name = "_authHandle"> The handle indicating the source of the authorization value
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "_ac"> Handle indicating the Attached Component to which the object will be sent
        ///        Auth Index: None </param>
        /// <param name = "_acDataIn"> Optional non sensitive information related to the object </param>
        public Tpm2AcSendRequest(TpmHandle _sendObject, TpmHandle _authHandle, TpmHandle _ac, byte[] _acDataIn)
        {
            sendObject = _sendObject;
            authHandle = _authHandle;
            ac = _ac;
            acDataIn = _acDataIn;
        }

        new public Tpm2AcSendRequest Copy() { return CreateCopy<Tpm2AcSendRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> The purpose of this command is to send (copy) a loaded object from the TPM
    /// to an Attached Component. </summary>
    [DataContract]
    [KnownType(typeof(AcOutput))]
    [SpecTypeName("AC_Send_Out")]
    public partial class Tpm2AcSendResponse: TpmStructureBase
    {
        /// <summary> May include AC specific data or information about an error. </summary>
        [MarshalAs(0)]
        [DataMember()]
        public AcOutput acDataOut { get; set; }

        public Tpm2AcSendResponse() {}

        public Tpm2AcSendResponse(Tpm2AcSendResponse src) { acDataOut = src.acDataOut; }

        new public Tpm2AcSendResponse Copy() { return CreateCopy<Tpm2AcSendResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command allows qualification of the sending (copying) of an Object to
    /// an Attached Component (AC). Qualification includes selection of the receiving AC and
    /// the method of authentication for the AC, and, in certain circumstances, the Object to
    /// be sent may be specified. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("Policy_AC_SendSelect_In")]
    public partial class Tpm2PolicyAcSendSelectRequest: TpmStructureBase
    {
        /// <summary> Handle for the policy session being extended
        /// Auth Index: None </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle policySession { get; set; }

        /// <summary> The Name of the Object to be sent </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "objectNameSize", 2)]
        [DataMember()]
        public byte[] objectName;

        /// <summary> The Name associated with authHandle used in the TPM2_AC_Send() command </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "authHandleNameSize", 2)]
        [DataMember()]
        public byte[] authHandleName;

        /// <summary> The Name of the Attached Component to which the Object will be sent </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "acNameSize", 2)]
        [DataMember()]
        public byte[] acName;

        /// <summary> If SET, objectName will be included in the value in
        /// policySessionpolicyDigest </summary>
        [MarshalAs(4)]
        [DataMember()]
        public byte includeObject { get; set; }

        public Tpm2PolicyAcSendSelectRequest() { policySession = new TpmHandle(); }

        /// <param name = "_policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "_objectName"> The Name of the Object to be sent </param>
        /// <param name = "_authHandleName"> The Name associated with authHandle used in the
        ///        TPM2_AC_Send() command </param>
        /// <param name = "_acName"> The Name of the Attached Component to which the Object will be
        ///        sent </param>
        /// <param name = "_includeObject"> If SET, objectName will be included in the value in
        ///        policySessionpolicyDigest </param>
        public Tpm2PolicyAcSendSelectRequest(TpmHandle _policySession, byte[] _objectName, byte[] _authHandleName, byte[] _acName, byte _includeObject)
        {
            policySession = _policySession;
            objectName = _objectName;
            authHandleName = _authHandleName;
            acName = _acName;
            includeObject = _includeObject;
        }

        new public Tpm2PolicyAcSendSelectRequest Copy() { return CreateCopy<Tpm2PolicyAcSendSelectRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This command is used to set the time remaining before an Authenticated
    /// Countdown Timer (ACT) expires. </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [SpecTypeName("ACT_SetTimeout_In")]
    public partial class Tpm2ActSetTimeoutRequest: TpmStructureBase
    {
        /// <summary> Handle of the selected ACT
        /// Auth Index: 1
        /// Auth Role: USER </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle actHandle { get; set; }

        /// <summary> The start timeout value for the ACT in seconds </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint startTimeout { get; set; }

        public Tpm2ActSetTimeoutRequest() { actHandle = new TpmHandle(); }

        /// <param name = "_actHandle"> Handle of the selected ACT
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "_startTimeout"> The start timeout value for the ACT in seconds </param>
        public Tpm2ActSetTimeoutRequest(TpmHandle _actHandle, uint _startTimeout)
        {
            actHandle = _actHandle;
            startTimeout = _startTimeout;
        }

        new public Tpm2ActSetTimeoutRequest Copy() { return CreateCopy<Tpm2ActSetTimeoutRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is a placeholder to allow testing of the dispatch code. </summary>
    [DataContract]
    [SpecTypeName("Vendor_TCG_Test_In")]
    public partial class Tpm2VendorTcgTestRequest: TpmStructureBase
    {
        /// <summary> Dummy data </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "inputDataSize", 2)]
        [DataMember()]
        public byte[] inputData;

        public Tpm2VendorTcgTestRequest() {}

        /// <param name = "_inputData"> Dummy data </param>
        public Tpm2VendorTcgTestRequest(byte[] _inputData) { inputData = _inputData; }

        new public Tpm2VendorTcgTestRequest Copy() { return CreateCopy<Tpm2VendorTcgTestRequest>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> This is a placeholder to allow testing of the dispatch code. </summary>
    [DataContract]
    [SpecTypeName("Vendor_TCG_Test_Out")]
    public partial class Tpm2VendorTcgTestResponse: TpmStructureBase
    {
        /// <summary> Dummy data </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "outputDataSize", 2)]
        [DataMember()]
        public byte[] outputData;

        public Tpm2VendorTcgTestResponse() {}

        public Tpm2VendorTcgTestResponse(Tpm2VendorTcgTestResponse src) { outputData = src.outputData; }

        new public Tpm2VendorTcgTestResponse Copy() { return CreateCopy<Tpm2VendorTcgTestResponse>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the RSA schemes that only need a hash algorithm as a scheme
    /// parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_RSASSA")]
    public partial class SchemeRsassa: SigSchemeRsassa
    {
        public SchemeRsassa() {}

        public SchemeRsassa(SchemeRsassa _SchemeRsassa) : base(_SchemeRsassa) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeRsassa(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeRsassa Copy() { return CreateCopy<SchemeRsassa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the RSA schemes that only need a hash algorithm as a scheme
    /// parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_RSAPSS")]
    public partial class SchemeRsapss: SigSchemeRsapss
    {
        public SchemeRsapss() {}

        public SchemeRsapss(SchemeRsapss _SchemeRsapss) : base(_SchemeRsapss) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeRsapss(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeRsapss Copy() { return CreateCopy<SchemeRsapss>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Most of the ECC signature schemes only require a hash algorithm to complete
    /// the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require
    /// a count value so they are typed to be TPMS_SCHEME_ECDAA. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_ECDSA")]
    public partial class SchemeEcdsa: SigSchemeEcdsa
    {
        public SchemeEcdsa() {}

        public SchemeEcdsa(SchemeEcdsa _SchemeEcdsa) : base(_SchemeEcdsa) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeEcdsa(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeEcdsa Copy() { return CreateCopy<SchemeEcdsa>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Most of the ECC signature schemes only require a hash algorithm to complete
    /// the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require
    /// a count value so they are typed to be TPMS_SCHEME_ECDAA. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_SM2")]
    public partial class SchemeSm2: SigSchemeSm2
    {
        public SchemeSm2() {}

        public SchemeSm2(SchemeSm2 _SchemeSm2) : base(_SchemeSm2) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeSm2(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeSm2 Copy() { return CreateCopy<SchemeSm2>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Most of the ECC signature schemes only require a hash algorithm to complete
    /// the definition and can be typed as TPMS_SCHEME_HASH. Anonymous algorithms also require
    /// a count value so they are typed to be TPMS_SCHEME_ECDAA. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_ECSCHNORR")]
    public partial class SchemeEcschnorr: SigSchemeEcschnorr
    {
        public SchemeEcschnorr() {}

        public SchemeEcschnorr(SchemeEcschnorr _SchemeEcschnorr) : base(_SchemeEcschnorr) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeEcschnorr(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeEcschnorr Copy() { return CreateCopy<SchemeEcschnorr>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the RSA encryption schemes that only need a hash algorithm as a
    /// controlling parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_OAEP")]
    public partial class SchemeOaep: EncSchemeOaep
    {
        public SchemeOaep() {}

        public SchemeOaep(SchemeOaep _SchemeOaep) : base(_SchemeOaep) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeOaep(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeOaep Copy() { return CreateCopy<SchemeOaep>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the RSA encryption schemes that only need a hash algorithm as a
    /// controlling parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_RSAES")]
    public partial class SchemeRsaes: EncSchemeRsaes
    {
        public SchemeRsaes() {}

        new public SchemeRsaes Copy() { return CreateCopy<SchemeRsaes>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the ECC schemes that only need a hash algorithm as a controlling
    /// parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_ECDH")]
    public partial class SchemeEcdh: KeySchemeEcdh
    {
        public SchemeEcdh() {}

        public SchemeEcdh(SchemeEcdh _SchemeEcdh) : base(_SchemeEcdh) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeEcdh(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeEcdh Copy() { return CreateCopy<SchemeEcdh>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These are the ECC schemes that only need a hash algorithm as a controlling
    /// parameter. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_ECMQV")]
    public partial class SchemeEcmqv: KeySchemeEcmqv
    {
        public SchemeEcmqv() {}

        public SchemeEcmqv(SchemeEcmqv _SchemeEcmqv) : base(_SchemeEcmqv) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeEcmqv(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeEcmqv Copy() { return CreateCopy<SchemeEcmqv>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These structures are used to define the key derivation for symmetric secret
    /// sharing using asymmetric methods. A secret sharing scheme is required in any
    /// asymmetric key with the decrypt attribute SET. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_MGF1")]
    public partial class SchemeMgf1: KdfSchemeMgf1
    {
        public SchemeMgf1() {}

        public SchemeMgf1(SchemeMgf1 _SchemeMgf1) : base(_SchemeMgf1) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeMgf1(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeMgf1 Copy() { return CreateCopy<SchemeMgf1>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These structures are used to define the key derivation for symmetric secret
    /// sharing using asymmetric methods. A secret sharing scheme is required in any
    /// asymmetric key with the decrypt attribute SET. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_KDF1_SP800_56A")]
    public partial class SchemeKdf1Sp80056a: KdfSchemeKdf1Sp80056a
    {
        public SchemeKdf1Sp80056a() {}

        public SchemeKdf1Sp80056a(SchemeKdf1Sp80056a _SchemeKdf1Sp80056a) : base(_SchemeKdf1Sp80056a) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeKdf1Sp80056a(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeKdf1Sp80056a Copy() { return CreateCopy<SchemeKdf1Sp80056a>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These structures are used to define the key derivation for symmetric secret
    /// sharing using asymmetric methods. A secret sharing scheme is required in any
    /// asymmetric key with the decrypt attribute SET. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_KDF2")]
    public partial class SchemeKdf2: KdfSchemeKdf2
    {
        public SchemeKdf2() {}

        public SchemeKdf2(SchemeKdf2 _SchemeKdf2) : base(_SchemeKdf2) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeKdf2(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeKdf2 Copy() { return CreateCopy<SchemeKdf2>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> These structures are used to define the key derivation for symmetric secret
    /// sharing using asymmetric methods. A secret sharing scheme is required in any
    /// asymmetric key with the decrypt attribute SET. </summary>
    [DataContract]
    [SpecTypeName("TPMS_SCHEME_KDF1_SP800_108")]
    public partial class SchemeKdf1Sp800108: KdfSchemeKdf1Sp800108
    {
        public SchemeKdf1Sp800108() {}

        public SchemeKdf1Sp800108(SchemeKdf1Sp800108 _SchemeKdf1Sp800108) : base(_SchemeKdf1Sp800108) {}

        /// <param name = "_hashAlg"> The hash algorithm used to digest the message </param>
        public SchemeKdf1Sp800108(TpmAlgId _hashAlg) : base(_hashAlg) {}

        new public SchemeKdf1Sp800108 Copy() { return CreateCopy<SchemeKdf1Sp800108>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Contains the public and the plaintext-sensitive and/or encrypted private
    /// part of a TPM key (or other object) </summary>
    [DataContract]
    [KnownType(typeof(TpmPrivate))]
    [KnownType(typeof(TpmPublic))]
    [KnownType(typeof(Sensitive))]
    [SpecTypeName("TssObject")]
    public partial class TssObject: TpmStructureBase
    {
        /// <summary> Public part of key </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPublic Public { get; set; }

        /// <summary> Sensitive part of key </summary>
        [MarshalAs(1)]
        [DataMember()]
        public Sensitive Sensitive { get; set; }

        /// <summary> Private part is the encrypted sensitive part of key </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmPrivate Private { get; set; }

        public TssObject() {}

        public TssObject(TssObject src)
        {
            Public = src.Public;
            Sensitive = src.Sensitive;
            Private = src.Private;
        }

        /// <param name = "_Public"> Public part of key </param>
        /// <param name = "_Sensitive"> Sensitive part of key </param>
        /// <param name = "_Private"> Private part is the encrypted sensitive part of key </param>
        public TssObject(TpmPublic _Public, Sensitive _Sensitive, TpmPrivate _Private)
        {
            Public = _Public;
            Sensitive = _Sensitive;
            Private = _Private;
        }

        new public TssObject Copy() { return CreateCopy<TssObject>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Contains a PCR index and associated hash(pcr-value) [TSS] </summary>
    [DataContract]
    [KnownType(typeof(TpmHash))]
    [SpecTypeName("PcrValue")]
    public partial class PcrValue: TpmStructureBase
    {
        /// <summary> PCR Index </summary>
        [MarshalAs(0)]
        [DataMember()]
        public uint index { get; set; }

        /// <summary> PCR Value </summary>
        [MarshalAs(1)]
        [DataMember()]
        public TpmHash value { get; set; }

        public PcrValue() {}

        public PcrValue(PcrValue src)
        {
            index = src.index;
            value = src.value;
        }

        /// <param name = "_index"> PCR Index </param>
        /// <param name = "_value"> PCR Value </param>
        public PcrValue(uint _index, TpmHash _value)
        {
            index = _index;
            value = _value;
        }

        new public PcrValue Copy() { return CreateCopy<PcrValue>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Structure representing a session block in a command buffer [TSS] </summary>
    [DataContract]
    [KnownType(typeof(TpmHandle))]
    [KnownType(typeof(SessionAttr))]
    [SpecTypeName("SessionIn")]
    public partial class SessionIn: TpmStructureBase
    {
        /// <summary> Session handle </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmHandle handle { get; set; }

        /// <summary> Caller nonce </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "nonceCallerSize", 2)]
        [DataMember()]
        public byte[] nonceCaller;

        /// <summary> Session attributes </summary>
        [MarshalAs(2)]
        [DataMember()]
        public SessionAttr attributes { get; set; }

        /// <summary> AuthValue (or HMAC) </summary>
        [MarshalAs(3, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;

        public SessionIn() { handle = new TpmHandle(); }

        public SessionIn(SessionIn src)
        {
            handle = src.handle;
            nonceCaller = src.nonceCaller;
            attributes = src.attributes;
            auth = src.auth;
        }

        /// <param name = "_handle"> Session handle </param>
        /// <param name = "_nonceCaller"> Caller nonce </param>
        /// <param name = "_attributes"> Session attributes </param>
        /// <param name = "_auth"> AuthValue (or HMAC) </param>
        public SessionIn(TpmHandle _handle, byte[] _nonceCaller, SessionAttr _attributes, byte[] _auth)
        {
            handle = _handle;
            nonceCaller = _nonceCaller;
            attributes = _attributes;
            auth = _auth;
        }

        new public SessionIn Copy() { return CreateCopy<SessionIn>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Structure representing a session block in a response buffer [TSS] </summary>
    [DataContract]
    [KnownType(typeof(SessionAttr))]
    [SpecTypeName("SessionOut")]
    public partial class SessionOut: TpmStructureBase
    {
        /// <summary> TPM nonce </summary>
        [MarshalAs(0, MarshalType.VariableLengthArray, "nonceTpmSize", 2)]
        [DataMember()]
        public byte[] nonceTpm;

        /// <summary> Session attributes </summary>
        [MarshalAs(1)]
        [DataMember()]
        public SessionAttr attributes { get; set; }

        /// <summary> HMAC value </summary>
        [MarshalAs(2, MarshalType.VariableLengthArray, "authSize", 2)]
        [DataMember()]
        public byte[] auth;

        public SessionOut() {}

        public SessionOut(SessionOut src)
        {
            nonceTpm = src.nonceTpm;
            attributes = src.attributes;
            auth = src.auth;
        }

        /// <param name = "_nonceTpm"> TPM nonce </param>
        /// <param name = "_attributes"> Session attributes </param>
        /// <param name = "_auth"> HMAC value </param>
        public SessionOut(byte[] _nonceTpm, SessionAttr _attributes, byte[] _auth)
        {
            nonceTpm = _nonceTpm;
            attributes = _attributes;
            auth = _auth;
        }

        new public SessionOut Copy() { return CreateCopy<SessionOut>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Command header [TSS] </summary>
    [DataContract]
    [KnownType(typeof(TpmCc))]
    [KnownType(typeof(TpmSt))]
    [SpecTypeName("CommandHeader")]
    public partial class CommandHeader: TpmStructureBase
    {
        /// <summary> Command tag (sessions, or no sessions) </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmSt Tag { get; set; }

        /// <summary> Total command buffer length </summary>
        [MarshalAs(1)]
        [DataMember()]
        public uint CommandSize { get; set; }

        /// <summary> Command code </summary>
        [MarshalAs(2)]
        [DataMember()]
        public TpmCc CommandCode { get; set; }

        public CommandHeader() {}

        public CommandHeader(CommandHeader src)
        {
            Tag = src.Tag;
            CommandSize = src.CommandSize;
            CommandCode = src.CommandCode;
        }

        /// <param name = "_Tag"> Command tag (sessions, or no sessions) </param>
        /// <param name = "_CommandSize"> Total command buffer length </param>
        /// <param name = "_CommandCode"> Command code </param>
        public CommandHeader(TpmSt _Tag, uint _CommandSize, TpmCc _CommandCode)
        {
            Tag = _Tag;
            CommandSize = _CommandSize;
            CommandCode = _CommandCode;
        }

        new public CommandHeader Copy() { return CreateCopy<CommandHeader>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Contains the public and private part of a TPM key </summary>
    [DataContract]
    [KnownType(typeof(TpmPublic))]
    [SpecTypeName("TSS_KEY")]
    public partial class TssKey: TpmStructureBase
    {
        /// <summary> Public part of key </summary>
        [MarshalAs(0)]
        [DataMember()]
        public TpmPublic publicPart { get; set; }

        /// <summary> Private part is the encrypted sensitive part of key </summary>
        [MarshalAs(1, MarshalType.VariableLengthArray, "privatePartSize", 2)]
        [DataMember()]
        public byte[] privatePart;

        public TssKey() {}

        public TssKey(TssKey src)
        {
            publicPart = src.publicPart;
            privatePart = src.privatePart;
        }

        /// <param name = "_publicPart"> Public part of key </param>
        /// <param name = "_privatePart"> Private part is the encrypted sensitive part of key </param>
        public TssKey(TpmPublic _publicPart, byte[] _privatePart)
        {
            publicPart = _publicPart;
            privatePart = _privatePart;
        }

        new public TssKey Copy() { return CreateCopy<TssKey>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Auto-derived from TPM2B_DIGEST to provide unique GetUnionSelector()
    /// implementation </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DIGEST_SYMCIPHER")]
    public partial class Tpm2bDigestSymcipher: Tpm2bDigest
    {
        public Tpm2bDigestSymcipher() {}

        public Tpm2bDigestSymcipher(Tpm2bDigestSymcipher _Tpm2bDigestSymcipher) : base(_Tpm2bDigestSymcipher) {}

        /// <param name = "_buffer"> The buffer area that can be no larger than a digest </param>
        public Tpm2bDigestSymcipher(byte[] _buffer) : base(_buffer) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Symcipher; }

        new public Tpm2bDigestSymcipher Copy() { return CreateCopy<Tpm2bDigestSymcipher>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    /// <summary> Auto-derived from TPM2B_DIGEST </summary>
    [DataContract]
    [SpecTypeName("TPM2B_DIGEST_KEYEDHASH")]
    public partial class Tpm2bDigestKeyedhash: Tpm2bDigest
    {
        public Tpm2bDigestKeyedhash() {}

        public Tpm2bDigestKeyedhash(Tpm2bDigestKeyedhash _Tpm2bDigestKeyedhash) : base(_Tpm2bDigestKeyedhash) {}

        /// <param name = "_buffer"> The buffer area that can be no larger than a digest </param>
        public Tpm2bDigestKeyedhash(byte[] _buffer) : base(_buffer) {}

        public override TpmAlgId GetUnionSelector() { return TpmAlgId.Keyedhash; }

        new public Tpm2bDigestKeyedhash Copy() { return CreateCopy<Tpm2bDigestKeyedhash>(); }

        public override TpmStructureBase Clone() { return Copy(); }
    }

    //-----------------------------------------------------------------------------
    //------------------------- COMMANDS -----------------------------------------
    //-----------------------------------------------------------------------------

    public partial class Tpm2
    {
        /// TPM2_Startup() is always preceded by _TPM_Init, which is the physical indication that TPM initialization is necessary because of a system-wide reset. TPM2_Startup() is only valid after _TPM_Init. Additional TPM2_Startup() commands are not allowed after it has completed successfully. If a TPM requires TPM2_Startup() and another command is received, or if the TPM receives TPM2_Startup() when it is not required, the TPM shall return TPM_RC_INITIALIZE.
        /// 
        /// <param name = "startupType"> TPM_SU_CLEAR or TPM_SU_STATE </param>
        [TpmCommand]
        public void Startup(
            Su startupType)
        {
            var req = new Tpm2StartupRequest(startupType);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.Startup, req, resp, 0, 0);
        }

        /// This command is used to prepare the TPM for a power cycle. The shutdownType parameter indicates how the subsequent TPM2_Startup() will be processed.
        /// 
        /// <param name = "shutdownType"> TPM_SU_CLEAR or TPM_SU_STATE </param>
        [TpmCommand]
        public void Shutdown(
            Su shutdownType)
        {
            var req = new Tpm2ShutdownRequest(shutdownType);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.Shutdown, req, resp, 0, 0);
        }

        /// This command causes the TPM to perform a test of its capabilities. If the fullTest is YES, the TPM will test all functions. If fullTest = NO, the TPM will only test those functions that have not previously been tested.
        /// 
        /// <param name = "fullTest"> YES if full test to be performed
        ///        NO if only test of untested functions required </param>
        [TpmCommand]
        public void SelfTest(
            byte fullTest)
        {
            var req = new Tpm2SelfTestRequest(fullTest);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.SelfTest, req, resp, 0, 0);
        }

        /// This command causes the TPM to perform a test of the selected algorithms.
        /// 
        /// <param name = "toTest"> List of algorithms that should be tested </param>
        /// <returns> toDoList - List of algorithms that need testing </returns>
        [TpmCommand]
        public TpmAlgId[] IncrementalSelfTest(
            TpmAlgId[] toTest)
        {
            var req = new Tpm2IncrementalSelfTestRequest(toTest);
            var resp = new Tpm2IncrementalSelfTestResponse();
            DispatchMethod(TpmCc.IncrementalSelfTest, req, resp, 0, 0);
            return resp.toDoList;
        }

        /// This command returns manufacturer-specific information regarding the results of a self-test and an indication of the test status.
        /// 
        /// <returns> outData - Test result data
        ///                     contains manufacturer-specific information
        ///           testResult - TBD </returns>
        [TpmCommand]
        public byte[] GetTestResult(
            out TpmRc testResult)
        {
            var req = new Tpm2GetTestResultRequest();
            var resp = new Tpm2GetTestResultResponse();
            DispatchMethod(TpmCc.GetTestResult, req, resp, 0, 0);
            testResult = resp.testResult;
            return resp.outData;
        }

        /// This command is used to start an authorization session using alternative methods of establishing the session key (sessionKey). The session key is then used to derive values used for authorization and for encrypting parameters.
        /// 
        /// <param name = "tpmKey"> Handle of a loaded decrypt key used to encrypt salt
        ///        may be TPM_RH_NULL
        ///        Auth Index: None </param>
        /// <param name = "bind"> Entity providing the authValue
        ///        may be TPM_RH_NULL
        ///        Auth Index: None </param>
        /// <param name = "nonceCaller"> Initial nonceCaller, sets nonceTPM size for the session
        ///        shall be at least 16 octets </param>
        /// <param name = "encryptedSalt"> Value encrypted according to the type of tpmKey
        ///        If tpmKey is TPM_RH_NULL, this shall be the Empty Buffer. </param>
        /// <param name = "sessionType"> Indicates the type of the session; simple HMAC or policy
        ///        (including a trial policy) </param>
        /// <param name = "symmetric"> The algorithm and key size for parameter encryption
        ///        may select TPM_ALG_NULL </param>
        /// <param name = "authHash"> Hash algorithm to use for the session
        ///        Shall be a hash algorithm supported by the TPM and not TPM_ALG_NULL </param>
        /// <returns> handle - Handle for the newly created session
        ///           nonceTPM - The initial nonce from the TPM, used in the computation of the sessionKey </returns>
        [TpmCommand]
        public TpmHandle StartAuthSession(
            TpmHandle tpmKey,
            TpmHandle bind,
            byte[] nonceCaller,
            byte[] encryptedSalt,
            TpmSe sessionType,
            SymDef symmetric,
            TpmAlgId authHash,
            out byte[] nonceTPM)
        {
            var req = new Tpm2StartAuthSessionRequest(tpmKey, bind, nonceCaller, encryptedSalt, sessionType, symmetric, authHash);
            var resp = new Tpm2StartAuthSessionResponse();
            DispatchMethod(TpmCc.StartAuthSession, req, resp, 2, 1);
            nonceTPM = resp.nonceTPM;
            return resp.handle;
        }

        /// This command allows a policy authorization session to be returned to its initial state. This command is used after the TPM returns TPM_RC_PCR_CHANGED. That response code indicates that a policy will fail because the PCR have changed after TPM2_PolicyPCR() was executed. Restarting the session allows the authorizations to be replayed because the session restarts with the same nonceTPM. If the PCR are valid for the policy, the policy may then succeed.
        /// 
        /// <param name = "sessionHandle"> The handle for the policy session </param>
        [TpmCommand]
        public void PolicyRestart(
            TpmHandle sessionHandle)
        {
            var req = new Tpm2PolicyRestartRequest(sessionHandle);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyRestart, req, resp, 1, 0);
        }

        /// This command is used to create an object that can be loaded into a TPM using TPM2_Load(). If the command completes successfully, the TPM will create the new object and return the objects creation data (creationData), its public area (outPublic), and its encrypted sensitive area (outPrivate). Preservation of the returned data is the responsibility of the caller. The object will need to be loaded (TPM2_Load()) before it may be used. The only difference between the inPublic TPMT_PUBLIC template and the outPublic TPMT_PUBLIC object is in the unique field.
        /// 
        /// <param name = "parentHandle"> Handle of parent for new object
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "inSensitive"> The sensitive data </param>
        /// <param name = "inPublic"> The public template </param>
        /// <param name = "outsideInfo"> Data that will be included in the creation data for this
        ///        object to provide permanent, verifiable linkage between this object and some object
        ///        owner data </param>
        /// <param name = "creationPCR"> PCR that will be used in creation data </param>
        /// <returns> outPrivate - The private portion of the object
        ///           outPublic - The public portion of the created object
        ///           creationData - Contains a TPMS_CREATION_DATA
        ///           creationHash - Digest of creationData using nameAlg of outPublic
        ///           creationTicket - Ticket used by TPM2_CertifyCreation() to validate that the
        ///                            creation data was produced by the TPM </returns>
        [TpmCommand]
        public TpmPrivate Create(
            TpmHandle parentHandle,
            SensitiveCreate inSensitive,
            TpmPublic inPublic,
            byte[] outsideInfo,
            PcrSelection[] creationPCR,
            out TpmPublic outPublic,
            out CreationData creationData,
            out byte[] creationHash,
            out TkCreation creationTicket)
        {
            var req = new Tpm2CreateRequest(parentHandle, inSensitive, inPublic, outsideInfo, creationPCR);
            var resp = new Tpm2CreateResponse();
            DispatchMethod(TpmCc.Create, req, resp, 1, 0);
            outPublic = resp.outPublic;
            creationData = resp.creationData;
            creationHash = resp.creationHash;
            creationTicket = resp.creationTicket;
            return resp.outPrivate;
        }

        /// This command is used to load objects into the TPM. This command is used when both a TPM2B_PUBLIC and TPM2B_PRIVATE are to be loaded. If only a TPM2B_PUBLIC is to be loaded, the TPM2_LoadExternal command is used.
        /// 
        /// <param name = "parentHandle"> TPM handle of parent key; shall not be a reserved handle
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "inPrivate"> The private portion of the object </param>
        /// <param name = "inPublic"> The public portion of the object </param>
        /// <returns> handle - Handle of type TPM_HT_TRANSIENT for the loaded object
        ///           name - Name of the loaded object </returns>
        [TpmCommand]
        public TpmHandle Load(
            TpmHandle parentHandle,
            TpmPrivate inPrivate,
            TpmPublic inPublic)
        {
            var req = new Tpm2LoadRequest(parentHandle, inPrivate, inPublic);
            var resp = new Tpm2LoadResponse();
            DispatchMethod(TpmCc.Load, req, resp, 1, 1);
            return resp.handle;
        }

        /// This command is used to load an object that is not a Protected Object into the TPM. The command allows loading of a public area or both a public and sensitive area.
        /// 
        /// <param name = "inPrivate"> The sensitive portion of the object (optional) </param>
        /// <param name = "inPublic"> The public portion of the object </param>
        /// <param name = "hierarchy"> Hierarchy with which the object area is associated </param>
        /// <returns> handle - Handle of type TPM_HT_TRANSIENT for the loaded object
        ///           name - Name of the loaded object </returns>
        [TpmCommand]
        public TpmHandle LoadExternal(
            Sensitive inPrivate,
            TpmPublic inPublic,
            TpmHandle hierarchy)
        {
            var req = new Tpm2LoadExternalRequest(inPrivate, inPublic, hierarchy);
            var resp = new Tpm2LoadExternalResponse();
            DispatchMethod(TpmCc.LoadExternal, req, resp, 0, 1);
            return resp.handle;
        }

        /// This command allows access to the public area of a loaded object.
        /// 
        /// <param name = "objectHandle"> TPM handle of an object
        ///        Auth Index: None </param>
        /// <returns> outPublic - Structure containing the public area of an object
        ///           name - Name of the object
        ///           qualifiedName - The Qualified Name of the object </returns>
        [TpmCommand]
        public TpmPublic ReadPublic(
            TpmHandle objectHandle,
            out byte[] name,
            out byte[] qualifiedName)
        {
            var req = new Tpm2ReadPublicRequest(objectHandle);
            var resp = new Tpm2ReadPublicResponse();
            DispatchMethod(TpmCc.ReadPublic, req, resp, 1, 0);
            name = resp.name;
            qualifiedName = resp.qualifiedName;
            return resp.outPublic;
        }

        /// This command enables the association of a credential with an object in a way that ensures that the TPM has validated the parameters of the credentialed object.
        /// 
        /// <param name = "activateHandle"> Handle of the object associated with certificate in credentialBlob
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "keyHandle"> Loaded key used to decrypt the TPMS_SENSITIVE in credentialBlob
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "credentialBlob"> The credential </param>
        /// <param name = "secret"> KeyHandle algorithm-dependent encrypted seed that protects
        ///        credentialBlob </param>
        /// <returns> certInfo - The decrypted certificate information
        ///                      the data should be no larger than the size of the digest of the
        ///                      nameAlg associated with keyHandle </returns>
        [TpmCommand]
        public byte[] ActivateCredential(
            TpmHandle activateHandle,
            TpmHandle keyHandle,
            IdObject credentialBlob,
            byte[] secret)
        {
            var req = new Tpm2ActivateCredentialRequest(activateHandle, keyHandle, credentialBlob, secret);
            var resp = new Tpm2ActivateCredentialResponse();
            DispatchMethod(TpmCc.ActivateCredential, req, resp, 2, 0);
            return resp.certInfo;
        }

        /// This command allows the TPM to perform the actions required of a Certificate Authority (CA) in creating a TPM2B_ID_OBJECT containing an activation credential.
        /// 
        /// <param name = "handle"> Loaded public area, used to encrypt the sensitive area containing
        ///        the credential key
        ///        Auth Index: None </param>
        /// <param name = "credential"> The credential information </param>
        /// <param name = "objectName"> Name of the object to which the credential applies </param>
        /// <returns> credentialBlob - The credential
        ///           secret - Handle algorithm-dependent data that wraps the key that encrypts credentialBlob </returns>
        [TpmCommand]
        public IdObject MakeCredential(
            TpmHandle handle,
            byte[] credential,
            byte[] objectName,
            out byte[] secret)
        {
            var req = new Tpm2MakeCredentialRequest(handle, credential, objectName);
            var resp = new Tpm2MakeCredentialResponse();
            DispatchMethod(TpmCc.MakeCredential, req, resp, 1, 0);
            secret = resp.secret;
            return resp.credentialBlob;
        }

        /// This command returns the data in a loaded Sealed Data Object.
        /// 
        /// <param name = "itemHandle"> Handle of a loaded data object
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <returns> outData - Unsealed data
        ///                     Size of outData is limited to be no more than 128 octets. </returns>
        [TpmCommand]
        public byte[] Unseal(
            TpmHandle itemHandle)
        {
            var req = new Tpm2UnsealRequest(itemHandle);
            var resp = new Tpm2UnsealResponse();
            DispatchMethod(TpmCc.Unseal, req, resp, 1, 0);
            return resp.outData;
        }

        /// This command is used to change the authorization secret for a TPM-resident object.
        /// 
        /// <param name = "objectHandle"> Handle of the object
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "parentHandle"> Handle of the parent
        ///        Auth Index: None </param>
        /// <param name = "newAuth"> New authorization value </param>
        /// <returns> outPrivate - Private area containing the new authorization value </returns>
        [TpmCommand]
        public TpmPrivate ObjectChangeAuth(
            TpmHandle objectHandle,
            TpmHandle parentHandle,
            byte[] newAuth)
        {
            var req = new Tpm2ObjectChangeAuthRequest(objectHandle, parentHandle, newAuth);
            var resp = new Tpm2ObjectChangeAuthResponse();
            DispatchMethod(TpmCc.ObjectChangeAuth, req, resp, 2, 0);
            return resp.outPrivate;
        }

        /// This command creates an object and loads it in the TPM. This command allows creation of any type of object (Primary, Ordinary, or Derived) depending on the type of parentHandle. If parentHandle references a Primary Seed, then a Primary Object is created; if parentHandle references a Storage Parent, then an Ordinary Object is created; and if parentHandle references a Derivation Parent, then a Derived Object is generated.
        /// 
        /// <param name = "parentHandle"> Handle of a transient storage key, a persistent storage key,
        ///        TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "inSensitive"> The sensitive data, see TPM 2.0 Part 1 Sensitive Values </param>
        /// <param name = "inPublic"> The public template </param>
        /// <returns> handle - Handle of type TPM_HT_TRANSIENT for created object
        ///           outPrivate - The sensitive area of the object (optional)
        ///           outPublic - The public portion of the created object
        ///           name - The name of the created object </returns>
        [TpmCommand]
        public TpmHandle CreateLoaded(
            TpmHandle parentHandle,
            SensitiveCreate inSensitive,
            byte[] inPublic,
            out TpmPrivate outPrivate,
            out TpmPublic outPublic)
        {
            var req = new Tpm2CreateLoadedRequest(parentHandle, inSensitive, inPublic);
            var resp = new Tpm2CreateLoadedResponse();
            DispatchMethod(TpmCc.CreateLoaded, req, resp, 1, 1);
            outPrivate = resp.outPrivate;
            outPublic = resp.outPublic;
            return resp.handle;
        }

        /// This command duplicates a loaded object so that it may be used in a different hierarchy. The new parent key for the duplicate may be on the same or different TPM or TPM_RH_NULL. Only the public area of newParentHandle is required to be loaded.
        /// 
        /// <param name = "objectHandle"> Loaded object to duplicate
        ///        Auth Index: 1
        ///        Auth Role: DUP </param>
        /// <param name = "newParentHandle"> Shall reference the public area of an asymmetric key
        ///        Auth Index: None </param>
        /// <param name = "encryptionKeyIn"> Optional symmetric encryption key
        ///        The size for this key is set to zero when the TPM is to generate the key. This
        ///        parameter may be encrypted. </param>
        /// <param name = "symmetricAlg"> Definition for the symmetric algorithm to be used for the
        ///        inner wrapper
        ///        may be TPM_ALG_NULL if no inner wrapper is applied </param>
        /// <returns> encryptionKeyOut - If the caller provided an encryption key or if symmetricAlg
        ///                              was TPM_ALG_NULL, then this will be the Empty Buffer;
        ///                              otherwise, it shall contain the TPM-generated, symmetric
        ///                              encryption key for the inner wrapper.
        ///           duplicate - Private area that may be encrypted by encryptionKeyIn; and may be
        ///                       doubly encrypted
        ///           outSymSeed - Seed protected by the asymmetric algorithms of new parent (NP) </returns>
        [TpmCommand]
        public byte[] Duplicate(
            TpmHandle objectHandle,
            TpmHandle newParentHandle,
            byte[] encryptionKeyIn,
            SymDefObject symmetricAlg,
            out TpmPrivate duplicate,
            out byte[] outSymSeed)
        {
            var req = new Tpm2DuplicateRequest(objectHandle, newParentHandle, encryptionKeyIn, symmetricAlg);
            var resp = new Tpm2DuplicateResponse();
            DispatchMethod(TpmCc.Duplicate, req, resp, 2, 0);
            duplicate = resp.duplicate;
            outSymSeed = resp.outSymSeed;
            return resp.encryptionKeyOut;
        }

        /// This command allows the TPM to serve in the role as a Duplication Authority. If proper authorization for use of the oldParent is provided, then an HMAC key and a symmetric key are recovered from inSymSeed and used to integrity check and decrypt inDuplicate. A new protection seed value is generated according to the methods appropriate for newParent and the blob is re-encrypted and a new integrity value is computed. The re-encrypted blob is returned in outDuplicate and the symmetric key returned in outSymKey.
        /// 
        /// <param name = "oldParent"> Parent of object
        ///        Auth Index: 1
        ///        Auth Role: User </param>
        /// <param name = "newParent"> New parent of the object
        ///        Auth Index: None </param>
        /// <param name = "inDuplicate"> An object encrypted using symmetric key derived from
        ///        inSymSeed </param>
        /// <param name = "name"> The Name of the object being rewrapped </param>
        /// <param name = "inSymSeed"> The seed for the symmetric key and HMAC key
        ///        needs oldParent private key to recover the seed and generate the symmetric key </param>
        /// <returns> outDuplicate - An object encrypted using symmetric key derived from outSymSeed
        ///           outSymSeed - Seed for a symmetric key protected by newParent asymmetric key </returns>
        [TpmCommand]
        public TpmPrivate Rewrap(
            TpmHandle oldParent,
            TpmHandle newParent,
            TpmPrivate inDuplicate,
            byte[] name,
            byte[] inSymSeed,
            out byte[] outSymSeed)
        {
            var req = new Tpm2RewrapRequest(oldParent, newParent, inDuplicate, name, inSymSeed);
            var resp = new Tpm2RewrapResponse();
            DispatchMethod(TpmCc.Rewrap, req, resp, 2, 0);
            outSymSeed = resp.outSymSeed;
            return resp.outDuplicate;
        }

        /// This command allows an object to be encrypted using the symmetric encryption values of a Storage Key. After encryption, the object may be loaded and used in the new hierarchy. The imported object (duplicate) may be singly encrypted, multiply encrypted, or unencrypted.
        /// 
        /// <param name = "parentHandle"> The handle of the new parent for the object
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "encryptionKey"> The optional symmetric encryption key used as the inner
        ///        wrapper for duplicate
        ///        If symmetricAlg is TPM_ALG_NULL, then this parameter shall be the Empty Buffer. </param>
        /// <param name = "objectPublic"> The public area of the object to be imported
        ///        This is provided so that the integrity value for duplicate and the object
        ///        attributes can be checked.
        ///        NOTE Even if the integrity value of the object is not checked on input, the object
        ///        Name is required to create the integrity value for the imported object. </param>
        /// <param name = "duplicate"> The symmetrically encrypted duplicate object that may contain
        ///        an inner symmetric wrapper </param>
        /// <param name = "inSymSeed"> The seed for the symmetric key and HMAC key
        ///        inSymSeed is encrypted/encoded using the algorithms of newParent. </param>
        /// <param name = "symmetricAlg"> Definition for the symmetric algorithm to use for the inner wrapper
        ///        If this algorithm is TPM_ALG_NULL, no inner wrapper is present and encryptionKey
        ///        shall be the Empty Buffer. </param>
        /// <returns> outPrivate - The sensitive area encrypted with the symmetric key of parentHandle </returns>
        [TpmCommand]
        public TpmPrivate Import(
            TpmHandle parentHandle,
            byte[] encryptionKey,
            TpmPublic objectPublic,
            TpmPrivate duplicate,
            byte[] inSymSeed,
            SymDefObject symmetricAlg)
        {
            var req = new Tpm2ImportRequest(parentHandle, encryptionKey, objectPublic, duplicate, inSymSeed, symmetricAlg);
            var resp = new Tpm2ImportResponse();
            DispatchMethod(TpmCc.Import, req, resp, 1, 0);
            return resp.outPrivate;
        }

        /// This command performs RSA encryption using the indicated padding scheme according to IETF RFC 8017. If the scheme of keyHandle is TPM_ALG_NULL, then the caller may use inScheme to specify the padding scheme. If scheme of keyHandle is not TPM_ALG_NULL, then inScheme shall either be TPM_ALG_NULL or be the same as scheme (TPM_RC_SCHEME).
        /// 
        /// <param name = "keyHandle"> Reference to public portion of RSA key to use for encryption
        ///        Auth Index: None </param>
        /// <param name = "message"> Message to be encrypted
        ///        NOTE 1 The data type was chosen because it limits the overall size of the input to
        ///        no greater than the size of the largest RSA public key. This may be larger than
        ///        allowed for keyHandle. </param>
        /// <param name = "inScheme"> The padding scheme to use if scheme associated with keyHandle is
        ///        TPM_ALG_NULL
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        /// <param name = "label"> Optional label L to be associated with the message
        ///        Size of the buffer is zero if no label is present
        ///        NOTE 2 See description of label above. </param>
        /// <returns> outData - Encrypted output </returns>
        [TpmCommand]
        public byte[] RsaEncrypt(
            TpmHandle keyHandle,
            byte[] message,
            IAsymSchemeUnion inScheme,
            byte[] label)
        {
            var req = new Tpm2RsaEncryptRequest(keyHandle, message, inScheme, label);
            var resp = new Tpm2RsaEncryptResponse();
            DispatchMethod(TpmCc.RsaEncrypt, req, resp, 1, 0);
            return resp.outData;
        }

        /// This command performs RSA decryption using the indicated padding scheme according to IETF RFC 8017 ((PKCS#1).
        /// 
        /// <param name = "keyHandle"> RSA key to use for decryption
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "cipherText"> Cipher text to be decrypted
        ///        NOTE An encrypted RSA data block is the size of the public modulus. </param>
        /// <param name = "inScheme"> The padding scheme to use if scheme associated with keyHandle is
        ///        TPM_ALG_NULL
        ///        One of: KeySchemeEcdh, KeySchemeEcmqv, SigSchemeRsassa, SigSchemeRsapss,
        ///        SigSchemeEcdsa, SigSchemeEcdaa, SigSchemeSm2, SigSchemeEcschnorr, EncSchemeRsaes,
        ///        EncSchemeOaep, SchemeHash, NullAsymScheme. </param>
        /// <param name = "label"> Label whose association with the message is to be verified </param>
        /// <returns> message - Decrypted output </returns>
        [TpmCommand]
        public byte[] RsaDecrypt(
            TpmHandle keyHandle,
            byte[] cipherText,
            IAsymSchemeUnion inScheme,
            byte[] label)
        {
            var req = new Tpm2RsaDecryptRequest(keyHandle, cipherText, inScheme, label);
            var resp = new Tpm2RsaDecryptResponse();
            DispatchMethod(TpmCc.RsaDecrypt, req, resp, 1, 0);
            return resp.message;
        }

        /// This command uses the TPM to generate an ephemeral key pair (de, Qe where Qe [de]G). It uses the private ephemeral key and a loaded public key (QS) to compute the shared secret value (P [hde]QS).
        /// 
        /// <param name = "keyHandle"> Handle of a loaded ECC key public area.
        ///        Auth Index: None </param>
        /// <returns> zPoint - Results of P h[de]Qs
        ///           pubPoint - Generated ephemeral public point (Qe) </returns>
        [TpmCommand]
        public EccPoint EcdhKeyGen(
            TpmHandle keyHandle,
            out EccPoint pubPoint)
        {
            var req = new Tpm2EcdhKeyGenRequest(keyHandle);
            var resp = new Tpm2EcdhKeyGenResponse();
            DispatchMethod(TpmCc.EcdhKeyGen, req, resp, 1, 0);
            pubPoint = resp.pubPoint;
            return resp.zPoint;
        }

        /// This command uses the TPM to recover the Z value from a public point (QB) and a private key (ds). It will perform the multiplication of the provided inPoint (QB) with the private key (ds) and return the coordinates of the resultant point (Z = (xZ , yZ) [hds]QB; where h is the cofactor of the curve).
        /// 
        /// <param name = "keyHandle"> Handle of a loaded ECC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "inPoint"> A public key </param>
        /// <returns> outPoint - X and Y coordinates of the product of the multiplication Z = (xZ ,
        ///                      yZ) [hdS]QB </returns>
        [TpmCommand]
        public EccPoint EcdhZGen(
            TpmHandle keyHandle,
            EccPoint inPoint)
        {
            var req = new Tpm2EcdhZGenRequest(keyHandle, inPoint);
            var resp = new Tpm2EcdhZGenResponse();
            DispatchMethod(TpmCc.EcdhZGen, req, resp, 1, 0);
            return resp.outPoint;
        }

        /// This command returns the parameters of an ECC curve identified by its TCG-assigned curveID.
        /// 
        /// <param name = "curveID"> Parameter set selector </param>
        /// <returns> parameters - ECC parameters for the selected curve </returns>
        [TpmCommand]
        public AlgorithmDetailEcc EccParameters(
            EccCurve curveID)
        {
            var req = new Tpm2EccParametersRequest(curveID);
            var resp = new Tpm2EccParametersResponse();
            DispatchMethod(TpmCc.EccParameters, req, resp, 0, 0);
            return resp.parameters;
        }

        /// This command supports two-phase key exchange protocols. The command is used in combination with TPM2_EC_Ephemeral(). TPM2_EC_Ephemeral() generates an ephemeral key and returns the public point of that ephemeral key along with a numeric value that allows the TPM to regenerate the associated private key.
        /// 
        /// <param name = "keyA"> Handle of an unrestricted decryption key ECC
        ///        The private key referenced by this handle is used as dS,A
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "inQsB"> Other partys static public key (Qs,B = (Xs,B, Ys,B)) </param>
        /// <param name = "inQeB"> Other party's ephemeral public key (Qe,B = (Xe,B, Ye,B)) </param>
        /// <param name = "inScheme"> The key exchange scheme </param>
        /// <param name = "counter"> Value returned by TPM2_EC_Ephemeral() </param>
        /// <returns> outZ1 - X and Y coordinates of the computed value (scheme dependent)
        ///           outZ2 - X and Y coordinates of the second computed value (scheme dependent) </returns>
        [TpmCommand]
        public EccPoint ZGen2Phase(
            TpmHandle keyA,
            EccPoint inQsB,
            EccPoint inQeB,
            TpmAlgId inScheme,
            ushort counter,
            out EccPoint outZ2)
        {
            var req = new Tpm2ZGen2PhaseRequest(keyA, inQsB, inQeB, inScheme, counter);
            var resp = new Tpm2ZGen2PhaseResponse();
            DispatchMethod(TpmCc.ZGen2Phase, req, resp, 1, 0);
            outZ2 = resp.outZ2;
            return resp.outZ1;
        }

        /// This command performs ECC encryption as described in Part 1, Annex D.
        /// 
        /// <param name = "keyHandle"> Reference to public portion of ECC key to use for encryption
        ///        Auth Index: None </param>
        /// <param name = "plainText"> Plaintext to be encrypted </param>
        /// <param name = "inScheme"> The KDF to use if scheme associated with keyHandle is TPM_ALG_NULL
        ///        One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2, KdfSchemeKdf1Sp800108,
        ///        SchemeHash, NullKdfScheme. </param>
        /// <returns> C1 - The public ephemeral key used for ECDH
        ///           C2 - The data block produced by the XOR process
        ///           C3 - The integrity value </returns>
        [TpmCommand]
        public EccPoint EccEncrypt(
            TpmHandle keyHandle,
            byte[] plainText,
            IKdfSchemeUnion inScheme,
            out byte[] C2,
            out byte[] C3)
        {
            var req = new Tpm2EccEncryptRequest(keyHandle, plainText, inScheme);
            var resp = new Tpm2EccEncryptResponse();
            DispatchMethod(TpmCc.EccEncrypt, req, resp, 1, 0);
            C2 = resp.C2;
            C3 = resp.C3;
            return resp.C1;
        }

        /// This command performs ECC decryption.
        /// 
        /// <param name = "keyHandle"> ECC key to use for decryption
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "C1"> The public ephemeral key used for ECDH </param>
        /// <param name = "C2"> The data block produced by the XOR process </param>
        /// <param name = "C3"> The integrity value </param>
        /// <param name = "inScheme"> The KDF to use if scheme associated with keyHandle is TPM_ALG_NULL
        ///        One of: KdfSchemeMgf1, KdfSchemeKdf1Sp80056a, KdfSchemeKdf2, KdfSchemeKdf1Sp800108,
        ///        SchemeHash, NullKdfScheme. </param>
        /// <returns> plainText - Decrypted output </returns>
        [TpmCommand]
        public byte[] EccDecrypt(
            TpmHandle keyHandle,
            EccPoint C1,
            byte[] C2,
            byte[] C3,
            IKdfSchemeUnion inScheme)
        {
            var req = new Tpm2EccDecryptRequest(keyHandle, C1, C2, C3, inScheme);
            var resp = new Tpm2EccDecryptResponse();
            DispatchMethod(TpmCc.EccDecrypt, req, resp, 1, 0);
            return resp.plainText;
        }

        /// NOTE 1 This command is deprecated, and TPM2_EncryptDecrypt2() is preferred. This should be reflected in platform-specific specifications.
        /// 
        /// <param name = "keyHandle"> The symmetric key used for the operation
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "decrypt"> If YES, then the operation is decryption; if NO, the operation is
        ///        encryption </param>
        /// <param name = "mode"> Symmetric encryption/decryption mode
        ///        this field shall match the default mode of the key or be TPM_ALG_NULL. </param>
        /// <param name = "ivIn"> An initial value as required by the algorithm </param>
        /// <param name = "inData"> The data to be encrypted/decrypted </param>
        /// <returns> outData - Encrypted or decrypted output
        ///           ivOut - Chaining value to use for IV in next round </returns>
        [TpmCommand]
        public byte[] EncryptDecrypt(
            TpmHandle keyHandle,
            byte decrypt,
            TpmAlgId mode,
            byte[] ivIn,
            byte[] inData,
            out byte[] ivOut)
        {
            var req = new Tpm2EncryptDecryptRequest(keyHandle, decrypt, mode, ivIn, inData);
            var resp = new Tpm2EncryptDecryptResponse();
            DispatchMethod(TpmCc.EncryptDecrypt, req, resp, 1, 0);
            ivOut = resp.ivOut;
            return resp.outData;
        }

        /// This command is identical to TPM2_EncryptDecrypt(), except that the inData parameter is the first parameter. This permits inData to be parameter encrypted.
        /// 
        /// <param name = "keyHandle"> The symmetric key used for the operation
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "inData"> The data to be encrypted/decrypted </param>
        /// <param name = "decrypt"> If YES, then the operation is decryption; if NO, the operation is
        ///        encryption </param>
        /// <param name = "mode"> Symmetric mode
        ///        this field shall match the default mode of the key or be TPM_ALG_NULL. </param>
        /// <param name = "ivIn"> An initial value as required by the algorithm </param>
        /// <returns> outData - Encrypted or decrypted output
        ///           ivOut - Chaining value to use for IV in next round </returns>
        [TpmCommand]
        public byte[] EncryptDecrypt2(
            TpmHandle keyHandle,
            byte[] inData,
            byte decrypt,
            TpmAlgId mode,
            byte[] ivIn,
            out byte[] ivOut)
        {
            var req = new Tpm2EncryptDecrypt2Request(keyHandle, inData, decrypt, mode, ivIn);
            var resp = new Tpm2EncryptDecrypt2Response();
            DispatchMethod(TpmCc.EncryptDecrypt2, req, resp, 1, 0);
            ivOut = resp.ivOut;
            return resp.outData;
        }

        /// This command performs a hash operation on a data buffer and returns the results.
        /// 
        /// <param name = "data"> Data to be hashed </param>
        /// <param name = "hashAlg"> Algorithm for the hash being computed shall not be TPM_ALG_NULL </param>
        /// <param name = "hierarchy"> Hierarchy to use for the ticket (TPM_RH_NULL allowed) </param>
        /// <returns> outHash - Results
        ///           validation - Ticket indicating that the sequence of octets used to compute
        ///                        outDigest did not start with TPM_GENERATED_VALUE
        ///                        will be a NULL ticket if the digest may not be signed with a
        ///                        restricted key </returns>
        [TpmCommand]
        public byte[] Hash(
            byte[] data,
            TpmAlgId hashAlg,
            TpmHandle hierarchy,
            out TkHashcheck validation)
        {
            var req = new Tpm2HashRequest(data, hashAlg, hierarchy);
            var resp = new Tpm2HashResponse();
            DispatchMethod(TpmCc.Hash, req, resp, 0, 0);
            validation = resp.validation;
            return resp.outHash;
        }

        /// This command performs an HMAC on the supplied data using the indicated hash algorithm.
        /// 
        /// <param name = "handle"> Handle for the symmetric signing key providing the HMAC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "buffer"> HMAC data </param>
        /// <param name = "hashAlg"> Algorithm to use for HMAC </param>
        /// <returns> outHMAC - The returned HMAC in a sized buffer </returns>
        [TpmCommand]
        public byte[] Hmac(
            TpmHandle handle,
            byte[] buffer,
            TpmAlgId hashAlg)
        {
            var req = new Tpm2HmacRequest(handle, buffer, hashAlg);
            var resp = new Tpm2HmacResponse();
            DispatchMethod(TpmCc.Hmac, req, resp, 1, 0);
            return resp.outHMAC;
        }

        /// This command performs an HMAC or a block cipher MAC on the supplied data using the indicated algorithm.
        /// 
        /// <param name = "handle"> Handle for the symmetric signing key providing the MAC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "buffer"> MAC data </param>
        /// <param name = "inScheme"> Algorithm to use for MAC </param>
        /// <returns> outMAC - The returned MAC in a sized buffer </returns>
        [TpmCommand]
        public byte[] Mac(
            TpmHandle handle,
            byte[] buffer,
            TpmAlgId inScheme)
        {
            var req = new Tpm2MacRequest(handle, buffer, inScheme);
            var resp = new Tpm2MacResponse();
            DispatchMethod(TpmCc.Mac, req, resp, 1, 0);
            return resp.outMAC;
        }

        /// This command returns the next bytesRequested octets from the random number generator (RNG).
        /// 
        /// <param name = "bytesRequested"> Number of octets to return </param>
        /// <returns> randomBytes - The random octets </returns>
        [TpmCommand]
        public byte[] GetRandom(
            ushort bytesRequested)
        {
            var req = new Tpm2GetRandomRequest(bytesRequested);
            var resp = new Tpm2GetRandomResponse();
            DispatchMethod(TpmCc.GetRandom, req, resp, 0, 0);
            return resp.randomBytes;
        }

        /// This command is used to add "additional information" to the RNG state.
        /// 
        /// <param name = "inData"> Additional information </param>
        [TpmCommand]
        public void StirRandom(
            byte[] inData)
        {
            var req = new Tpm2StirRandomRequest(inData);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.StirRandom, req, resp, 0, 0);
        }

        /// This command starts an HMAC sequence. The TPM will create and initialize an HMAC sequence structure, assign a handle to the sequence, and set the authValue of the sequence object to the value in auth.
        /// 
        /// <param name = "handle"> Handle of an HMAC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "auth"> Authorization value for subsequent use of the sequence </param>
        /// <param name = "hashAlg"> The hash algorithm to use for the HMAC </param>
        /// <returns> handle - A handle to reference the sequence </returns>
        [TpmCommand]
        public TpmHandle HmacStart(
            TpmHandle handle,
            byte[] auth,
            TpmAlgId hashAlg)
        {
            var req = new Tpm2HmacStartRequest(handle, auth, hashAlg);
            var resp = new Tpm2HmacStartResponse();
            DispatchMethod(TpmCc.HmacStart, req, resp, 1, 1);
            return resp.handle;
        }

        /// This command starts a MAC sequence. The TPM will create and initialize a MAC sequence structure, assign a handle to the sequence, and set the authValue of the sequence object to the value in auth.
        /// 
        /// <param name = "handle"> Handle of a MAC key
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "auth"> Authorization value for subsequent use of the sequence </param>
        /// <param name = "inScheme"> The algorithm to use for the MAC </param>
        /// <returns> handle - A handle to reference the sequence </returns>
        [TpmCommand]
        public TpmHandle MacStart(
            TpmHandle handle,
            byte[] auth,
            TpmAlgId inScheme)
        {
            var req = new Tpm2MacStartRequest(handle, auth, inScheme);
            var resp = new Tpm2MacStartResponse();
            DispatchMethod(TpmCc.MacStart, req, resp, 1, 1);
            return resp.handle;
        }

        /// This command starts a hash or an Event Sequence. If hashAlg is an implemented hash, then a hash sequence is started. If hashAlg is TPM_ALG_NULL, then an Event Sequence is started. If hashAlg is neither an implemented algorithm nor TPM_ALG_NULL, then the TPM shall return TPM_RC_HASH.
        /// 
        /// <param name = "auth"> Authorization value for subsequent use of the sequence </param>
        /// <param name = "hashAlg"> The hash algorithm to use for the hash sequence
        ///        An Event Sequence starts if this is TPM_ALG_NULL. </param>
        /// <returns> handle - A handle to reference the sequence </returns>
        [TpmCommand]
        public TpmHandle HashSequenceStart(
            byte[] auth,
            TpmAlgId hashAlg)
        {
            var req = new Tpm2HashSequenceStartRequest(auth, hashAlg);
            var resp = new Tpm2HashSequenceStartResponse();
            DispatchMethod(TpmCc.HashSequenceStart, req, resp, 0, 1);
            return resp.handle;
        }

        /// This command is used to add data to a hash or HMAC sequence. The amount of data in buffer may be any size up to the limits of the TPM.
        /// 
        /// <param name = "sequenceHandle"> Handle for the sequence object
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "buffer"> Data to be added to hash </param>
        [TpmCommand]
        public void SequenceUpdate(
            TpmHandle sequenceHandle,
            byte[] buffer)
        {
            var req = new Tpm2SequenceUpdateRequest(sequenceHandle, buffer);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.SequenceUpdate, req, resp, 1, 0);
        }

        /// This command adds the last part of data, if any, to a hash/HMAC sequence and returns the result.
        /// 
        /// <param name = "sequenceHandle"> Authorization for the sequence
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "buffer"> Data to be added to the hash/HMAC </param>
        /// <param name = "hierarchy"> Hierarchy of the ticket for a hash </param>
        /// <returns> result - The returned HMAC or digest in a sized buffer
        ///           validation - Ticket indicating that the sequence of octets used to compute
        ///                        outDigest did not start with TPM_GENERATED_VALUE
        ///                        This is a NULL Ticket when the sequence is HMAC. </returns>
        [TpmCommand]
        public byte[] SequenceComplete(
            TpmHandle sequenceHandle,
            byte[] buffer,
            TpmHandle hierarchy,
            out TkHashcheck validation)
        {
            var req = new Tpm2SequenceCompleteRequest(sequenceHandle, buffer, hierarchy);
            var resp = new Tpm2SequenceCompleteResponse();
            DispatchMethod(TpmCc.SequenceComplete, req, resp, 1, 0);
            validation = resp.validation;
            return resp.result;
        }

        /// This command adds the last part of data, if any, to an Event Sequence and returns the result in a digest list. If pcrHandle references a PCR and not TPM_RH_NULL, then the returned digest list is processed in the same manner as the digest list input parameter to TPM2_PCR_Extend(). That is, if a bank contains a PCR associated with pcrHandle, it is extended with the associated digest value from the list.
        /// 
        /// <param name = "pcrHandle"> PCR to be extended with the Event data
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "sequenceHandle"> Authorization for the sequence
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "buffer"> Data to be added to the Event </param>
        /// <returns> results - List of digests computed for the PCR </returns>
        [TpmCommand]
        public TpmHash[] EventSequenceComplete(
            TpmHandle pcrHandle,
            TpmHandle sequenceHandle,
            byte[] buffer)
        {
            var req = new Tpm2EventSequenceCompleteRequest(pcrHandle, sequenceHandle, buffer);
            var resp = new Tpm2EventSequenceCompleteResponse();
            DispatchMethod(TpmCc.EventSequenceComplete, req, resp, 2, 0);
            return resp.results;
        }

        /// The purpose of this command is to prove that an object with a specific Name is loaded in the TPM. By certifying that the object is loaded, the TPM warrants that a public area with a given Name is self-consistent and associated with a valid sensitive area. If a relying party has a public area that has the same Name as a Name certified with this command, then the values in that public area are correct.
        /// 
        /// <param name = "objectHandle"> Handle of the object to be certified
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "signHandle"> Handle of the key used to sign the attestation structure
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "qualifyingData"> User provided qualifying data </param>
        /// <param name = "inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <returns> certifyInfo - The structure that was signed
        ///           signature - The asymmetric signature over certifyInfo using the key referenced
        ///                       by signHandle </returns>
        [TpmCommand]
        public Attest Certify(
            TpmHandle objectHandle,
            TpmHandle signHandle,
            byte[] qualifyingData,
            ISigSchemeUnion inScheme,
            out ISignatureUnion signature)
        {
            var req = new Tpm2CertifyRequest(objectHandle, signHandle, qualifyingData, inScheme);
            var resp = new Tpm2CertifyResponse();
            DispatchMethod(TpmCc.Certify, req, resp, 2, 0);
            signature = resp.signature;
            return resp.certifyInfo;
        }

        /// This command is used to prove the association between an object and its creation data. The TPM will validate that the ticket was produced by the TPM and that the ticket validates the association between a loaded public area and the provided hash of the creation data (creationHash).
        /// 
        /// <param name = "signHandle"> Handle of the key that will sign the attestation block
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "objectHandle"> The object associated with the creation data
        ///        Auth Index: None </param>
        /// <param name = "qualifyingData"> User-provided qualifying data </param>
        /// <param name = "creationHash"> Hash of the creation data produced by TPM2_Create() or
        ///        TPM2_CreatePrimary() </param>
        /// <param name = "inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "creationTicket"> Ticket produced by TPM2_Create() or TPM2_CreatePrimary() </param>
        /// <returns> certifyInfo - The structure that was signed
        ///           signature - The signature over certifyInfo </returns>
        [TpmCommand]
        public Attest CertifyCreation(
            TpmHandle signHandle,
            TpmHandle objectHandle,
            byte[] qualifyingData,
            byte[] creationHash,
            ISigSchemeUnion inScheme,
            TkCreation creationTicket,
            out ISignatureUnion signature)
        {
            var req = new Tpm2CertifyCreationRequest(signHandle, objectHandle, qualifyingData, creationHash, inScheme, creationTicket);
            var resp = new Tpm2CertifyCreationResponse();
            DispatchMethod(TpmCc.CertifyCreation, req, resp, 2, 0);
            signature = resp.signature;
            return resp.certifyInfo;
        }

        /// This command is used to quote PCR values.
        /// 
        /// <param name = "signHandle"> Handle of key that will perform signature
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "qualifyingData"> Data supplied by the caller </param>
        /// <param name = "inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "PCRselect"> PCR set to quote </param>
        /// <returns> quoted - The quoted information
        ///           signature - The signature over quoted </returns>
        [TpmCommand]
        public Attest Quote(
            TpmHandle signHandle,
            byte[] qualifyingData,
            ISigSchemeUnion inScheme,
            PcrSelection[] PCRselect,
            out ISignatureUnion signature)
        {
            var req = new Tpm2QuoteRequest(signHandle, qualifyingData, inScheme, PCRselect);
            var resp = new Tpm2QuoteResponse();
            DispatchMethod(TpmCc.Quote, req, resp, 1, 0);
            signature = resp.signature;
            return resp.quoted;
        }

        /// This command returns a digital signature of the audit session digest.
        /// 
        /// <param name = "privacyAdminHandle"> Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "signHandle"> Handle of the signing key
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "sessionHandle"> Handle of the audit session
        ///        Auth Index: None </param>
        /// <param name = "qualifyingData"> User-provided qualifying data may be zero-length </param>
        /// <param name = "inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <returns> auditInfo - The audit information that was signed
        ///           signature - The signature over auditInfo </returns>
        [TpmCommand]
        public Attest GetSessionAuditDigest(
            TpmHandle privacyAdminHandle,
            TpmHandle signHandle,
            TpmHandle sessionHandle,
            byte[] qualifyingData,
            ISigSchemeUnion inScheme,
            out ISignatureUnion signature)
        {
            var req = new Tpm2GetSessionAuditDigestRequest(privacyAdminHandle, signHandle, sessionHandle, qualifyingData, inScheme);
            var resp = new Tpm2GetSessionAuditDigestResponse();
            DispatchMethod(TpmCc.GetSessionAuditDigest, req, resp, 3, 0);
            signature = resp.signature;
            return resp.auditInfo;
        }

        /// This command returns the current value of the command audit digest, a digest of the commands being audited, and the audit hash algorithm. These values are placed in an attestation structure and signed with the key referenced by signHandle.
        /// 
        /// <param name = "privacyHandle"> Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "signHandle"> The handle of the signing key
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "qualifyingData"> Other data to associate with this audit digest </param>
        /// <param name = "inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <returns> auditInfo - The auditInfo that was signed
        ///           signature - The signature over auditInfo </returns>
        [TpmCommand]
        public Attest GetCommandAuditDigest(
            TpmHandle privacyHandle,
            TpmHandle signHandle,
            byte[] qualifyingData,
            ISigSchemeUnion inScheme,
            out ISignatureUnion signature)
        {
            var req = new Tpm2GetCommandAuditDigestRequest(privacyHandle, signHandle, qualifyingData, inScheme);
            var resp = new Tpm2GetCommandAuditDigestResponse();
            DispatchMethod(TpmCc.GetCommandAuditDigest, req, resp, 2, 0);
            signature = resp.signature;
            return resp.auditInfo;
        }

        /// This command returns the current values of Time and Clock.
        /// 
        /// <param name = "privacyAdminHandle"> Handle of the privacy administrator (TPM_RH_ENDORSEMENT)
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "signHandle"> The keyHandle identifier of a loaded key that can perform
        ///        digital signatures
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "qualifyingData"> Data to tick stamp </param>
        /// <param name = "inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <returns> timeInfo - Standard TPM-generated attestation block
        ///           signature - The signature over timeInfo </returns>
        [TpmCommand]
        public Attest GetTime(
            TpmHandle privacyAdminHandle,
            TpmHandle signHandle,
            byte[] qualifyingData,
            ISigSchemeUnion inScheme,
            out ISignatureUnion signature)
        {
            var req = new Tpm2GetTimeRequest(privacyAdminHandle, signHandle, qualifyingData, inScheme);
            var resp = new Tpm2GetTimeResponse();
            DispatchMethod(TpmCc.GetTime, req, resp, 2, 0);
            signature = resp.signature;
            return resp.timeInfo;
        }

        /// The purpose of this command is to generate an X.509 certificate that proves an object with a specific public key and attributes is loaded in the TPM. In contrast to TPM2_Certify, which uses a TCG-defined data structure to convey attestation information, TPM2_CertifyX509 encodes the attestation information in a DER-encoded X.509 certificate that is compliant with RFC5280 Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile.
        /// 
        /// <param name = "objectHandle"> Handle of the object to be certified
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "signHandle"> Handle of the key used to sign the attestation structure
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "reserved"> Shall be an Empty Buffer </param>
        /// <param name = "inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "partialCertificate"> A DER encoded partial certificate </param>
        /// <returns> addedToCertificate - A DER encoded SEQUENCE containing the DER encoded fields
        ///                                added to partialCertificate to make it a complete RFC5280
        ///                                TBSCertificate.
        ///           tbsDigest - The digest that was signed
        ///           signature - The signature over tbsDigest </returns>
        [TpmCommand]
        public byte[] CertifyX509(
            TpmHandle objectHandle,
            TpmHandle signHandle,
            byte[] reserved,
            ISigSchemeUnion inScheme,
            byte[] partialCertificate,
            out byte[] tbsDigest,
            out ISignatureUnion signature)
        {
            var req = new Tpm2CertifyX509Request(objectHandle, signHandle, reserved, inScheme, partialCertificate);
            var resp = new Tpm2CertifyX509Response();
            DispatchMethod(TpmCc.CertifyX509, req, resp, 2, 0);
            tbsDigest = resp.tbsDigest;
            signature = resp.signature;
            return resp.addedToCertificate;
        }

        /// TPM2_Commit() performs the first part of an ECC anonymous signing operation. The TPM will perform the point multiplications on the provided points and return intermediate signing values. The signHandle parameter shall refer to an ECC key and the signing scheme must be anonymous (TPM_RC_SCHEME).
        /// 
        /// <param name = "signHandle"> Handle of the key that will be used in the signing operation
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "P1"> A point (M) on the curve used by signHandle </param>
        /// <param name = "s2"> Octet array used to derive x-coordinate of a base point </param>
        /// <param name = "y2"> Y coordinate of the point associated with s2 </param>
        /// <returns> K - ECC point K [ds](x2, y2)
        ///           L - ECC point L [r](x2, y2)
        ///           E - ECC point E [r]P1
        ///           counter - Least-significant 16 bits of commitCount </returns>
        [TpmCommand]
        public EccPoint Commit(
            TpmHandle signHandle,
            EccPoint P1,
            byte[] s2,
            byte[] y2,
            out EccPoint L,
            out EccPoint E,
            out ushort counter)
        {
            var req = new Tpm2CommitRequest(signHandle, P1, s2, y2);
            var resp = new Tpm2CommitResponse();
            DispatchMethod(TpmCc.Commit, req, resp, 1, 0);
            L = resp.L;
            E = resp.E;
            counter = resp.counter;
            return resp.K;
        }

        /// TPM2_EC_Ephemeral() creates an ephemeral key for use in a two-phase key exchange protocol.
        /// 
        /// <param name = "curveID"> The curve for the computed ephemeral point </param>
        /// <returns> Q - Ephemeral public key Q [r]G
        ///           counter - Least-significant 16 bits of commitCount </returns>
        [TpmCommand]
        public EccPoint EcEphemeral(
            EccCurve curveID,
            out ushort counter)
        {
            var req = new Tpm2EcEphemeralRequest(curveID);
            var resp = new Tpm2EcEphemeralResponse();
            DispatchMethod(TpmCc.EcEphemeral, req, resp, 0, 0);
            counter = resp.counter;
            return resp.Q;
        }

        /// This command uses loaded keys to validate a signature on a message with the message digest passed to the TPM.
        /// 
        /// <param name = "keyHandle"> Handle of public key that will be used in the validation
        ///        Auth Index: None </param>
        /// <param name = "digest"> Digest of the signed message </param>
        /// <param name = "signature"> Signature to be tested
        ///        One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        ///        SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </param>
        /// <returns> validation - This ticket is produced by TPM2_VerifySignature(). This formulation
        ///                        is used for multiple ticket uses. The ticket provides evidence that
        ///                        the TPM has validated that a digest was signed by a key with the
        ///                        Name of keyName. The ticket is computed by </returns>
        [TpmCommand]
        public TkVerified VerifySignature(
            TpmHandle keyHandle,
            byte[] digest,
            ISignatureUnion signature)
        {
            var req = new Tpm2VerifySignatureRequest(keyHandle, digest, signature);
            var resp = new Tpm2VerifySignatureResponse();
            DispatchMethod(TpmCc.VerifySignature, req, resp, 1, 0);
            return resp.validation;
        }

        /// This command causes the TPM to sign an externally provided hash with the specified symmetric or asymmetric signing key.
        /// 
        /// <param name = "keyHandle"> Handle of key that will perform signing
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "digest"> Digest to be signed </param>
        /// <param name = "inScheme"> Signing scheme to use if the scheme for keyHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "validation"> Proof that digest was created by the TPM
        ///        If keyHandle is not a restricted signing key, then this may be a NULL Ticket with
        ///        tag = TPM_ST_CHECKHASH. </param>
        /// <returns> signature - The signature </returns>
        [TpmCommand]
        public ISignatureUnion Sign(
            TpmHandle keyHandle,
            byte[] digest,
            ISigSchemeUnion inScheme,
            TkHashcheck validation)
        {
            var req = new Tpm2SignRequest(keyHandle, digest, inScheme, validation);
            var resp = new Tpm2SignResponse();
            DispatchMethod(TpmCc.Sign, req, resp, 1, 0);
            return resp.signature;
        }

        /// This command may be used by the Privacy Administrator or platform to change the audit status of a command or to set the hash algorithm used for the audit digest, but not both at the same time.
        /// 
        /// <param name = "auth"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "auditAlg"> Hash algorithm for the audit digest; if TPM_ALG_NULL, then the
        ///        hash is not changed </param>
        /// <param name = "setList"> List of commands that will be added to those that will be audited
        ///        </param>
        /// <param name = "clearList"> List of commands that will no longer be audited </param>
        [TpmCommand]
        public void SetCommandCodeAuditStatus(
            TpmHandle auth,
            TpmAlgId auditAlg,
            TpmCc[] setList,
            TpmCc[] clearList)
        {
            var req = new Tpm2SetCommandCodeAuditStatusRequest(auth, auditAlg, setList, clearList);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.SetCommandCodeAuditStatus, req, resp, 1, 0);
        }

        /// This command is used to cause an update to the indicated PCR. The digests parameter contains one or more tagged digest values identified by an algorithm ID. For each digest, the PCR associated with pcrHandle is Extended into the bank identified by the tag (hashAlg).
        /// 
        /// <param name = "pcrHandle"> Handle of the PCR
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "digests"> List of tagged digest values to be extended </param>
        [TpmCommand]
        public void PcrExtend(
            TpmHandle pcrHandle,
            TpmHash[] digests)
        {
            var req = new Tpm2PcrExtendRequest(pcrHandle, digests);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PcrExtend, req, resp, 1, 0);
        }

        /// This command is used to cause an update to the indicated PCR.
        /// 
        /// <param name = "pcrHandle"> Handle of the PCR
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "eventData"> Event data in sized buffer </param>
        /// <returns> digests - Table 80 shows the basic hash-agile structure used in this
        ///                     specification. To handle hash agility, this structure uses the hashAlg
        ///                     parameter to indicate the algorithm used to compute the digest and, by
        ///                     implication, the size of the digest. </returns>
        [TpmCommand]
        public TpmHash[] PcrEvent(
            TpmHandle pcrHandle,
            byte[] eventData)
        {
            var req = new Tpm2PcrEventRequest(pcrHandle, eventData);
            var resp = new Tpm2PcrEventResponse();
            DispatchMethod(TpmCc.PcrEvent, req, resp, 1, 0);
            return resp.digests;
        }

        /// This command returns the values of all PCR specified in pcrSelectionIn.
        /// 
        /// <param name = "pcrSelectionIn"> The selection of PCR to read </param>
        /// <returns> pcrUpdateCounter - The current value of the PCR update counter
        ///           pcrSelectionOut - The PCR in the returned list
        ///           pcrValues - The contents of the PCR indicated in pcrSelectOut-? pcrSelection[]
        ///                       as tagged digests </returns>
        [TpmCommand]
        public uint PcrRead(
            PcrSelection[] pcrSelectionIn,
            out PcrSelection[] pcrSelectionOut,
            out Tpm2bDigest[] pcrValues)
        {
            var req = new Tpm2PcrReadRequest(pcrSelectionIn);
            var resp = new Tpm2PcrReadResponse();
            DispatchMethod(TpmCc.PcrRead, req, resp, 0, 0);
            pcrSelectionOut = resp.pcrSelectionOut;
            pcrValues = resp.pcrValues;
            return resp.pcrUpdateCounter;
        }

        /// This command is used to set the desired PCR allocation of PCR and algorithms. This command requires Platform Authorization.
        /// 
        /// <param name = "authHandle"> TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "pcrAllocation"> The requested allocation </param>
        /// <returns> allocationSuccess - YES if the allocation succeeded
        ///           maxPCR - Maximum number of PCR that may be in a bank
        ///           sizeNeeded - Number of octets required to satisfy the request
        ///           sizeAvailable - Number of octets available. Computed before the allocation. </returns>
        [TpmCommand]
        public byte PcrAllocate(
            TpmHandle authHandle,
            PcrSelection[] pcrAllocation,
            out uint maxPCR,
            out uint sizeNeeded,
            out uint sizeAvailable)
        {
            var req = new Tpm2PcrAllocateRequest(authHandle, pcrAllocation);
            var resp = new Tpm2PcrAllocateResponse();
            DispatchMethod(TpmCc.PcrAllocate, req, resp, 1, 0);
            maxPCR = resp.maxPCR;
            sizeNeeded = resp.sizeNeeded;
            sizeAvailable = resp.sizeAvailable;
            return resp.allocationSuccess;
        }

        /// This command is used to associate a policy with a PCR or group of PCR. The policy determines the conditions under which a PCR may be extended or reset.
        /// 
        /// <param name = "authHandle"> TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "authPolicy"> The desired authPolicy </param>
        /// <param name = "hashAlg"> The hash algorithm of the policy </param>
        /// <param name = "pcrNum"> The PCR for which the policy is to be set </param>
        [TpmCommand]
        public void PcrSetAuthPolicy(
            TpmHandle authHandle,
            byte[] authPolicy,
            TpmAlgId hashAlg,
            TpmHandle pcrNum)
        {
            var req = new Tpm2PcrSetAuthPolicyRequest(authHandle, authPolicy, hashAlg, pcrNum);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PcrSetAuthPolicy, req, resp, 1, 0);
        }

        /// This command changes the authValue of a PCR or group of PCR.
        /// 
        /// <param name = "pcrHandle"> Handle for a PCR that may have an authorization value set
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "auth"> The desired authorization value </param>
        [TpmCommand]
        public void PcrSetAuthValue(
            TpmHandle pcrHandle,
            byte[] auth)
        {
            var req = new Tpm2PcrSetAuthValueRequest(pcrHandle, auth);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PcrSetAuthValue, req, resp, 1, 0);
        }

        /// If the attribute of a PCR allows the PCR to be reset and proper authorization is provided, then this command may be used to set the PCR in all banks to zero. The attributes of the PCR may restrict the locality that can perform the reset operation.
        /// 
        /// <param name = "pcrHandle"> The PCR to reset
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        [TpmCommand]
        public void PcrReset(
            TpmHandle pcrHandle)
        {
            var req = new Tpm2PcrResetRequest(pcrHandle);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PcrReset, req, resp, 1, 0);
        }

        /// This command includes a signed authorization in a policy. The command ties the policy to a signing key by including the Name of the signing key in the policyDigest
        /// 
        /// <param name = "authObject"> Handle for a key that will validate the signature
        ///        Auth Index: None </param>
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "nonceTPM"> The policy nonce for the session
        ///        This can be the Empty Buffer. </param>
        /// <param name = "cpHashA"> Digest of the command parameters to which this authorization is limited
        ///        This is not the cpHash for this command but the cpHash for the command to which
        ///        this policy session will be applied. If it is not limited, the parameter will be
        ///        the Empty Buffer. </param>
        /// <param name = "policyRef"> A reference to a policy relating to the authorization may be
        ///        the Empty Buffer
        ///        Size is limited to be no larger than the nonce size supported on the TPM. </param>
        /// <param name = "expiration"> Time when authorization will expire, measured in seconds from
        ///        the time that nonceTPM was generated
        ///        If expiration is non-negative, a NULL Ticket is returned. See 23.2.5. </param>
        /// <param name = "auth"> Signed authorization (not optional)
        ///        One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        ///        SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </param>
        /// <returns> timeout - Implementation-specific time value, used to indicate to the TPM when
        ///                     the ticket expires
        ///                     NOTE If policyTicket is a NULL Ticket, then this shall be the Empty Buffer.
        ///           policyTicket - Produced if the command succeeds and expiration in the command
        ///                          was non-zero; this ticket will use the TPMT_ST_AUTH_SIGNED
        ///                          structure tag. See 23.2.5 </returns>
        [TpmCommand]
        public byte[] PolicySigned(
            TpmHandle authObject,
            TpmHandle policySession,
            byte[] nonceTPM,
            byte[] cpHashA,
            byte[] policyRef,
            int expiration,
            ISignatureUnion auth,
            out TkAuth policyTicket)
        {
            var req = new Tpm2PolicySignedRequest(authObject, policySession, nonceTPM, cpHashA, policyRef, expiration, auth);
            var resp = new Tpm2PolicySignedResponse();
            DispatchMethod(TpmCc.PolicySigned, req, resp, 2, 0);
            policyTicket = resp.policyTicket;
            return resp.timeout;
        }

        /// This command includes a secret-based authorization to a policy. The caller proves knowledge of the secret value using an authorization session using the authValue associated with authHandle. A password session, an HMAC session, or a policy session containing TPM2_PolicyAuthValue() or TPM2_PolicyPassword() will satisfy this requirement.
        /// 
        /// <param name = "authHandle"> Handle for an entity providing the authorization
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "nonceTPM"> The policy nonce for the session
        ///        This can be the Empty Buffer. </param>
        /// <param name = "cpHashA"> Digest of the command parameters to which this authorization is limited
        ///        This not the cpHash for this command but the cpHash for the command to which this
        ///        policy session will be applied. If it is not limited, the parameter will be the
        ///        Empty Buffer. </param>
        /// <param name = "policyRef"> A reference to a policy relating to the authorization may be
        ///        the Empty Buffer
        ///        Size is limited to be no larger than the nonce size supported on the TPM. </param>
        /// <param name = "expiration"> Time when authorization will expire, measured in seconds from
        ///        the time that nonceTPM was generated
        ///        If expiration is non-negative, a NULL Ticket is returned. See 23.2.5. </param>
        /// <returns> timeout - Implementation-specific time value used to indicate to the TPM when
        ///                     the ticket expires
        ///           policyTicket - Produced if the command succeeds and expiration in the command
        ///                          was non-zero ( See 23.2.5). This ticket will use the
        ///                          TPMT_ST_AUTH_SECRET structure tag </returns>
        [TpmCommand]
        public byte[] PolicySecret(
            TpmHandle authHandle,
            TpmHandle policySession,
            byte[] nonceTPM,
            byte[] cpHashA,
            byte[] policyRef,
            int expiration,
            out TkAuth policyTicket)
        {
            var req = new Tpm2PolicySecretRequest(authHandle, policySession, nonceTPM, cpHashA, policyRef, expiration);
            var resp = new Tpm2PolicySecretResponse();
            DispatchMethod(TpmCc.PolicySecret, req, resp, 2, 0);
            policyTicket = resp.policyTicket;
            return resp.timeout;
        }

        /// This command is similar to TPM2_PolicySigned() except that it takes a ticket instead of a signed authorization. The ticket represents a validated authorization that had an expiration time associated with it.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "timeout"> Time when authorization will expire
        ///        The contents are TPM specific. This shall be the value returned when ticket was
        ///        produced. </param>
        /// <param name = "cpHashA"> Digest of the command parameters to which this authorization is limited
        ///        If it is not limited, the parameter will be the Empty Buffer. </param>
        /// <param name = "policyRef"> Reference to a qualifier for the policy may be the Empty Buffer
        ///        </param>
        /// <param name = "authName"> Name of the object that provided the authorization </param>
        /// <param name = "ticket"> An authorization ticket returned by the TPM in response to a
        ///        TPM2_PolicySigned() or TPM2_PolicySecret() </param>
        [TpmCommand]
        public void PolicyTicket(
            TpmHandle policySession,
            byte[] timeout,
            byte[] cpHashA,
            byte[] policyRef,
            byte[] authName,
            TkAuth ticket)
        {
            var req = new Tpm2PolicyTicketRequest(policySession, timeout, cpHashA, policyRef, authName, ticket);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyTicket, req, resp, 1, 0);
        }

        /// This command allows options in authorizations without requiring that the TPM evaluate all of the options. If a policy may be satisfied by different sets of conditions, the TPM need only evaluate one set that satisfies the policy. This command will indicate that one of the required sets of conditions has been satisfied.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "pHashList"> The list of hashes to check for a match </param>
        [TpmCommand]
        public void PolicyOR(
            TpmHandle policySession,
            Tpm2bDigest[] pHashList)
        {
            var req = new Tpm2PolicyORRequest(policySession, pHashList);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyOR, req, resp, 1, 0);
        }

        /// This command is used to cause conditional gating of a policy based on PCR. This command together with TPM2_PolicyOR() allows one group of authorizations to occur when PCR are in one state and a different set of authorizations when the PCR are in a different state.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "pcrDigest"> Expected digest value of the selected PCR using the hash
        ///        algorithm of the session; may be zero length </param>
        /// <param name = "pcrs"> The PCR to include in the check digest </param>
        [TpmCommand]
        public void PolicyPCR(
            TpmHandle policySession,
            byte[] pcrDigest,
            PcrSelection[] pcrs)
        {
            var req = new Tpm2PolicyPCRRequest(policySession, pcrDigest, pcrs);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyPCR, req, resp, 1, 0);
        }

        /// This command indicates that the authorization will be limited to a specific locality.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "locality"> The allowed localities for the policy </param>
        [TpmCommand]
        public void PolicyLocality(
            TpmHandle policySession,
            LocalityAttr locality)
        {
            var req = new Tpm2PolicyLocalityRequest(policySession, locality);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyLocality, req, resp, 1, 0);
        }

        /// This command is used to cause conditional gating of a policy based on the contents of an NV Index. It is an immediate assertion. The NV index is validated during the TPM2_PolicyNV() command, not when the session is used for authorization.
        /// 
        /// <param name = "authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> The NV Index of the area to read
        ///        Auth Index: None </param>
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "operandB"> The second operand </param>
        /// <param name = "offset"> The octet offset in the NV Index for the start of operand A </param>
        /// <param name = "operation"> The comparison to make </param>
        [TpmCommand]
        public void PolicyNV(
            TpmHandle authHandle,
            TpmHandle nvIndex,
            TpmHandle policySession,
            byte[] operandB,
            ushort offset,
            Eo operation)
        {
            var req = new Tpm2PolicyNVRequest(authHandle, nvIndex, policySession, operandB, offset, operation);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyNV, req, resp, 3, 0);
        }

        /// This command is used to cause conditional gating of a policy based on the contents of the TPMS_TIME_INFO structure.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "operandB"> The second operand </param>
        /// <param name = "offset"> The octet offset in the TPMS_TIME_INFO structure for the start of
        ///        operand A </param>
        /// <param name = "operation"> The comparison to make </param>
        [TpmCommand]
        public void PolicyCounterTimer(
            TpmHandle policySession,
            byte[] operandB,
            ushort offset,
            Eo operation)
        {
            var req = new Tpm2PolicyCounterTimerRequest(policySession, operandB, offset, operation);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyCounterTimer, req, resp, 1, 0);
        }

        /// This command indicates that the authorization will be limited to a specific command code.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "code"> The allowed commandCode </param>
        [TpmCommand]
        public void PolicyCommandCode(
            TpmHandle policySession,
            TpmCc code)
        {
            var req = new Tpm2PolicyCommandCodeRequest(policySession, code);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyCommandCode, req, resp, 1, 0);
        }

        /// This command indicates that physical presence will need to be asserted at the time the authorization is performed.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        [TpmCommand]
        public void PolicyPhysicalPresence(
            TpmHandle policySession)
        {
            var req = new Tpm2PolicyPhysicalPresenceRequest(policySession);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyPhysicalPresence, req, resp, 1, 0);
        }

        /// This command is used to allow a policy to be bound to a specific command and command parameters.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "cpHashA"> The cpHash added to the policy </param>
        [TpmCommand]
        public void PolicyCpHash(
            TpmHandle policySession,
            byte[] cpHashA)
        {
            var req = new Tpm2PolicyCpHashRequest(policySession, cpHashA);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyCpHash, req, resp, 1, 0);
        }

        /// This command allows a policy to be bound to a specific set of TPM entities without being bound to the parameters of the command. This is most useful for commands such as TPM2_Duplicate() and for TPM2_PCR_Event() when the referenced PCR requires a policy.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "nameHash"> The digest to be added to the policy </param>
        [TpmCommand]
        public void PolicyNameHash(
            TpmHandle policySession,
            byte[] nameHash)
        {
            var req = new Tpm2PolicyNameHashRequest(policySession, nameHash);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyNameHash, req, resp, 1, 0);
        }

        /// This command allows qualification of duplication to allow duplication to a selected new parent.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "objectName"> The Name of the object to be duplicated </param>
        /// <param name = "newParentName"> The Name of the new parent </param>
        /// <param name = "includeObject"> If YES, the objectName will be included in the value in
        ///        policySessionpolicyDigest </param>
        [TpmCommand]
        public void PolicyDuplicationSelect(
            TpmHandle policySession,
            byte[] objectName,
            byte[] newParentName,
            byte includeObject)
        {
            var req = new Tpm2PolicyDuplicationSelectRequest(policySession, objectName, newParentName, includeObject);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyDuplicationSelect, req, resp, 1, 0);
        }

        /// This command allows policies to change. If a policy were static, then it would be difficult to add users to a policy. This command lets a policy authority sign a new policy so that it may be used in an existing policy.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "approvedPolicy"> Digest of the policy being approved </param>
        /// <param name = "policyRef"> A policy qualifier </param>
        /// <param name = "keySign"> Name of a key that can sign a policy addition </param>
        /// <param name = "checkTicket"> Ticket validating that approvedPolicy and policyRef were
        ///        signed by keySign </param>
        [TpmCommand]
        public void PolicyAuthorize(
            TpmHandle policySession,
            byte[] approvedPolicy,
            byte[] policyRef,
            byte[] keySign,
            TkVerified checkTicket)
        {
            var req = new Tpm2PolicyAuthorizeRequest(policySession, approvedPolicy, policyRef, keySign, checkTicket);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyAuthorize, req, resp, 1, 0);
        }

        /// This command allows a policy to be bound to the authorization value of the authorized entity.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        [TpmCommand]
        public void PolicyAuthValue(
            TpmHandle policySession)
        {
            var req = new Tpm2PolicyAuthValueRequest(policySession);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyAuthValue, req, resp, 1, 0);
        }

        /// This command allows a policy to be bound to the authorization value of the authorized object.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        [TpmCommand]
        public void PolicyPassword(
            TpmHandle policySession)
        {
            var req = new Tpm2PolicyPasswordRequest(policySession);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyPassword, req, resp, 1, 0);
        }

        /// This command returns the current policyDigest of the session. This command allows the TPM to be used to perform the actions required to pre-compute the authPolicy for an object.
        /// 
        /// <param name = "policySession"> Handle for the policy session
        ///        Auth Index: None </param>
        /// <returns> policyDigest - The current value of the policySessionpolicyDigest </returns>
        [TpmCommand]
        public byte[] PolicyGetDigest(
            TpmHandle policySession)
        {
            var req = new Tpm2PolicyGetDigestRequest(policySession);
            var resp = new Tpm2PolicyGetDigestResponse();
            DispatchMethod(TpmCc.PolicyGetDigest, req, resp, 1, 0);
            return resp.policyDigest;
        }

        /// This command allows a policy to be bound to the TPMA_NV_WRITTEN attributes. This is a deferred assertion. Values are stored in the policy session context and checked when the policy is used for authorization.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "writtenSet"> YES if NV Index is required to have been written
        ///        NO if NV Index is required not to have been written </param>
        [TpmCommand]
        public void PolicyNvWritten(
            TpmHandle policySession,
            byte writtenSet)
        {
            var req = new Tpm2PolicyNvWrittenRequest(policySession, writtenSet);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyNvWritten, req, resp, 1, 0);
        }

        /// This command allows a policy to be bound to a specific creation template. This is most useful for an object creation command such as TPM2_Create(), TPM2_CreatePrimary(), or TPM2_CreateLoaded().
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "templateHash"> The digest to be added to the policy </param>
        [TpmCommand]
        public void PolicyTemplate(
            TpmHandle policySession,
            byte[] templateHash)
        {
            var req = new Tpm2PolicyTemplateRequest(policySession, templateHash);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyTemplate, req, resp, 1, 0);
        }

        /// This command provides a capability that is the equivalent of a revocable policy. With TPM2_PolicyAuthorize(), the authorization ticket never expires, so the authorization may not be withdrawn. With this command, the approved policy is kept in an NV Index location so that the policy may be changed as needed to render the old policy unusable.
        /// 
        /// <param name = "authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> The NV Index of the area to read
        ///        Auth Index: None </param>
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        [TpmCommand]
        public void PolicyAuthorizeNV(
            TpmHandle authHandle,
            TpmHandle nvIndex,
            TpmHandle policySession)
        {
            var req = new Tpm2PolicyAuthorizeNVRequest(authHandle, nvIndex, policySession);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyAuthorizeNV, req, resp, 3, 0);
        }

        /// This command is used to create a Primary Object under one of the Primary Seeds or a Temporary Object under TPM_RH_NULL. The command uses a TPM2B_PUBLIC as a template for the object to be created. The size of the unique field shall not be checked for consistency with the other object parameters. The command will create and load a Primary Object. The sensitive area is not returned.
        /// 
        /// <param name = "primaryHandle"> TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM+{PP}, or TPM_RH_NULL
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "inSensitive"> The sensitive data, see TPM 2.0 Part 1 Sensitive Values </param>
        /// <param name = "inPublic"> The public template </param>
        /// <param name = "outsideInfo"> Data that will be included in the creation data for this
        ///        object to provide permanent, verifiable linkage between this object and some object
        ///        owner data </param>
        /// <param name = "creationPCR"> PCR that will be used in creation data </param>
        /// <returns> handle - Handle of type TPM_HT_TRANSIENT for created Primary Object
        ///           outPublic - The public portion of the created object
        ///           creationData - Contains a TPMT_CREATION_DATA
        ///           creationHash - Digest of creationData using nameAlg of outPublic
        ///           creationTicket - Ticket used by TPM2_CertifyCreation() to validate that the
        ///                            creation data was produced by the TPM
        ///           name - The name of the created object </returns>
        [TpmCommand]
        public TpmHandle CreatePrimary(
            TpmHandle primaryHandle,
            SensitiveCreate inSensitive,
            TpmPublic inPublic,
            byte[] outsideInfo,
            PcrSelection[] creationPCR,
            out TpmPublic outPublic,
            out CreationData creationData,
            out byte[] creationHash,
            out TkCreation creationTicket)
        {
            var req = new Tpm2CreatePrimaryRequest(primaryHandle, inSensitive, inPublic, outsideInfo, creationPCR);
            var resp = new Tpm2CreatePrimaryResponse();
            DispatchMethod(TpmCc.CreatePrimary, req, resp, 1, 1);
            outPublic = resp.outPublic;
            creationData = resp.creationData;
            creationHash = resp.creationHash;
            creationTicket = resp.creationTicket;
            return resp.handle;
        }

        /// This command enables and disables use of a hierarchy and its associated NV storage. The command allows phEnable, phEnableNV, shEnable, and ehEnable to be changed when the proper authorization is provided.
        /// 
        /// <param name = "authHandle"> TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "enable"> The enable being modified
        ///        TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPM_RH_PLATFORM, or TPM_RH_PLATFORM_NV </param>
        /// <param name = "state"> YES if the enable should be SET, NO if the enable should be CLEAR </param>
        [TpmCommand]
        public void HierarchyControl(
            TpmHandle authHandle,
            TpmHandle enable,
            byte state)
        {
            var req = new Tpm2HierarchyControlRequest(authHandle, enable, state);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.HierarchyControl, req, resp, 1, 0);
        }

        /// This command allows setting of the authorization policy for the lockout (lockoutPolicy), the platform hierarchy (platformPolicy), the storage hierarchy (ownerPolicy), and the endorsement hierarchy (endorsementPolicy). On TPMs implementing Authenticated Countdown Timers (ACT), this command may also be used to set the authorization policy for an ACT.
        /// 
        /// <param name = "authHandle"> TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER, TPMI_RH_ACT
        ///        or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "authPolicy"> An authorization policy digest; may be the Empty Buffer
        ///        If hashAlg is TPM_ALG_NULL, then this shall be an Empty Buffer. </param>
        /// <param name = "hashAlg"> The hash algorithm to use for the policy
        ///        If the authPolicy is an Empty Buffer, then this field shall be TPM_ALG_NULL. </param>
        [TpmCommand]
        public void SetPrimaryPolicy(
            TpmHandle authHandle,
            byte[] authPolicy,
            TpmAlgId hashAlg)
        {
            var req = new Tpm2SetPrimaryPolicyRequest(authHandle, authPolicy, hashAlg);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.SetPrimaryPolicy, req, resp, 1, 0);
        }

        /// This replaces the current platform primary seed (PPS) with a value from the RNG and sets platformPolicy to the default initialization value (the Empty Buffer).
        /// 
        /// <param name = "authHandle"> TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        [TpmCommand]
        public void ChangePPS(
            TpmHandle authHandle)
        {
            var req = new Tpm2ChangePPSRequest(authHandle);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.ChangePPS, req, resp, 1, 0);
        }

        /// This replaces the current endorsement primary seed (EPS) with a value from the RNG and sets the Endorsement hierarchy controls to their default initialization values: ehEnable is SET, endorsementAuth and endorsementPolicy are both set to the Empty Buffer. It will flush any resident objects (transient or persistent) in the Endorsement hierarchy and not allow objects in the hierarchy associated with the previous EPS to be loaded.
        /// 
        /// <param name = "authHandle"> TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        [TpmCommand]
        public void ChangeEPS(
            TpmHandle authHandle)
        {
            var req = new Tpm2ChangeEPSRequest(authHandle);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.ChangeEPS, req, resp, 1, 0);
        }

        /// This command removes all TPM context associated with a specific Owner.
        /// 
        /// <param name = "authHandle"> TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        [TpmCommand]
        public void Clear(
            TpmHandle authHandle)
        {
            var req = new Tpm2ClearRequest(authHandle);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.Clear, req, resp, 1, 0);
        }

        /// TPM2_ClearControl() disables and enables the execution of TPM2_Clear().
        /// 
        /// <param name = "auth"> TPM_RH_LOCKOUT or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "disable"> YES if the disableOwnerClear flag is to be SET, NO if the flag is
        ///        to be CLEAR. </param>
        [TpmCommand]
        public void ClearControl(
            TpmHandle auth,
            byte disable)
        {
            var req = new Tpm2ClearControlRequest(auth, disable);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.ClearControl, req, resp, 1, 0);
        }

        /// This command allows the authorization secret for a hierarchy or lockout to be changed using the current authorization value as the command authorization.
        /// 
        /// <param name = "authHandle"> TPM_RH_LOCKOUT, TPM_RH_ENDORSEMENT, TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "newAuth"> New authorization value </param>
        [TpmCommand]
        public void HierarchyChangeAuth(
            TpmHandle authHandle,
            byte[] newAuth)
        {
            var req = new Tpm2HierarchyChangeAuthRequest(authHandle, newAuth);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.HierarchyChangeAuth, req, resp, 1, 0);
        }

        /// This command cancels the effect of a TPM lockout due to a number of successive authorization failures. If this command is properly authorized, the lockout counter is set to zero.
        /// 
        /// <param name = "lockHandle"> TPM_RH_LOCKOUT
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        [TpmCommand]
        public void DictionaryAttackLockReset(
            TpmHandle lockHandle)
        {
            var req = new Tpm2DictionaryAttackLockResetRequest(lockHandle);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.DictionaryAttackLockReset, req, resp, 1, 0);
        }

        /// This command changes the lockout parameters.
        /// 
        /// <param name = "lockHandle"> TPM_RH_LOCKOUT
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "newMaxTries"> Count of authorization failures before the lockout is imposed
        ///        </param>
        /// <param name = "newRecoveryTime"> Time in seconds before the authorization failure count is
        ///        automatically decremented
        ///        A value of zero indicates that DA protection is disabled. </param>
        /// <param name = "lockoutRecovery"> Time in seconds after a lockoutAuth failure before use of
        ///        lockoutAuth is allowed
        ///        A value of zero indicates that a reboot is required. </param>
        [TpmCommand]
        public void DictionaryAttackParameters(
            TpmHandle lockHandle,
            uint newMaxTries,
            uint newRecoveryTime,
            uint lockoutRecovery)
        {
            var req = new Tpm2DictionaryAttackParametersRequest(lockHandle, newMaxTries, newRecoveryTime, lockoutRecovery);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.DictionaryAttackParameters, req, resp, 1, 0);
        }

        /// This command is used to determine which commands require assertion of Physical Presence (PP) in addition to platformAuth/platformPolicy.
        /// 
        /// <param name = "auth"> TPM_RH_PLATFORM+PP
        ///        Auth Index: 1
        ///        Auth Role: USER + Physical Presence </param>
        /// <param name = "setList"> List of commands to be added to those that will require that
        ///        Physical Presence be asserted </param>
        /// <param name = "clearList"> List of commands that will no longer require that Physical
        ///        Presence be asserted </param>
        [TpmCommand]
        public void PpCommands(
            TpmHandle auth,
            TpmCc[] setList,
            TpmCc[] clearList)
        {
            var req = new Tpm2PpCommandsRequest(auth, setList, clearList);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PpCommands, req, resp, 1, 0);
        }

        /// This command allows the platform to change the set of algorithms that are used by the TPM. The algorithmSet setting is a vendor-dependent value.
        /// 
        /// <param name = "authHandle"> TPM_RH_PLATFORM
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "algorithmSet"> A TPM vendor-dependent value indicating the algorithm set
        ///        selection </param>
        [TpmCommand]
        public void SetAlgorithmSet(
            TpmHandle authHandle,
            uint algorithmSet)
        {
            var req = new Tpm2SetAlgorithmSetRequest(authHandle, algorithmSet);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.SetAlgorithmSet, req, resp, 1, 0);
        }

        /// This command uses platformPolicy and a TPM Vendor Authorization Key to authorize a Field Upgrade Manifest.
        /// 
        /// <param name = "authorization"> TPM_RH_PLATFORM+{PP}
        ///        Auth Index:1
        ///        Auth Role: ADMIN </param>
        /// <param name = "keyHandle"> Handle of a public area that contains the TPM Vendor
        ///        Authorization Key that will be used to validate manifestSignature
        ///        Auth Index: None </param>
        /// <param name = "fuDigest"> Digest of the first block in the field upgrade sequence </param>
        /// <param name = "manifestSignature"> Signature over fuDigest using the key associated with
        ///        keyHandle (not optional)
        ///        One of: SignatureRsassa, SignatureRsapss, SignatureEcdsa, SignatureEcdaa,
        ///        SignatureSm2, SignatureEcschnorr, TpmHash, SchemeHash, NullSignature. </param>
        [TpmCommand]
        public void FieldUpgradeStart(
            TpmHandle authorization,
            TpmHandle keyHandle,
            byte[] fuDigest,
            ISignatureUnion manifestSignature)
        {
            var req = new Tpm2FieldUpgradeStartRequest(authorization, keyHandle, fuDigest, manifestSignature);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.FieldUpgradeStart, req, resp, 2, 0);
        }

        /// This command will take the actual field upgrade image to be installed on the TPM. The exact format of fuData is vendor-specific. This command is only possible following a successful TPM2_FieldUpgradeStart(). If the TPM has not received a properly authorized TPM2_FieldUpgradeStart(), then the TPM shall return TPM_RC_FIELDUPGRADE.
        /// 
        /// <param name = "fuData"> Field upgrade image data </param>
        /// <returns> nextDigest - Tagged digest of the next block
        ///                        TPM_ALG_NULL if field update is complete
        ///           firstDigest - Tagged digest of the first block of the sequence </returns>
        [TpmCommand]
        public TpmHash FieldUpgradeData(
            byte[] fuData,
            out TpmHash firstDigest)
        {
            var req = new Tpm2FieldUpgradeDataRequest(fuData);
            var resp = new Tpm2FieldUpgradeDataResponse();
            DispatchMethod(TpmCc.FieldUpgradeData, req, resp, 0, 0);
            firstDigest = resp.firstDigest;
            return resp.nextDigest;
        }

        /// This command is used to read a copy of the current firmware installed in the TPM.
        /// 
        /// <param name = "sequenceNumber"> The number of previous calls to this command in this sequence
        ///        set to 0 on the first call </param>
        /// <returns> fuData - Field upgrade image data </returns>
        [TpmCommand]
        public byte[] FirmwareRead(
            uint sequenceNumber)
        {
            var req = new Tpm2FirmwareReadRequest(sequenceNumber);
            var resp = new Tpm2FirmwareReadResponse();
            DispatchMethod(TpmCc.FirmwareRead, req, resp, 0, 0);
            return resp.fuData;
        }

        /// This command saves a session context, object context, or sequence object context outside the TPM.
        /// 
        /// <param name = "saveHandle"> Handle of the resource to save
        ///        Auth Index: None </param>
        /// <returns> context - This structure is used in TPM2_ContextLoad() and TPM2_ContextSave().
        ///                     If the values of the TPMS_CONTEXT structure in TPM2_ContextLoad() are
        ///                     not the same as the values when the context was saved
        ///                     (TPM2_ContextSave()), then the TPM shall not load the context. </returns>
        [TpmCommand]
        public Context ContextSave(
            TpmHandle saveHandle)
        {
            var req = new Tpm2ContextSaveRequest(saveHandle);
            var resp = new Tpm2ContextSaveResponse();
            DispatchMethod(TpmCc.ContextSave, req, resp, 1, 0);
            return resp.context;
        }

        /// This command is used to reload a context that has been saved by TPM2_ContextSave().
        /// 
        /// <param name = "context"> The context blob </param>
        /// <returns> handle - The handle assigned to the resource after it has been successfully loaded </returns>
        [TpmCommand]
        public TpmHandle ContextLoad(
            Context context)
        {
            var req = new Tpm2ContextLoadRequest(context);
            var resp = new Tpm2ContextLoadResponse();
            DispatchMethod(TpmCc.ContextLoad, req, resp, 0, 1);
            return resp.handle;
        }

        /// This command causes all context associated with a loaded object, sequence object, or session to be removed from TPM memory.
        /// 
        /// <param name = "flushHandle"> The handle of the item to flush
        ///        NOTE This is a use of a handle as a parameter. </param>
        [TpmCommand]
        public void FlushContext(
            TpmHandle flushHandle)
        {
            var req = new Tpm2FlushContextRequest(flushHandle);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.FlushContext, req, resp, 0, 0);
        }

        /// This command allows certain Transient Objects to be made persistent or a persistent object to be evicted.
        /// 
        /// <param name = "auth"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "objectHandle"> The handle of a loaded object
        ///        Auth Index: None </param>
        /// <param name = "persistentHandle"> If objectHandle is a transient object handle, then this
        ///        is the persistent handle for the object
        ///        if objectHandle is a persistent object handle, then it shall be the same value as
        ///        persistentHandle </param>
        [TpmCommand]
        public void EvictControl(
            TpmHandle auth,
            TpmHandle objectHandle,
            TpmHandle persistentHandle)
        {
            var req = new Tpm2EvictControlRequest(auth, objectHandle, persistentHandle);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.EvictControl, req, resp, 2, 0);
        }

        /// This command reads the current TPMS_TIME_INFO structure that contains the current setting of Time, Clock, resetCount, and restartCount.
        /// 
        /// <returns> currentTime - This structure is used in, e.g., the TPM2_GetTime() attestation
        ///                         and TPM2_ReadClock(). </returns>
        [TpmCommand]
        public TimeInfo ReadClock(
        )
        {
            var req = new Tpm2ReadClockRequest();
            var resp = new Tpm2ReadClockResponse();
            DispatchMethod(TpmCc.ReadClock, req, resp, 0, 0);
            return resp.currentTime;
        }

        /// This command is used to advance the value of the TPMs Clock. The command will fail if newTime is less than the current value of Clock or if the new time is greater than FFFF00000000000016. If both of these checks succeed, Clock is set to newTime. If either of these checks fails, the TPM shall return TPM_RC_VALUE and make no change to Clock.
        /// 
        /// <param name = "auth"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "newTime"> New Clock setting in milliseconds </param>
        [TpmCommand]
        public void ClockSet(
            TpmHandle auth,
            ulong newTime)
        {
            var req = new Tpm2ClockSetRequest(auth, newTime);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.ClockSet, req, resp, 1, 0);
        }

        /// This command adjusts the rate of advance of Clock and Time to provide a better approximation to real time.
        /// 
        /// <param name = "auth"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Handle: 1
        ///        Auth Role: USER </param>
        /// <param name = "rateAdjust"> Adjustment to current Clock update rate </param>
        [TpmCommand]
        public void ClockRateAdjust(
            TpmHandle auth,
            ClockAdjust rateAdjust)
        {
            var req = new Tpm2ClockRateAdjustRequest(auth, rateAdjust);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.ClockRateAdjust, req, resp, 1, 0);
        }

        /// This command returns various information regarding the TPM and its current state.
        /// 
        /// <param name = "capability"> Group selection; determines the format of the response </param>
        /// <param name = "property"> Further definition of information </param>
        /// <param name = "propertyCount"> Number of properties of the indicated type to return </param>
        /// <returns> moreData - Flag to indicate if there are more values of this type
        ///           capabilityData - The capability data </returns>
        [TpmCommand]
        public byte GetCapability(
            Cap capability,
            uint property,
            uint propertyCount,
            out ICapabilitiesUnion capabilityData)
        {
            var req = new Tpm2GetCapabilityRequest(capability, property, propertyCount);
            var resp = new Tpm2GetCapabilityResponse();
            DispatchMethod(TpmCc.GetCapability, req, resp, 0, 0);
            capabilityData = resp.capabilityData;
            return resp.moreData;
        }

        /// This command is used to check to see if specific combinations of algorithm parameters are supported.
        /// 
        /// <param name = "parameters"> Algorithm parameters to be validated
        ///        One of: KeyedhashParms, SymcipherParms, RsaParms, EccParms, AsymParms. </param>
        [TpmCommand]
        public void TestParms(
            IPublicParmsUnion parameters)
        {
            var req = new Tpm2TestParmsRequest(parameters);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.TestParms, req, resp, 0, 0);
        }

        /// This command defines the attributes of an NV Index and causes the TPM to reserve space to hold the data associated with the NV Index. If a definition already exists at the NV Index, the TPM will return TPM_RC_NV_DEFINED.
        /// 
        /// <param name = "authHandle"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "auth"> The authorization value </param>
        /// <param name = "publicInfo"> The public parameters of the NV area </param>
        [TpmCommand]
        public void NvDefineSpace(
            TpmHandle authHandle,
            byte[] auth,
            NvPublic publicInfo)
        {
            var req = new Tpm2NvDefineSpaceRequest(authHandle, auth, publicInfo);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvDefineSpace, req, resp, 1, 0);
        }

        /// This command removes an Index from the TPM.
        /// 
        /// <param name = "authHandle"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> The NV Index to remove from NV space
        ///        Auth Index: None </param>
        [TpmCommand]
        public void NvUndefineSpace(
            TpmHandle authHandle,
            TpmHandle nvIndex)
        {
            var req = new Tpm2NvUndefineSpaceRequest(authHandle, nvIndex);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvUndefineSpace, req, resp, 2, 0);
        }

        /// This command allows removal of a platform-created NV Index that has TPMA_NV_POLICY_DELETE SET.
        /// 
        /// <param name = "nvIndex"> Index to be deleted
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "platform"> TPM_RH_PLATFORM + {PP}
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        [TpmCommand]
        public void NvUndefineSpaceSpecial(
            TpmHandle nvIndex,
            TpmHandle platform)
        {
            var req = new Tpm2NvUndefineSpaceSpecialRequest(nvIndex, platform);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvUndefineSpaceSpecial, req, resp, 2, 0);
        }

        /// This command is used to read the public area and Name of an NV Index. The public area of an Index is not privacy-sensitive and no authorization is required to read this data.
        /// 
        /// <param name = "nvIndex"> The NV Index
        ///        Auth Index: None </param>
        /// <returns> nvPublic - The public area of the NV Index
        ///           nvName - The Name of the nvIndex </returns>
        [TpmCommand]
        public NvPublic NvReadPublic(
            TpmHandle nvIndex,
            out byte[] nvName)
        {
            var req = new Tpm2NvReadPublicRequest(nvIndex);
            var resp = new Tpm2NvReadPublicResponse();
            DispatchMethod(TpmCc.NvReadPublic, req, resp, 1, 0);
            nvName = resp.nvName;
            return resp.nvPublic;
        }

        /// This command writes a value to an area in NV memory that was previously defined by TPM2_NV_DefineSpace().
        /// 
        /// <param name = "authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> The NV Index of the area to write
        ///        Auth Index: None </param>
        /// <param name = "data"> The data to write </param>
        /// <param name = "offset"> The octet offset into the NV Area </param>
        [TpmCommand]
        public void NvWrite(
            TpmHandle authHandle,
            TpmHandle nvIndex,
            byte[] data,
            ushort offset)
        {
            var req = new Tpm2NvWriteRequest(authHandle, nvIndex, data, offset);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvWrite, req, resp, 2, 0);
        }

        /// This command is used to increment the value in an NV Index that has the TPM_NT_COUNTER attribute. The data value of the NV Index is incremented by one.
        /// 
        /// <param name = "authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> The NV Index to increment
        ///        Auth Index: None </param>
        [TpmCommand]
        public void NvIncrement(
            TpmHandle authHandle,
            TpmHandle nvIndex)
        {
            var req = new Tpm2NvIncrementRequest(authHandle, nvIndex);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvIncrement, req, resp, 2, 0);
        }

        /// This command extends a value to an area in NV memory that was previously defined by TPM2_NV_DefineSpace.
        /// 
        /// <param name = "authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> The NV Index to extend
        ///        Auth Index: None </param>
        /// <param name = "data"> The data to extend </param>
        [TpmCommand]
        public void NvExtend(
            TpmHandle authHandle,
            TpmHandle nvIndex,
            byte[] data)
        {
            var req = new Tpm2NvExtendRequest(authHandle, nvIndex, data);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvExtend, req, resp, 2, 0);
        }

        /// This command is used to SET bits in an NV Index that was created as a bit field. Any number of bits from 0 to 64 may be SET. The contents of bits are ORed with the current contents of the NV Index.
        /// 
        /// <param name = "authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> NV Index of the area in which the bit is to be set
        ///        Auth Index: None </param>
        /// <param name = "bits"> The data to OR with the current contents </param>
        [TpmCommand]
        public void NvSetBits(
            TpmHandle authHandle,
            TpmHandle nvIndex,
            ulong bits)
        {
            var req = new Tpm2NvSetBitsRequest(authHandle, nvIndex, bits);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvSetBits, req, resp, 2, 0);
        }

        /// If the TPMA_NV_WRITEDEFINE or TPMA_NV_WRITE_STCLEAR attributes of an NV location are SET, then this command may be used to inhibit further writes of the NV Index.
        /// 
        /// <param name = "authHandle"> Handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> The NV Index of the area to lock
        ///        Auth Index: None </param>
        [TpmCommand]
        public void NvWriteLock(
            TpmHandle authHandle,
            TpmHandle nvIndex)
        {
            var req = new Tpm2NvWriteLockRequest(authHandle, nvIndex);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvWriteLock, req, resp, 2, 0);
        }

        /// The command will SET TPMA_NV_WRITELOCKED for all indexes that have their TPMA_NV_GLOBALLOCK attribute SET.
        /// 
        /// <param name = "authHandle"> TPM_RH_OWNER or TPM_RH_PLATFORM+{PP}
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        [TpmCommand]
        public void NvGlobalWriteLock(
            TpmHandle authHandle)
        {
            var req = new Tpm2NvGlobalWriteLockRequest(authHandle);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvGlobalWriteLock, req, resp, 1, 0);
        }

        /// This command reads a value from an area in NV memory previously defined by TPM2_NV_DefineSpace().
        /// 
        /// <param name = "authHandle"> The handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> The NV Index to be read
        ///        Auth Index: None </param>
        /// <param name = "size"> Number of octets to read </param>
        /// <param name = "offset"> Octet offset into the NV area
        ///        This value shall be less than or equal to the size of the nvIndex data. </param>
        /// <returns> data - The data read </returns>
        [TpmCommand]
        public byte[] NvRead(
            TpmHandle authHandle,
            TpmHandle nvIndex,
            ushort size,
            ushort offset)
        {
            var req = new Tpm2NvReadRequest(authHandle, nvIndex, size, offset);
            var resp = new Tpm2NvReadResponse();
            DispatchMethod(TpmCc.NvRead, req, resp, 2, 0);
            return resp.data;
        }

        /// If TPMA_NV_READ_STCLEAR is SET in an Index, then this command may be used to prevent further reads of the NV Index until the next TPM2_Startup (TPM_SU_CLEAR).
        /// 
        /// <param name = "authHandle"> The handle indicating the source of the authorization value
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> The NV Index to be locked
        ///        Auth Index: None </param>
        [TpmCommand]
        public void NvReadLock(
            TpmHandle authHandle,
            TpmHandle nvIndex)
        {
            var req = new Tpm2NvReadLockRequest(authHandle, nvIndex);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvReadLock, req, resp, 2, 0);
        }

        /// This command allows the authorization secret for an NV Index to be changed.
        /// 
        /// <param name = "nvIndex"> Handle of the entity
        ///        Auth Index: 1
        ///        Auth Role: ADMIN </param>
        /// <param name = "newAuth"> New authorization value </param>
        [TpmCommand]
        public void NvChangeAuth(
            TpmHandle nvIndex,
            byte[] newAuth)
        {
            var req = new Tpm2NvChangeAuthRequest(nvIndex, newAuth);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.NvChangeAuth, req, resp, 1, 0);
        }

        /// The purpose of this command is to certify the contents of an NV Index or portion of an NV Index.
        /// 
        /// <param name = "signHandle"> Handle of the key used to sign the attestation structure
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "authHandle"> Handle indicating the source of the authorization value for
        ///        the NV Index
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "nvIndex"> Index for the area to be certified
        ///        Auth Index: None </param>
        /// <param name = "qualifyingData"> User-provided qualifying data </param>
        /// <param name = "inScheme"> Signing scheme to use if the scheme for signHandle is TPM_ALG_NULL
        ///        One of: SigSchemeRsassa, SigSchemeRsapss, SigSchemeEcdsa, SigSchemeEcdaa,
        ///        SigSchemeSm2, SigSchemeEcschnorr, SchemeHmac, SchemeHash, NullSigScheme. </param>
        /// <param name = "size"> Number of octets to certify </param>
        /// <param name = "offset"> Octet offset into the NV area
        ///        This value shall be less than or equal to the size of the nvIndex data. </param>
        /// <returns> certifyInfo - The structure that was signed
        ///           signature - The asymmetric signature over certifyInfo using the key referenced
        ///                       by signHandle </returns>
        [TpmCommand]
        public Attest NvCertify(
            TpmHandle signHandle,
            TpmHandle authHandle,
            TpmHandle nvIndex,
            byte[] qualifyingData,
            ISigSchemeUnion inScheme,
            ushort size,
            ushort offset,
            out ISignatureUnion signature)
        {
            var req = new Tpm2NvCertifyRequest(signHandle, authHandle, nvIndex, qualifyingData, inScheme, size, offset);
            var resp = new Tpm2NvCertifyResponse();
            DispatchMethod(TpmCc.NvCertify, req, resp, 3, 0);
            signature = resp.signature;
            return resp.certifyInfo;
        }

        /// The purpose of this command is to obtain information about an Attached Component referenced by an AC handle.
        /// 
        /// <param name = "ac"> Handle indicating the Attached Component
        ///        Auth Index: None </param>
        /// <param name = "capability"> Starting info type </param>
        /// <param name = "count"> Maximum number of values to return </param>
        /// <returns> moreData - Flag to indicate whether there are more values
        ///           capabilitiesData - List of capabilities </returns>
        [TpmCommand]
        public byte AcGetCapability(
            TpmHandle ac,
            At capability,
            uint count,
            out AcOutput[] capabilitiesData)
        {
            var req = new Tpm2AcGetCapabilityRequest(ac, capability, count);
            var resp = new Tpm2AcGetCapabilityResponse();
            DispatchMethod(TpmCc.AcGetCapability, req, resp, 1, 0);
            capabilitiesData = resp.capabilitiesData;
            return resp.moreData;
        }

        /// The purpose of this command is to send (copy) a loaded object from the TPM to an Attached Component.
        /// 
        /// <param name = "sendObject"> Handle of the object being sent to ac
        ///        Auth Index: 1
        ///        Auth Role: DUP </param>
        /// <param name = "authHandle"> The handle indicating the source of the authorization value
        ///        Auth Index: 2
        ///        Auth Role: USER </param>
        /// <param name = "ac"> Handle indicating the Attached Component to which the object will be sent
        ///        Auth Index: None </param>
        /// <param name = "acDataIn"> Optional non sensitive information related to the object </param>
        /// <returns> acDataOut - May include AC specific data or information about an error. </returns>
        [TpmCommand]
        public AcOutput AcSend(
            TpmHandle sendObject,
            TpmHandle authHandle,
            TpmHandle ac,
            byte[] acDataIn)
        {
            var req = new Tpm2AcSendRequest(sendObject, authHandle, ac, acDataIn);
            var resp = new Tpm2AcSendResponse();
            DispatchMethod(TpmCc.AcSend, req, resp, 3, 0);
            return resp.acDataOut;
        }

        /// This command allows qualification of the sending (copying) of an Object to an Attached Component (AC). Qualification includes selection of the receiving AC and the method of authentication for the AC, and, in certain circumstances, the Object to be sent may be specified.
        /// 
        /// <param name = "policySession"> Handle for the policy session being extended
        ///        Auth Index: None </param>
        /// <param name = "objectName"> The Name of the Object to be sent </param>
        /// <param name = "authHandleName"> The Name associated with authHandle used in the
        ///        TPM2_AC_Send() command </param>
        /// <param name = "acName"> The Name of the Attached Component to which the Object will be
        ///        sent </param>
        /// <param name = "includeObject"> If SET, objectName will be included in the value in
        ///        policySessionpolicyDigest </param>
        [TpmCommand]
        public void PolicyAcSendSelect(
            TpmHandle policySession,
            byte[] objectName,
            byte[] authHandleName,
            byte[] acName,
            byte includeObject)
        {
            var req = new Tpm2PolicyAcSendSelectRequest(policySession, objectName, authHandleName, acName, includeObject);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.PolicyAcSendSelect, req, resp, 1, 0);
        }

        /// This command is used to set the time remaining before an Authenticated Countdown Timer (ACT) expires.
        /// 
        /// <param name = "actHandle"> Handle of the selected ACT
        ///        Auth Index: 1
        ///        Auth Role: USER </param>
        /// <param name = "startTimeout"> The start timeout value for the ACT in seconds </param>
        [TpmCommand]
        public void ActSetTimeout(
            TpmHandle actHandle,
            uint startTimeout)
        {
            var req = new Tpm2ActSetTimeoutRequest(actHandle, startTimeout);
            var resp = new EmptyResponse();
            DispatchMethod(TpmCc.ActSetTimeout, req, resp, 1, 0);
        }

        /// This is a placeholder to allow testing of the dispatch code.
        /// 
        /// <param name = "inputData"> Dummy data </param>
        /// <returns> outputData - Dummy data </returns>
        [TpmCommand]
        public byte[] VendorTcgTest(
            byte[] inputData)
        {
            var req = new Tpm2VendorTcgTestRequest(inputData);
            var resp = new Tpm2VendorTcgTestResponse();
            DispatchMethod(TpmCc.VendorTcgTest, req, resp, 0, 0);
            return resp.outputData;
        }

    }

    //-----------------------------------------------------------------------------
    //------------------------- COMMAND INFO -----------------------------------
    //-----------------------------------------------------------------------------
    public static class CommandInformation
    {
        public static CommandInfo[] Info = new CommandInfo[]
        {
            new CommandInfo(TpmCc.Startup, 0, 0, 0, typeof(Tpm2StartupRequest), typeof(EmptyResponse), 0, ""),
            new CommandInfo(TpmCc.Shutdown, 0, 0, 0, typeof(Tpm2ShutdownRequest), typeof(EmptyResponse), 0, ""),
            new CommandInfo(TpmCc.SelfTest, 0, 0, 0, typeof(Tpm2SelfTestRequest), typeof(EmptyResponse), 0, ""),
            new CommandInfo(TpmCc.IncrementalSelfTest, 0, 0, 0, typeof(Tpm2IncrementalSelfTestRequest), typeof(Tpm2IncrementalSelfTestResponse), 10, ""),
            new CommandInfo(TpmCc.GetTestResult, 0, 0, 0, typeof(Tpm2GetTestResultRequest), typeof(Tpm2GetTestResultResponse), 4, ""),
            new CommandInfo(TpmCc.StartAuthSession, 2, 1, 0, typeof(Tpm2StartAuthSessionRequest), typeof(Tpm2StartAuthSessionResponse), 5, "TPMI_DH_OBJECT TPMI_DH_ENTITY"),
            new CommandInfo(TpmCc.PolicyRestart, 1, 0, 0, typeof(Tpm2PolicyRestartRequest), typeof(EmptyResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.Create, 1, 0, 1, typeof(Tpm2CreateRequest), typeof(Tpm2CreateResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Load, 1, 1, 1, typeof(Tpm2LoadRequest), typeof(Tpm2LoadResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.LoadExternal, 0, 1, 0, typeof(Tpm2LoadExternalRequest), typeof(Tpm2LoadExternalResponse), 5, ""),
            new CommandInfo(TpmCc.ReadPublic, 1, 0, 0, typeof(Tpm2ReadPublicRequest), typeof(Tpm2ReadPublicResponse), 4, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.ActivateCredential, 2, 0, 2, typeof(Tpm2ActivateCredentialRequest), typeof(Tpm2ActivateCredentialResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.MakeCredential, 1, 0, 0, typeof(Tpm2MakeCredentialRequest), typeof(Tpm2MakeCredentialResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Unseal, 1, 0, 1, typeof(Tpm2UnsealRequest), typeof(Tpm2UnsealResponse), 4, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.ObjectChangeAuth, 2, 0, 1, typeof(Tpm2ObjectChangeAuthRequest), typeof(Tpm2ObjectChangeAuthResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.CreateLoaded, 1, 1, 1, typeof(Tpm2CreateLoadedRequest), typeof(Tpm2CreateLoadedResponse), 5, "TPMI_DH_PARENT"),
            new CommandInfo(TpmCc.Duplicate, 2, 0, 1, typeof(Tpm2DuplicateRequest), typeof(Tpm2DuplicateResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Rewrap, 2, 0, 1, typeof(Tpm2RewrapRequest), typeof(Tpm2RewrapResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Import, 1, 0, 1, typeof(Tpm2ImportRequest), typeof(Tpm2ImportResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.RsaEncrypt, 1, 0, 0, typeof(Tpm2RsaEncryptRequest), typeof(Tpm2RsaEncryptResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.RsaDecrypt, 1, 0, 1, typeof(Tpm2RsaDecryptRequest), typeof(Tpm2RsaDecryptResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EcdhKeyGen, 1, 0, 0, typeof(Tpm2EcdhKeyGenRequest), typeof(Tpm2EcdhKeyGenResponse), 4, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EcdhZGen, 1, 0, 1, typeof(Tpm2EcdhZGenRequest), typeof(Tpm2EcdhZGenResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EccParameters, 0, 0, 0, typeof(Tpm2EccParametersRequest), typeof(Tpm2EccParametersResponse), 0, ""),
            new CommandInfo(TpmCc.ZGen2Phase, 1, 0, 1, typeof(Tpm2ZGen2PhaseRequest), typeof(Tpm2ZGen2PhaseResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EccEncrypt, 1, 0, 0, typeof(Tpm2EccEncryptRequest), typeof(Tpm2EccEncryptResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EccDecrypt, 1, 0, 1, typeof(Tpm2EccDecryptRequest), typeof(Tpm2EccDecryptResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EncryptDecrypt, 1, 0, 1, typeof(Tpm2EncryptDecryptRequest), typeof(Tpm2EncryptDecryptResponse), 4, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EncryptDecrypt2, 1, 0, 1, typeof(Tpm2EncryptDecrypt2Request), typeof(Tpm2EncryptDecrypt2Response), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Hash, 0, 0, 0, typeof(Tpm2HashRequest), typeof(Tpm2HashResponse), 5, ""),
            new CommandInfo(TpmCc.Hmac, 1, 0, 1, typeof(Tpm2HmacRequest), typeof(Tpm2HmacResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Mac, 1, 0, 1, typeof(Tpm2MacRequest), typeof(Tpm2MacResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.GetRandom, 0, 0, 0, typeof(Tpm2GetRandomRequest), typeof(Tpm2GetRandomResponse), 4, ""),
            new CommandInfo(TpmCc.StirRandom, 0, 0, 0, typeof(Tpm2StirRandomRequest), typeof(EmptyResponse), 1, ""),
            new CommandInfo(TpmCc.HmacStart, 1, 1, 1, typeof(Tpm2HmacStartRequest), typeof(Tpm2HmacStartResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.MacStart, 1, 1, 1, typeof(Tpm2MacStartRequest), typeof(Tpm2MacStartResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.HashSequenceStart, 0, 1, 0, typeof(Tpm2HashSequenceStartRequest), typeof(Tpm2HashSequenceStartResponse), 1, ""),
            new CommandInfo(TpmCc.SequenceUpdate, 1, 0, 1, typeof(Tpm2SequenceUpdateRequest), typeof(EmptyResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.SequenceComplete, 1, 0, 1, typeof(Tpm2SequenceCompleteRequest), typeof(Tpm2SequenceCompleteResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EventSequenceComplete, 2, 0, 2, typeof(Tpm2EventSequenceCompleteRequest), typeof(Tpm2EventSequenceCompleteResponse), 9, "TPMI_DH_PCR TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Certify, 2, 0, 2, typeof(Tpm2CertifyRequest), typeof(Tpm2CertifyResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.CertifyCreation, 2, 0, 1, typeof(Tpm2CertifyCreationRequest), typeof(Tpm2CertifyCreationResponse), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Quote, 1, 0, 1, typeof(Tpm2QuoteRequest), typeof(Tpm2QuoteResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.GetSessionAuditDigest, 3, 0, 2, typeof(Tpm2GetSessionAuditDigestRequest), typeof(Tpm2GetSessionAuditDigestResponse), 5, "TPMI_RH_ENDORSEMENT TPMI_DH_OBJECT TPMI_SH_HMAC"),
            new CommandInfo(TpmCc.GetCommandAuditDigest, 2, 0, 2, typeof(Tpm2GetCommandAuditDigestRequest), typeof(Tpm2GetCommandAuditDigestResponse), 5, "TPMI_RH_ENDORSEMENT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.GetTime, 2, 0, 2, typeof(Tpm2GetTimeRequest), typeof(Tpm2GetTimeResponse), 5, "TPMI_RH_ENDORSEMENT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.CertifyX509, 2, 0, 2, typeof(Tpm2CertifyX509Request), typeof(Tpm2CertifyX509Response), 5, "TPMI_DH_OBJECT TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Commit, 1, 0, 1, typeof(Tpm2CommitRequest), typeof(Tpm2CommitResponse), 5, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.EcEphemeral, 0, 0, 0, typeof(Tpm2EcEphemeralRequest), typeof(Tpm2EcEphemeralResponse), 4, ""),
            new CommandInfo(TpmCc.VerifySignature, 1, 0, 0, typeof(Tpm2VerifySignatureRequest), typeof(Tpm2VerifySignatureResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.Sign, 1, 0, 1, typeof(Tpm2SignRequest), typeof(Tpm2SignResponse), 1, "TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.SetCommandCodeAuditStatus, 1, 0, 1, typeof(Tpm2SetCommandCodeAuditStatusRequest), typeof(EmptyResponse), 0, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.PcrExtend, 1, 0, 1, typeof(Tpm2PcrExtendRequest), typeof(EmptyResponse), 2, "TPMI_DH_PCR"),
            new CommandInfo(TpmCc.PcrEvent, 1, 0, 1, typeof(Tpm2PcrEventRequest), typeof(Tpm2PcrEventResponse), 9, "TPMI_DH_PCR"),
            new CommandInfo(TpmCc.PcrRead, 0, 0, 0, typeof(Tpm2PcrReadRequest), typeof(Tpm2PcrReadResponse), 2, ""),
            new CommandInfo(TpmCc.PcrAllocate, 1, 0, 1, typeof(Tpm2PcrAllocateRequest), typeof(Tpm2PcrAllocateResponse), 2, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.PcrSetAuthPolicy, 1, 0, 1, typeof(Tpm2PcrSetAuthPolicyRequest), typeof(EmptyResponse), 1, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.PcrSetAuthValue, 1, 0, 1, typeof(Tpm2PcrSetAuthValueRequest), typeof(EmptyResponse), 1, "TPMI_DH_PCR"),
            new CommandInfo(TpmCc.PcrReset, 1, 0, 1, typeof(Tpm2PcrResetRequest), typeof(EmptyResponse), 0, "TPMI_DH_PCR"),
            new CommandInfo(TpmCc.PolicySigned, 2, 0, 0, typeof(Tpm2PolicySignedRequest), typeof(Tpm2PolicySignedResponse), 5, "TPMI_DH_OBJECT TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicySecret, 2, 0, 1, typeof(Tpm2PolicySecretRequest), typeof(Tpm2PolicySecretResponse), 5, "TPMI_DH_ENTITY TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyTicket, 1, 0, 0, typeof(Tpm2PolicyTicketRequest), typeof(EmptyResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyOR, 1, 0, 0, typeof(Tpm2PolicyORRequest), typeof(EmptyResponse), 2, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyPCR, 1, 0, 0, typeof(Tpm2PolicyPCRRequest), typeof(EmptyResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyLocality, 1, 0, 0, typeof(Tpm2PolicyLocalityRequest), typeof(EmptyResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyNV, 3, 0, 1, typeof(Tpm2PolicyNVRequest), typeof(EmptyResponse), 1, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyCounterTimer, 1, 0, 0, typeof(Tpm2PolicyCounterTimerRequest), typeof(EmptyResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyCommandCode, 1, 0, 0, typeof(Tpm2PolicyCommandCodeRequest), typeof(EmptyResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyPhysicalPresence, 1, 0, 0, typeof(Tpm2PolicyPhysicalPresenceRequest), typeof(EmptyResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyCpHash, 1, 0, 0, typeof(Tpm2PolicyCpHashRequest), typeof(EmptyResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyNameHash, 1, 0, 0, typeof(Tpm2PolicyNameHashRequest), typeof(EmptyResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyDuplicationSelect, 1, 0, 0, typeof(Tpm2PolicyDuplicationSelectRequest), typeof(EmptyResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyAuthorize, 1, 0, 0, typeof(Tpm2PolicyAuthorizeRequest), typeof(EmptyResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyAuthValue, 1, 0, 0, typeof(Tpm2PolicyAuthValueRequest), typeof(EmptyResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyPassword, 1, 0, 0, typeof(Tpm2PolicyPasswordRequest), typeof(EmptyResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyGetDigest, 1, 0, 0, typeof(Tpm2PolicyGetDigestRequest), typeof(Tpm2PolicyGetDigestResponse), 4, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyNvWritten, 1, 0, 0, typeof(Tpm2PolicyNvWrittenRequest), typeof(EmptyResponse), 0, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyTemplate, 1, 0, 0, typeof(Tpm2PolicyTemplateRequest), typeof(EmptyResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.PolicyAuthorizeNV, 3, 0, 1, typeof(Tpm2PolicyAuthorizeNVRequest), typeof(EmptyResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.CreatePrimary, 1, 1, 1, typeof(Tpm2CreatePrimaryRequest), typeof(Tpm2CreatePrimaryResponse), 5, "TPMI_RH_HIERARCHY"),
            new CommandInfo(TpmCc.HierarchyControl, 1, 0, 1, typeof(Tpm2HierarchyControlRequest), typeof(EmptyResponse), 0, "TPMI_RH_HIERARCHY"),
            new CommandInfo(TpmCc.SetPrimaryPolicy, 1, 0, 1, typeof(Tpm2SetPrimaryPolicyRequest), typeof(EmptyResponse), 1, "TPMI_RH_HIERARCHY_POLICY"),
            new CommandInfo(TpmCc.ChangePPS, 1, 0, 1, typeof(Tpm2ChangePPSRequest), typeof(EmptyResponse), 0, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.ChangeEPS, 1, 0, 1, typeof(Tpm2ChangeEPSRequest), typeof(EmptyResponse), 0, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.Clear, 1, 0, 1, typeof(Tpm2ClearRequest), typeof(EmptyResponse), 0, "TPMI_RH_CLEAR"),
            new CommandInfo(TpmCc.ClearControl, 1, 0, 1, typeof(Tpm2ClearControlRequest), typeof(EmptyResponse), 0, "TPMI_RH_CLEAR"),
            new CommandInfo(TpmCc.HierarchyChangeAuth, 1, 0, 1, typeof(Tpm2HierarchyChangeAuthRequest), typeof(EmptyResponse), 1, "TPMI_RH_HIERARCHY_AUTH"),
            new CommandInfo(TpmCc.DictionaryAttackLockReset, 1, 0, 1, typeof(Tpm2DictionaryAttackLockResetRequest), typeof(EmptyResponse), 0, "TPMI_RH_LOCKOUT"),
            new CommandInfo(TpmCc.DictionaryAttackParameters, 1, 0, 1, typeof(Tpm2DictionaryAttackParametersRequest), typeof(EmptyResponse), 0, "TPMI_RH_LOCKOUT"),
            new CommandInfo(TpmCc.PpCommands, 1, 0, 1, typeof(Tpm2PpCommandsRequest), typeof(EmptyResponse), 2, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.SetAlgorithmSet, 1, 0, 1, typeof(Tpm2SetAlgorithmSetRequest), typeof(EmptyResponse), 0, "TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.FieldUpgradeStart, 2, 0, 1, typeof(Tpm2FieldUpgradeStartRequest), typeof(EmptyResponse), 1, "TPMI_RH_PLATFORM TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.FieldUpgradeData, 0, 0, 0, typeof(Tpm2FieldUpgradeDataRequest), typeof(Tpm2FieldUpgradeDataResponse), 1, ""),
            new CommandInfo(TpmCc.FirmwareRead, 0, 0, 0, typeof(Tpm2FirmwareReadRequest), typeof(Tpm2FirmwareReadResponse), 4, ""),
            new CommandInfo(TpmCc.ContextSave, 1, 0, 0, typeof(Tpm2ContextSaveRequest), typeof(Tpm2ContextSaveResponse), 0, "TPMI_DH_CONTEXT"),
            new CommandInfo(TpmCc.ContextLoad, 0, 1, 0, typeof(Tpm2ContextLoadRequest), typeof(Tpm2ContextLoadResponse), 0, ""),
            new CommandInfo(TpmCc.FlushContext, 0, 0, 0, typeof(Tpm2FlushContextRequest), typeof(EmptyResponse), 0, ""),
            new CommandInfo(TpmCc.EvictControl, 2, 0, 1, typeof(Tpm2EvictControlRequest), typeof(EmptyResponse), 0, "TPMI_RH_PROVISION TPMI_DH_OBJECT"),
            new CommandInfo(TpmCc.ReadClock, 0, 0, 0, typeof(Tpm2ReadClockRequest), typeof(Tpm2ReadClockResponse), 0, ""),
            new CommandInfo(TpmCc.ClockSet, 1, 0, 1, typeof(Tpm2ClockSetRequest), typeof(EmptyResponse), 0, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.ClockRateAdjust, 1, 0, 1, typeof(Tpm2ClockRateAdjustRequest), typeof(EmptyResponse), 0, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.GetCapability, 0, 0, 0, typeof(Tpm2GetCapabilityRequest), typeof(Tpm2GetCapabilityResponse), 0, ""),
            new CommandInfo(TpmCc.TestParms, 0, 0, 0, typeof(Tpm2TestParmsRequest), typeof(EmptyResponse), 0, ""),
            new CommandInfo(TpmCc.NvDefineSpace, 1, 0, 1, typeof(Tpm2NvDefineSpaceRequest), typeof(EmptyResponse), 1, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.NvUndefineSpace, 2, 0, 1, typeof(Tpm2NvUndefineSpaceRequest), typeof(EmptyResponse), 0, "TPMI_RH_PROVISION TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvUndefineSpaceSpecial, 2, 0, 2, typeof(Tpm2NvUndefineSpaceSpecialRequest), typeof(EmptyResponse), 0, "TPMI_RH_NV_INDEX TPMI_RH_PLATFORM"),
            new CommandInfo(TpmCc.NvReadPublic, 1, 0, 0, typeof(Tpm2NvReadPublicRequest), typeof(Tpm2NvReadPublicResponse), 4, "TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvWrite, 2, 0, 1, typeof(Tpm2NvWriteRequest), typeof(EmptyResponse), 1, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvIncrement, 2, 0, 1, typeof(Tpm2NvIncrementRequest), typeof(EmptyResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvExtend, 2, 0, 1, typeof(Tpm2NvExtendRequest), typeof(EmptyResponse), 1, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvSetBits, 2, 0, 1, typeof(Tpm2NvSetBitsRequest), typeof(EmptyResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvWriteLock, 2, 0, 1, typeof(Tpm2NvWriteLockRequest), typeof(EmptyResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvGlobalWriteLock, 1, 0, 1, typeof(Tpm2NvGlobalWriteLockRequest), typeof(EmptyResponse), 0, "TPMI_RH_PROVISION"),
            new CommandInfo(TpmCc.NvRead, 2, 0, 1, typeof(Tpm2NvReadRequest), typeof(Tpm2NvReadResponse), 4, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvReadLock, 2, 0, 1, typeof(Tpm2NvReadLockRequest), typeof(EmptyResponse), 0, "TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvChangeAuth, 1, 0, 1, typeof(Tpm2NvChangeAuthRequest), typeof(EmptyResponse), 1, "TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.NvCertify, 3, 0, 2, typeof(Tpm2NvCertifyRequest), typeof(Tpm2NvCertifyResponse), 5, "TPMI_DH_OBJECT TPMI_RH_NV_AUTH TPMI_RH_NV_INDEX"),
            new CommandInfo(TpmCc.AcGetCapability, 1, 0, 0, typeof(Tpm2AcGetCapabilityRequest), typeof(Tpm2AcGetCapabilityResponse), 0, "TPMI_RH_AC"),
            new CommandInfo(TpmCc.AcSend, 3, 0, 2, typeof(Tpm2AcSendRequest), typeof(Tpm2AcSendResponse), 1, "TPMI_DH_OBJECT TPMI_RH_NV_AUTH TPMI_RH_AC"),
            new CommandInfo(TpmCc.PolicyAcSendSelect, 1, 0, 0, typeof(Tpm2PolicyAcSendSelectRequest), typeof(EmptyResponse), 1, "TPMI_SH_POLICY"),
            new CommandInfo(TpmCc.ActSetTimeout, 1, 0, 1, typeof(Tpm2ActSetTimeoutRequest), typeof(EmptyResponse), 0, "TPMI_RH_ACT"),
            new CommandInfo(TpmCc.VendorTcgTest, 0, 0, 0, typeof(Tpm2VendorTcgTestRequest), typeof(Tpm2VendorTcgTestResponse), 5, "")};

    }

}

