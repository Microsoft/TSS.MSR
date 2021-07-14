/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using Tpm2Lib;
using Tpm2Tester;
using System.Diagnostics;
using System;

using Org.BouncyCastle.X509;
//using Org.BouncyCastle.Cms; // for DefaultDigestAlgorithmIdentifierFinder
// no DefaultSignatureAlgorithmIdentifierFinder

//
// This file contains examples of TPM 2.0 test routines
//
// Note that the names of the namespace and class(es) containing the tests can be any.
//

namespace Tpm2TestSuite
{
    partial class Tpm2Tests
    {

        void TestCertifyX509Impl(Tpm2 tpm, TestContext testCtx,
                                 TpmPublic subjectTemplate, TpmPublic sigKeyTemplate,
                                 PolicyTree policy, string testLabel)
        {
            var partialCert = X509Helpers.MakePartialCert(subjectTemplate);
            var partialCertBytes = partialCert.GetDerEncoded();

            // If you want to paste in your own hex put it here and s
            //var partialCertBytes = Globs.ByteArrayFromHex("01020304");

            // Certify RSA with RSA
            TpmPublic certifyingKeyPub, keyToBeCertifiedPub;
            TpmHandle hSigKey = Substrate.CreatePrimary(tpm, sigKeyTemplate, out certifyingKeyPub);
            TpmHandle hSubjectKey = Substrate.CreatePrimary(tpm, subjectTemplate, out keyToBeCertifiedPub);

            AuthSession sess = tpm.StartAuthSessionEx(TpmSe.Policy, TpmAlgId.Sha256);
            sess.RunPolicy(tpm, policy);

            ISignatureUnion sig;
            byte[] tbsHash;
            byte[] addedTo = tpm[sess].CertifyX509(hSubjectKey, hSigKey,
                                                   null, new NullSigScheme(), partialCertBytes,
                                                   out tbsHash, out sig);

            tpm.FlushContext(sess);
            tpm.FlushContext(hSubjectKey);

            var addedToCert = AddedToCertificate.FromDerEncoding(addedTo);
            X509Certificate returnedCert = X509Helpers.AssembleCertificate(partialCert, addedToCert,
                                    sig is SignatureRsa ? ((SignatureRsa)sig).GetTpmRepresentation()
                                                        : ((SignatureEcc)sig).GetTpmRepresentation());

            // Does the expected hash match the returned hash?
            var tbsBytes = returnedCert.GetTbsCertificate();
            var expectedTbsHash = TpmHash.FromData(TpmAlgId.Sha256, tbsBytes);
            Debug.Assert(Globs.ArraysAreEqual(expectedTbsHash.HashData, tbsHash));

            // Is the cert properly signed?
            if (TpmHelper.GetScheme(sigKeyTemplate).GetUnionSelector() != TpmAlgId.Rsapss)
            {
                // Software crypto layer does not support PSS
                bool sigOk = certifyingKeyPub.VerifySignatureOverHash(tbsHash, sig);
                if (sigKeyTemplate.type == TpmAlgId.Ecc)
                {
                    testCtx.Assert("Sign" + testLabel, sigOk);
                }
                else
                    testCtx.Assert("Sign" + testLabel, sigOk);
            }
            tpm.VerifySignature(hSigKey, tbsHash, sig);

            tpm.FlushContext(hSigKey);
        }

        [Test(Profile.TPM20, Privileges.StandardUser, Category.Misc, Special.None)]
        void TestCertifyX509(Tpm2 tpm, TestContext testCtx)
        {
            if (!TpmCfg.IsImplemented(TpmCc.CertifyX509))
            {
                Substrate.WriteToLog("TestCertifyX509 skipped", ConsoleColor.DarkCyan);
                return;
            }

            ObjectAttr attr = ObjectAttr.Restricted | ObjectAttr.Sign
                            | ObjectAttr.FixedParent | ObjectAttr.FixedTPM
                            | ObjectAttr.UserWithAuth | ObjectAttr.AdminWithPolicy
                            | ObjectAttr.SensitiveDataOrigin;

            var policy = new PolicyTree(TpmAlgId.Sha256);
            policy.SetPolicyRoot(new TpmPolicyCommand(TpmCc.CertifyX509));

            var keyTemplateRsa = new TpmPublic(TpmAlgId.Sha256, attr, policy.GetPolicyDigest(),
                    new RsaParms(new SymDefObject(), new SchemeRsassa(TpmAlgId.Sha256), 2048, 0),
                    new Tpm2bPublicKeyRsa()
            );
            var keyTemplateEcc = new TpmPublic(TpmAlgId.Sha256, attr, policy.GetPolicyDigest(),
                    new EccParms(new SymDefObject(), new SchemeEcdsa(TpmAlgId.Sha256),
                                 EccCurve.NistP256, new NullKdfScheme()),
                    new EccPoint()
            );
            var keyTemplatePss = new TpmPublic(TpmAlgId.Sha256, attr, policy.GetPolicyDigest(),
                    new RsaParms(new SymDefObject(), new SchemeRsapss(TpmAlgId.Sha256), 2048, 0),
                    new Tpm2bPublicKeyRsa()
            );
            TestCertifyX509Impl(tpm, testCtx, keyTemplateRsa, keyTemplateRsa, policy, "RsaWithRsa.1");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateRsa, keyTemplateEcc, policy, "RsaWithEcc.1");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateEcc, keyTemplateEcc, policy, "EccWithEcc.1");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateEcc, keyTemplateRsa, policy, "EccWithRsa.1");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateRsa, keyTemplatePss, policy, "RsaWithPss.1");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateEcc, keyTemplatePss, policy, "EccWithPss.1");

            attr &= ~(ObjectAttr.Restricted | ObjectAttr.FixedParent | ObjectAttr.FixedTPM);
            keyTemplateRsa.objectAttributes = attr;
            keyTemplateEcc.objectAttributes = attr;
            keyTemplatePss.objectAttributes = attr;
            TestCertifyX509Impl(tpm, testCtx, keyTemplateRsa, keyTemplateRsa, policy, "RsaWithRsa.2");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateRsa, keyTemplateEcc, policy, "RsaWithEcc.2");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateEcc, keyTemplateEcc, policy, "EccWithEcc.2");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateEcc, keyTemplateRsa, policy, "EccWithRsa.2");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateRsa, keyTemplatePss, policy, "RsaWithPss.2");
            TestCertifyX509Impl(tpm, testCtx, keyTemplateEcc, keyTemplatePss, policy, "EccWithPss.2");
        } // TestCertifyX509
    }
}
