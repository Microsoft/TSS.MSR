# TSS.MSR

## TPM 2.0 ecosystem

Trusted Platform Module (TPM) is a security component forming roots of trust in many PCs, servers and mobile devices. TPMs provide security functionality in the areas of:

* Cryptographic key generation, protection, management, and use
* Cryptographic device identity
* Secure logging and log-reporting, i.e., attestation
* Secure non-volatile storage
* Other functions including hashing, random number generation, a secure clock, etc.

Microsoft Windows operating system relies on the TPM for a number of its security functions.  Examples include BitLocker™ drive encryption, the Windows Virtual Smart Card feature, and the Platform Crypto Provider. Windows 10 [requires][Win10Tpm20Compliance] TPM 2.0 to be enabled in all its desktop editions (Home, Pro, Enterprise, and Education) and in server editions running guarded fabric.

Both Windows and Linux operating systems expose low-level programmatic access to their TPM 2.0 devices. On Windows TPM 2.0 is available via TPM Base Services (TBS) API, and on Linux - via /dev/tpm0 or /dev/tpmrm0 device file abstractions.  For the purposes of TPM 2.0 application development it is extremely convenient to use the [TPM 2.0 simulator] developed, open-sourced, and maintained on behalf of [TCG] by Microsoft.

## TPM Software Stack (TSS) implementations from Microsoft

All flavors of TPM 2.0 devices mentioned in the previous section communicate with applications via a rather complex binary interface defined by the TCG's [TPM 2.0 specification] wrapped into OS/simulator specific protocols. Writing code for manual creation of the TPM 2.0 command buffers, parsing response buffers, building HMAC and policy sessions, verifying audit data, etc., is extremely tedious, time consuming, and error prone task.

In order to facilitate the development of applications and services using TPM 2.0, Microsoft has developed a series of TSS implementations for different programming languages. All these implementations provide complete representation of the TPM 2.0 API (commands, data structures, enumerations, unions) using the means of the corresponding languages, and some of them - additional functionality that greatly simplifies communications with TPM 2.0. All TSS.MSR implementations provide abstraction for Windows/Linux/Simulator TPM 2.0 devices.

### [TSS.Net], [TSS.CPP] and [TSS.Rust]

TSS.Net, TSS.CPP and TSS.Rust are written in C#, C++ and Rust correspondingly, and are the richest TSS implementations in this collection. Besides complete abstraction of the TPM 2.0 interface, they implement additional functionality, such as:

* automatic handling of HMAC and policy sessions;
* expected audit, policy and cpHashes computation;
* object oriented representation of the policy commands;
* multiple helpers simplifying bridging between software crypto and TPM 2.0.

### [TSS.Java], [TSS.JS], and [TSS.Py]

These implementations are for Java, Node.JS, and Python environments, and at the moment they provide complete abstraction of the TPM 2.0 interface without most of the additional capabilities of TSS.Net or TSS.CPP. Node.JS version is written in the TypeScript language.

## [TSS Code Generator]

[TssCodeGen](TssCodeGen/README.md) is the tool that parses [TPM 2.0 specification] documents and updates the TSS implementations in this repo so that all TPM 2.0 entity and command definitions match the contents of the specification. The tool can be easily extended to support other programming languages, as all language specific processing is highly localized and most of the logic is language independent.


## [Tpm2Tester]

This is the TSS.Net based [framework][TestSubstrate] used by the official TPM 2.0 compliance test suite and TPM 2.0 components of the Microsoft [Windows HLK]. See its [README](Tpm2Tester/README.md) document for the details of the framework API and usage.

Along with it comes a [sample test suite][TestSuite] that not only demonstrates the framework usage, but also contains additional samples of the TPM 2.0 use cases, and is convenient for quick prototyping and testing of TPM 2.0 based scenarios.

## System Requirements

TSS.Net is a cross-platform .NET Standard library and requires Visual Studio 2017 or above to build it. It can target one of the following .NET framework flavors: .NET 4.7.2, .NET Core 2.1 (for both Windows and Linux), .NET Standard 2.0, and .NET UWP 10.0. You can download the latest versions of the .NET Framework [here](https://www.microsoft.com/net/download/windows).

TSS.Rust requires Rust 1.70 or above and uses Cargo as its build system.

TSS.Java uses Java SE 8 or above, TSS.JS requires Node.js 4.8.4 or higher, and TSS.Py supports Python 2.7 and 3.5+.

## Platform Crypto Provider Toolkit

The TSS.MSR project also provides the TPM Platform Crypto Provider Toolkit.  It contains sample code, utilities, and documentation for using TPM-related functionality on Windows 8.x/10 systems. It covers TPM-backed Crypto-Next-Gen (CNG) Platform Crypto Provider, and illustrates how attestation service providers can use the new Windows 8.x features. Both TPM 1.2 and TPM 2.0-based systems are supported.

## See Also

* Projects related to [Windows 10 IoT Core Security](https://github.com/ms-iot/security).
* Resource constrained TPM access lib for IoT, [Urchin](https://github.com/ms-iot/security/tree/master/Urchin).

## Questions and Feedback

We hope that the TSS.MSR project will prove useful to both software developers and researchers in their development of security solutions and applications for the Windows operating system.

Feel free to use Issues section of this Github repo for any quetsions or problems.

For private feedback please use tssdotnet@microsoft.com (for all managed languages) or tssdotcpp@microsoft.com mailing lists.


[TSS.Net]: ./TSS.NET
[TSS.CPP]: ./TSS.CPP
[TSS.Rust]: ./TSS.Rust
[TSS.Java]: ./TSS.Java
[TSS.JS]: ./TSS.JS
[TSS.Py]: ./TSS.Py
[TSS Code Generator]: ./TssCodeGen
[Tpm2Tester]: ./Tpm2Tester
[TestSubstrate]: ./Tpm2Tester/TestSubstrate
[TestSuite]: ./Tpm2Tester/TestSuite
[TCG]: http://trustedcomputinggroup.org
[TPM 2.0 simulator]: https://github.com/Microsoft/ms-tpm-20-ref/tree/master/TPMCmd/Simulator
[TPM 2.0 specification]: https://trustedcomputinggroup.org/resource/tpm-library-specification/
[Windows HLK]: https://docs.microsoft.com/en-us/windows-hardware/test/hlk/
[Win10Tpm20Compliance]: https://docs.microsoft.com/en-us/windows/security/hardware-protection/tpm/tpm-recommendations#tpm-20-compliance-for-windows-10
