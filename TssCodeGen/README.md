# **TSS Code Generator (*TssCodeGen*)**


# Purpose

This is the tool that automatically (re)generates the interface part of the TPM Software Stack (TSS) implementations for all supported programming languages/frameworks ([.Net][TSS.Net], [C++][TSS.CPP], [Rust][TSS.Rust], [Java][TSS.Java], [Node.js][TSS.JS], [Python][TSS.Py]) based on the TCG's [TPM 2.0 specification] documents.

Auto-generated code includes the following components of the TPM 2.0 interface:
* constants (represented as enums);
* flags (represented as enums);
* bitfields (represented as enums);
* data structures (represented as classes) with their marshaling code (or metadata in the case of .Net);
* unions (represented as interfaces or abstract classes) and their factory (used when unmarshaling);
* command prototypes (represented as methods of the main `Tpm2` class) and classes encapsulating sets of input parameters (used only internally by the TSS implementations) and output values (when a command has multiple response parameters).


# Usage

When built and run in-place from a Visual Studio with no command line options provided, the tool will pick the TPM 2.0 specification data from the [TpmSpec](./TpmSpec) directory, and update TSS for all supported languages in this repo clone. 

If the tool is used from a directory different from the one used by the Visual Studio build, you may need to use command line options to specify the location of the TPM 2.0 specification documents (`-spec`) and the target TSS implementations (`-dest`). You can also specify a subset of target TSS programming languages to update using a combination of options `-dotNet`, `-cpp`, `-java`, `-node`, `-py`, `-rust`.

Run the tool with the `-help` option to get more detailed information about its command line options.


# Architecture

This section gives a high level overview of the *TssCodeGen* architecture. 

Originally created as a .Net-only tool *TssCodeGen* gradually evolved to support TSS written in other programming languages (first C++ was added, then Java, then Node.js and Python). The primary purpose of its current design is maximal unification across different programming languages both on the side of the tool and on the side of the resulting TSS, so that adding new languages or adopting changes in the TPM 2.0 specification requires only minimal modifications in the tool code base.


## *High level workflow*

The tool works in three phases:

1) Table extraction phase.

   If the the specifications folder (`-spec` command line option) contains an XML file `RawTables.xml` and no `-extract` command line option was used, then this step is bypassed.
   
   Otherwise, the [TableExtractor](./src/TableExtractor.cs) class:
   * Parses the TPM 2.0 spec documents (*Part 2* and *Part 3* of the TPM 2.0 Specification, *TCG Algorithm Registry*, and *TPM 2.0 Vendor-Specific*).
   * Extracts tables with the definitions of all the required TPM 2.0 entities (data structures, unions, constants, attributes, commands, algorithm descriptions) together with the corresponding descriptions or surrounding text fragments to be used as comments.
   * Saves extracted data in the XML file `RawTables.xml` located in the same specifications directory.

   Note that table extraction logic uses Microsoft Office interop API that is very slow, this is why it is recommended to keep the intermediate `RawTables.xml` file with extracted data until the specification documents change. 

2) Type extraction phase.

   The tool reads the `RawTables.xml` file, and uses the [TypeExtractor](./src/TypeExtractor.cs) class to parse the TPM 2.0 specification tables and create an internal abstract syntax tree (AST) representing all TPM 2.0 entities.
   
   During the extraction process, the tool:
   
   * Transcribes data types defined in the TPM 2.0 specification expanding *agile algorithm notation* (`!ALG.<`*`AlgSpec`*`>`) based on the *TCG Algorithm Registry* document contents.
   * Creates artificial data structures representing TPM 2.0 commands.
   * Creates `NULL-data structures` (corresponding to the universal `ALG_ID_NULL` selector).
   
   At the postprocessing step the type extractor performs the following transformations:

   * Adds fundamental integer and Boolean data type definitions;
   * Adds a few custom data structures making TSS interface more convenient;
   * For data structures with members of the types belonging to the following TPM 2.0 type families:

     - sized arrays and data structures (`TPM2B_`)
     - lists (`TPML_`)
     - typedefs (`TPMI_`)

     flattens them by replacing original types directly with their innermost array/struct/value types.

3) Code generation phase.
   
   A specialized class for each of the target program language ([CGenDotNet](./src/CGenDotNet.cs), [CGenCpp](./src/CGenCpp.cs), [CGenRust](./src/CGenRust.cs), [CGenJava](./src/CGenJava.cs), [CGenNode](./src/CGenNode.cs), [CGenPy](./src/CGenPy.cs)) produces the code based on the AST representation.


## *Abstract Syntax Tree (AST) classes*

Classes representing AST elements are defined in the [TpmTypes.cs](./src/TpmTypes.cs) source file. There are three main groups of them:

* Data types: `TpmValueType`, `TpmEnum`, `TpmBitfield`, `TpmStruct`, `TpmUnion`, `TpmTypedef`. They are all derived from the `TpmType` base class.
* Fields of different kinds: `BitfieldElement`, `StructField`, `UnionMember`. They are all derived from the `TpmField` base class. 
* Two classes representing constants and flags: `TpmConstExpr` and `TpmNamedConstant`. Constants defined in the TPM 2.0 specification as expressions (usually involving other constants) are evaluated using helper classes from the [Expression.cs](./src/Expression.cs) source file.

Note that there is no special AST class type for TPM commands. This is because a command is represented by a pair of `TpmStruct` classes comprising sets of its input and response parameters.

Some instances of the `StructField` classes reference metadata of the `Domain` type (defined together with other pertaining types in the [Domain.cs](./src/Domain.cs) source file). They define possible ranges or sets of values for for the corersponding data structure fields. Only [TSS.Net] has this information transferred to its code - it was used for validation purposes during early stages of the TPM 2.0 development, and is currently used by the [TPM 2.0 testing framework](../Tpm2Tester/TestSubstrate) for deep-penetration fuzzing purposes. Code generators for other languages ignore these metadata. 


## *Mapping TPM 2.0 specification syntax and naming conventions to the target languages*

Even though [TPM 2.0 specification] defines TPM 2.0 entities and commands by means of programming lnguage neutral MS Word tables, the overall design of the TPM 2.0 API surface implies a C implementation (after all, C is the language of the [TPM 2.0 reference implementation]). The naming conventions used by the specification are ALL_CAPS for most of the TPM 2.0 type and constant names, mixed ALL_CAPS/CamelStyle for commands, and camelStyle for attribute amd field names. It also uses a set of eight different `TPMX_` prefixes to mark different kinds of data types, and multiple prefixes to form logical groups of constants. Such, somewhat eclectic (partly because of the TPM 1.2 legacy), naming conventions are quite different from those used by the majority of modern programming language communities. This was why for the [TSS.Net] (that was the first TSS ever built for TPM 2.0) it was decided to apply blanket name translation to the CamelCase style commonly used by .Net developers. However, for language bindings added later the name translation is almost completely avoided to simplify both the TPM 2.0 specification usage by developers and porting abundant TPM 2.0 code written in C to the new TSS languages. 

To simplify adding new programming languages and make the tool code more lucid the majority of target language specific transformations are encapsulated in the [TargetLang] and [TpmTypeTranslations](./src/TpmTranslations.cs) classes. Class [TargetLang], in particular, abstracts the syntax and representation of fundamental types, member references, conditions, etc.

Except for TSS.Net, names used by the TPM 2.0 specification are mostly left intact, except that the `TPM2_` prefix is dropped from the command names when they are made methods of the `Tpm2` class, and prefixes of constants and attributes are separated and serve as the containing *enum* names. C++ variant uses different capitalization for some method names.

Naming conventions used by [TSS.Net] are different due to legacy reasons (a large body of existing code ). It converts ALL_CAPS style of the TPM 2.0 specification to the CamelCase traditional for .Net, and aggressively eliminates various `TPMX_` prefixes by either dropping them completely or converting them into enum names or type name suffixes. TSS.Net also relies heavily on the reflection capabilities absent in most other languages, so instead of producing marshaling and serialization code the .Net code generator only adds  metadata to the classes and data fields. (Reflection is also used as the foundation for the advanced TPM 2.0 testing infrastructure built on top of TSS.Net.)

Type extractor generates `TpmEnum` AST classes for the constants defined in the TPM 2.0 specification (often as values of a `TPMI_` typedef type). TPM 2.0 attributes are represented by the `TpmBitfield` AST classes with a collection of related `BitfieldElement` instances. Both `TpmEnum` and `TpmBitfield` are mapped to *enums* in the target languages. In C++ and Java versions enums are implemented using classes to preserve common usage model across different languages (the design of the enums support in Java is particularly weird because of complete absence of user defined type conversions in the language).

TPM 2.0 specification profusely uses C typedefs to specify different restrictions on different usages of values of the same underlying type. Since such bounds checks are meaningless on the TSS side, `TpmTypedef` AST classes are always represented with their underlying types: fundamental integral/Boolean, enum or class.

TPM 2.0 specification also intensively uses tagged unions. Since none of the managed languages support unions in any meaningful way (e.g. .Net CLR allows defining unions of references, but not of data structures), a TPM 2.0 union represented by an instance of the `TpmUnion` AST class is mapped to an *interface* (or an abstract base class) with a single `GetUnionSelector()` method. Union members represented by a collection of the `UnionMember` AST classes become data structures that implement the corresponding union interface, with the `GetUnionSelector()` method returning the tag value (usually an algorithm ID) that specifies which union member is currently "active". E.g., the following C union:

```C
union TPMU_SCHEME_KEYEDHASH {
    TPMS_SCHEME_HMAC hmac;
    TPMS_SCHEME_XOR xor;
    TPMS_NULL_SCHEME_KEYEDHASH null;
};
```

is represented in the following manner:

```JS
interface TPMU_SCHEME_KEYEDHASH
{
    GetUnionSelector(): TPM_ALG_ID;
}

class TPMS_SCHEME_HMAC extends TpmStructure implements TPMU_SCHEME_KEYEDHASH { ... }
class TPMS_SCHEME_XOR extends TpmStructure implements TPMU_SCHEME_KEYEDHASH { ... }
class TPMS_NULL_SCHEME_KEYEDHASH extends TpmStructure implements TPMU_SCHEME_KEYEDHASH, TPMU_SIG_SCHEME, ... { ... }
```

Note that even though C++ can easily represent unions using original C notation, `TSS.CPP` nevertheless uses the same interface based approach for the sake of uniformity across all the supported languages.


## *Code generation phase*

Auto-generated code for all TSS language bindings uses mostly the same unified architecture and naming conventions (with .Net being more different than the others). Correspondingly, code generation workflows for different languages are very similar, too. 

Code generator classes for all languages inherit from the same base class [CodeGenBase](./src/CodeGenBase.cs) that implements the following common functionality:

* Output formatting infrastructure: a family of `Write()`, `TabIn()`, and `TabOut()` methods;
* Commentary formatting using the current target language specific annotation conventions: a family of `WriteComment()` methods, `GetParamComment()`, and `GetReturnComment()`;
* Snippets handling: `LoadSnips()` and `InsertSnip()`;
* TPM bitfields processing: `GetBifieldElements()`;
* Marshaling code generation: `GetToTpmFieldsMarshalOps()` and `GetFromTpmFieldsMarshalOps()`.

.Net variant requires sweeping name conversion, while other languages also apply some limited name transformations. On the other hand, expressions that specify values of many constants also need translation to the target language syntax. To avoid repeated conversions during code generation and to unify the code of the code generators across different target languages, AST classes use a pair of members to represent each type name, struct/union member name, or arithmetic expression (e.g. `SpecName` and `Name`, or `SpecValue` and `Value`). The first member of each pair keeps the original name used by the TPM 2.0 specifiaction. It is set during the type extraction phase and never changes. The second member of the pair is updated by `TargetLang.SetTargetLang()` as described below.

To generate code for the given target language the tool:

* Invokes the `TargetLang.SetTargetLang()` method that:
  - Properly updates global language dependent settings.
  - Walks the whole AST and updates the target language dependent members (type/field names and expressions) with the results of the original name or expression translation to the target language syntax/conventions.
* Instantiates the corresponding code generator class.
* invokes its overridden `CodeGenBase.Generate()` method that produces the actual code.

The `CodeGenBase.Generate()` method implements the same generic workflow for all target languages. It walks the AST class several times (except for Java that only needs two passes, as it stores each definition in a separate source file) in order to generate the TPM entities in the following order:

* Enum definitions from the `TpmEnum` instances.
* Enum definitions from the `TpmBitfield` and realted `BitfieldElement` instances.
* TPM union interfaces definitions from the `TpmUnion` instances.
* TPM union factory implementation from the collection of the `UnionMember` and realted `UnionMember` instances.
  - Union factory is used to instantiate the correct union member (class implementing the given union interface) based on the union type and selector (tag) value. This is necessary while unmarshaling TPM structures with fields of a union type.
* Class definitions from all `TpmStruct` instances. This includes field definitions, constructors, marshaling methods (except for [TSS.Net]), and on case-by-case basis additional interface methods.
  - The set of automatically generated methods for a few TPM 2.0 structures is extended with custom additions via .snips files ([C++](../TSS.CPP/Src/TpmExtensions.cpp.snips), [Rust](../TSS.Rust/src/tpm_extensions.rs.snips), [Java](../TSS.Java/src/TpmExtensions.java.snips), [Node.js](../TSS.JS/src/TpmExtensions.js.snips), [Python](../TSS.Py/src/TpmExtensions.py.snips)). Snippet files contain fragments of the code that are appended to the auto-generated classes (class declarations in the case of C++) without any additional translations. Note that [TSS.Net] does not use this mechanism, as it custmizes its auto-generated classes using *partial classes* syntax.
* TPM command definitions from the select `TpmStruct` instances representing command and response parameters.

.Net code generator additionally creates a static class with marshaling metadata `CommandInformation`, and for C++ two maps for enum-to-string and string-to-enum conversions (`Enum2StrMap` and `Str2EnumMap`) are generated.

Generated code is accumulated in an internal buffer and then is written out to a destination source file. The mapping of the produced definitions to the source files is different for different target languages (mostly for historical reasons, and in the case of Java it is the language requirement):

* [TSS.JS] and [TSS.Py] use identical source files organization. They keep all TPM data types and the union factory definitions in one source ([TpmTypes.ts](../TSS.JS/src/TpmTypes.ts) and [TpmTypes.py](../TSS.Py/src/TpmTypes.py)), and TPM commands in the other ([Tpm.ts](../TSS.JS/src/Tpm.ts) and [Tpm.py](../TSS.Py/src/Tpm.py)).
* [TSS.CPP] follows [TSS.JS]/[TSS.Py] in splitting the TPM data type and command *declarations* between two header files ([TpmTypes.h](../TSS.CPP/include/TpmTypes.h) and [Tpm2.h](../TSS.CPP/include/Tpm2.h)). Yet it additionally creates the third source file for the *definitions* of marshaling methods, union factory and enum names conversion maps ([TpmTypes.cpp](../TSS.CPP/Src/TpmTypes.cpp)).
  - Note also that in contrast to other languages the C++ output sources are not completely (re)created by the code generator, but are rather *updated* by means of replacing their sections marked by the `<<AUTOGEN_BEGIN>>` comment with the new auto-generated code.
* [TSS.Net] places all auto-generated definitions in the single source file ([X_TpmDefs.cs](../TSS.NET/TSS.NET/X_TpmDefs.cs)).
* [TSS.Rust] keeps all TPM data types in [tpm_types.rs](../TSS.Rust/src/tpm_types.rs) and TPM command definitions in [tpm2.rs](../TSS.Rust/src/tpm2.rs), similar to [TSS.JS]/[TSS.Py]. Rust unions are represented as enums with tuple variants.
* Java keeps each definition in its own [separate source file](../TSS.Java/src/tss/tpm), plus [Tpm.java](../TSS.Java/src/tss/Tpm.java) for TPM command definitions.



[TSS.Net]: ../TSS.NET
[TSS.CPP]: ../TSS.CPP
[TSS.Rust]: ../TSS.Rust
[TSS.Java]: ../TSS.Java
[TSS.JS]: ../TSS.JS
[TSS.Py]: ../TSS.Py
[TargetLang]: ./src/TargetLang.cs
[TPM 2.0 specification]: https://trustedcomputinggroup.org/resource/tpm-library-specification/
[TPM 2.0 reference implementation]: https://github.com/Microsoft/ms-tpm-20-ref
