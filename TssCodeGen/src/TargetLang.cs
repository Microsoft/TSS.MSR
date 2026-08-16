/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;


namespace CodeGen
{
    /// <summary> Supported target programming languages </summary>
    public enum Lang
    {
        None = 0,
        DotNet,
        CPP,
        Java,
        JS,
        Py,
        Rust
    }

    /// <summary> Handles language specific syntax of the generated code and translations of names, types 
    /// and expressions from their original form in the TPM 2.0 spec to the current target language.
    /// </summary>
    /// <remarks> Other places dealing with language specific syntax can be identified by looking up 
    /// the 'TargetLang.' qualifier, as they are all conditioned on the one of the properties specifying 
    /// the current target language: Curent, DotNet, Cpp, Java, Node, Py. </remarks>
    public static partial class TargetLang
    {
        /// <summary> Maps each target language to its code generator class </summary>
        static Dictionary<Lang, Type> CodeGenerators = new Dictionary<Lang, Type>
        {
            { Lang.CPP,  typeof(CGenCpp) },
            { Lang.Java, typeof(CGenJava) },
            { Lang.JS,   typeof(CGenNode) },
            { Lang.Py,   typeof(CGenPy) },
            { Lang.Rust, typeof(CGenRust) }
        };
        
        static Lang _curLang = Lang.None;

        // "this" qualifier together with the dereferencing operator
        // (as is used to access other class members in member functions)
        static string _thisQual;

        static string _null;
        static string _new;
        static string _quote;
        static string _digestSize;

        static HashSet<TpmEnum> GeneratedEnums;

        struct ElementaryType
        {
            public int Size;
            public string[] Names;

            public ElementaryType(int size, params string[] nameList)
            {
                Size = size;
                Names = nameList;
            }
        }

        static Dictionary<string, ElementaryType> ElementaryTypes = new Dictionary<string, ElementaryType> {
                //                                 .Net      C++       Java     TypeScript  Python    Rust
                { "BYTE",   new ElementaryType(1, "byte",   "BYTE",   "byte",    "number",  "int",    "u8")},
                { "UINT8",  new ElementaryType(1, "byte",   "UINT8",  "byte",    "number",  "int",    "u8")},
                { "INT8",   new ElementaryType(1, "sbyte",  "INT8",   "byte",    "number",  "int",    "i8")},
                { "UINT16", new ElementaryType(2, "ushort", "UINT16", "int",     "number",  "int",    "u16")},
                { "INT16",  new ElementaryType(2, "short",  "INT16",  "int",     "number",  "int",    "i16")},
                { "UINT32", new ElementaryType(4, "uint",   "UINT32", "int",     "number",  "int",    "u32")},
                { "INT32",  new ElementaryType(4, "int",    "INT32",  "int",     "number",  "int",    "i32")},
                { "UINT64", new ElementaryType(8, "ulong",  "UINT64", "long",    "number",  "int",    "u64")},
                { "INT64",  new ElementaryType(8, "long",   "INT64",  "long",    "number",  "int",    "i64")},
                { "BOOL",   new ElementaryType(1, "bool",   "BOOL",   "boolean", "boolean", "bool",   "bool")}
        };

        static HashSet<string> ElementaryTypesCurrentLang => 
            ElementaryTypes.Select(et => et.Value.Names[(int)Current - 1]).ToHashSet();

        public static IEnumerable<TpmValueType> GetElementaryTypes()
            => ElementaryTypes.Select(et => new TpmValueType(et.Key, et.Value.Size));
        
        public static string NameFor(string typeName) => ElementaryTypes[typeName].Names[(int)Current - 1];

        public static Lang Current => _curLang;

        public static bool DotNet => _curLang == Lang.DotNet;
        public static bool Cpp => _curLang == Lang.CPP;
        public static bool Java => _curLang == Lang.Java;
        public static bool Node => _curLang == Lang.JS;
        public static bool Py => _curLang == Lang.Py;
        public static bool Rust => _curLang == Lang.Rust;

        public static bool IsOneOf(params Lang[] toCompare) => Current.IsOneOf(toCompare);

        // Standalone "this" reference (as used, e.g. to pass it as a function argument)
        public static string This => (Py || Rust) ? "self" : "this";
        public static string ThisMember => _thisQual;
        public static string ClassMember => (Cpp || Rust) ? "::" : ".";

        public static string AsReference(bool isConst) => Rust ? (isConst ? ".as_ref()" : ".as_mut()") : "";
        // In Rust a union field is an Option<>, and an absent value must be reported as an error
        // rather than panicking. All the marshaling methods return Result<(), TpmError>.
        public static string UnionMember(bool isConst) => Rust ? AsReference(isConst) + ".ok_or(TpmError::InvalidUnion)?." : Member;
        public static string Member => Cpp ? "->" : ".";
        public static string Null => _null;
        public static string Neg => Py ? "not " : "!";
        public static string LineComment => Py ? "#" : "//";

        public static string If(string cond) => Py ? $"if {cond}:" : $"if ({cond})";
        
        public static string IfNull(string obj) => TargetLang.If(Rust ? $"{obj}.is_none()" : $"{obj} == {TargetLang.Null}");

        public static string Quote(string str) => _quote + str + _quote;

        public static string TypeInfo(string typeName) => typeName + (Java ? ".class" : Rust ? "::type_id()" : "");

        public static string LocalVar(string varName, string typeName)
            => Py ? varName : Node ? $"let {varName}: {typeName}" : Rust ? $"let r#{varName}: {typeName}" : $"{typeName} {varName}";

        public static string NewObject(string type) => Rust ? $"{type}::default()" : $"{_new}{type}()";

        public static string DigestSize(string hashAlgField) => $"{_digestSize}({_thisQual}{hashAlgField})";

        public static string GetUnionValue(int sizeInBytes) => Rust ? GetEnumValue("", $"u{sizeInBytes}") : "";

        public static string GetEnumValue(string enumValue, string enumTypename, int valueSizeInBytes = 4) {
            if (!Rust) return enumValue;
            
            // In Rust, if the enum type is a primitive type (such as i32), we need to get the unsigned version of it
            // (e.g. u32) using the "as" operator, as into() isn't implemented for such conversions
            if (ElementaryTypesCurrentLang.Contains(enumTypename)) {
                return $"{enumValue} as u{valueSizeInBytes * 8}";
            }
            
            // Otherwise, we can use the into() method to convert the enum value to the target type
            return $"{enumValue}.into()";
        }

        public static string ParseEnum(string selectorTypeName, string value, string underlyingType) {
            if (!Rust) return value;

            if (ElementaryTypesCurrentLang.Contains(selectorTypeName)) 
            {
                return $"{value} as {underlyingType}";
            }

            return $"{selectorTypeName}({value} as {underlyingType})";
        }


        public static int MaxCommentLine => TargetLang.Py ? 72 : 90;

        public static string EnumeratorAsUint(string name)
        {
            // TranslateConstExpr() takes care of .toInt() required in Java
            return (TargetLang.DotNet ? "(uint)" : "") + TranslateConstExpr(name);
        }

        public static CodeGenBase NewCodeGen (Lang lang, string rootDir)
            => (CodeGenBase)Activator.CreateInstance(CodeGenerators[lang], rootDir);

        /// <summary> This method is called before code generation for the given target
        /// language begins </summary>
        public static void SetTargetLang(Lang lang)
        {
            // This assertion will fail if a new target language is added to the Lang enum
            // without also adding the corresponding code generator to CodeGenerators
            Debug.Assert(Enum.GetValues(typeof(Lang)).Length == CodeGenerators.Count + 2);

            _curLang = lang;
            _thisQual = DotNet || Cpp || Java ? "" : This + ".";
            _null = Py ? "None" : Rust ? "Default::default()" : Cpp ? "nullptr" : "null";
            _new = DotNet || Java || Node ? "new " : Rust ? "" : "";
            _quote = Py || Node ? "'" : Rust ? "\"" : "\"";
            _digestSize = Cpp ? "TPMT_HA::DigestSize" : Rust ? "Crypto::digestSize" : "Crypto.digestSize";

            GeneratedEnums = new HashSet<TpmEnum>();

            // First translate names
            foreach (var t in TpmTypes.TheTypes)
            {
                t.Name = TranslateTypeName(t);
                if (t is TpmEnum)
                {
                    var e  = t as TpmEnum;
                    foreach (var c in e.Members)
                    {
                        c.Name = TransConstantName(c.SpecName, c.EnclosingEnum);
                        c.OldStyleName = TransConstantName(c.SpecName, c.EnclosingEnum, true);
                    }
                }
            }

            // Then translate expressions specifying enum member values.
            // Note that we cannot simply iterate TpmTypes.Constants, as in many languages
            // the order of enum definitions is important (tracked by GeneratedEnums()/IsGenerated()).
            foreach (var e in TpmTypes.Get<TpmEnum>())
            {
                // Take care
                Debug.Assert(!GeneratedEnums.Contains(e));
                GeneratedEnums.Add(e);
                foreach (var c in e.Members)
                    c.Value = TranslateConstExpr(c.SpecValue, c.EnclosingEnum);
            }

            // At last translate 
            foreach (var s in TpmTypes.Get<TpmStruct>())
            {
                foreach (var f in s.Fields)
                    f.TypeName = TranslateFieldType(f);
            }
        }

        static bool IsGenerated(TpmEnum e)
        {
            // In Java and Rust mutual order of definitions is not important
            return Java || Rust || (GeneratedEnums != null && GeneratedEnums.Contains(e));
        }

    } // static class TargetLang
}
