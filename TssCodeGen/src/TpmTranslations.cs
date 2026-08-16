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
    public static class TpmTypeTranslations
    {
        // Just so that the resulting API looks nicer.
        internal static string[] DontFlatten = new string[] { "TPM2B_PRIVATE" };

        // The spec uses these two sorts of tagged structure commonly
        //     { len, array[len] }   and
        //     { selector, [select]union }
        // This routine changes references to these sorts of structure to an embedded form.
        public static void FlattenTaggedStructures()
        {
            // Build the list of tagged structures
            List<TpmStruct> taggedStructs = new List<TpmStruct>();
            foreach(TpmType tp in TpmTypes.TheTypes)
            {
                var s = tp as TpmStruct;
                if (s == null)
                    continue;
                var t = s;
                while (t != null && t.Fields.Count != 2)
                {
                    t = t.DerivedFrom;
                }
                if (t == null || s.SpecName.IsOneOf(DontFlatten))
                {
                    continue;
                }
                if((t.Fields[0].MarshalType == MarshalType.ArrayCount) ||
                    (t.Fields[0].MarshalType == MarshalType.UnionSelector) ||
                    (t.Fields[0].MarshalType == MarshalType.LengthOfStruct)
                )
                {
                    taggedStructs.Add(s);
                }            
            }

            // find references to the tagged structures and replace them
            foreach (TpmType tp in TpmTypes.TheTypes)
            {
                if (!(tp is TpmStruct))
                    continue;
                TpmStruct t = (TpmStruct)tp;

                for (int j = 0; j < t.Fields.Count; j++)
                {
                    StructField origField = t.Fields[j];

                    if (origField.IsArray())
                    {
                        continue;   // Don't flatten arrays
                    }
                    var toEmbed = origField.Type as TpmStruct;
                    if (taggedStructs.Contains(toEmbed))
                    {
                        // If a structure to flatten is one without fields of its own,
                        // but is derived from a flattenable one, unwind the inheritance chain.
                        while (toEmbed != null && toEmbed.Fields.Count != 2)
                        {
                            toEmbed = toEmbed.DerivedFrom;
                        }

                        StructField tagToEmbed = toEmbed.Fields[0];
                        Debug.Assert(origField.MinVal == null || origField.MinVal == tagToEmbed.MinVal);
                        Debug.Assert(origField.MaxVal == null || origField.MaxVal == tagToEmbed.MaxVal);

                        var  bufToEmbed = toEmbed.Fields[1];
                        string newTagName = origField.Name + Helpers.Capitalize(tagToEmbed.Name);
                        string newBufTypeName = bufToEmbed.Type.SpecName;
                        var newTagField = new StructField(tagToEmbed, newTagName);
                        t.Fields[j] = newTagField;

                        switch (tagToEmbed.MarshalType)
                        {
                            case MarshalType.UnionSelector:
                            {
                                var newField = new UnionField(newBufTypeName, origField.Name,
                                                              origField.Comment, newTagName, t);
                                t.Fields.Insert(j + 1, newField);
                                break;
                            }
                            case MarshalType.ArrayCount:
                            {
                                var newField = new VariableLengthArray(newBufTypeName, origField.Name,
                                                                       origField.Comment, newTagName, t);
                                t.Fields.Insert(j + 1, newField);
                                break;
                            }
                            case MarshalType.LengthOfStruct:
                            {
                                var newField = new StructField(newBufTypeName, origField.Name,
                                                                     origField.Comment);
                                t.Fields.Insert(j + 1, newField);
                                newTagField.MarshalType = MarshalType.LengthOfStruct;
                                newTagField.SizedField = newField;
                                newField.MarshalType = MarshalType.SizedStruct;
                                newField.SizeTagField = newTagField;
                                break;
                            }
                            default:
                                throw new Exception("");
                        }
                    } // j-loop
                }
            }
        }

        static string[] StructsWithEncryptedBuffer = new string[] { "TPMS_ID_OBJECT", "TPMS_CONTEXT_DATA" };

        static void FixStructsWithEncryptedBuffer()
        {
            foreach (var typeName in StructsWithEncryptedBuffer)
            {
                var s = (TpmStruct)TpmTypes.Lookup(typeName);
                var f = s.Fields[3];
                Debug.Assert(f.Name.StartsWith("enc"));
                Debug.Assert(f.MarshalType == MarshalType.VariableLengthArray);
                f.MarshalType = MarshalType.EncryptedVariableLengthArray;
                Debug.Assert(f.SizeTagField != null);
                s.Fields[2] = f;
                s.Fields.RemoveAt(3);
            }
        }

        static void FixTpm2bStructs()
        {
            foreach (var s in TpmTypes.Get<TpmStruct>().Where(s => s.Fields.Count == 2 && s.StripTypedefs().SpecName.StartsWith("TPM2B_")))
            {
                var tagField = s.Fields[0];
                var dataField = s.Fields[1];
                if (tagField.MarshalType == MarshalType.ArrayCount)
                {
                    // A TPM2B struct has a byte count as the first member that contains the size of the second member.
                    // The second member can be either a byte buffer or a data structure. In the latter case the type
                    // of the data structure can be obtained from the name of the TPM2B struct.
                    string structName = s.SpecName.Replace("TPM2B_", "TPMS_");
                    if (!TpmTypes.Contains(structName))
                        continue;
                    dataField = s.Fields[1] =
                        new StructField(structName, dataField.Name, dataField.Comment);
                }
                tagField.MarshalType = MarshalType.LengthOfStruct;
                dataField.MarshalType = MarshalType.SizedStruct;
                tagField.SizedField = dataField;
                dataField.SizeTagField = tagField;
                dataField.Domain = tagField.Domain;
            }
        }

        public static string GetEnumPrefix(string memberName, string enumName, bool oldStyle = false)
        {
            if (oldStyle)
            {
                if (TargetLang.DotNet)
                    return enumName == "TPM_ALG_ID" ? "TPM_ALG_" : enumName + "_";
            }
            else if (memberName == "TPM_RS_PW")
                return "TPM_RS_";
            else if (enumName == "TPMA_LOCALITY")
                return "TPM_";

            int curPos = 0,
                prefixLen = 0;
            int maxPrefixLen = Math.Min(memberName.Length, enumName.Length);
            while (curPos < maxPrefixLen && memberName[curPos] == enumName[curPos])
            {
                if (memberName[curPos++] == '_')
                    prefixLen = curPos;
            }
            if (curPos == maxPrefixLen && memberName.Length > curPos && memberName[curPos] == '_')
                prefixLen = curPos + 1;
            return memberName.Substring(0, prefixLen);
        }

        public static string RemoveEnumPrefix(string specName, string enclosingTypeName, bool oldStyle = false)
        {
            string prefix = GetEnumPrefix(specName, enclosingTypeName, oldStyle);
            return specName.StartsWith(prefix) ? specName.Substring(prefix.Length) : specName;
        }

        public static void AddDerivedStruct(TpmStruct baseStruct, UnionMember curMember,
                                            TpmUnion curUnion, string comment = null)
        {
            string baseTypeName = baseStruct.SpecName;
            string newTypeName = baseTypeName + "_" + RemoveEnumPrefix(curMember.SelectorValue.SpecName,
                                                        curMember.SelectorValue.EnclosingEnum.SpecName);
            
            if (!TpmTypes.Contains(newTypeName))
            {
                var newStruct = new TpmStruct(newTypeName,
                                              comment ?? "Auto-derived from " + baseTypeName,
                                              baseStruct);
                TpmTypes.Add(newStruct);
            }

            var s = (TpmStruct)TpmTypes.Lookup(newTypeName);
            s.RegisterContainingUnion(curUnion);
            // Fix up the union field
            curMember.Type = s;
        }

        static void FixEnumTypeCollisions()
        {
            List<TpmStruct> toAdd = new List<TpmStruct>();
            for (int j = 0; j < TpmTypes.TheTypes.Count; j++)
            {
                TpmType tp = TpmTypes.TheTypes[j];
                if (!(tp is TpmUnion &&
                      tp.SpecName.IsOneOf(new string[] { "TPMU_PUBLIC_ID", "TPMU_SIGNATURE" })))
                {
                    continue;
                }

                // See if we have collisions.
                // Collided member types are converted into derived types by adding selector name to the base
                // type name. Struct that became a base one inherits from all the union interfaces, while
                // a derived struct only inherits from the base one and implements interfaces of the unions,
                // of which it is a member.
                // Base class B provides a union interface implementation only if this union contains a member
                // of type B. If a union U contains members of types derived from B, then B's implementation
                // of U's interface methods just throws NotImplementedException exception.
                TpmUnion u = (TpmUnion)tp;
                var dict = new Dictionary<string, UnionMember>();
                foreach (UnionMember m in u.Members)
                {
                    string typeName = m.Type.SpecName;
                    string selectorName = m.SelectorValue.Name;
                    if (dict.ContainsKey(typeName))
                    {
                        // Collision detected.
                        Debug.WriteLine("Collision in {0} [{1}] -- {2}", u.Name, selectorName, typeName);

                        TpmStruct baseStruct = (TpmStruct)TpmTypes.Lookup(typeName);
                        AddDerivedStruct(baseStruct, m, u,
                                         "Auto-derived from " + baseStruct.SpecName +
                                         " to provide unique GetUnionSelector() implementation");
                        if (dict[typeName] != null)
                        {
                            // Create the derived structure for the first occurrence.
                            AddDerivedStruct(baseStruct, dict[typeName], u);
                            // But do it only once...
                            dict[typeName] = null;
                        }
                    }
                    else
                    {
                        dict.Add(typeName, m);
                    }
                }
            }
        } // FixEnumTypeCollisions()

        static void FlattenLists()
        {
            var structs = TpmTypes.TheTypes.Where(x => x is TpmStruct).Cast<TpmStruct>();
            foreach (TpmStruct s in structs)
            {
                List<StructField> toMod = new List<StructField>();
                foreach (StructField f in s.Fields)
                {
                    var typeName = f.Type.SpecName;
                    if (typeName.StartsWith("TPML_") || typeName.StartsWith("TPM2B")) toMod.Add(f);
                }
                if (toMod.Count() == 0)
                    continue;
            }
        }

        public static void DoFixups()
        {
            // Many TPM structs represent a length-prefixed array or structure.
            // When such struct is a fields of another (enclosing) structure, get rid of the struct
            // wrapper and place the payload array/struct directly as the member of the enclosing struct.
            FixTpm2bStructs();
            FlattenTaggedStructures();
            FixStructsWithEncryptedBuffer();
            FlattenLists();

            // This command allows session based encryption.
            foreach (var s in TpmTypes.Get<TpmStruct>().Where(s => s.IsCmdStruct()))
            {
                if (s.Fields.Count > s.NumHandles &&
                    s.Fields[s.NumHandles].MarshalType.IsOneOf(MarshalType.ArrayCount, MarshalType.LengthOfStruct))
                {
                    // This command allows session based encryption.
                    Debug.Assert(s.Fields.Count > s.NumHandles + 1);
                    var sizeField = s.Fields[s.NumHandles];
                    var sizedField = s.Fields[s.NumHandles + 1];
                    var cmdInfo = s.Info as CmdStructInfo;
                    cmdInfo.SessEncSizeLen = sizeField.Type.GetSize();
                    cmdInfo.SessEncValLen = sizeField.MarshalType == MarshalType.LengthOfStruct
                                          ? 1 : sizedField.Type.GetSize();
                }
            }

            TpmStruct[] symDefs = { (TpmStruct)TpmTypes.Lookup("TPMT_SYM_DEF"),
                                    (TpmStruct)TpmTypes.Lookup("TPMT_SYM_DEF_OBJECT") };
            var fieldTypes = new string[] { "TPM_ALG_ID", "UINT16", "TPM_ALG_ID" };
            Debug.Assert(symDefs[0].Fields.Count == symDefs[1].Fields.Count &&
                         symDefs[0].Fields.Count == fieldTypes.Length);

            for (int i = 0; i < fieldTypes.Length; ++i)
            {
                foreach (var sd in symDefs)
                {
                    sd.Fields[i].MarshalType = MarshalType.Normal;
                    sd.Fields[i].Type = TpmTypes.Lookup(fieldTypes[i]);
                }
            }
            symDefs[0].Fields[0].Attrs = symDefs[1].Fields[0].Attrs |= StructFieldAttr.TermOnNull;

            FixEnumTypeCollisions();
        }
    } // class TpmTypeTranslations


    // This part of the TargetLang class handles names, types and expressions translation 
    // from their original form in the TPM 2.0 spec to the current target language.
    public static partial class TargetLang
    {
        public static string[,] TypeNameOverrides = 
        {
            {"TPM_ALG_ID", "TpmAlgId"},
            {"TPM_CC", "TpmCc"}, 
            {"TPM_RC", "TpmRc"}, 
            {"TPM_ST", "TpmSt"},
            {"TPM_RH", "TpmRh"},
            {"TPM_RS", "TpmRs"},
            {"TPM_HC", "TpmHc"},
            {"TPM_SE", "TpmSe"},
            {"TPM_HANDLE", "TpmHandle"},
            {"TPM2B_PRIVATE", "TpmPrivate"},
            {"TPMT_PUBLIC", "TpmPublic"},
            {"TPMS_DERIVE", "TpmDerive"},
            {"TPMT_HA", "TpmHash"}
        };

        public static string[,] TypeNamePrefixes = 
        {
            {"TPMU_", "Union"},
            {"TPML_", "Array"},
            {"TPMA_", "Attr"},
            {"TPMS_", ""},
            {"TPMT_", ""},
            {"TPM_" , ""}
        };

        internal static string ToCamelStyle(string s)
        {
            string result = s[0] == '_' ? "_" : "";
            string[] words = s.Split(new[] { '_' });
            for (int j = 0; j < words.Length; j++)
            {
                result += Helpers.Capitalize(words[j]);
            }
            return result;
        }

        public static string NameToDotNet(string name)
        {
            if (name.Contains("__"))
                return name;
            Debug.Assert(!Char.IsDigit(name[0]));

            return Helpers.ToCamelStyle(name);
        }

        public static string TypeToDotNet(string typeName)
        {
            if (typeName.EndsWith("Response"))
                typeName = "TPM2_" + typeName.Substring(0, typeName.Length - 8) + "_RESPONSE";

            if (typeName == null || typeName.Contains("__") ||
                !typeName.Contains('_') && typeName.ToUpper() != typeName )
            {
                return typeName;
            }
            for (int j = 0; j < TypeNameOverrides.GetLength(0); ++j)
            {
                if (typeName == TypeNameOverrides[j, 0])
                    return TypeNameOverrides[j, 1];
            }

            // Drop type name prefix and add the corresponding suffix if necessary.
            string qualifier = "";
            for (int j = 0; j < TypeNamePrefixes.GetLength(0); ++j)
            {
                string prefix = TypeNamePrefixes[j, 0];
                if (typeName.StartsWith(prefix))
                {
                    typeName = typeName.Substring(prefix.Length);
                    qualifier = TypeNamePrefixes[j, 1];
                    break;
                }
            }
            return Helpers.ToCamelStyle(typeName) + qualifier;
        }

        static string[] ConflictingStdCppMacros = { "NULL", "ERROR", "TRUE", "FALSE" };

        static string FixupInvalidName(string name)
        {
            if (char.IsNumber(name[0]) ||
                TargetLang.Cpp && name.IsOneOf(ConflictingStdCppMacros))
            {
                name = "_" + name;
            }
            return name;
        }

        /// <remarks> Old style - pre 2020 (TpmRh.TpmRsPw, EccCurve.TpmEccXxx instead of TpmRh.Pw, EccCurve.Xxx) </remarks>
        public static string TransConstantName(string specName, TpmType enclosingType, bool oldStyle = false)
        {
            string name = TpmTypeTranslations.RemoveEnumPrefix(specName, enclosingType.SpecName, oldStyle);
            name = FixupInvalidName(name);
            return TargetLang.DotNet ? NameToDotNet(name) : name;
        }

        public static string TranslateTypeName(TpmType t)
        {
            var underType = t.StripTypedefs();
            if (underType is TpmValueType)
                return TargetLang.NameFor(underType.SpecName);

            return TargetLang.DotNet ? (underType is TpmUnion ? "I" : "") + TypeToDotNet(underType.SpecName)
                                     : underType.SpecName;
        }

        /// <summary> Makes constant values specified as arithmetic expressions comply with the current
        /// langauge syntax (adds enum type name qualifiers and type casts when necessary, eliminates 
        /// sizeof() operators when unsupported, etc.) </summary>
        public static string TranslateConstExpr(TpmConstExpr ce, TpmEnum enclosingEnum = null)
        {
            var nameDelimiters = new char[] { ' ', ',', '{', '}',
                                              '(', ')', '+', '-', '<', '*', '/', '`' };
            string suffix = TargetLang.Java ? ".toInt()" : TargetLang.Rust ? ".into()" : "";
            string expr = ce.Expr;
            string[] tokens = expr.Split(nameDelimiters);
            bool sizeofOccurred = false,
                 commentNeeded = false;
            foreach (string token in tokens)
            {
                if (token.Length == 0)
                    continue;
                if (token == "sizeof")
                {
                    Debug.Assert(!sizeofOccurred);
                    sizeofOccurred = true;
                    continue;
                }
                if (Expression.IsNumber(token))
                {
                    if (token == "00")
                    {
                        Debug.Assert(expr == token);
                        expr = "0";
                    }
                    Debug.Assert(!sizeofOccurred);
                    continue;
                }

                TpmNamedConstant nc = TpmTypes.LookupConstant(token);
                if (enclosingEnum != null && nc?.EnclosingEnum == enclosingEnum)
                {
                    // Members of the enum being processed do not need to be qualified
                    Debug.Assert(token == nc.SpecName);
                    expr = expr.Replace(token, nc.Name + suffix);
                    continue;
                }
                if (!TpmTypes.ContainsConstant(token))
                {
                    // This must be a type name operand of sizeof()
                    Debug.Assert(sizeofOccurred);
                    sizeofOccurred = false;
                    TpmType t = TpmTypes.Lookup(token);
                    if (t is TpmStruct || TargetLang.IsOneOf(Lang.Java, Lang.JS, Lang.Py, Lang.Rust))
                    {
                        string sizeofExpr = "sizeof(" + token + ")";
                        Debug.Assert(expr.Contains(sizeofExpr));
                        commentNeeded = TargetLang.Py || TargetLang.Rust;
                        string origExpr = (TargetLang.Py || TargetLang.Rust) ? "" : $"/*{sizeofExpr}*/";
                        expr = expr.Replace(sizeofExpr, $"0x{t.GetSize():X}{origExpr}");
                    }
                    else if (TargetLang.DotNet)
                    {
                        expr = expr.Replace(token, t.StripTypedefs().Name);
                    }
                }
                else
                {
                    nc = TpmTypes.LookupConstant(token);
                    var translated = nc.QualifiedName + suffix;
                    if (!TargetLang.IsGenerated(nc.EnclosingEnum))
                    {
                        translated = nc.NumericValue.ToString();
                        if (!TargetLang.Py && !TargetLang.Rust)
                            translated += "/*" + token + "*/";
                        else
                            commentNeeded = true;
                    }
                    expr = expr.Replace(token, translated);
                }
            } // foreach token

            if (TargetLang.DotNet && expr.Contains("<<"))
            {
                // Shift operator in .Net requires right operand of type 'int' and unsigned left one.
                int curPos = 0;
                expr = expr.Replace(" << ", "<<");
                do
                {
                    int pos = expr.IndexOf("<<", curPos);
                    if (pos == -1)
                        break;
                    curPos = pos + 2 + 6; // Add sizes of "<<" and "(uint)"
                    while (char.IsLetterOrDigit(expr[--pos]) || expr[pos] == '.')
                        continue;
                    expr = expr.Insert(pos + 1, "(uint)");
                } while (true);
                expr = expr.Replace("<<", " << (int)");
            }
            
            // For Rust, we might need to add type suffixes for literals
            if (TargetLang.Rust && expr.Contains("<<"))
            {
                expr = expr.Replace("<<", " << ");
            }

            if (commentNeeded)
                expr += TargetLang.Rust ? $" /* {ce.Expr} */" : $"  # {ce.Expr}";
            return expr;
        } // TranslateConstExpr()

        /// <summary> Constructs language specific representation of the given TPM structure field type
        /// for the currently active language. In particular, applies array and byte buffer conventions.
        /// </summary>
        /// <param name="f"> Structure field metadata extracted from the TPM spec </param>
        /// <returns> Language specific representation of the given TPM structure field type </returns>
        static string TranslateFieldType(StructField f)
        {
            string typeName = f.Type.Name;

            if (f.IsByteBuffer())
            {
                if (TargetLang.Cpp)
                    typeName = "ByteVec";
                else if (TargetLang.Rust)
                    return "Vec<u8>";
                else
                {
                    if (TargetLang.Node)
                        return "Buffer";
                    else if (TargetLang.Py)
                        return "bytes";
                    return typeName + "[]";
                }
            }
            else if (f.IsArray())
            {
                if (TargetLang.Cpp)
                    typeName = $"vector<{typeName}>";
                else if (TargetLang.Rust)
                    typeName = $"Vec<{typeName}>";
                else
                    return typeName + "[]";
            }
            return typeName;
        }
    } // partial class TargetLang

} // namespace CodeGen
