/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

namespace CodeGen
{
    /// <summary> Target language independent base class for code generators </summary>
    public abstract class CodeGenBase
    {
        protected string RootDir;

        string AutogenBeginTag = null;

        // Code is built in TpmDefs, and then merged/written out when complete
        protected StringBuilder GeneratedCode = new StringBuilder();

        Dictionary<string, List<string>> Snips = new Dictionary<string, List<string>>();

        public static string eol => "\n";

        public static string This => TargetLang.This;
        public static string ThisMember => TargetLang.ThisMember;

        public static readonly string[] ForceJustOneReturnParm = new string[] { "Load", "LoadExternal" };

        /// <summary> Spec names of the structures a default-constructed instance of which must marshal
        /// as an empty (zero size) object instead of reporting the absent union field as an error. </summary>
        /// <remarks> Only TPMT_SENSITIVE relies on this: TPM2_LoadExternal takes an empty inPrivate
        /// sized object when only the public part of a key is loaded. Currently honored by the Rust
        /// generator only; the other target languages apply the convention to every structure whose
        /// union selector is its first marshaled field. </remarks>
        public static readonly string[] EmptyMarshalingStructs = new string[] { "TPMT_SENSITIVE" };


        protected CodeGenBase(string rootDir, string snipsFileName = null)
        {
            RootDir = rootDir;

            // Load snippets - custom additions (usually helper methods) to the TPM types
            if (snipsFileName != null)
                LoadSnips(rootDir + snipsFileName);
        }


        internal abstract void Generate();


        static void AddBitfieldElt(List<TpmNamedConstant> elements, string name, long val,
                                   string comment = null, string oldStyleName = null, bool custom = false)
        {
            // Comment is null only for custom enumerators "XXX_BIT_OFFSET" and "XXX_BIT_LENGTH"
            var value = comment == null ? val.ToString() : ToHex(val);
            var nc = new TpmNamedConstant(null, custom ? null : name, value, comment);
            nc.Name = name;
            nc.Value = value;
            nc.OldStyleName = oldStyleName ?? name;
            elements.Add(nc);
        }

        public static List<TpmNamedConstant> GetBifieldElements(TpmBitfield bf)
        {
            var elements = new List<TpmNamedConstant>();
            foreach (var b in bf.Elements)
            {
                if (b.StartBit == b.EndBit)
                {
                    AddBitfieldElt(elements, b.TranslatedName, 1 << b.StartBit, b.Comment, b.OldStyleName);
                }
                else // multibit members of a bitfield
                {
                    string typeName = b.Name;
                    if (TpmTypes.Contains(typeName))
                    {
                        // Type typeName defines allowed values for this multi-bit field
                        var e = TpmTypes.Lookup(typeName) as TpmEnum;
                        if (e != null)
                        {
                            foreach (var v in e.Members)
                            {
                                AddBitfieldElt(elements, v.Name, v.NumericValue << b.EndBit, v.Comment);
                            }
                        }
                    }

                    // Multi-bit bitfield 'name' is additionally represented by several enumerators:
                    //   name_BIT_MASK - bit mask selecting all bits of the field 
                    //   name_BIT_OFFSET - offset of the field's low order bit 
                    //   name_BIT_LENGTH - number of bits in the field
                    string nameBase = b.Name.Contains("_") ? TargetLang.NameToDotNet(b.Name) : b.Name;
                    int len = b.StartBit - b.EndBit + 1;
                    var suff = TargetLang.DotNet ? new string[] { "BitMask", "BitOffset", "BitLength" }
                                                 : new string[] { "_BIT_MASK", "_BIT_OFFSET", "_BIT_LENGTH" };
                    AddBitfieldElt(elements, nameBase + suff[0], ((1 << len) - 1) << b.EndBit, b.Comment, null, true);
                    AddBitfieldElt(elements, nameBase + suff[1], b.EndBit, null, null, true);
                    AddBitfieldElt(elements, nameBase + suff[2], len, null, null, true);
                    if (TargetLang.DotNet && bf.Name == "LocalityAttr")
                    {
                        // For backward compatibility
                        for (int i = 0; i < len; ++i)
                            AddBitfieldElt(elements, $"{nameBase}Bit{i}", 1 << (b.EndBit + i), "", null, true);
                    }
                } // multibit members of a bitfield
            }
            return elements;
        }

        /// <param name="structSpecName"> Spec name of the structure being marshaled. Only supplied by
        /// the Rust generator, which limits the empty-object convention to EmptyMarshalingStructs. </param>
        public static List<string> GetToTpmFieldsMarshalOps(StructField[] fields, string structSpecName = null)
        {
            var marshalOps = new List<string>();
            string fieldNamePrefix = TargetLang.Rust ? "&" : "";
            string resultSuffix = TargetLang.Rust ? "?" : "";

            foreach (StructField f in fields)
            {
                int size = f.Type.GetSize();
                string fieldName = ThisMember + f.Name;
                switch (f.MarshalType)
                {
                    case MarshalType.Normal:
                        if (f.IsValueType())
                            marshalOps.Add($"buf.write{WireNameForInt(size)}({TargetLang.GetEnumValue(fieldName, f.TypeName, size)})");
                        else
                            marshalOps.Add($"{fieldName}.toTpm(buf){resultSuffix}");

                        if (f.Attrs.HasFlag(StructFieldAttr.TermOnNull))
                        {
                            string earlyReturn = TargetLang.Rust ? " { return Ok(()) }" : " return";
                            marshalOps.Add(TargetLang.If($"{fieldName} == {TpmTypes.AlgNull}") + earlyReturn);
                        }
                        break;

                    case MarshalType.ConstantValue:
                        marshalOps.Add($"buf.write{WireNameForInt(size)}({TargetLang.GetEnumValue(ConstTag(f), f.TypeName, size)})");
                        break;

                    case MarshalType.SizedStruct:
                        Debug.Assert(f.SizeTagField != null);
                        marshalOps.Add($"buf.writeSizedObj({fieldNamePrefix + fieldName}){resultSuffix}");
                        break;

                    case MarshalType.EncryptedVariableLengthArray:
                    case MarshalType.SpecialVariableLengthArray:
                        // TPMT_HA size is tagged by its hash alg (the first field)
                        marshalOps.Add($"buf.writeByteBuf({fieldNamePrefix + fieldName})");
                        break;

                    case MarshalType.VariableLengthArray:
                        var sizeTagLen = f.SizeTagField.Type.GetSize();
                        if (f.IsByteBuffer())
                        {
                            // Rust doesn't support default arguments for functions, so we need to pass the size tag length explicitly
                            bool shouldNotPassSizeTag = sizeTagLen == 2 && !TargetLang.Rust;
                            marshalOps.Add($"buf.writeSizedByteBuf({fieldNamePrefix}{fieldName}" + (shouldNotPassSizeTag ? ")" : $", {sizeTagLen})"));
                        }
                        else if (f.IsValueType())
                            marshalOps.Add($"buf.writeValArr({fieldName + TargetLang.AsReference(true)}, {size})");
                        else
                            marshalOps.Add($"buf.writeObjArr({fieldName + TargetLang.AsReference(true)}){resultSuffix}");
                        break;

                    case MarshalType.UnionSelector:
                        // A trick to allow using default-constructed TPMT_SENSITIVE as an empty (non-marshaling) object.
                        // Rust restricts it to EmptyMarshalingStructs, so that any other absent union is reported.
                        string unionField = ThisMember + f.RelatedUnion.Name;
                        if (f == fields.First() &&
                            (!TargetLang.Rust || EmptyMarshalingStructs.Contains(structSpecName)))
                        {
                            string earlyReturn = TargetLang.Rust ? " { return Ok(()) }" : " return";
                            marshalOps.Add(TargetLang.IfNull(unionField) + earlyReturn);
                        }

                        marshalOps.Add($"buf.write{WireNameForInt(size)}({unionField}{TargetLang.UnionMember(true)}GetUnionSelector(){TargetLang.GetUnionValue(size)})");
                        break;

                    case MarshalType.UnionObject:
                        marshalOps.Add($"{fieldName}{TargetLang.UnionMember(true)}toTpm(buf){resultSuffix}");
                        break;

                    default:
                        Debug.Assert(false);
                        break;
                }
            }
            return marshalOps;
        } // GetToTpmFieldsMarshalOps()

        public static List<string> GetFromTpmFieldsMarshalOps(StructField[] fields)
        {
            string resultSuffix = TargetLang.Rust ? "?" : "";

            var marshalOps = new List<string>();
            foreach (StructField f in fields)
            {
                int size = f.Type.GetSize();
                string fieldName = ThisMember + f.Name;
                switch (f.MarshalType)
                {
                    case MarshalType.Normal:
                        if (f.IsValueType())
                            marshalOps.Add($"{fieldName} = {TargetLang.ParseEnum(f.TypeName, $"buf.read{WireNameForInt(size)}()", f.Type.GetFinalUnderlyingType().Name)}");
                        else
                            marshalOps.Add(TargetLang.Cpp || TargetLang.Rust ? $"{fieldName}.initFromTpm(buf){resultSuffix}"
                                                          : $"{fieldName} = {f.TypeName}.fromTpm(buf){resultSuffix}");

                        if (f.Attrs.HasFlag(StructFieldAttr.TermOnNull))
                        {
                            string earlyReturn = TargetLang.Rust ? " { return Ok(()) }" : " return";
                            marshalOps.Add(TargetLang.If($"{fieldName} == {TpmTypes.AlgNull}") + earlyReturn);
                        }
                        break;

                    case MarshalType.ConstantValue:
                        // TODO: Add assertion by comparing with the expected constant
                        marshalOps.Add($"buf.read{WireNameForInt(size)}()");
                        break;

                    case MarshalType.SizedStruct:
                        Debug.Assert(f.SizeTagField != null);
                        marshalOps.Add(TargetLang.Cpp ? $"buf.readSizedObj({fieldName})" :
                                       TargetLang.Rust ? $"buf.readSizedObj(&mut {fieldName})?" :
                                       $"{fieldName} = buf.createSizedObj({TargetLang.TypeInfo(f.TypeName)})");
                        break;

                    case MarshalType.EncryptedVariableLengthArray:
                        marshalOps.Add($"{fieldName} = buf.readByteBuf(buf.getCurStuctRemainingSize())");
                        break;

                    case MarshalType.SpecialVariableLengthArray:
                        // TPMT_HA size is inferred from the hash algorithm
                        Debug.Assert(f.IsByteBuffer() && f.SizeTagField.Type.GetSize() == 2);
                        marshalOps.Add($"{fieldName} = buf.readByteBuf({TargetLang.DigestSize(f.SizeTagField.Name)})");
                        break;

                    case MarshalType.VariableLengthArray:
                        var sizeTagLen = f.SizeTagField.Type.GetSize();
                        if (f.IsByteBuffer())
                        {
                            // Rust doesn't support default arguments for functions, so we need to pass the size tag length explicitly
                            bool shouldNotPassSizeTag = sizeTagLen == 2 && !TargetLang.Rust;
                            marshalOps.Add($"{fieldName} = buf.readSizedByteBuf(" + (shouldNotPassSizeTag ? ")" : $"{sizeTagLen})"));
                        }
                        else if (f.IsValueType())
                            marshalOps.Add(TargetLang.Cpp ? $"buf.readValArr({fieldName}, {f.Type.GetSize()})" :
                                           TargetLang.Rust ? $"buf.readValArr({fieldName + TargetLang.AsReference(false)}, {f.Type.GetSize()})?" :
                                           $"{fieldName} = buf.readValArr({f.Type.GetSize()})");
                        else
                            marshalOps.Add(TargetLang.Cpp || TargetLang.Rust ? $"buf.readObjArr({fieldName + TargetLang.AsReference(false)}){resultSuffix}"
                                                          : $"{fieldName} = buf.readObjArr({TargetLang.TypeInfo(f.TypeName.TrimEnd('[', ']'))})");
                        break;

                    case MarshalType.UnionSelector:
                        var localVar = TargetLang.LocalVar(f.Name, f.TypeName);
                        if (f.IsValueType())
                        {
                            marshalOps.Add($"{localVar} = {TargetLang.ParseEnum(f.TypeName, $"buf.read{WireNameForInt(size)}()", f.Type.GetFinalUnderlyingType().Name)}");
                        }
                        else
                            marshalOps.Add($"{localVar} = {f.TypeName}.fromTpm(buf){resultSuffix}");
                        break;

                    case MarshalType.UnionObject:
                        var selector = (f as UnionField).UnionSelector;
                        var selectorName = selector.Name;
                        if (TargetLang.Cpp)
                            marshalOps.Add($"UnionFactory::Create({fieldName}, {selectorName})");
                        else if (TargetLang.Rust)
                            marshalOps.Add($"{fieldName} = {f.TypeName}::create(r#{selectorName})?");
                        else
                            marshalOps.Add($"{fieldName} = UnionFactory.create({TargetLang.Quote(f.TypeName)}, {selectorName})");

                        marshalOps.Add($"{fieldName}{TargetLang.UnionMember(false)}initFromTpm(buf){resultSuffix}");
                        break;
                    default:
                        break;
                }
            }
            return marshalOps;
        } // GetFromTpmFieldsMarshalOps()

        void AddSnip(string type, List<string> snipLines)
        {
            if (snipLines.Count == 0)
                return;
            // trim trailing empty lines
            for (int i = snipLines.Count - 1; i > 0 && snipLines[i] == ""; --i)
            {
                snipLines.RemoveAt(i);
            }
            if (snipLines.Count() != 0)
                Snips.Add(type, snipLines);
        }

        /// <summary>
        /// The file snipsPath contains snippets of code to be added to the auto-generated types
        /// </summary>
        internal void LoadSnips(string snipsPath)
        {
            var lines = File.ReadAllLines(snipsPath);
            string curType = "";
            List<string> snipLines = new List<string>();
            foreach (string line in lines)
            {
                if (line.StartsWith(">>"))
                {
                    AddSnip(curType, snipLines);
                    snipLines = new List<string>();
                    var bits = line.Split(new char[] { ' ' });
                    curType = bits[bits.Length - 1];
                    if (Snips.ContainsKey(curType))
                        throw new Exception("Only one snips-section per-type");
                    continue;
                }
                snipLines.Add(line);
            }
            AddSnip(curType, snipLines);
        }

        /// <summary> The snippet lines inserted into the given type's definition, or an empty
        /// sequence if the type has no snippet. </summary>
        /// <remarks> A generator needs to look at these when the code it emits elsewhere must
        /// account for what the snippet declares. The Rust generator does: a struct's Default
        /// implementation has to initialize the fields the snippet injects, too. </remarks>
        protected IEnumerable<string> GetSnip(string typeName)
            => Snips.TryGetValue(typeName, out var snip) ? snip : Enumerable.Empty<string>();

        protected void InsertSnip(string typeName)
        {
            // Insert the custom snippets if there are any
            if (!Snips.ContainsKey(typeName))
                return;
            Write("");
            var snip = Snips[typeName];
            foreach (var l in snip)
                Write(l);
        }

        internal void UpdateExistingSource(string fileName)
        {
            var filePath = RootDir + fileName;

            // First, make sure that the source files to be updated by the code generator 
            // both are writable and have the correct format.
            FileAttributes attr = File.GetAttributes(filePath);
            if (attr.HasFlag(FileAttributes.ReadOnly))
            {
                Console.WriteLine($"File '{fileName}' must be writable.");
                return;
            }

            string commentToken = TargetLang.LineComment;
            string autogenTag = $"{commentToken} <<AUTOGEN_BEGIN>>";
            string existingCode = File.ReadAllText(filePath);
            int autogenStart = existingCode.IndexOf(autogenTag);
            if (autogenStart == -1)
            {
                Console.WriteLine($"File '{fileName}' must begin with a warning about autogenerated code and '{autogenTag}' comment.");
                return;
            }

            autogenStart = existingCode.IndexOf(autogenTag, autogenStart + autogenTag.Length);
            if (autogenStart == -1)
            {
                Console.WriteLine($"File '{fileName}' must contain the '{autogenTag}' marker.");
                return;
            }

            string generatedCode = GeneratedCode.ToString();
            GeneratedCode.Clear();

            if (AutogenBeginTag == null)
            {
                Write(autogenTag);
                Write($"{commentToken} ------------------------------------------------------------------------------------------------");
                Write($"{commentToken} DO NOT REMOVE the <<AUTOGEN_BEGIN>> comment!");
                Write($"{commentToken} DO NOT MODIFY any code below this point - all manual changes will be lost!");
                Write($"{commentToken} ------------------------------------------------------------------------------------------------");
                Write("");
                AutogenBeginTag = GeneratedCode.ToString();
                GeneratedCode.Clear();
            }

            File.WriteAllText(filePath, existingCode.Substring(0, autogenStart) + AutogenBeginTag + generatedCode);
        }

        internal static string GetCommandName(TpmStruct req)
        {
            return req.SpecName.Replace("TPM2_", "").Replace("_REQUEST", "");
        }

        internal static TpmStruct GetRespStruct(TpmStruct req)
        {
            return (TpmStruct)TpmTypes.Lookup(req.SpecName.Replace("_REQUEST", "Response").Substring(5));
        }

        internal static string Separator<T>(T elem, IEnumerable<T> list, string sep = ",", string term = "")
        {
            return Object.ReferenceEquals(list.Last(), elem) ? term : sep;
        }

        internal static string ToHex(long value)
        {
            // Cast to uint to avoid sign-extension of 32-bit values (e.g. 0x80000000)
            return "0x" + Convert.ToString((uint)value, 16).ToUpper();
        }
        internal static string ToHex(ulong value) { return ToHex((long)value); }

        internal static string WireNameForInt(int size)
        {
            switch (size)
            {
                case 1: return "Byte";
                case 2: return "Short";
                case 4: return "Int";
                case 8: return "Int64";
            }
            Debug.Assert("WireNameForInt(): unsupported size" == null);
            return null;
        }

        internal static string ConstTag(StructField f)
        {
            string rawName = f.Domain[0, Constraint.Type.Single].Expr;
            return TpmTypes.LookupConstant(rawName).QualifiedName;
        }

        protected string NsQualifiedType(StructField f, string nameSpace)
        {
            return (f.Type.IsElementary() ? "" : nameSpace) + f.TypeName;
        }

        /// <param name="unionField"> Name of the filed of a union interface type associated with the returned tag </param>
        /// <returns> Name of the union selector (tag) fieled or null </returns>
        public static string GetUnionSelectorFieldInfo(TpmStruct s, out string unionField)
        {
            unionField = null;
            var selectors = s.Fields.Where(f => f.MarshalType == MarshalType.UnionSelector);
            if (selectors.Count() == 0)
                return null;

            // If a struct is a member of multiple unions, all of them are expected to use the same selector value
            unionField = selectors.First().Name;
            return selectors.First().RelatedUnion.Name;
        }

        /// <param name="selVal"> Upon return set to the value (qualified enum memeber) of the selector (or null). </param>
        /// <returns> Union selector type name if 's' is a member of a tagged union. Otherwise null. </returns>
        public static string GetUnionSelectorType(TpmUnion u)
        {
            return u.Members[0].SelectorValue.EnclosingEnum.Name;
        }

        /// <param name="selVal"> Upon return set to the value (qualified enum memeber) of the selector (or null). </param>
        /// <returns> Union selector type name if 's' is a member of a tagged union. Otherwise null. </returns>
        public static string GetUnionMemberSelectorInfo(TpmStruct s, out string selVal)
        {
            selVal = null;
            if (s.IsCmdStruct() || s.ContainingUnions.Count == 0)
                return null;

            // If a struct is a member of multiple unions, all of them are expected to use the same selector value
            TpmUnion u = s.ContainingUnions.ElementAt(0);
            selVal = s.SpecName == TpmTypes.EmptyUnionBaseName ? TpmTypes.AlgNull
                   : u.GetMemberOfType(s).SelectorValue.QualifiedName;
            return GetUnionSelectorType(u);
        }

        public static string GetUnionChoicesList(TpmType t)
        {
            if (!(t is TpmUnion))
                return "";
            var uniqueFields = (t as TpmUnion).Members.Distinct().ToList();
            string unionList = string.Join(", ", uniqueFields.ConvertAll(f => f.Type.Name).Distinct());
            return $"One of: {unionList}.";
        }

        public static string AsSummary(string comment)
        {
            return string.IsNullOrEmpty(comment) ? comment
                    : (TargetLang.Cpp || TargetLang.DotNet)
                    ? "<summary> " + comment + " </summary>" : comment;
        }

        public static string AsRemark(string comment)
        {
            if (comment == "")
                return comment;
            return eol + (TargetLang.Cpp || TargetLang.DotNet
                            ? "<remarks> " + comment + " </remarks>" : comment);
        }

        // Javadoc does not allow empty comments for @param and similar tags
        public static string MandatoryComment(string comment)
        {
            return string.IsNullOrWhiteSpace(comment) ? "TBD" : comment;
        }

        public static string GetParamComment(StructField f, string prefix = "", string indent = "       ")
        {
            string beg = TargetLang.DotNet || TargetLang.Cpp ? "<param name = \""
                       : TargetLang.Java || TargetLang.Node ? "@param " : "";
            string med = TargetLang.DotNet || TargetLang.Cpp ? "\"> "
                       : TargetLang.Java || TargetLang.Node ? " " : ": ";
            string end = TargetLang.DotNet || TargetLang.Cpp ? " </param>"
                       : TargetLang.Java || TargetLang.Node ? "" : "";

            string unionList = GetUnionChoicesList(f.Type);
            string comment = f.Comment + (unionList == "" ? "" : eol + unionList);
            string fieldType = TargetLang.Py ? $" ({f.TypeName})" : "";
            return Helpers.WrapText(beg + prefix + f.Name + fieldType + med + MandatoryComment(comment) + end, indent);
        }

        public static string GetReturnComment(StructField[] respFields)
        {
            string beg = TargetLang.DotNet || TargetLang.Cpp ? "<returns> "
                       : TargetLang.Java || TargetLang.Node ? "@return " : "    ";
            string end = TargetLang.DotNet || TargetLang.Cpp ? " </returns>"
                       : TargetLang.Java || TargetLang.Node ? "" : "";
            string lbr = (TargetLang.Java || TargetLang.Node ? "<br>" : "") + "\n";
            string nlp = new string(' ', beg.Length);
            if (respFields.Length == 0)
                return "";
            string comment = "";
            string returnComment = respFields[0].Comment;
            if (returnComment == "")
                returnComment = respFields[0].Type.Comment;

            string intro = $"{beg}{respFields[0].Name} - ",
                    indent = new string(' ', intro.Length);

            comment += Helpers.WrapText(intro + MandatoryComment(returnComment), indent);
            for (int i = 1; i < respFields.Length; ++i)
            {
                intro = $"{nlp}{respFields[i].Name} - ";
                indent = new string(' ', intro.Length);
                comment += lbr + Helpers.WrapText(intro + MandatoryComment(respFields[i].Comment), indent);
            }
            return comment + end;
        }

        /// <summary> Writes multi- or single-line comment for a class, method, or field (depending
        /// on the new line characters presence. </summary>
        /// <remarks> Add '\n' to the beginning of `end` to make it go on a separate line. </remarks>
        protected void WriteComment(string comment, string beg, string mid, string end = "", bool wrap = true)
        {
            // Unconditionally insert an empty line in the case of DotNet, as even if the comment is empty,
            // the commented field or enumerator will be prepended with one or more attribute clauses
            // that need separation.
            if (TargetLang.DotNet)
                Write("");

            if (string.IsNullOrWhiteSpace(comment))
                return;

            // Prepend the comment with an empty line, unless it's python
            if (!TargetLang.Py)
                Write("");

            bool inlineEnd = end == "" || end[0] != '\n';
            comment = comment.TrimEnd(new char[] { ' ', '\n' }).Replace("\r", "");
            comment = beg + comment + (inlineEnd ? end : "");
            if (wrap)
                comment = Helpers.WrapText(comment, mid);
            else
                comment = comment.Replace("\n", "\n" + mid);
            if (!inlineEnd)
            {
                if (!comment.Contains('\n'))
                {
                    if (end.StartsWith("\n"))
                        end = end.Substring(1);
                    end = " " + end.TrimStart(' ');
                }
                comment += end;
            }
            var lines = comment.Split(new char[] { '\n' });
            for (int i = 0; i < lines.Length; ++i)
                Write(lines[i]);
            CommentWritten = true;
        }

        protected abstract void WriteComment(string comment, bool wrap = true);

        private void WriteComment(string comment, TpmType t)
        {
            WriteComment(AsSummary(comment) + AsRemark(GetUnionChoicesList(t)));
        }

        protected void WriteComment(TpmType t)
        {
            WriteComment(t.Comment, t);
        }

        protected void WriteComment(TpmField f)
        {
            WriteComment(f.Comment, f.Type);
        }

        protected void WriteComment(TpmNamedConstant nc)
        {
            WriteComment(AsSummary(nc.Comment));
        }

        protected bool NewLine = true,
                        EmptyLineWritten = false,
                        CommentWritten = false;

        protected const int SpacesPerTab = 4;
        protected int IndentLevel;

        protected string CurIndent()
        {
            return new string(' ', IndentLevel * SpacesPerTab);
        }

        protected void Write(string str, bool newLine = true)
        {
            if (newLine && str == "")
            {
                if (EmptyLineWritten)
                {
                    // No double empty lines in the output
                    Debug.Assert(NewLine);
                }
                else
                {
                    GeneratedCode.AppendLine();
                    EmptyLineWritten = NewLine = true;
                }
                return;
            }
            if (TargetLang.Java && str.StartsWith("@") && !EmptyLineWritten && !CommentWritten)
            {
                GeneratedCode.AppendLine();
                NewLine = true;
            }

            string curIndent = CurIndent(),
                    indent = NewLine ? curIndent : "";
            var lines = str.Replace("\r", "").Split(new char[] { '\n' });
            for (int i = 0; i < lines.Length; ++i)
            {
                GeneratedCode.Append(indent + lines[i]);
                indent = "\r\n" + curIndent;
            }

            if (newLine)
                GeneratedCode.AppendLine();

            EmptyLineWritten = (NewLine && str == "")
                            || (newLine && str.EndsWith(eol));
            NewLine = newLine || str.EndsWith(eol);
            CommentWritten = false;
        }

        protected void WriteLine(string fmt, params object[] args)
        {
            Write(string.Format(fmt, args), true);
        }

        protected void TabIn()
        {
            EmptyLineWritten = true;
            IndentLevel++;
        }

        protected void TabOut()
        {
            IndentLevel--;
        }

        protected void TabIn(string openingToken)
        {
            if (!NewLine)
                Write("");
            Write(openingToken);
            TabIn();
        }

        protected void TabOut(string closingToken, bool extraNewLine = true)
        {
            TabOut();
            Write(closingToken);
            if (extraNewLine && closingToken.StartsWith(TargetLang.Py ? "#" : "}"))
                Write("");
        }
    } // class CodeGenBase
}
