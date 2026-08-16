/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CodeGen
{
    /// <summary> Java TSS code generator </summary>
    class CGenJava : CodeGenBase
    {
        bool needsUtil; // needs java.util.*

        public CGenJava(string rootDir) : base(rootDir + @"src\", "TpmExtensions.java.snips") { }

        internal override void Generate()
        {
            // Go through the types generating code
            foreach (var t in TpmTypes.Get<TpmType>())
            {
                if (t is TpmEnum)
                    GenEnum(t as TpmEnum);
                else if (t is TpmBitfield)
                    GenBitfield(t as TpmBitfield);
                else if (t is TpmUnion)
                    GenUnion(t as TpmUnion);
                else if (t is TpmStruct)
                    GenStruct(t as TpmStruct);
                else
                    continue;

                string typeName = t.Name;
                WriteDef(GetJavaFileName(typeName), null, false);
            }

            GenUnionFactory();
            WriteDef(GetJavaFileName("UnionFactory"), null, false);

            // Now generate the TPM methods
            GenCommands();
            WriteDef(GetJavaFileName(), null, true);

            foreach (var t in TpmTypes.TheTypes.Where(t => !t.Implement))
            {
                string typeName = t.Name;
                File.Delete(GetJavaFileName(typeName));
            }
        }

        string GetJavaFileName(string typeName = null)
        {
            if (typeName != null)
                return RootDir + "tss\\tpm\\" + typeName + ".java";
            return RootDir + "tss\\Tpm.java";
        }

        internal static bool ConflictingEnumMember(string name, string typeName)
        {
            return (typeName == "TPM_RC" && name == "H"
                || typeName == "TPM_ALG_ID" && name == "LAST"
                || typeName == "TPM_HT" && (name == "LOADED_SESSION" || name == "SAVED_SESSION"));
        }

        /// <summary> Constants and bitfields are represented as classes derived 
        /// from TpmEnum, and TpmAttribute correspondingly in Java </summary>
        void GenEnum(TpmType e, List<TpmNamedConstant> elements, long wireSize)
        {
            needsUtil = true;  // Collection needs java.util.*

            WriteComment(e);

            string baseClass = e is TpmEnum ? "TpmEnum" : "TpmAttribute";
            Write($"public final class {e.Name} extends {baseClass}<{e.Name}>");
            TabIn("{");
            WriteComment("Values from enum _N are only intended to be used in case labels of a switch " +
                        "statement using the result of this.asEnum() method as the switch condition. " +
                        "However, their Java names are identical to those of the constants defined in this class further below, " +
                       $"so for any other usage just prepend them with the {e.Name}. qualifier.");
            Write("public enum _N {");
            TabIn();
            foreach (var v in elements)
            {
                WriteComment(v);
                Write($"{v.Name}{Separator(v, elements)}");
            }
            TabOut("}");

            Write($"private static ValueMap<{e.Name}> _ValueMap = new ValueMap<{e.Name}>();");

            WriteComment("These definitions provide mapping of the Java enum constants to their TPM integer values");
            Write($"public static final {e.Name}");
            TabIn();

            foreach (var v in elements)
            {
                // Workaround for multiple enum members with the same value.
                // Conversion from int will never return enumerators in the following if-statement
                string conflict = e is TpmEnum && ConflictingEnumMember(v.Name, e.Name) ? ", true" : "";
                string delimiter = Separator(v, elements, ",", ";");
                Write($"{v.Name} = new {e.Name}({v.Value}, _N.{v.Name}{conflict}){delimiter}");
            }
            TabOut("");

            // Backward compat
            if (e.Name == "TPM_RH")
            {
                WriteComment("@deprecated Use {@link #PW} instead");
                Write("@Deprecated");
                Write($"public static final {e.Name} RS_PW = new {e.Name}(PW.toInt(), _N.PW, true);", true);
            }

            Write($"public {e.Name} () {{ super(0, _ValueMap); }}", true);
            Write($"public {e.Name} (int value) {{ super(value, _ValueMap); }}", true);
            if (e is TpmBitfield)
                Write($"public {e.Name} ({e.Name}...attrs) {{ super(_ValueMap, attrs); }}", true);
            Write($"public static {e.Name} fromInt (int value) {{ return TpmEnum.fromInt(value, _ValueMap, {e.Name}.class); }}", true);
            Write($"public static {e.Name} fromTpm (byte[] buf) {{ return TpmEnum.fromTpm(buf, _ValueMap, {e.Name}.class); }}", true);
            Write($"public static {e.Name} fromTpm (TpmBuffer buf) {{ return TpmEnum.fromTpm(buf, _ValueMap, {e.Name}.class); }}", true);
            Write($"public {e.Name}._N asEnum() {{ return ({e.Name}._N)NameAsEnum; }}", true);
            Write($"public static Collection<{e.Name}> values() {{ return _ValueMap.values(); }}", true);
            if (e is TpmBitfield)
            {
                Write($"public boolean hasAttr ({ e.Name} attr) {{ return super.hasAttr(attr); }}", true);
                Write($"public {e.Name} maskAttr ({e.Name} attr) {{ return super.maskAttr(attr, _ValueMap, {e.Name}.class); }}", true);
            }

            // Do not include params and bits of a mask of a multibit member of a bitfield
            // into the fromInt() conversion map
            Write($"private {e.Name} (int value, _N nameAsEnum) {{ super(value, nameAsEnum, _ValueMap); }}", true);
            Write($"private {e.Name} (int value, _N nameAsEnum, boolean noConvFromInt) {{ super(value, nameAsEnum, null); }}", true);

            Write("@Override");
            Write($"protected int wireSize() {{ return {wireSize}; }}");

            InsertSnip(e.Name);
            TabOut("}", false);
        } // GenEnum

        void GenEnum(TpmEnum e)
        {
            GenEnum(e, e.Members, e.UnderlyingType.GetSize());
        }

        void GenBitfield(TpmBitfield bf)
        {
            GenEnum(bf, GetBifieldElements(bf), bf.GetSize());
        }

        /// <summary>
        /// Unions in C are translated into Java classes implementing the interface that defines the union 
        /// </summary>
        /// <param name="u"></param>
        void GenUnion(TpmUnion u)
        {
            WriteComment(u);
            Write($"public interface {u.Name} extends TpmUnion");
            TabIn("{");
            Write($"public {GetUnionSelectorType(u)} GetUnionSelector();");
            TabOut("}", false);
        }

        void GenUnionFactory()
        {
            WriteComment("Holds static factory method for instantiating TPM unions.\n" +
                "Note: A wrapper class is used instead of simply static function solely " +
                "for the sake of uniformity with languages like C# and Java.");
            Write("class UnionFactory");
            TabIn("{");
            WriteComment("Creates specific TPM union member based on the union type and selector (tag) value");
            Write("@SuppressWarnings(\"unchecked\")");
            Write("public static <U extends TpmUnion, S extends TpmEnum<S>>");
            Write("U create(String unionType, S selector) // S = TPM_ALG_ID | TPM_CAP | TPM_ST");
            TabIn("{");
            string elsePref = "";
            foreach (TpmUnion u in TpmTypes.Get<TpmUnion>())
            {
                TabIn($"{elsePref}if (unionType == \"{u.Name}\")");
                elsePref = "else ";
                TabIn($"switch ((({GetUnionSelectorType(u)})selector).asEnum()) {{");
                foreach (UnionMember m in u.Members)
                {
                    string newObj = m.Type.IsElementary() ? TargetLang.Null : $"new {m.Type.Name}()";
                    Write($"case {m.SelectorValue.Name}: return (U) {newObj};");
                }
                Write("default:");
                TabOut("}", false);  // switch (selector)
                TabOut();   // if / else if
            }
            TabIn("else");
            Write("throw new RuntimeException(\"UnionFactory::Create(): Unknown union type \" + unionType);");
            TabOut("throw new RuntimeException(\"Unknown selector value \" + selector.toString() + \" for union \" + unionType);");
            TabOut("} // create()");
            TabOut("}; // class UnionFactory");
        }

        void GenGetUnionSelector(TpmStruct s)
        {
            string selType = GetUnionMemberSelectorInfo(s, out string selVal);
            if (selType != null)
            {
                WriteComment("TpmUnion method");
                Write($"public {selType} GetUnionSelector() {{ return {selVal}; }}");
            }
        }

        public void GenMarshalingMethod(bool dirTo, TpmStruct s)
        {
            var fields = s.MarshalFields;
            if (s.DerivedFrom != null || fields.Count() == 0)
                return;

            string dir = dirTo ? "to" : "initFrom",
                   proto = $"public void {dir}Tpm(TpmBuffer buf)";

            var marshalOps = dirTo ? GetToTpmFieldsMarshalOps(fields)
                                   : GetFromTpmFieldsMarshalOps(fields);

            WriteComment("TpmMarshaller method");
            Write("@Override");
            if (marshalOps.Count == 1)
            {
                // Lay it out in a single line
                Write($"{proto} {{ {marshalOps[0]}; }}");
            }
            else
            {
                Write(proto);
                TabIn("{");
                foreach (var op in marshalOps)
                    Write($"{op};");
                TabOut("}", false);
            }
        } // GenMarshalingMethod()

        void GenStruct(TpmStruct s)
        {
            bool hasBase = s.DerivedFrom != null;
            string className = s.Name;
            string classBases = hasBase ? s.DerivedFrom.Name
                              : !s.IsCmdStruct() ? "TpmStructure"
                              : s.Info.IsRequest() ? "ReqStructure" : "RespStructure";

            // If this struct is not derived from another one and is a member of one or more unions,
            // it must implement the corresponding union interfaces
            if (!s.IsCmdStruct() && !hasBase)
            {
                string unionInterfaces = string.Join(", ", s.ContainingUnions.Select(u => u.Name));
                if (unionInterfaces != "")
                    classBases += " implements " + unionInterfaces;
            }

            // Javadoc comment for the data structure
            WriteComment(s);

            // Class header
            Write($"public class {className} extends {classBases}");
            TabIn("{");

            //
            // Fields
            //
            Debug.Assert(s.Fields.Count == 0 || !hasBase);
            foreach (var f in s.NonSizeFields)
            {
                if (f.MarshalType == MarshalType.ConstantValue)
                    continue;

                WriteComment(f);
                if (f.MarshalType == MarshalType.UnionSelector)
                {
                    var unionField = f.RelatedUnion;
                    var u = (TpmUnion)unionField.Type;
                    Write($"public {f.TypeName} {f.Name}() {{ ", false);
                    if (u.NullSelector == null)
                        Write($"return {unionField.Name}.GetUnionSelector(); }}");
                    else
                    {
                        Write($"return {unionField.Name} != null ? {unionField.Name}.GetUnionSelector()" +
                                                              $" : {u.NullSelector.QualifiedName}; }}");
                    }
                }
                else
                    Write($"public {f.TypeName} {f.Name};");
            }

            //
            // Default constructor
            //
            var fieldsToInit = s.NonDefaultInitFields;
            Write("");
            Write($"public {className}()", false);
            if (fieldsToInit.Count() == 0)
            {
                Write(" {}");
            }
            else if (fieldsToInit.Count() == 1)
            {
                var f = fieldsToInit[0];
                Write($" {{ {f.Name} = {f.GetInitVal()}; }}");
            }
            else
            {
                TabIn("{");
                foreach (StructField f in fieldsToInit)
                    Write($"{f.Name} = {f.GetInitVal()};");
                TabOut("}");
            }

            //
            // Member-wise constructor
            //
            var ctorParams = s.FieldHolder.NonTagFields;
            if (!s.Info.IsResponse() && ctorParams.Count() != 0)
            {
                // Javadoc comments (note that we provide a bit more info for union parameters)
                string javaDocComment = "";
                foreach (var p in ctorParams)
                    javaDocComment += GetParamComment(p, "_") + eol;
                WriteComment(javaDocComment);

                string ctorOpen = $"public {className}(";
                string ctorParamList = string.Join(", ", ctorParams.Select(p => p.TypeName + " _" + p.Name));
                Write(ctorOpen + ctorParamList + ")", false);
                if (hasBase)
                {
                    if (ctorParams.Length == 1)
                        Write($" {{ super(_{ctorParams[0].Name}); }}");
                    else
                    {
                        string ctorParamNamesList = string.Join(", ", ctorParams.Select(p => "_" + p.Name));
                        TabIn("{");
                        Write($"super({ctorParamNamesList});");
                        TabOut("}");
                    }
                }
                else if (ctorParams.Length == 1)
                {
                    var p = ctorParams[0];
                    Write($" {{ {p.Name} = _{p.Name}; }}");
                }
                else
                {
                    TabIn("{");
                    foreach (var p in ctorParams)
                    {
                        // We turn shorts into ints in constructor args, to allow external API users
                        // avoid incessant casting. Instead the cast is hidden in the constructor body.
                        // Note that we cannot change the type of the corresponding members, as it is
                        // dictated by the TPM 2.0 spec.
                        Write($"{p.Name} = _{p.Name};");
                    }
                    TabOut("}");
                }
            }

            //
            // Union interface: TpmUnion.GetUnionSelector()
            //
            GenGetUnionSelector(s);

            //
            // Marshaling
            //
            GenMarshalingMethod(true, s);
            GenMarshalingMethod(false, s);

            WriteComment("@deprecated Use {@link #toBytes()} instead\n" +
                         "@return Wire (marshaled) representation of this object");
            Write("public byte[] toTpm () { return toBytes(); }");

            WriteComment("Static marshaling helper\n" +
                         "@param byteBuf Wire representation of the object\n" +
                         "@return New object constructed from its wire representation");
            Write($"public static {className} fromBytes (byte[] byteBuf) ");
            TabIn("{");
            Write($"return new TpmBuffer(byteBuf).createObj({className}.class);");
            TabOut("}");

            WriteComment("@deprecated Use {@link #fromBytes(byte[])} instead\n" +
                         "@param byteBuf Wire representation of the object\n" +
                         "@return New object constructed from its wire representation");
            Write($"public static {className} fromTpm (byte[] byteBuf)  {{ return fromBytes(byteBuf); }}");

            WriteComment("Static marshaling helper\n" +
                         "@param buf Wire representation of the object\n" +
                         "@return New object constructed from its wire representation");
            Write($"public static {className} fromTpm (TpmBuffer buf) ");
            TabIn("{");
            Write($"return buf.createObj({className}.class);");
            TabOut("}");

            Write("@Override");
            Write("public String toString()");
            TabIn("{");
            Write($"TpmStructurePrinter _p = new TpmStructurePrinter(\"{s.Name}\");");
            Write("toStringInternal(_p, 1);");
            Write("_p.endStruct();");
            Write("return _p.toString();");
            TabOut("}", false);

            if (s.Fields.Count() > 0)
            {
                Write("@Override");
                Write("public void toStringInternal(TpmStructurePrinter _p, int d)");
                TabIn("{");
                foreach (StructField f in ctorParams)
                    Write($"_p.add(d, \"{f.TypeName}\", \"{f.Name}\", {f.Name});");
                TabOut("}", false);
            }

            var info = s.IsCmdStruct() ? s.Info as CmdStructInfo : null;
            if (info != null && (info.NumHandles != 0 || info.SessEncSizeLen != 0))
            {
                if (info.NumHandles != 0)
                {
                    Write("@Override");
                    Write($"public int numHandles() {{ return {info.NumHandles}; }}");
                    if (info.IsRequest())
                    {
                        string handles = string.Join(", ", s.Fields.Take(info.NumHandles).Select(f => ThisMember + f.Name));
                        Write("@Override");
                        Write($"public int numAuthHandles() {{ return {info.NumAuthHandles}; }}");
                        Write("@Override");
                        Write($"public TPM_HANDLE[] getHandles() {{ return new TPM_HANDLE[] {{{handles}}}; }}");
                    }
                    else
                    {
                        Debug.Assert(info.NumHandles == 1 && info.NumAuthHandles == 0);
                        Write("@Override");
                        Write($"public TPM_HANDLE getHandle() {{ return {ThisMember}{s.Fields[0].Name}; }}");
                        Write("@Override");
                        Write($"public void setHandle(TPM_HANDLE h) {{ {ThisMember}{s.Fields[0].Name} = h; }}");
                    }
                }
                if (info.SessEncSizeLen != 0)
                {
                    Debug.Assert(info.SessEncValLen != 0);
                    Write("@Override");
                    Write($"public SessEncInfo sessEncInfo() {{ return new SessEncInfo({info.SessEncSizeLen}, {info.SessEncValLen}); }}");
                }
            }

            InsertSnip(s.Name);
            TabOut("}", false);
        } // GenStruct()

        void GenCommands()
        {
            string tpmComment =
                "The Tpm class provides Java functions to program a TPM.\n" +
                "<P>\n" + 
                "The TPM spec defines TPM command with names like TPM2_PCR_Read().\n" +
                "The Java rendering of the spec drops the 'TPM2_' prefix: e.g. PCR_Read().\n" +
                "The Tpm and TpmBase classes also provide a few helper-functions: for example,\n" +
                "the command _allowErrors() tells to not throw an exception if the next\n" +
                "TPM command returns an error. Such helpers have names beginning with underscore '_'.\n" +
                "<P>\n" +
                "Tpm objects must be \"connected\" to a physical TPM or TPM simulator using the _setDevice()\n" +
                "method.  Some devices (like the TPM simulator) need to be configured before they can be used.\n" +
                "See the sample code that is part of the TSS.Java distribution for more information.";

            WriteComment(tpmComment);
            Write($"public class Tpm extends TpmBase");
            TabIn("{");
            foreach (var req in TpmTypes.Get<TpmStruct>().Where(s => s.Info.IsRequest()))
            {
                GenCommand(req);
            }

            InsertSnip("Tpm");
            TabOut("}", false);
        } // GenCommands()

        void GenCommand(TpmStruct req)
        {
            var resp = GetRespStruct(req);
            var cmdName = GetCommandName(req);
            string respType = resp.Name;
            string cmdCode = "TPM_CC." + cmdName;
            var fields = req.NonTagFields;
            var respFields = resp.NonTagFields;
            if (ForceJustOneReturnParm.Contains(cmdName))
                respFields = respFields.Take(1).ToArray();

            int numOutParms = respFields.Count();
            string returnType = numOutParms == 1 ? respFields[0].TypeName
                              : numOutParms == 0 ? "void" : respType;

            // javadoc annotation
            string annotation = req.Comment + eol + eol;
            foreach (var f in fields)
                annotation += GetParamComment(f) + eol;
            annotation += GetReturnComment(respFields);
            WriteComment(annotation);

            // method definition
            string paramList = "";
            string reqStructInitList = "";
            foreach (var f in fields)
            {
                string comma = Separator(f, fields, ", ");
                paramList += f.TypeName + " " + f.Name + comma;
                reqStructInitList += f.Name + comma;
            }

            Write($"public {returnType} {cmdName}({paramList})");
            TabIn("{");
            Write($"{req.Name} req = new {req.Name}({reqStructInitList});");

            string outParm = "null";
            if (numOutParms != 0)
            {
                Write($"{respType} resp = new {respType}();");
                outParm = "resp";
            }

            Write($"DispatchCommand({cmdCode}, req, {outParm});");
            if (numOutParms == 0)
                Write("return;");
            else if (numOutParms == 1)
                Write("return resp." + respFields[0].Name + ";");
            else
                Write("return resp;");

            TabOut("}");
        } // GenCommand()


        const string ExtraImportsTag = "//ExtraImports";

        string typesTemplate =
            "package tss.tpm;\n" +
            "\n" +
            "import tss.*;\n" +
            ExtraImportsTag + "\n" +
            "\n" +
            "// -----------This is an auto-generated file: do not edit\n" +
            "\n" +
            "//>>>\n" +
            "//<<<\n";

        string tpmObjectTemplate =
            "package tss;\n" +
            "\n" +
            "import tss.tpm.*;\n" +
            ExtraImportsTag + "\n" +
            "\n" +
            "// -----------This is an auto-generated file: do not edit\n" +
            "\n" +
            "//>>>\n" +
            "//<<<\n";


        /// <summary> Writes GeneratedCode to the destination using appropriate template </summary>
        /// <remarks> Replaces everything between  //>>> and //<<< in template file </remarks>
        /// <param name="fileName"> Destination file </param>
        /// <param name="toRemove"> Lines containing toRemove entries are deleted </param>
        /// <param name="tpmCommands"> Selects the appropriate template </param>
        void WriteDef(string fileName, string[] toRemove, bool tpmCommands)
        {
            string template = tpmCommands ? tpmObjectTemplate : typesTemplate;
            StringBuilder b = new StringBuilder();
            string terminatorLine;
            using (StringReader sr = new StringReader(template))
            {
                while (true)
                {
                    string line = sr.ReadLine();
                    if (line == null)
                        break;
                    if (toRemove != null && toRemove.Any(frag => line.Contains(frag)))
                        continue;
                    b.AppendLine(line);
                    if (line.Contains("//>>>"))
                    {
                        // skip everything until the terminator
                        while (true)
                        {
                            var l = sr.ReadLine();
                            if (l == null)
                                throw new Exception("Terminator not found");
                            if (l.Contains("//<<<"))
                            {
                                terminatorLine = l;
                                break;
                            }
                        }
                        // and insert the defs
                        b.AppendLine(GeneratedCode.ToString());
                        GeneratedCode.Clear();
                        b.AppendLine(terminatorLine);
                    }
                }
            }

            string temp = b.ToString();
            b.Clear();
            temp = temp.Replace(ExtraImportsTag, needsUtil ? "import java.util.*;" : "");
            needsUtil = false;
            File.WriteAllText(fileName, temp);
        }

        protected override void WriteComment(string comment, bool wrap = true)
        {
            WriteComment(comment, "/** ", " *  ", "\n */", wrap);
        }
    } // class CGenJava
}
