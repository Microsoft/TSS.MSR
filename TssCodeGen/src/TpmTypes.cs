/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace CodeGen
{

    /// <summary> Static class containing dictionaries with AST classes and their access and manipulation helpers </summary>
    public static class TpmTypes
    {
        static public readonly string EmptyUnionBaseName = "TPMS_NULL_UNION";
        static public TpmStruct EmptyUnionBase;

        static public  List<TpmType> TheTypes = new List<TpmType>();

        static Dictionary<string, TpmType> TypeIndex = new Dictionary<string, TpmType>();
        static Dictionary<string, TpmNamedConstant> ConstantIndex = new Dictionary<string, TpmNamedConstant>();

        public static IEnumerable<TpmNamedConstant> Constants => ConstantIndex.Values;

        public static IEnumerable<T> Get<T>() where T: TpmType
        {
            return TheTypes.Where(t => t is T && t.Implement).Cast<T>();
        }

        /// <summary> Adds fundamental type definitions and a couple of custom classes </summary>
        internal static void Init()
        {
            foreach (var et in TargetLang.GetElementaryTypes())
                Add(et);

            TpmStruct s = new TpmStruct("TPM_HANDLE", "Handle of a loaded TPM key or other object [TSS]", null, null, true);
            s.Add(new StructField("UINT32", "handle", "Handle value"));
            s.UnderlyingType = Lookup("UINT32");
            Add(s);

            // Create and register empty structs for unions
            string descr = "Base class for empty union elements.\n" +
                    "An empty union element does not contain any data to marshal.\n" +
                    "This data structure can be used in place of any other union\n" +
                    "initialized with its own empty element.";
            EmptyUnionBase = new TpmStruct(EmptyUnionBaseName, descr);
            Add(EmptyUnionBase);
        }

        public static void InitEnum (string[,] values, string insertAfter = null)
        {
            var e = new TpmEnum (values[0, 0], values[0, 1], values[0, 2]);
            for (int i = 1; i < values.GetLength(0); ++i)
            {
                e.Add(values[i,0], values[i, 1], values[i, 2]);
            }
            Add(e, insertAfter);
        }

        internal static void Add(TpmType t, string insertAfter = null)
        {
            if (TypeIndex.ContainsKey(t.SpecName))
            {
                Debug.WriteLine($"TpmType.Add: Type {t.SpecName} is already defined");
                return;
            }

            if (insertAfter == null)
                TheTypes.Add(t);
            else
                TheTypes.Insert(TheTypes.IndexOf(TheTypes.First(x => x.SpecName == insertAfter)) + 1, t);

            TypeIndex.Add(t.SpecName, t);
            return;
        }

        internal static bool Remove(string typeName)
        {
            if (!TypeIndex.ContainsKey(typeName))
            {
                return false;
            }
            TheTypes.Remove(TypeIndex[typeName]);
            TypeIndex.Remove(typeName);
            return true;
        }

        internal static TpmType Lookup(string name)
        {
            return TypeIndex.ContainsKey(name) ? TypeIndex[name] : null;
        }

        internal static bool Contains(string name)
        {
            return TypeIndex.ContainsKey(name);
        }

        internal static bool AddConstant(TpmNamedConstant nc)
        {
            if (ConstantIndex.ContainsKey(nc.SpecName) ||
                (nc.SpecName.ToLower().Contains("reserved") && nc.EnclosingEnum.SpecName != "TPM_RC"))
            {
                return false;
            }
            ConstantIndex.Add(nc.SpecName, nc);
            return true;
        }

        internal static bool RemoveConstant(string name)
        {
            if (!ConstantIndex.ContainsKey(name))
                return false;
            ConstantIndex.Remove(name);
            return true;
        }

        internal static TpmNamedConstant LookupConstant(string constantName)
        {
            if (!ConstantIndex.ContainsKey(constantName))
            {
                //string altName = "ALG_" + constantName + "_VALUE";
                string altName = "TPM_ALG_" + constantName;
                if (ConstantIndex.ContainsKey(altName))
                    return ConstantIndex[altName];
                else
                    return null;
            }
            return ConstantIndex[constantName];
        }

        internal static bool ContainsConstant(string constantName)
            => ConstantIndex.ContainsKey(constantName) || ConstantIndex.ContainsKey("TPM_ALG_" + constantName);

        public static string AlgNull => TpmTypes.LookupConstant("TPM_ALG_NULL").QualifiedName;
    } // static class TpmTypes


    /// <summary> Base class for the AST classes representing all TPM 2.0 spec data types </summary>
    public abstract class TpmType
    {
        public TpmType UnderlyingType;
        public string SpecName;
        public string Name;
        public string Comment;
        protected int Size;

        // Response code that should be returned if unmarshaling the object of this
        // type fails (for typedefs and enums).
        public TpmConstExpr UnmarshalingError;

        public bool Implement = true;
        public bool InheritMarshalingID = false; // for C++ only

        void Init(string specName, string comment, int size, TpmType underlyingType)
        {
            SpecName = specName;
            Comment = comment;
            Size = size;
            UnderlyingType = underlyingType;
        }

        public TpmType (TpmType src)
        {
            Init(src.SpecName, src.Comment, src.Size, src.UnderlyingType);
        }

        public TpmType (string specName, string comment = "", string underlyingType = null, int size = 0)
        {
            Init(specName, comment, size,
                 underlyingType == null ? null : TpmTypes.Lookup(underlyingType));
        }

        // Types that do not have an underlying type, must override this method.
        // Size in bytes of the TPM representation built for an entity of the type
        // defined by this TpmType-derived object .
        public virtual int CalcSize()
        {
            return UnderlyingType.GetSize();
        }

        public int GetSize()
        {
            if (Size == 0)
                Size = CalcSize();
            return Size;
        }

        public static bool operator == (TpmType lhs, TpmType rhs)
        {
            return (object)lhs == null ? (object)rhs == null
                                       : (object)rhs != null && lhs.SpecName == rhs.SpecName;
        }

        public static bool operator != (TpmType lhs, TpmType rhs)
        {
            return !(lhs == rhs);
        }

        public static bool operator < (TpmType lhs, TpmType rhs)
        {
            return (object)lhs == null ? (object)rhs != null
                                       : (object)rhs != null && string.Compare(lhs.SpecName, rhs.SpecName) < 0;
        }

        public static bool operator > (TpmType lhs, TpmType rhs)
        {
            return !((lhs < rhs) || (lhs == rhs));
        }

        public override bool Equals(Object obj)
        {
            return this == (TpmType)obj;
        }

        public override int GetHashCode()
        {
            return SpecName.GetHashCode();
        }

        public TpmType StripTypedefs()
            => this is TpmTypedef ? UnderlyingType.StripTypedefs() : this;

        public TpmType GetFinalUnderlyingType()
            => UnderlyingType == null ? this : UnderlyingType.GetFinalUnderlyingType();

        public bool IsElementary() => StripTypedefs() is TpmValueType;

        public bool IsAlgOrHashAlg() => SpecName.IsOneOf("TPMI_ALG_HASH", "TPM_ALG_ID");
    } // class TpmType


    /// <summary> Base class for the AST classes representing fields of the TPM 2.0 spec 
    /// enums, bitfields, and unions. </summary>
    public class TpmField
    {
        /// <summary> Data type associated by the TPM 2.0 spec with this field </summary>
        /// <remarks> In the case of data structures the actual type of the field in the resulting
        /// TSS code (and whether any filed is generated at all) takes into account other field 
        /// attributes (e.g. whether it is an array or constant). </remarks>
        public TpmType Type;

        /// <summary> Original field name in the TPM 2.0 spec </summary>
        /// <remarks> A few names are simplified during the type extraction phase, but otherwise
        /// these names are used unchanaged by all target languages (with the only exclusion being
        /// capitalization of ) </remarks>
        public string Name;

        /// <summary> Comment associated with this field in the TPM 2.0 spec </summary>
        public string Comment;

        public TpmField(string fieldTypeName, string fieldName, string comment)
        {
            Type = TpmTypes.Lookup(fieldTypeName);
            Name = fieldName;
            Comment = comment;
        }
    } // class TpmField

    /// <summary> AST class representing a TPM 2.0 typedef </summary>
    /// <remarks> TSS implementations for all languages (including C++ for consistency) implement typedefs
    /// as derived classes. <BR>
    /// Note also that these TSS implementations do not provide TPMI_ typedefs (aliases of integer types),
    /// as they are only inroduced in the TPM 2.0 spec to specify tighter type/value checks in the TPM 
    /// // implementations, and duplicating the same checks on the TSS side does not make any sense.
    /// </remarks>
    public class TpmTypedef : TpmType
    {
        public Domain  Values = new CodeGen.Domain();
        public TpmConstExpr OptionalValue;

        public TpmTypedef(string typeName, string underlyingType, string comment)
            : base(typeName, comment, underlyingType)
        {
        }
    }


    // Represents TPM 2.0 primitive types
    public class TpmValueType : TpmType
    {
        public TpmValueType(string typeName, int size)
            : base(typeName, "", null, size)
        {
        }

        public override int CalcSize()
        {
            return Size;
        }
    }


    /// <summary> AST class representing a TPM 2.0 enum </summary>
    /// <remarks> Enums are defined in the TPM 2.0 spec as a group of named constants with 
    /// a common prefix in the same table. This prfix forms the name of the enumeration class.
    /// </remarks> 
    public class TpmEnum : TpmType
    {
        public List<TpmNamedConstant> Members;

        public TpmEnum(string typeName, string underlyingType, string comment)
            : base (typeName, comment, underlyingType)
        {
            Members = new List<TpmNamedConstant>();
        }

        public TpmNamedConstant Add(string name, string value, string comment)
        {
            var nc = new TpmNamedConstant(this, name, value, comment);
            if (!TpmTypes.AddConstant(nc))
                return null;
            Members.Add(nc);
            return nc;
        }

        public bool Remove(TpmNamedConstant member)
        {
            if (!TpmTypes.RemoveConstant(member.SpecName))
                return false;
            return Members.Remove(member);
        }
    } // class TpmEnum


    /// <summary> AST class representing a TPM 2.0 bitfield </summary>
    public class TpmBitfield : TpmType
    {
        public List<BitfieldElement> Elements;

        public TpmBitfield(string typeName, string underlyingType, string comment)
            : base(typeName, comment, underlyingType)
        {
            Elements = new List<BitfieldElement>();
        }

        public BitfieldElement Add(string name, string comment, int startBit, int endBit)
        {
            if (name.ToLower() == "reserved")
                return null;

            BitfieldElement newRow = new BitfieldElement(name, comment, startBit, endBit, this);
            Elements.Add(newRow);
            return newRow;
        }
    } // class TpmBitfield


    /// <summary> AST class representing a member of a TPM 2.0 bitfield </summary>
    public class BitfieldElement : TpmField
    {
        public int StartBit;
        public int EndBit;
        TpmBitfield EnclosingBitfield;

        public BitfieldElement(string name, string comment,
                               int startBit, int endBit, TpmBitfield enclosingBitfield)
            : base("UINT32", name, comment)
        {
            Name = name;
            Comment = comment;
            StartBit = startBit;
            EndBit = endBit;
            EnclosingBitfield = enclosingBitfield;
        }

        public int CalcSize()
        {
            return EnclosingBitfield.GetSize();
        }

        public static bool operator == (BitfieldElement lhs, BitfieldElement rhs)
        {
            return (object)lhs == null ? (object)rhs == null
                                       : (object)rhs != null &&
                                         lhs.Name == rhs.Name && lhs.Name == rhs.Name;
        }

        public static bool operator != (BitfieldElement lhs, BitfieldElement rhs)
        {
            return !(lhs == rhs);
        }

        public override bool Equals(Object obj)
        {
            return this == (BitfieldElement)obj;
        }

        public override int GetHashCode()
        {
            return EnclosingBitfield.SpecName.GetHashCode() ^ Name.GetHashCode();
        }

        public string TranslatedName => TargetLang.TransConstantName(Name, EnclosingBitfield);
        
        // For backward compatibility
        public string OldStyleName => TargetLang.TransConstantName(Name, EnclosingBitfield, true);
    } // class BitfieldElement


    /// <summary> A structure information query interface (with default behavior) </summary>
    public class StructInfo
    {
        public virtual bool IsRequest() { return false; }
        public virtual bool IsResponse() { return false; }
    }

    /// <summary> Structure information base class </summary>
    public class TpmStructInfo : StructInfo
    {
        public HashSet<TpmUnion> ContainingUnions;

        public TpmStructInfo()
        {
            ContainingUnions = new HashSet<TpmUnion>();
        }
    }

    /// <summary> Structure information class specialized for the (custom) data structures
    /// representing TPM 2.0 command (request) and response parametrs </summary>
    public class CmdStructInfo : StructInfo
    {
        public bool Request;
        public int  NumHandles,
                    NumAuthHandles,
                    SessEncSizeLen,
                    SessEncValLen;

        public CmdStructInfo(bool request, int numHandles)
        {
            Request = request;
            NumHandles = numHandles;
        }

        public override bool IsRequest() { return Request; }
        public override bool IsResponse() { return !Request; }
    }

    /// <summary> AST class representing a TPM 2.0 data structure </summary>
    public class TpmStruct : TpmType
    {
        public TpmStruct DerivedFrom;
        public List<StructField> Fields;

        public StructInfo Info;

        public bool IsCmdStruct() => Info is CmdStructInfo;

        public int NumHandles => (Info as CmdStructInfo).NumHandles;
        public int NumAuthHandles => (Info as CmdStructInfo).NumAuthHandles;

        public HashSet<TpmUnion> ContainingUnions => (Info as TpmStructInfo)?.ContainingUnions;


        public TpmStruct(TpmStruct src)
            : base(src)
        {
            Fields = src.Fields;
            DerivedFrom = src.DerivedFrom;
            Info = src.Info;
        }

        public TpmStruct(string typeName, string comment,
                         TpmStruct derivedFrom = null, StructInfo info = null,
                         bool customizedImpl = false)
            : base(typeName, comment)
        {
            Fields = new List<StructField>();
            DerivedFrom = derivedFrom;
            Debug.Assert(DerivedFrom == null || TpmTypes.Contains(DerivedFrom.SpecName));
            Info = info ?? new TpmStructInfo();
        }

        public void RemoveFields(int pos = -1, int numFileds = -1)
        {
            if (pos == -1)
                Fields.Clear();
            else
                Fields.RemoveRange(pos, numFileds != -1 ? numFileds : Fields.Count - pos);
        }

        public override string ToString() => Name;

        public IEnumerable<StructField> TagFields => Fields.Where(f => f.IsTag());

        public StructField[] NonTagFields => Fields.Where(f => !f.IsTag()).ToArray();

        public StructField[] NonSizeFields
            => Fields.Where(f => f.MarshalType != MarshalType.ArrayCount && 
                            f.MarshalType != MarshalType.LengthOfStruct).ToArray();

        public StructField[] MarshalFields { get {
            var fields = NonSizeFields;
            if (!IsCmdStruct() || NumHandles == 0 || (TargetLang.DotNet && Info.IsResponse()))
                return fields;
            return fields.Skip(NumHandles).ToArray(); }
        }

        // NOTE: Changes together with StructField.GetInitVal()
        public StructField[] NonDefaultInitFields { get {
            return NonTagFields.Where(f => {
                    if (f.IsArray())
                        return false;
                    string typeName = f.Type.StripTypedefs().SpecName;
                    return typeName == "UINT32" && f.Name == "handle" ||
                            (TargetLang.Cpp ? typeName == "TPM_ALG_ID"
                                        : typeName.IsOneOf("TPM_ALG_ID", "TPM_HANDLE"));
            }).ToArray(); }
        }

        public TpmStruct FieldHolder
            => DerivedFrom == null ? this :
               DerivedFrom.DerivedFrom == null ? DerivedFrom : DerivedFrom.DerivedFrom;

        public void Add(StructField f)
        {
            Fields.Add(f);
            var countTag = f.SizeTagField;
            if (countTag == null)
            {
                Debug.Assert(f.SizedField == null || f.IsTag() || f.Type.IsAlgOrHashAlg());
                return;
            }
            Debug.Assert(countTag.MarshalType == MarshalType.LengthOfStruct ? f.MarshalType == MarshalType.Normal : f.IsArray());

            // TSS implementations marshal variable length byte buffers tagged with an algorithm as fixed size arrays,
            // i.e. without marshaling the numeric size tag, as the algorithm tag (marshaled as a normal field)
            // is used to determine the buffer size.
            if (countTag.MarshalType == MarshalType.Normal && countTag.Type.IsAlgOrHashAlg())
                f.MarshalType = MarshalType.SpecialVariableLengthArray;
        }

        public void RegisterContainingUnion(TpmUnion u)
        {
            if (u.Implement && !ContainingUnions.Contains(u))
            {
                ContainingUnions.Add(u);
                if (DerivedFrom != null)
                    DerivedFrom.RegisterContainingUnion(u);
            }
        }

        public StructField Lookup(string name)
        {
            foreach (StructField f in Fields)
            {
                if (name == f.Name)
                    return f;
            }
            return null;
        }

        public override int CalcSize()
        {
            int size = 0;
            foreach (var f in Fields)
            {
                var counter = f.SizeTagField;
                Debug.Assert(counter == null ||
                             (counter.MarshalType == MarshalType.LengthOfStruct ? f.MarshalType == MarshalType.SizedStruct : f.IsArray()));
                Debug.Assert(f.SizedField == null || f.IsTag() || f.Type.IsAlgOrHashAlg());
                if (counter != null)
                {
                    if (counter.MarshalType == MarshalType.LengthOfStruct)
                        size += (int)counter.MaxVal.NumericValue;
                    else if (counter.MarshalType == MarshalType.Normal && counter.Type.IsAlgOrHashAlg())
                        size += 64; // corresponds to SHA512 digest size
                    continue;
                }
                size += (int)f.Type.GetSize() * (counter != null ? (int)counter.MaxVal.NumericValue : 1);
            }
            return size;
        }
    } // class TpmStruct


    /// <summary> AST class representing a TPM 2.0 union </summary>
    /// <remarks> Since none of the managed languages supports unions, all TSS implementations
    /// model them using interface-based approach. C union from the TPM 2.0 spec becomes an interface,
    /// and its member structures become classes implementing this interface. The only method of the
    /// union interface returns selector value (usually algorithm ID) corersponding to the given member.
    /// </remarks>
    public class TpmUnion : TpmType
    {
        public List<UnionMember> Members;
        public bool AllowNull = false;
        public TpmNamedConstant NullSelector;

        public TpmUnion(string typeName, string comment)
            : base(typeName, comment)
        {
            Members = new List<UnionMember>();
        }

        public override int CalcSize()
        {
            int size = 0;
            foreach (var f in Members)
            {
                int fieldSize = f.Type.GetSize();
                if (f.ArraySize != null)
                    fieldSize *= (int)f.ArraySize.NumericValue;
                size = Math.Max(size, fieldSize);
            }
            return size;
        }

        public void Add(UnionMember newMem)
        {
            Members.Add(newMem);

            TpmType tdt = newMem.Type.StripTypedefs();
            if (tdt is TpmStruct)
                (tdt as TpmStruct).RegisterContainingUnion(this);
        }

        public UnionMember GetMemberOfType(TpmStruct s)
        {
            UnionMember elt = null;
            do {
                elt = GetElementOfType(s);
                s = s.DerivedFrom; 
            } while (elt == null && s != null);
            return elt;
        }

        public UnionMember GetElementOfType(TpmStruct s)
        {
            // First look for the exact type match ...
            foreach (UnionMember m in Members)
            {
                if (m.Type.SpecName == s.SpecName)
                    return m;
            }
            // ... then see if we have a matching typedef or derived type
            foreach (UnionMember m in Members)
            {
                if (m.Type is TpmTypedef)
                {
                    TpmType underlyingType = m.Type.StripTypedefs();
                    if (underlyingType.SpecName == s.SpecName)
                        return m;
                }
                else if (m.Type is TpmStruct)
                {
                    TpmStruct b = (m.Type as TpmStruct).DerivedFrom;
                    while (b != null)
                    {
                        if (b.SpecName == s.SpecName)
                            return m;
                        b = b.DerivedFrom;
                    }
                }
            }
            return null;
        }

        public bool IsSubsetOf(TpmUnion u)
        {
            foreach (UnionMember m in Members)
            {
                if (!u.Members.Contains(m) &&
                    !m.Type.SpecName.StartsWith("TPMS_NULL_"))
                {
                    return false;
                }
            }
            return true;
        }
    } // class TpmUnion


    /// <summary> AST class representing a member data structure of a TPM 2.0 union </summary>
    /// <remarks> See the remarks to the TpmUnion class </remarks>
    public class UnionMember : TpmField
    {
        public TpmNamedConstant SelectorValue;
        public TpmConstExpr ArraySize;

        public UnionMember(string typeName, string fieldName, string selectorName, string comment)
            : base(typeName, fieldName, comment)
        {
            Match m;
            if ((m = Regex.Match(fieldName, @"^(?<name>\w+)\s*\[?(?<val>[^\]]*)\)?]?")).Success)
            {
                Name = m.Groups["name"].ToString();
                Debug.Assert(Name.Length > 0);

                string arraySize = m.Groups["val"].ToString();
                if (arraySize != "")
                {
                    ArraySize = arraySize;
                }
            }
            SelectorValue = TpmTypes.LookupConstant(selectorName); 
        }

        public static bool operator == (UnionMember lhs, UnionMember rhs)
        {
            return (object)lhs == null ? (object)rhs == null
                                       : (object)rhs != null && lhs.Type == rhs.Type;
        }

        public static bool operator != (UnionMember lhs, UnionMember rhs)
        {
            return !(lhs == rhs);
        }

        public override bool Equals(Object obj)
        {
            return this == (UnionMember)obj;
        }

        public override int GetHashCode()
        {
            return (int)Type.GetHashCode();
        }
    } // class TpmUnionElement


    /// <summary> Specifies how a TPM data structure member should be marshaled 
    /// (i.e. converted to/from the wire representation defined by the TPM 2.0 spec) </summary>
    public enum MarshalType
    {
        ConstantValue, 
        Normal,
        ArrayCount, 
        FixedLengthArray,
        VariableLengthArray,
        SpecialVariableLengthArray,
        EncryptedVariableLengthArray,
        SizedStruct,
        LengthOfStruct,
        UnionSelector,
        UnionObject
    }

    public enum StructFieldAttr
    {
        NeedsAuth = 0x01,   // Unused by the TSS CodeGen
        // MayBeNull indicates that a structure may be null (i.e. not marshaled at all)
        MayBeNull = 0x02,   // Unused by the TSS CodeGen
        TermOnNull = 0x04
    }

    /// <summary> AST class representing a field of a TPM 2.0 data structure </summary>
    public class StructField : TpmField
    {
        /// <summary> Actual data type of this field expressed with the current target language syntax </summary>
        /// <remarks> In the case of data structures the actual type of the field in the resulting
        /// TSS code (and whether any filed is generated at all) takes into account other field 
        /// attributes (e.g. whether it is an array or constant). </remarks>
        public string TypeName;

        /// <summary> Defines the complete type of this field, its wire representation, 
        /// and its role in the marshaling of other fields </summary>
        public MarshalType MarshalType;

        /// <summary> Properties affecting various (post-)marshaling checks done by the TPM </summary>
        /// <remarks> TSS Codegen only uses the TermOnNull attribute </remarks>
        public StructFieldAttr Attrs = 0;

        /// <summary> Some fields serve as tags for other fields, and this member holds the reference
        /// to the filed paired with this one (either the tag or the tagged). </summary>
        /// <remarks> Specific relationships are reflected by the properties used to access this member:
        /// RelatedUnion, SizedField, SizeTagField, or UnionField.UnionSelector. </remarks>
        protected StructField AssociatedField = null;

        /// <summary> Another field of this struct (of a union interface type), for which this field 
        /// serves as a tag (i.e. determines the concrete type of the object implementing the union 
        /// interface) </summary>
        /// <remarks> There may be more than one union field associated with the same tag fieled </remarks>
        public UnionField RelatedUnion
        {
            get => MarshalType == MarshalType.UnionSelector ? AssociatedField as UnionField : null;
            set => AssociatedField = value;
        }

        /// <summary> If this member is set, it references other field of the same data structure (of 
        /// a structure or an array type), and this object is an int field that specifies the size of
        /// the refernced field. </summary>
        public StructField SizedField
        {
            get => AssociatedField != null && AssociatedField.IsSized() ? AssociatedField : null;
            set => AssociatedField = value;
        }

        /// <summary> If this field is a structure or an array that has an associated size field 
        /// (a tag field), this member references the tag filed. Note that all constraints on allowed
        /// size are specified by the Domain member of the tag field (even though the TPM 2.0 spec
        /// often splits them between size and array fields). </summary>
        public StructField SizeTagField
        {
            get => IsSized() ? AssociatedField : null;
            set => AssociatedField = value;
        }

        bool IsSized()
        {
            return MarshalType.IsOneOf(MarshalType.SizedStruct, MarshalType.VariableLengthArray,
                                       MarshalType.SpecialVariableLengthArray, MarshalType.EncryptedVariableLengthArray);
        }

        /// <summary> Underlying memebr for the Domain property </summary>
        Domain _Domain = null;

        /// <summary> If set, specifies allowed values of this field </summary>
        /// <remarks> Allowed values may be a single value, a range of values, or a list of values </remarks>
        public Domain Domain
        {
            get => _Domain ?? (_Domain = new CodeGen.Domain());
            set => _Domain = value;
        }

        public StructField(string typeName, string fieldName, string comment,
                           MarshalType fieldSort = MarshalType.Normal)
            : base(typeName, fieldName, comment)
        {
            MarshalType = fieldSort;
        }

        public StructField(StructField src, string newFieldName)
            : this (src.Type.SpecName, newFieldName, src.Comment, src.MarshalType)
        {
            _Domain = src._Domain;
            Attrs = src.Attrs;
        }

        public TpmConstExpr MinVal => Domain?.Count == 0 ? null : Domain[0, Constraint.Type.Min];
        public TpmConstExpr MaxVal => Domain?.Count == 0 ? null : Domain[0, Constraint.Type.Max];

        public bool IsArray() => this is VariableLengthArray;

        public bool IsByteBuffer() => IsArray() && Type.SpecName == "BYTE";

        public bool IsSizeTag()
            => MarshalType.IsOneOf(MarshalType.ArrayCount, MarshalType.LengthOfStruct);

        public bool IsTag()
            => IsSizeTag() || MarshalType.IsOneOf(MarshalType.UnionSelector, MarshalType.ConstantValue);

        public bool IsValueType()
        {
            var underlyingType = Type.StripTypedefs();
            Debug.Assert(Type.SpecName != "TPMT_HA" || !(underlyingType is TpmValueType));
            return underlyingType is TpmValueType ||
                   (!TargetLang.Java && (underlyingType is TpmEnum || underlyingType is TpmBitfield));
        }

        public bool IsEnum()
        {
            var type = Type.StripTypedefs();
            return type is TpmEnum || type is TpmBitfield;
        }

        public void SetRelatedUnion(UnionField f)
        {
            Debug.Assert(f.UnionSelector != null);
            if (RelatedUnion == null)
                RelatedUnion = f;
            else
            {
                // No more than 2 union fields in the same data structure in the current TPM 2.0 spec
                Debug.Assert(RelatedUnion.NextUnion == null);
                RelatedUnion.NextUnion = f;
                Debug.Assert(RelatedUnion.UnionSelector == f.UnionSelector);
            }
        }

        // NOTE: Changes together with TpmStruct.NonDefaultInitFields()
        public string GetInitVal()
        {
            if (IsArray())
                return TargetLang.Null;

            string typeName = Type.StripTypedefs().SpecName;
            if (typeName == "UINT32" && Name == "handle")
                return TargetLang.EnumeratorAsUint("TPM_RH_NULL");
            if (typeName == "TPM_ALG_ID")
                return TpmTypes.AlgNull;
            if (typeName == "TPM_HANDLE")
                return TargetLang.NewObject(Type.Name);
            return IsValueType() ? "0" : TargetLang.Null;
        }
    } // class StructField


    /// <summary> AST class representing a array member of a TPM 2.0 data structure </summary>
    public class VariableLengthArray : StructField
    {
        public VariableLengthArray(string typeName, string fieldName, string comment,
                                   string arrayCountName, TpmStruct enclosingStruct)
            : base(typeName, fieldName, comment, MarshalType.VariableLengthArray)
        {
            // The tag field must have its MarshalType correctly set before assignment to the SizeTagField preperty
            StructField tag = enclosingStruct.Lookup(arrayCountName);
            tag.MarshalType = MarshalType.ArrayCount;
            tag.SizedField = this;
            SizeTagField = tag;
        }
    }

    /// <summary> AST class representing a union member of a TPM 2.0 data structure </summary>
    public class UnionField : StructField
    {
        /// <summary> Reference to the field that serves as a tag (selector) for this fieled
        /// of a union interface type. (The tag specifies the concrete type of the object 
        /// implementing the interface that is the value of this field.) </summary>
        public StructField UnionSelector
        {
            get => AssociatedField;
            set => AssociatedField = value;
        }

        /// <summary> Next union field (of the same data structure) associated with the same
        /// tag fieled or null </summary>
        public UnionField NextUnion = null;

        public UnionField(string typeName, string fieldName, string comment,
                          string unionSelector, TpmStruct enclosingStruct)
            : base(typeName, fieldName, comment, MarshalType.UnionObject)
        {
            UnionSelector = enclosingStruct.Lookup(unionSelector);
            UnionSelector.SetRelatedUnion(this);
            enclosingStruct.Lookup(unionSelector).MarshalType = MarshalType.UnionSelector;
        }
    } // class UnionField


    /// <summary> Class capturing an expression specifying a constant value in the TPM 2.0 spec </summary>
    public class TpmConstExpr
    {
        /// <summary> Original form of the constant expression in the TPM 2.0 spec.
        /// <remarks> It may be a number, a named constant (TpmNamedConstant) or 
        /// an arithmetic expression thereof. </remarks>
        public string Expr;

        public TpmConstExpr(string expr)
        {
            Expr = expr;
        }

        public static implicit operator TpmConstExpr(string s)
        {
            return new TpmConstExpr(s);
        }

        /// <summary> Result of computing the constant's value expression </summary>
        public long NumericValue => Expression.Eval(Expr);
    } // class TpmConstExpr


    /// <summary> Class representing members of TPM 2.0 enums </summary>
    public class TpmNamedConstant
    {
        /// <summary> Original constant name in the TPM 2.0 spec </summary>
        public string SpecName;

        /// <summary> Original value of the constant in the TPM 2.0 spec </summary>
        public TpmConstExpr SpecValue;

        /// <summary> Comment associated with this constant in the TPM 2.0 spec </summary>
        public string Comment;

        /// <summary> Enum containing this constant as its member </summary>
        public TpmEnum EnclosingEnum;

        /// <summary> Name transformed in accordance with the current target language conventions </summary>
        public string Name;

        /// <summary> Name transformed in accordance with the current target language conventions </summary>
        /// <remarks> For backward compatibility only </remarks>
        public string OldStyleName;

        /// <summary> Value transformed in accordance with the current target language syntax </summary>
        public string Value;

        public TpmNamedConstant(TpmEnum enclosingEnum, string specName, string value, string comment)
        {
            EnclosingEnum = enclosingEnum;
            SpecName = specName;
            SpecValue = value;
            Comment = comment;
            Debug.Assert(value == null || specName != value);
        }

        /// <summary> Result of computing the constant's value expression </summary>
        public long NumericValue => SpecValue.NumericValue;

        /// <summary> Enum member name qualified with the its enum type name </summary>
        public string QualifiedName => EnclosingEnum.Name + TargetLang.ClassMember + Name;
    } // class TpmNamedConstant
}
