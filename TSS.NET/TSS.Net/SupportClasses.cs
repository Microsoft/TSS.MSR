/* 
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Linq;
using System.Text;

#if !TSS_USE_BCRYPT
using System.Security.Cryptography;
#endif


namespace Tpm2Lib
{
    public class ByteBuf
    {
        private const int DefaultSize = 1024;
        private int PutPos;
        private int GetPos;
        private byte[] Buf;

        public ByteBuf()
        {
            Buf = new byte[DefaultSize];
            PutPos = 0;
            GetPos = 0;
        }

        public ByteBuf(int size)
        {
            Buf = new byte[size];
            PutPos = 0;
            GetPos = 0;
        }

        public ByteBuf(byte[] x)
        {
            Buf = x;
            GetPos = 0;
            PutPos = x.Length;
        }

        public ByteBuf Clone()
        {
            var newBuf = new ByteBuf(GetBuffer());
            newBuf.GetPos = GetPos;
            newBuf.PutPos = PutPos;
            return newBuf;
        }

        public int BytesRemaining()
        {
            return PutPos - GetPos;
        }

        public void Append(byte[] x)
        {
            if (PutPos + x.Length > Buf.Length)
            {
                // Extend the array
                int newLen = Buf.Length * 2;
                if (newLen < PutPos + x.Length)
                {
                    // Big input hack
                    newLen = (PutPos + x.Length) + 1024;
                }
                var buf2 = new byte[newLen];
                Array.Copy(Buf, buf2, Buf.Length);
                Buf = buf2;
            }
            Array.Copy(x, 0, Buf, PutPos, x.Length);
            PutPos += x.Length;
        }

        public byte[] GetBuffer()
        {
            var temp = new byte[PutPos];
            Array.Copy(Buf, temp, PutPos);
            return temp;
        }

        public void SetBytesInMiddle(byte[] bytesToSet, int pos)
        {
            if (pos + bytesToSet.Length > GetSize())
            {
                Globs.Throw<ArgumentOutOfRangeException>("Position is not in allocated buffer");
                if (GetSize() > pos)
                    Array.Copy(bytesToSet, 0, Buf, pos, GetSize() - pos);
                return;
            }
            Array.Copy(bytesToSet, 0, Buf, pos, bytesToSet.Length);
        }

        public byte[] GetBytesInMiddle(int startPos, int length)
        {
            var temp = new byte[length];
            Array.Copy(Buf, startPos, temp, 0, length);
            return temp;
        }

        public byte[] RemoveBytesInMiddle(int startPos, int length)
        {
            byte[] res = GetBytesInMiddle(startPos, length);
            // Close the gap
            for (int j = startPos; j < PutPos - length; j++)
            {
                Buf[j] = Buf[j + length];
            }
            PutPos -= length;
            return res;
        }

        public void Reset()
        {
            PutPos = 0;
            GetPos = 0;
        }

        public int GetSize()
        {
            return PutPos;
        }

        public int GetGetPos()
        {
            return GetPos;
        }

        public void SetGetPos(int newGetPos)
        {
            if (newGetPos < 0 || newGetPos > GetSize())
            {
                Globs.Throw("SetGetPos: Invalid position");
                GetPos = newGetPos < 0 ? 0 : GetSize();
                return;
            }
            GetPos = newGetPos;
        }

        public byte[] Extract(int num)
        {
            if (GetPos + num > PutPos)
            {
                Globs.Throw<ArgumentOutOfRangeException>("ByteBuf exception removing "
                    + num + " bytes at position " + GetPos + " from an array of " + PutPos);
                return null;
            }
            var ret = new byte[num];
            Array.Copy(Buf, GetPos, ret, 0, num);
            GetPos += num;
            return ret;
        }
    }

    /// <summary>
    /// provide implementation of a pseudo-RNG used by all TSS.Net facilities. 
    /// </summary>
    public class PRNG
    {
        public const int RandMaxBytes = 1024 * 1024;

        /// <summary>
        /// PRNG seed for the  for this run.  Can be set by SetRngSeed() or from
        /// the standard system RNG.
        /// </summary>
        private byte[] Seed;

        /// <summary>
        /// A buffer of random data that is emptied on calls to GetRandom() and filled
        /// when the buffer is empty through FillRandBuf().
        /// </summary>
        private ByteBuf Buf = new ByteBuf();

        /// <summary>
        /// Counter for each round of buffer filling.
        /// </summary>
        private int Round;

#if !TSS_USE_BCRYPT
        /// <summary>
        /// Default RNG used by the library
        /// </summary>
        private static readonly RNGCryptoServiceProvider CryptoRand = new RNGCryptoServiceProvider();
#endif

        /// <summary>
        /// Creates a copy of the current object
        /// </summary>
        public PRNG Clone()
        {
            var prng = new PRNG();
            lock (this)
            {
                prng.Seed = Globs.CopyData(Seed);
                prng.Buf = Buf.Clone();
                prng.Round = Round;
            }
            return prng;
        }

        /// <summary>
        /// Set the PRNG seed. If this routine is not called then the seed is generated
        /// by the system RNG. Note that there is one RNG shared by all threads using
        /// TPM library services, so non-determinism is to be expected in multi-threaded
        /// programs even when the RNG is seeded.
        /// </summary>
        public void SetRngSeed(string seed)
        {
            lock (this)
            {
                Seed = seed == null ? new byte[0]
                                    : CryptoLib.HashData(TpmAlgId.Sha256,
                                                         Encoding.UTF8.GetBytes(seed));
                Round = 0;
                FillRandBuf();
            }
        }

        /// <summary>
        /// Set the tester PRNG seed to random value from the system RNG
        /// </summary>
        public void SetRngRandomSeed()
        {
            lock (this)
            {
                if (Seed != null)
                    return;
                Seed = new byte[32];
#if TSS_USE_BCRYPT
                var rnd = new Random();
                rnd.NextBytes(Seed);
#else
                CryptoRand.GetBytes(Seed);
#endif
                Round = 0;
                FillRandBuf();
            }
        }

        /// <summary>
        /// Retrives the requested number of pseudo-random bytes from the internal pool,
        /// and replenishes it, if necessary.
        /// </summary>
        public byte[] GetRandomBytes(int numBytes)
        {
            if (numBytes > RandMaxBytes)
            {
                Globs.Throw<ArgumentException>("GetRandomBytes: Too many bytes requested " + numBytes);
                numBytes = RandMaxBytes;
            }
            // Make sure that the RNG is properly seeded
            if (Seed == null)
            {
                SetRngRandomSeed();
            }
            // Fill or refill the buffer
            lock (this)
            {
                    // ReSharper disable once PossibleNullReferenceException
                if (Buf.BytesRemaining() < numBytes)
                {
                    FillRandBuf();
                }
                // And return the data
                return Buf.Extract(numBytes);
            }
        }

        private void FillRandBuf()
        {
            // Fill the buffer with random data
            byte[] data = KDF.KDFa(TpmAlgId.Sha256, Seed, "RNG",
                                   BitConverter.GetBytes(Round),
                                   new byte[0], RandMaxBytes * 8);
            Round++;
            Buf = new ByteBuf(data);
        }
    } // PRNG

    /// <summary>
    /// Provides formatting for structures and other TPM types.
    /// </summary>
    internal class TpmStructPrinter
    {
        private StringBuilder B;

        /// <summary>
        /// Current printing indent
        /// </summary>
        private int Indent;

        internal TpmStructPrinter()
        {
            B = new StringBuilder();
            Indent = 0;
        }

        public override String ToString()
        {
            // Do some final formatting (change ^ for tab)
            int firstCharInLine = 0;
            int numSpacesAtStart = 0;
            bool inStartSpaces = true;
            int tabNum = 0;

            for (int j = 0; j < B.Length; j++)
            {
                if (B[j] == '\n')
                {
                    firstCharInLine = j;
                    inStartSpaces = true;
                    tabNum = 0;
                    numSpacesAtStart = 0;
                    continue;
                }
                if (inStartSpaces && B[j] != ' ')
                {
                    inStartSpaces = false;
                    firstCharInLine = j;
                    numSpacesAtStart++;
                }
                if (B[j] == '^')
                {
                    tabNum++;
                    int tabPos = numSpacesAtStart + 0 + tabNum * 16;
                    int currentColumn = j - firstCharInLine;
                    string toInsert = " "; // At least one space
                    if (currentColumn < tabPos)
                    {
                        toInsert = new string(' ', tabPos - currentColumn);
                    }
                    B = B.Replace("^", toInsert, j, 1);
                }
            }
            return B.ToString();
        }

        internal void PrintName(string name)
        {
            B.AppendFormat("{0}\n", name);
            Indent++;
        }

        private void AddLine(StringBuilder b, string formatString, params string[] data)
        {
            const int firstTab = 24;
            const int secondTab = 50;
            // Coding
            //   @ - first tab
            //   # - second tab
            // We always add indent spaces

            // ReSharper disable once RedundantAssignment
            String s = formatString = Spaces() + formatString;

            // Is anything too big to fit?
            if (data[1].Length > secondTab - firstTab)
            {
                string dd = data[1];
                if (dd.Contains('|'))
                {
                    // Split enum OR onto multiple lines
                    dd = dd.Replace("|", "|\n" + new String(' ', firstTab + 1));
                }
                if (dd.Contains(".."))
                {
                    // Split hex array
                    dd = dd.Replace("..", "..\n" + new String(' ', firstTab + 2));
                }
                data[1] = dd;

            }

            // Fill it in
            // ReSharper disable once CoVariantArrayConversion
            s = String.Format(s, data);

            // Set the tabs
            string outS = "";
            int column = 0;
            foreach (char c in s)
            {
                if (c == '\n')
                {
                    column = -1;
                }
                if (c == '@')
                {
                    int numSpaces = firstTab - column;
                    if (numSpaces <= 0)
                    {
                        numSpaces = 1;
                    }
                    outS += new String(' ', numSpaces);
                    column += numSpaces;
                    continue;
                }
                if (c == '#')
                {
                    int numSpaces = secondTab - column;
                    if (numSpaces <= 0)
                    {
                        numSpaces = 1;
                    }
                    outS += new String(' ', numSpaces);
                    column += numSpaces;
                    continue;
                }
                outS += c;
                column++;
            }
            outS += "\n";
            b.Append(outS);
        }

        internal void Print(string name, string type, Object o)
        {
            if (o == null)
            {
                // E.g. inPrivate null SomeStruct
                AddLine(B, "{0}@{1}#{2}", name, "null", type);
                return;
            }

            // ReSharper disable once CanBeReplacedWithTryCastAndCheckForNull
            if (o is TpmStructureBase)
            {
                string ss = type;
                if (ss.StartsWith("I"))
                {
                    // If the member is an interface, also print the type of entity being dumped
                    string intType = o.GetType().ToString();
                    intType = intType.Substring(intType.LastIndexOf('.') + 1);

                    type = intType;
                }
                if(o is TpmHandle)
                {
                   TpmHandle tpmHandle = o as TpmHandle;
                   //Pring the HT of the handle
                    string handleName = tpmHandle.GetType().ToString();
                    //If it is a permanet handle, pring also the RH name
                    if(tpmHandle.GetType() == Ht.Permanent)
                        handleName += " -" + ((TpmRh)tpmHandle.handle).ToString();
                    name = string.Format("({0})", handleName);
                }
                // Print name and type but not the contents (printed recursively later)
                AddLine(B, "{0}@-#{1}", name, type);
                // Recurse
                Indent++;
                ((TpmStructureBase)o).ToStringInternal(this);
                Indent--;
                return;
            }

            // ReSharper disable once CanBeReplacedWithTryCastAndCheckForNull
            if (o is Enum)
            {
                var en = (Enum)o;
                string s = Enum.Format(en.GetType(), en, "g");
                s = s.Replace(',', '|');
                // name   Elem1|Elem2
                AddLine(B, "{0}@{1}#{2}", name, s, type);
                return;
            }

            if (o is ValueType)
            {
                //checked that this actually works with Int64, etc.
                var val = o is UInt64 ? (Int64)Convert.ToUInt64(o) : Convert.ToInt64(o);

                string hexString = Convert.ToString(val, 16);

                // ReSharper disable once SpecifyACultureInStringConversionExplicitly
                AddLine(B, "{0}@{1} (0x{2})#{3}", name, o.ToString(), hexString, type);
                return;
            }

            // ReSharper disable once CanBeReplacedWithTryCastAndCheckForNull
            if (o is Array)
            {
                var a = (Array)o;
                Type elementType = o.GetType().GetElementType();
                if (elementType == typeof (byte))
                {
                    // Byte arrays as special - 
                    string hexString = "0x" + Globs.HexFromByteArray((byte[])a, 8);
                    string typeString = String.Format("byte[{0}]", a.Length);
                    AddLine(B, "{0}@{1}#{2}", name, hexString, typeString);
                    return;
                }
                // ReSharper disable once RedundantIfElseBlock
                else
                {
                    B.AppendFormat("{0}Array - {1}[{2}]\n", Spaces(), type, a.Length);
                    Indent++;
                    for (int j = 0; j < a.Length; j++)
                    {
                        Object elem = a.GetValue(j);
                        // ReSharper disable once SpecifyACultureInStringConversionExplicitly
                        Print(elem.GetType().ToString(), j.ToString(), elem);
                    }
                    Indent--;
                    return;
                }
            }
            Globs.Throw<NotImplementedException>("Print: Unknown type " + o.GetType());
        }

        private string Spaces()
        {
            return new String(' ', Indent * 2);
        }
    }
}
