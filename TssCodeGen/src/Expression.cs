/*
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See the LICENSE file in the project root for full license information.
 */

using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Globalization;


namespace CodeGen
{

    class Token
    {
    }

    // Uses long (64-bit) to correctly handle unsigned 32-bit TPM constants (e.g. 0x80000000)
    // that would overflow a signed int.
    class Operand : Token
    {
        string  _Value;
        long?   _NumValue;

        public Operand (string val) { _Value = val; }
        public Operand (long   val) { _NumValue = val; }

        public static implicit operator Operand (string val) { return new Operand(val); }
        public static implicit operator Operand (long   val) { return new Operand(val); }

        public string Value { get { return _Value; } }

        public long NumericValue
        {
            get
            {
                if (_NumValue == null)
                    _NumValue = Expression.Eval(Value);
                return (long)_NumValue;
            }
        }
    } // class Operand

    enum OpCode
    {
        None,
        LeftParen,
        RightParen,
        Plus,
        Minus,
        Mul,
        Div,
        Shl,
        Sizeof
    }

    class Operator : Token
    {
        static readonly string[] OpString =  {"", "(", ")", "+", "-", "*", "/", "<<", "sizeof"};
        static readonly int[]    Priority =  { 0,  0,   0,   2,   2,   3,   3,   1,    4 };

        OpCode Op;

        public Operator (OpCode op) { Op = op; }

        public static bool operator < (Operator lhs, Operator rhs)
        {
            return Priority[(int)lhs.Op] < Priority[(int)rhs.Op];
        }

        public static bool operator > (Operator lhs, Operator rhs)
        {
            return Priority[(int)lhs.Op] > Priority[(int)rhs.Op];
        }

        public static bool operator <= (Operator lhs, Operator rhs)
        {
            return !(lhs > rhs);
        }

        public static bool operator >= (Operator lhs, Operator rhs)
        {
            return !(lhs < rhs);
        }

        public bool Is (OpCode op)
        {
            return Op == op;
        }

        public long Apply (long lhs, long rhs)
        {
            switch(Op)
            {
                case OpCode.Plus: return lhs + rhs;
                case OpCode.Minus: return lhs - rhs;
                case OpCode.Mul: return lhs * rhs;
                case OpCode.Div: return lhs / rhs;
                case OpCode.Shl: return lhs << (int)rhs;
            }
            throw new Exception("Unknown OpCode");
        }

        public void Apply (Stack<Operand> operands)
        {
            if (Op == OpCode.Sizeof)
            {
                operands.Push((int)TpmTypes.Lookup(operands.Pop().Value).GetSize());
                return;
            }
            Operand rhs = operands.Pop();
            Operand lhs = operands.Pop();
            operands.Push(Apply(lhs.NumericValue, rhs.NumericValue));
        }
    } // class Operator

    class Expression
    {
        public static bool IsNumber(string val)
        {
            long numIs;
            return Int64.TryParse(val, out numIs) ||
                   val.ToLower().StartsWith("0x") &&
                   Int64.TryParse(val.Substring(2), NumberStyles.HexNumber,
                                  new NumberFormatInfo(), out numIs);
        }

        /// <remarks> If this method goes into an infinite loop, this usually means that 
        /// the Part 2, or  Vendor Specicfic part of the TPM 2.0 spec added a new constant 
        /// value defined not in a table, but rather in a NOTE. In this case this definition
        /// needs to be manually added into the ImplementationConstants array. </remarks>
        public static long Eval(string val)
        {
            if (IsNumber(val))
            {
                return Convert.ToInt64(val, val.ToLower().StartsWith("0x") ? 16 : 10);
            }
            if (TpmTypes.ContainsConstant(val))
            {
                return TpmTypes.LookupConstant(val).NumericValue;
            }

            var tokens = Tokenize(val);
            var ops = new Stack<Operator>();
            var values = new Stack<Operand>();
            for (int i = 0; i < tokens.Length; ++i)
            {
                var tok = tokens[i];

                if (tok is Operand)
                {
                    values.Push((Operand)tok);
                    continue;
                }
                var op = (Operator)tok;
                if (op.Is(OpCode.Sizeof))
                {
                    Debug.Assert(tokens.Length > i + 2);
                    string typeName = (tokens[i + 2] as Operand).Value;
                    Debug.Assert(TpmTypes.Contains(typeName));
                    var e = TpmTypes.Lookup(typeName);
                    // Workaround for _PRIVATE max size
                    values.Push(new Operand(typeName == "_PRIVATE" ? 1024 : e.GetSize()));
                    i += 3;
                    continue;
                }
                if (ops.Count == 0 || op.Is(OpCode.LeftParen) || ops.Peek() < op)
                {
                    Debug.Assert(!op.Is(OpCode.RightParen));
                    ops.Push(op);
                    continue;
                }
                else
                {
                    do {
                        Operator prevOp = ops.Pop();
                        if (prevOp.Is(OpCode.LeftParen))
                        {
                            Debug.Assert(op.Is(OpCode.RightParen));
                            break;
                        }
                        prevOp.Apply(values);
                    }
                    while (ops.Count > 0 && ops.Peek() >= op);

                    if (!op.Is(OpCode.RightParen))
                    {
                        ops.Push(op);
                    }
                }
            }
            while (ops.Count > 0)
            {
                ops.Pop().Apply(values);
            }
            Debug.Assert(values.Count == 1);
            long res = values.Pop().NumericValue;
            return res;
        }

        static bool IsWhitespace (char c)
        {
            return c == ' ' || c <= 32;
        }

        static Token[] Tokenize (string expression)
        {
            var tokens = new List<Token>();
            char[] expr = expression.ToCharArray();
            int i = 0;
            while (i < expr.Length)
            {
                // Skip whitespace
                while (IsWhitespace(expr[i]) && ++i < expr.Length)
                {
                    continue;
                }
                if (i == expr.Length)
                {
                    break;
                }

                OpCode op = ParseOpCode(expr, ref i);
                if (op != OpCode.None)
                {
                    tokens.Add(new Operator(op));
                    continue;
                }

                int j = i, k = 0;
                while (op == OpCode.None && !IsWhitespace(expr[i]) && ++i < expr.Length)
                {
                    k = i;
                    op = ParseOpCode(expr, ref i);
                }
                tokens.Add(new Operand(new string(expr, j, (op == OpCode.None ? i : k) - j)));
                if (op != OpCode.None)
                {
                    tokens.Add(new Operator(op));
                }
            }
            return tokens.ToArray();
        }

        static OpCode ParseOpCode (char[] expr, ref int idx)
        {
            switch (expr[idx++])
            {
            case '(':
                return OpCode.LeftParen;
            case ')':
                return OpCode.RightParen;
            case '+':
                return OpCode.Plus;
            case '-':
                return OpCode.Minus;
            case '*':
                return OpCode.Mul;
            case '/':
                return OpCode.Div;
            case '<':
                if (idx < expr.Length && expr[idx++] == '<')
                {
                    return OpCode.Shl;
                }
                idx -= 2;
                throw new Exception(string.Format("Unsupported op code at pos {0} in expression {1}", idx, expr.ToString()));
            case 's':
            {
                // Match 'sizeof()' sub-expression
                const int funcNameLen = 6;
                if (expr.Length > idx + funcNameLen)
                {
                    char sep = expr[idx + funcNameLen - 1];
                    if (new string(expr, idx - 1, funcNameLen) == "sizeof" &&
                        (sep == ' ' || sep == '('))
                    {
                        idx += funcNameLen - 1;
                        return OpCode.Sizeof;
                    }
                }
                break;
            }
            }
            --idx;
            return OpCode.None;
        }
    } // class Expression
}
