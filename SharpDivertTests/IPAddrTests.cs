/*
 * IPAddrTests.cs
 * Copyright gcrtnst
 *
 * This file is part of SharpDivert.
 *
 * SharpDivert is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * SharpDivert is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with SharpDivert.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SharpDivert is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * SharpDivert is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with SharpDivert; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

using System.Collections.Generic;
using System.Runtime.CompilerServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpDivert;

namespace SharpDivertTests
{
    [TestClass]
    public class IPv4AddrTests
    {
        [TestMethod]
        [DataRow("127.0.0.1", (uint)0x7f000001)]
        public void Parse_ValidString(string input, uint expected)
        {
            var addr = IPv4Addr.Parse(input);
            var actual = Unsafe.As<IPv4Addr, uint>(ref addr);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        [DataRow("")]
        [DataRow("2001:db8:85a3::8a2e:370:7334")]
        public void Parse_InvalidString(string input)
        {
            var e = Assert.ThrowsException<WinDivertException>(() => IPv4Addr.Parse(input));
            Assert.AreEqual("WinDivertHelperParseIPv4Address", e.WinDivertNativeMethod);
            Assert.AreEqual(87, e.NativeErrorCode);
        }

        [TestMethod]
        [DataRow((uint)0x7f000001, "127.0.0.1")]
        public void ToString(uint input, string expected)
        {
            var addr = new IPv4Addr();
            Unsafe.As<IPv4Addr, uint>(ref addr) = input;
            var actual = addr.ToString();
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        [DataRow("127.0.0.1")]
        public void Equals_EquivalentObject(string input)
        {
            var left = IPv4Addr.Parse(input);
            var right = (object?)left;
            Assert.IsTrue(left.Equals(right));
        }

        public static IEnumerable<object?[]> Equals_NonEquivalentObject_Data => new object?[][]
        {
            new object?[] { IPv4Addr.Parse("127.0.0.1"), null },
            new object?[] { IPv4Addr.Parse("127.0.0.1"), IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334") },
            new object?[] { IPv4Addr.Parse("127.0.0.1"), (NetworkIPv4Addr) IPv4Addr.Parse("127.0.0.1") },
            new object?[] { IPv4Addr.Parse("127.0.0.1"), IPv4Addr.Parse("127.0.0.2") },
        };

        [TestMethod]
        [DynamicData(nameof(Equals_NonEquivalentObject_Data))]
        public void Equals_NonEquivalentObject(IPv4Addr left, object? right) => Assert.IsFalse(left.Equals(right));

        [TestMethod]
        [DataRow("0.0.0.0")]
        [DataRow("127.0.0.1")]
        [DataRow("255.255.255.255")]
        public void GetHashCode(string input)
        {
            var addr1 = IPv4Addr.Parse(input);
            var addr2 = IPv4Addr.Parse(input);
            var hash1 = addr1.GetHashCode();
            var hash2 = addr2.GetHashCode();
            Assert.AreEqual(hash1, hash2);
        }
    }

    [TestClass]
    public class NetworkIPv4AddrTests
    {
        [TestMethod]
        [DataRow((uint)0x7f000001, (byte)0x7f, (byte)0x00, (byte)0x00, (byte)0x01)]
        public unsafe void Op_Implicit_NetworkIPv4Addr(uint input, byte expected0, byte expected1, byte expected2, byte expected3)
        {
            var addr = new IPv4Addr();
            Unsafe.As<IPv4Addr, uint>(ref addr) = input;
            var actual = (NetworkIPv4Addr)addr;
            Assert.AreEqual(expected0, ((byte*)&actual)[0]);
            Assert.AreEqual(expected1, ((byte*)&actual)[1]);
            Assert.AreEqual(expected2, ((byte*)&actual)[2]);
            Assert.AreEqual(expected3, ((byte*)&actual)[3]);
        }

        [TestMethod]
        [DataRow((byte)0x7f, (byte)0x00, (byte)0x00, (byte)0x01, (uint)0x7f000001)]
        public unsafe void Op_Implicit_IPv4Addr(byte input0, byte input1, byte input2, byte input3, uint expected)
        {
            var inputAddr = new NetworkIPv4Addr();
            ((byte*)&inputAddr)[0] = input0;
            ((byte*)&inputAddr)[1] = input1;
            ((byte*)&inputAddr)[2] = input2;
            ((byte*)&inputAddr)[3] = input3;
            var actualAddr = (IPv4Addr)inputAddr;
            var actual = Unsafe.As<IPv4Addr, uint>(ref actualAddr);
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        [DataRow("127.0.0.1")]
        public void Equals_EquivalentObject(string input)
        {
            var left = (NetworkIPv4Addr)IPv4Addr.Parse(input);
            var right = (object?)(NetworkIPv4Addr)IPv4Addr.Parse(input);
            Assert.IsTrue(left.Equals(right));
        }

        public static IEnumerable<object?[]> Equals_NonEquivalentObject_Data => new object?[][]
        {
            new object?[] { (NetworkIPv4Addr)IPv4Addr.Parse("127.0.0.1"), null },
            new object?[] { (NetworkIPv4Addr)IPv4Addr.Parse("127.0.0.1"), IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334") },
            new object?[] { (NetworkIPv4Addr)IPv4Addr.Parse("127.0.0.1"), IPv4Addr.Parse("127.0.0.1") },
            new object?[] { (NetworkIPv4Addr)IPv4Addr.Parse("127.0.0.1"), (NetworkIPv4Addr)IPv4Addr.Parse("127.0.0.2") },
        };

        [TestMethod]
        [DynamicData(nameof(Equals_NonEquivalentObject_Data))]
        public void Equals_NonEquivalentObject(NetworkIPv4Addr left, object? right) => Assert.IsFalse(left.Equals(right));

        [TestMethod]
        [DataRow("0.0.0.0")]
        [DataRow("127.0.0.1")]
        [DataRow("255.255.255.255")]
        public void GetHashCode(string input)
        {
            var addr1 = (NetworkIPv4Addr)IPv4Addr.Parse(input);
            var addr2 = (NetworkIPv4Addr)IPv4Addr.Parse(input);
            var hash1 = addr1.GetHashCode();
            var hash2 = addr2.GetHashCode();
            Assert.AreEqual(hash1, hash2);
        }
    }

    [TestClass]
    public class IPv6AddrTests
    {
        [TestMethod]
        [DataRow("2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334")]
        [DataRow("127.0.0.1", "::7f00:1")]
        public void Parse_ValidString(string input, string expected)
        {
            var addr = IPv6Addr.Parse(input);
            var actual = addr.ToString();
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        [DataRow("")]
        public void Parse_InvalidString(string input)
        {
            var e = Assert.ThrowsException<WinDivertException>(() => IPv6Addr.Parse(input));
            Assert.AreEqual("WinDivertHelperParseIPv6Address", e.WinDivertNativeMethod);
            Assert.AreEqual(87, e.NativeErrorCode);
        }

        [TestMethod]
        [DataRow("2001:db8:85a3::8a2e:370:7334")]
        public void Equals_EquivalentObject(string input)
        {
            var left = IPv6Addr.Parse(input);
            var right = (object?)IPv6Addr.Parse(input);
            Assert.IsTrue(left.Equals(right));
        }

        public static IEnumerable<object?[]> Equals_NonEquivalentObject_Data => new object?[][]
        {
            new object?[] { IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334"), null },
            new object?[] { IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334"), IPv4Addr.Parse("127.0.0.1") },
            new object?[] { IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334"), (NetworkIPv6Addr)IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334") },
            new object?[] { IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334"), IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7335") },
        };

        [TestMethod]
        [DynamicData(nameof(Equals_NonEquivalentObject_Data))]
        public void Equals_NonEquivalentObject(IPv6Addr left, object? right) => Assert.IsFalse(left.Equals(right));

        [TestMethod]
        [DataRow("::")]
        [DataRow("2001:db8:85a3::8a2e:370:7334")]
        [DataRow("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
        public void GetHashCode(string input)
        {
            var addr1 = IPv6Addr.Parse(input);
            var addr2 = IPv6Addr.Parse(input);
            var hash1 = addr1.GetHashCode();
            var hash2 = addr2.GetHashCode();
            Assert.AreEqual(hash1, hash2);
        }
    }

    [TestClass]
    public class NetworkIPv6AddrTests
    {
        [TestMethod]
        public unsafe void Op_Implicit_NetworkIPv6Addr()
        {
            var input = IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334");
            var actual = (NetworkIPv6Addr)input;
            Assert.AreEqual<byte>(0x20, ((byte*)&actual)[0]);
            Assert.AreEqual<byte>(0x01, ((byte*)&actual)[1]);
            Assert.AreEqual<byte>(0x0d, ((byte*)&actual)[2]);
            Assert.AreEqual<byte>(0xb8, ((byte*)&actual)[3]);
            Assert.AreEqual<byte>(0x85, ((byte*)&actual)[4]);
            Assert.AreEqual<byte>(0xa3, ((byte*)&actual)[5]);
            Assert.AreEqual<byte>(0x00, ((byte*)&actual)[6]);
            Assert.AreEqual<byte>(0x00, ((byte*)&actual)[7]);
            Assert.AreEqual<byte>(0x00, ((byte*)&actual)[8]);
            Assert.AreEqual<byte>(0x00, ((byte*)&actual)[9]);
            Assert.AreEqual<byte>(0x8a, ((byte*)&actual)[10]);
            Assert.AreEqual<byte>(0x2e, ((byte*)&actual)[11]);
            Assert.AreEqual<byte>(0x03, ((byte*)&actual)[12]);
            Assert.AreEqual<byte>(0x70, ((byte*)&actual)[13]);
            Assert.AreEqual<byte>(0x73, ((byte*)&actual)[14]);
            Assert.AreEqual<byte>(0x34, ((byte*)&actual)[15]);
        }

        [TestMethod]
        public unsafe void Op_Implicit_IPv6Addr()
        {
            var input = new NetworkIPv6Addr();
            ((byte*)&input)[0] = 0x20;
            ((byte*)&input)[1] = 0x01;
            ((byte*)&input)[2] = 0x0d;
            ((byte*)&input)[3] = 0xb8;
            ((byte*)&input)[4] = 0x85;
            ((byte*)&input)[5] = 0xa3;
            ((byte*)&input)[6] = 0x00;
            ((byte*)&input)[7] = 0x00;
            ((byte*)&input)[8] = 0x00;
            ((byte*)&input)[9] = 0x00;
            ((byte*)&input)[10] = 0x8a;
            ((byte*)&input)[11] = 0x2e;
            ((byte*)&input)[12] = 0x03;
            ((byte*)&input)[13] = 0x70;
            ((byte*)&input)[14] = 0x73;
            ((byte*)&input)[15] = 0x34;
            var actual = (IPv6Addr)input;
            var expected = IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334");
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        [DataRow("2001:db8:85a3::8a2e:370:7334")]
        public void Equals_EquivalentObject(string input)
        {
            var left = (NetworkIPv6Addr)IPv6Addr.Parse(input);
            var right = (object?)(NetworkIPv6Addr)IPv6Addr.Parse(input);
            Assert.IsTrue(left.Equals(right));
        }

        public static IEnumerable<object?[]> Equals_NonEquivalentObject_Data => new object?[][]
        {
            new object?[] { (NetworkIPv6Addr)IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334"), null },
            new object?[] { (NetworkIPv6Addr)IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334"), IPv4Addr.Parse("127.0.0.1") },
            new object?[] { (NetworkIPv6Addr)IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334"), IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334") },
            new object?[] { (NetworkIPv6Addr)IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7334"), (NetworkIPv6Addr)IPv6Addr.Parse("2001:db8:85a3::8a2e:370:7335") },
        };

        [TestMethod]
        [DynamicData(nameof(Equals_NonEquivalentObject_Data))]
        public void Equals_NonEquivalentObject(NetworkIPv6Addr left, object? right) => Assert.IsFalse(left.Equals(right));

        [TestMethod]
        [DataRow("::")]
        [DataRow("2001:db8:85a3::8a2e:370:7334")]
        [DataRow("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")]
        public void GetHashCode(string input)
        {
            var addr1 = (NetworkIPv6Addr)IPv6Addr.Parse(input);
            var addr2 = (NetworkIPv6Addr)IPv6Addr.Parse(input);
            var hash1 = addr1.GetHashCode();
            var hash2 = addr2.GetHashCode();
            Assert.AreEqual(hash1, hash2);
        }
    }
}
