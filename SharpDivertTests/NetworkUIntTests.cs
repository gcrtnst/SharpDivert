/*
 * NetworkUInt16Tests.cs
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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using SharpDivert;

namespace SharpDivertTests
{
    [TestClass]
    public class NetworkUInt16Tests
    {
        [TestMethod]
        [DataRow((ushort)0x0123, (byte)0x01, (byte)0x23)]
        public unsafe void Op_Implicit_NetworkUInt16(ushort input, byte expected0, byte expected1)
        {
            var actual = (NetworkUInt16)input;
            Assert.AreEqual(expected0, ((byte*)&actual)[0]);
            Assert.AreEqual(expected1, ((byte*)&actual)[1]);
        }

        [TestMethod]
        [DataRow((byte)0x01, (byte)0x23, (ushort)0x0123)]
        public unsafe void Op_Implicit_UInt16(byte input0, byte input1, ushort expected)
        {
            var x = new NetworkUInt16();
            ((byte*)&x)[0] = input0;
            ((byte*)&x)[1] = input1;
            var actual = (ushort)x;
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        [DataRow((ushort)0x0123)]
        public void Equals_EquivalentObject(ushort x)
        {
            var left = (NetworkUInt16)x;
            var right = (NetworkUInt16)x;
            Assert.IsTrue(left.Equals(right));
        }

        public static IEnumerable<object?[]> Equals_NonEquivalentObject_Data => new object?[][]
        {
            new object?[] { (NetworkUInt16)0x0123, null },
            new object?[] { (NetworkUInt16)0x0123, (ushort)0x2301 },
            new object?[] { (NetworkUInt16)0x0123, (ushort)0x0123 },
            new object?[] { (NetworkUInt16)0x0123, (NetworkUInt16)0x2301 },
        };

        [TestMethod]
        [DynamicData(nameof(Equals_NonEquivalentObject_Data))]
        public void Equals_NonEquivalentObject(NetworkUInt16 left, object? right) => Assert.IsFalse(left.Equals(right));
    }

    [TestClass]
    public class NetworkUInt32Tests
    {
        [TestMethod]
        [DataRow((uint)0x01234567, (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67)]
        public unsafe void Op_Implicit_NetworkUInt32(uint input, byte expected0, byte expected1, byte expected2, byte expected3)
        {
            var actual = (NetworkUInt32)input;
            Assert.AreEqual(expected0, ((byte*)&actual)[0]);
            Assert.AreEqual(expected1, ((byte*)&actual)[1]);
            Assert.AreEqual(expected2, ((byte*)&actual)[2]);
            Assert.AreEqual(expected3, ((byte*)&actual)[3]);
        }

        [TestMethod]
        [DataRow((byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (uint)0x01234567)]
        public unsafe void Op_Implicit_UInt32(byte input0, byte input1, byte input2, byte input3, uint expected)
        {
            var x = new NetworkUInt32();
            ((byte*)&x)[0] = input0;
            ((byte*)&x)[1] = input1;
            ((byte*)&x)[2] = input2;
            ((byte*)&x)[3] = input3;
            var actual = (uint)x;
            Assert.AreEqual(expected, actual);
        }

        [TestMethod]
        [DataRow((uint)0x01234567)]
        public void Equals_EquivalentObject(uint x)
        {
            var left = (NetworkUInt32)x;
            var right = (NetworkUInt32)x;
            Assert.IsTrue(left.Equals(right));
        }

        public static IEnumerable<object?[]> Equals_NonEquivalentObject_Data => new object?[][]
        {
            new object?[] { (NetworkUInt32)0x01234567, null },
            new object?[] { (NetworkUInt32)0x01234567, (uint)0x67452301 },
            new object?[] { (NetworkUInt32)0x01234567, (uint)0x01234567 },
            new object?[] { (NetworkUInt32)0x01234567, (NetworkUInt32)0x67452301 },
        };

        [TestMethod]
        [DynamicData(nameof(Equals_NonEquivalentObject_Data))]
        public void Equals_NonEquivalentObject(NetworkUInt32 left, object? right) => Assert.IsFalse(left.Equals(right));
    }
}
