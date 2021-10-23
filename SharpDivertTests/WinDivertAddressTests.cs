/*
 * WinDivertAddressTests.cs
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
using SharpDivert;

namespace SharpDivertTests
{
    [TestClass]
    public class WinDivertAddressTests
    {
        [TestMethod]
        [DataRow(nameof(WinDivertAddress.Sniffed), (byte)(1 << 0))]
        [DataRow(nameof(WinDivertAddress.Outbound), (byte)(1 << 1))]
        [DataRow(nameof(WinDivertAddress.Loopback), (byte)(1 << 2))]
        [DataRow(nameof(WinDivertAddress.Impostor), (byte)(1 << 3))]
        [DataRow(nameof(WinDivertAddress.IPv6), (byte)(1 << 4))]
        [DataRow(nameof(WinDivertAddress.IPChecksum), (byte)(1 << 5))]
        [DataRow(nameof(WinDivertAddress.TCPChecksum), (byte)(1 << 6))]
        [DataRow(nameof(WinDivertAddress.UDPChecksum), (byte)(1 << 7))]
        public unsafe void Flag_Get(string name, byte input)
        {
            var addr = new WinDivertAddress();
            var flag = addr.GetType().GetProperty(name)!;
            Assert.IsFalse((bool)flag.GetValue(addr)!);

            *((byte*)&addr + 10) = input;
            Assert.IsTrue((bool)flag.GetValue(addr)!);
        }

        [TestMethod]
        [DataRow(nameof(WinDivertAddress.Sniffed), (byte)(1 << 0))]
        [DataRow(nameof(WinDivertAddress.Outbound), (byte)(1 << 1))]
        [DataRow(nameof(WinDivertAddress.Loopback), (byte)(1 << 2))]
        [DataRow(nameof(WinDivertAddress.Impostor), (byte)(1 << 3))]
        [DataRow(nameof(WinDivertAddress.IPv6), (byte)(1 << 4))]
        [DataRow(nameof(WinDivertAddress.IPChecksum), (byte)(1 << 5))]
        [DataRow(nameof(WinDivertAddress.TCPChecksum), (byte)(1 << 6))]
        [DataRow(nameof(WinDivertAddress.UDPChecksum), (byte)(1 << 7))]
        public unsafe void Flag_Set(string name, byte expected)
        {
            var addr = new WinDivertAddress();
            var flag = addr.GetType().GetProperty(name)!;
            var obj = (object)addr;
            flag.SetValue(obj, true);
            addr = (WinDivertAddress)obj;
            Assert.AreEqual(expected, *((byte*)&addr + 10));
        }
    }
}
