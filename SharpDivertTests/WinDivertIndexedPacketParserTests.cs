/*
 * WinDivertIndexedPacketParserTests.cs
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

using System;
using System.Net;
using System.Net.Sockets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpDivert;

namespace SharpDivertTests
{
    [TestClass]
    public class WinDivertIndexedPacketParserTests
    {
        private const int Port1 = 52149;
        private const int Port2 = 52150;
        private readonly Memory<byte> recv;

        public WinDivertIndexedPacketParserTests()
        {
            var send = new byte[] { 0, 1, 2 };
            var packet = new Memory<byte>(new byte[WinDivert.MTUMax]);
            var abuf = (Span<WinDivertAddress>)stackalloc WinDivertAddress[3];

            using var sender = new UdpClient(new IPEndPoint(IPAddress.Loopback, Port1));
            sender.Connect(IPAddress.Loopback, Port2);

            using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, Port2));
            receiver.Connect(IPAddress.Loopback, Port1);

            using var divert = new WinDivert($"udp.SrcPort == {Port1} and udp.DstPort == {Port2} and loopback", WinDivert.Layer.Network, 0, WinDivert.Flag.Sniff | WinDivert.Flag.RecvOnly);
            _ = sender.Send(send, 1);
            _ = sender.Send(send, 2);
            _ = sender.Send(send, 3);

            var recvOff = 0;
            var addrOff = 0;
            while (addrOff < 3)
            {
                var (recvLen, addrLen) = divert.RecvEx(packet.Span[recvOff..], abuf[addrOff..]);
                recvOff += (int)recvLen;
                addrOff += (int)addrLen;
            }
            recv = packet[..recvOff];
        }

        [TestMethod]
        public void MoveNext()
        {
            using var enumerator = new WinDivertIndexedPacketParser(recv).GetEnumerator();
            Assert.IsTrue(enumerator.MoveNext());
            Assert.AreEqual(0, enumerator.Current.Item1);
            Assert.AreEqual<byte>(17, enumerator.Current.Item2.Protocol);
            Assert.IsTrue(enumerator.MoveNext());
            Assert.AreEqual(1, enumerator.Current.Item1);
            Assert.AreEqual<byte>(17, enumerator.Current.Item2.Protocol);
            Assert.IsTrue(enumerator.MoveNext());
            Assert.AreEqual(2, enumerator.Current.Item1);
            Assert.AreEqual<byte>(17, enumerator.Current.Item2.Protocol);
            Assert.IsFalse(enumerator.MoveNext());
            Assert.IsFalse(enumerator.MoveNext());
        }

        [TestMethod]
        public void Reset()
        {
            using var enumerator = new WinDivertIndexedPacketParser(recv).GetEnumerator();
            _ = enumerator.MoveNext();
            _ = enumerator.MoveNext();
            _ = enumerator.MoveNext();
            enumerator.Reset();
            Assert.IsTrue(enumerator.MoveNext());
            Assert.AreEqual(0, enumerator.Current.Item1);
            Assert.AreEqual<byte>(17, enumerator.Current.Item2.Protocol);
        }
    }
}
