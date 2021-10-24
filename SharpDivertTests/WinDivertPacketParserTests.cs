/*
 * WinDivertPacketParserTests.cs
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
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpDivert;

namespace SharpDivertTests
{
    [TestClass]
    public class WinDivertPacketParserTests
    {
        private const int Port1 = 52149;
        private const int Port2 = 52150;
        private readonly Memory<byte> recv;

        public WinDivertPacketParserTests()
        {
            var send = new byte[] { 0, 1, 2 };
            var packet = new Memory<byte>(new byte[0xFF * 3]);
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
        public void MoveNext_TestReturnValue()
        {
            using var enumerator = new WinDivertPacketParser(recv).GetEnumerator();
            Assert.IsTrue(enumerator.MoveNext());
            Assert.IsTrue(enumerator.MoveNext());
            Assert.IsTrue(enumerator.MoveNext());
            Assert.IsFalse(enumerator.MoveNext());
            Assert.IsFalse(enumerator.MoveNext());
        }

        [TestMethod]
        public unsafe void MoveNext_TestCurrent()
        {
            using var hmem = recv.Pin();
            var parseList = new List<WinDivertParseResult>(new WinDivertPacketParser(recv));
            Assert.AreEqual(3, parseList.Count);

            var packetOff1 = parseList[0].Packet.Length;
            var packetOff2 = packetOff1 + parseList[1].Packet.Length;
            Assert.IsTrue(recv.Span[..packetOff1] == parseList[0].Packet.Span);
            Assert.IsTrue(recv.Span[packetOff1..packetOff2] == parseList[1].Packet.Span);
            Assert.IsTrue(recv.Span[packetOff2..] == parseList[2].Packet.Span);

            var localhost = (NetworkIPv4Addr)IPv4Addr.Parse("127.0.0.1");
            var protocol = (byte)17;
            Assert.IsTrue(parseList[0].IPv4Hdr != null);
            Assert.IsTrue(parseList[1].IPv4Hdr != null);
            Assert.IsTrue(parseList[2].IPv4Hdr != null);
            Assert.AreEqual(parseList[0].Packet.Length, parseList[0].IPv4Hdr->Length);
            Assert.AreEqual(parseList[1].Packet.Length, parseList[1].IPv4Hdr->Length);
            Assert.AreEqual(parseList[2].Packet.Length, parseList[2].IPv4Hdr->Length);
            Assert.AreEqual(protocol, parseList[0].IPv4Hdr->Protocol);
            Assert.AreEqual(protocol, parseList[1].IPv4Hdr->Protocol);
            Assert.AreEqual(protocol, parseList[2].IPv4Hdr->Protocol);
            Assert.AreEqual(localhost, parseList[0].IPv4Hdr->SrcAddr);
            Assert.AreEqual(localhost, parseList[1].IPv4Hdr->SrcAddr);
            Assert.AreEqual(localhost, parseList[2].IPv4Hdr->SrcAddr);
            Assert.AreEqual(localhost, parseList[0].IPv4Hdr->DstAddr);
            Assert.AreEqual(localhost, parseList[1].IPv4Hdr->DstAddr);
            Assert.AreEqual(localhost, parseList[2].IPv4Hdr->DstAddr);

            Assert.IsTrue(parseList[0].IPv6Hdr == null);
            Assert.IsTrue(parseList[1].IPv6Hdr == null);
            Assert.IsTrue(parseList[2].IPv6Hdr == null);

            Assert.AreEqual(protocol, parseList[0].Protocol);
            Assert.AreEqual(protocol, parseList[1].Protocol);
            Assert.AreEqual(protocol, parseList[2].Protocol);

            Assert.IsTrue(parseList[0].ICMPv4Hdr == null);
            Assert.IsTrue(parseList[1].ICMPv4Hdr == null);
            Assert.IsTrue(parseList[2].ICMPv4Hdr == null);

            Assert.IsTrue(parseList[0].ICMPv6Hdr == null);
            Assert.IsTrue(parseList[1].ICMPv6Hdr == null);
            Assert.IsTrue(parseList[2].ICMPv6Hdr == null);

            Assert.IsTrue(parseList[0].TCPHdr == null);
            Assert.IsTrue(parseList[1].TCPHdr == null);
            Assert.IsTrue(parseList[2].TCPHdr == null);

            Assert.IsTrue(parseList[0].UDPHdr != null);
            Assert.IsTrue(parseList[1].UDPHdr != null);
            Assert.IsTrue(parseList[2].UDPHdr != null);
            Assert.AreEqual(Port1, parseList[0].UDPHdr->SrcPort);
            Assert.AreEqual(Port1, parseList[1].UDPHdr->SrcPort);
            Assert.AreEqual(Port1, parseList[2].UDPHdr->SrcPort);
            Assert.AreEqual(Port2, parseList[0].UDPHdr->DstPort);
            Assert.AreEqual(Port2, parseList[1].UDPHdr->DstPort);
            Assert.AreEqual(Port2, parseList[2].UDPHdr->DstPort);
            Assert.AreEqual(parseList[0].Data.Length + 8, parseList[0].UDPHdr->Length);
            Assert.AreEqual(parseList[1].Data.Length + 8, parseList[1].UDPHdr->Length);
            Assert.AreEqual(parseList[2].Data.Length + 8, parseList[2].UDPHdr->Length);

            Assert.IsTrue(parseList[0].Packet.Span[^parseList[0].Data.Length..] == parseList[0].Data.Span);
            Assert.IsTrue(parseList[1].Packet.Span[^parseList[1].Data.Length..] == parseList[1].Data.Span);
            Assert.IsTrue(parseList[2].Packet.Span[^parseList[2].Data.Length..] == parseList[2].Data.Span);
        }

        [TestMethod]
        public void Reset()
        {
            using var enumerator = new WinDivertPacketParser(recv).GetEnumerator();
            _ = enumerator.MoveNext();
            _ = enumerator.MoveNext();
            _ = enumerator.MoveNext();
            enumerator.Reset();
            Assert.IsTrue(enumerator.MoveNext());
            Assert.IsTrue(enumerator.MoveNext());
            Assert.IsTrue(enumerator.MoveNext());
            Assert.IsFalse(enumerator.MoveNext());
            Assert.IsFalse(enumerator.MoveNext());
        }
    }
}
