/*
 * Program.cs
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

// The following code is the same as the code in README.md.

using System;
using SharpDivert;

using var divert = new WinDivert("(outbound and tcp.DstPort == 1234) or (inbound and tcp.SrcPort == 80)", WinDivert.Layer.Network, 0, 0);
var recvBuf = new Memory<byte>(new byte[WinDivert.MTUMax]);
var addrBuf = new Memory<WinDivertAddress>(new WinDivertAddress[1]);

while (true)
{
    var (recvLen, addrLen) = divert.RecvEx(recvBuf.Span, addrBuf.Span);
    var recv = recvBuf[..(int)recvLen];
    var addr = addrBuf[..(int)addrLen];
    foreach (var (i, p) in new WinDivertIndexedPacketParser(recv))
    {
        unsafe
        {
            if (addr.Span[i].Outbound)
            {
                Console.WriteLine(">");
                p.TCPHdr->DstPort = 80;
            }
            else
            {
                Console.WriteLine("<");
                p.TCPHdr->SrcPort = 1234;
            }
        }
    }
    _ = divert.SendEx(recv.Span, addr.Span);
}
