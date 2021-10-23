using System;
using SharpDivert;

using var divert = new WinDivert("(outbound and tcp.DstPort == 1234) or (inbound and tcp.SrcPort == 80)", WinDivert.Layer.Network, 0, 0);
var recvBuf = new Memory<byte>(new byte[40 + 0xFFFF]);
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
