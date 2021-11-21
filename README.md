# SharpDivert
.NET bindings for [WinDivert](https://reqrypt.org/windivert.html).

## Getting Started
1. Install SharpDivert from [NuGet](https://www.nuget.org/packages/SharpDivert/).
2. Download the WinDivert v2.2 binary from [the homepage](https://reqrypt.org/windivert.html) and put it in the program directory.
3. Write your code. [WinDivert Reference Manual](https://reqrypt.org/windivert-doc.html) may help you.

The following sample code rewrites the TCP port for outgoing packets from 1234 to 80, and the TCP port for incoming packets from 80 to 1234. Run this code and try opening http://example.com:1234/ in your browser.
```cs
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
```

Note that WinDivert must be run with administrative privileges. `requestedExecutionLevel` in app.manifest may be useful.

## Security Warning
Be careful not to execute any malicious code, as applications containing WinDivert are run with administrative privileges. Program files, such as WinDivert.dll, should not be rewritten without administrative privileges. Make sure that the DLL search path is set properly to avoid loading invalid WinDivert.dll.

## Remarks
SharpDivert is only used in a limited number of applications and has not been fully tested. Some features are missing. Issues and pull requests are welcome.

## License
SharpDivert is dual-licensed under your choice of the GNU Lesser General Public License (LGPL) Version 3 or the GNU General Public License (GPL) Version 2. See the LICENSE file for more information.

