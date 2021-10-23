/*
 * WinDivert.cs
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

using Microsoft.Win32.SafeHandles;
using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace SharpDivert
{
    public class WinDivert : IDisposable
    {
        private readonly SafeWinDivertHandle handle;

        public WinDivert(string filter, Layer layer, short priority, Flag flags)
        {
            var fobj = CompileFilter(filter, layer);
            handle = Open(fobj.Span, layer, priority, flags);
        }

        public WinDivert(ReadOnlySpan<byte> filter, Layer layer, short priority, Flag flags) => handle = Open(filter, layer, priority, flags);

        private static unsafe SafeWinDivertHandle Open(ReadOnlySpan<byte> filter, Layer layer, short priority, Flag flags)
        {
            if (filter.IsEmpty) throw new ArgumentException(null, nameof(filter));

            var hraw = (IntPtr)(-1);
            fixed (byte* pFilter = filter) hraw = NativeMethods.WinDivertOpen(pFilter, layer, priority, flags);
            if (hraw == (IntPtr)(-1)) throw new Win32Exception();
            return new SafeWinDivertHandle(hraw, true);
        }

        public unsafe (uint recvLen, uint addrLen) RecvEx(Span<byte> packet, Span<WinDivertAddress> abuf)
        {
            var recvLen = (uint)0;
            var addrLen = (uint)0;
            var pAddrLen = (uint*)null;
            if (!abuf.IsEmpty)
            {
                addrLen = (uint)(abuf.Length * sizeof(WinDivertAddress));
                pAddrLen = &addrLen;
            }

            using (var href = new SafeHandleReference(handle, (IntPtr)(-1)))
            {
                var success = false;
                fixed (byte* pPacket = packet) fixed (WinDivertAddress* pAbuf = abuf)
                {
                    success = NativeMethods.WinDivertRecvEx(href.RawHandle, pPacket, (uint)packet.Length, &recvLen, 0, pAbuf, pAddrLen, null);
                }
                if (!success) throw new Win32Exception();
            }

            addrLen /= (uint)sizeof(WinDivertAddress);
            return (recvLen, addrLen);
        }

        public unsafe uint SendEx(ReadOnlySpan<byte> packet, ReadOnlySpan<WinDivertAddress> addr)
        {
            using var href = new SafeHandleReference(handle, (IntPtr)(-1));
            var sendLen = (uint)0;
            var success = false;
            fixed (byte* pPacket = packet) fixed (WinDivertAddress* pAddr = addr)
            {
                success = NativeMethods.WinDivertSendEx(href.RawHandle, pPacket, (uint)packet.Length, &sendLen, 0, pAddr, (uint)(addr.Length * sizeof(WinDivertAddress)), null);
            }
            if (!success) throw new Win32Exception();
            return sendLen;
        }

        public ulong QueueLength
        {
            get => GetParam(Param.QueueLength);
            set => SetParam(Param.QueueLength, value);
        }

        public ulong QueueTime
        {
            get => GetParam(Param.QueueTime);
            set => SetParam(Param.QueueTime, value);
        }

        public ulong QueueSize
        {
            get => GetParam(Param.QueueSize);
            set => SetParam(Param.QueueSize, value);
        }

        public ulong VersionMajor => GetParam(Param.VersionMajor);
        public ulong VersionMinor => GetParam(Param.VersionMinor);

        private ulong GetParam(Param param)
        {
            using var href = new SafeHandleReference(handle, (IntPtr)(-1));
            var success = NativeMethods.WinDivertGetParam(href.RawHandle, param, out var value);
            if (!success) throw new Win32Exception();
            return value;
        }

        private void SetParam(Param param, ulong value)
        {
            using var href = new SafeHandleReference(handle, (IntPtr)(-1));
            var success = NativeMethods.WinDivertSetParam(href.RawHandle, param, value);
            if (!success) throw new Win32Exception();
        }

        public void ShutdownRecv() => Shutdown(ShutdownHow.Recv);
        public void ShutdownSend() => Shutdown(ShutdownHow.Send);
        public void Shutdown() => Shutdown(ShutdownHow.Both);

        private void Shutdown(ShutdownHow how)
        {
            using var href = new SafeHandleReference(handle, (IntPtr)(-1));
            var success = NativeMethods.WinDivertShutdown(href.RawHandle, how);
            if (!success) throw new Win32Exception();
        }

#pragma warning disable CA1816
        public void Dispose() => handle.Dispose();
#pragma warning restore CA1816

        public static unsafe void CalcChecksums(Span<byte> packet, ref WinDivertAddress addr, ChecksumFlag flags)
        {
            var success = false;
            fixed (void* pPacket = packet) fixed (WinDivertAddress* pAddr = &addr)
            {
                success = NativeMethods.WinDivertHelperCalcChecksums(pPacket, (uint)packet.Length, pAddr, flags);
            }
            if (!success) throw new ArgumentException(null);
        }

        public static unsafe ReadOnlyMemory<byte> CompileFilter(string filter, Layer layer)
        {
            var buffer = (Span<byte>)stackalloc byte[256 * 24];
            var pErrorStr = (byte*)null;
            var errorPos = (uint)0;
            var success = false;

            fixed (byte* pBuffer = buffer) success = NativeMethods.WinDivertHelperCompileFilter(filter, layer, pBuffer, (uint)buffer.Length, &pErrorStr, &errorPos);
            if (!success)
            {
                var errorLen = 0;
                while (*(pErrorStr + errorLen) != 0) errorLen++;
                var errorStr = Encoding.ASCII.GetString(pErrorStr, errorLen);
                throw new WinDivertInvalidFilterException(errorStr, errorPos, nameof(filter));
            }

            var fobjLen = buffer.IndexOf((byte)0) + 1;
            var fobj = new Memory<byte>(new byte[fobjLen]);
            buffer[..fobjLen].CopyTo(fobj.Span);
            return fobj;
        }

        public enum Layer
        {
            Network = 0,
            NetworkForward = 1,
            Flow = 2,
            Socket = 3,
            Reflect = 4,
        }

        public enum Event
        {
            NetworkPacket = 0,
            FlowEstablished = 1,
            FlowDeleted = 2,
            SocketBind = 3,
            SocketConnect = 4,
            SocketListen = 5,
            SocketAccept = 6,
            SocketClose = 7,
            ReflectOpen = 8,
            ReflectClose = 9,
        }

        [Flags]
        public enum Flag : ulong
        {
            Sniff = 0x0001,
            Drop = 0x0002,
            RecvOnly = 0x0004,
            ReadOnly = RecvOnly,
            SendOnly = 0x0008,
            WriteOnly = SendOnly,
            NoInstall = 0x0010,
            Fragments = 0x0020,
        }

        internal enum Param
        {
            QueueLength = 0,
            QueueTime = 1,
            QueueSize = 2,
            VersionMajor = 3,
            VersionMinor = 4,
        }

        internal enum ShutdownHow
        {
            Recv = 0x1,
            Send = 0x2,
            Both = 0x3,
        }

        [Flags]
        public enum ChecksumFlag : ulong
        {
            NoIPv4Checksum = 1,
            NoICMPv4Checksum = 2,
            NoICMPv6Checksum = 4,
            NoTCPChecksum = 8,
            NoUDPChecksum = 16,
        }
    }

    public class SafeWinDivertHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeWinDivertHandle(IntPtr existingHandle, bool ownsHandle) : base(ownsHandle) => SetHandle(existingHandle);
        protected override bool ReleaseHandle() => NativeMethods.WinDivertClose(handle);
    }

    public struct SafeHandleReference : IDisposable
    {
        public IntPtr RawHandle { get; private set; }

        private readonly SafeHandle? handle;
        private readonly IntPtr invalid;
        private bool reference;

        public SafeHandleReference(SafeHandle? handle, IntPtr invalid)
        {
            RawHandle = invalid;
            this.handle = handle;
            this.invalid = invalid;
            reference = false;
            if (handle is null || handle.IsInvalid || handle.IsClosed) return;
            handle.DangerousAddRef(ref reference);
            RawHandle = handle.DangerousGetHandle();
        }

        public void Dispose()
        {
            RawHandle = invalid;
            if (reference)
            {
                handle?.DangerousRelease();
                reference = false;
            }
        }
    }

    public struct WinDivertIndexedPacketParser : IEnumerable<(int, WinDivertParseResult)>
    {
        private readonly WinDivertPacketParser e;

        public WinDivertIndexedPacketParser(Memory<byte> packet) => e = new WinDivertPacketParser(packet);
        public WinDivertIndexedPacketParser(WinDivertPacketParser e) => this.e = e;
        public WinDivertIndexedPacketEnumerator GetEnumerator() => new(e.GetEnumerator());
        IEnumerator<(int, WinDivertParseResult)> IEnumerable<(int, WinDivertParseResult)>.GetEnumerator() => GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    public struct WinDivertIndexedPacketEnumerator : IEnumerator<(int, WinDivertParseResult)>
    {
        private WinDivertPacketEnumerator e;
        private int i;

        public (int, WinDivertParseResult) Current => (i, e.Current);
        object IEnumerator.Current => Current;

        internal WinDivertIndexedPacketEnumerator(WinDivertPacketEnumerator e)
        {
            this.e = e;
            i = -1;
        }

        public bool MoveNext()
        {
            var success = e.MoveNext();
            if (!success) return false;
            i++;
            return true;
        }

        public void Reset()
        {
            e.Reset();
            i = -1;
        }

        public void Dispose() => e.Dispose();
    }

    public struct WinDivertPacketParser : IEnumerable<WinDivertParseResult>
    {
        private readonly Memory<byte> packet;

        public WinDivertPacketParser(Memory<byte> packet) => this.packet = packet;
        public WinDivertPacketEnumerator GetEnumerator() => new(packet);
        IEnumerator<WinDivertParseResult> IEnumerable<WinDivertParseResult>.GetEnumerator() => new WinDivertPacketEnumerator(packet);
        IEnumerator IEnumerable.GetEnumerator() => new WinDivertPacketEnumerator(packet);
    }

    public unsafe struct WinDivertPacketEnumerator : IEnumerator<WinDivertParseResult>
    {
        private readonly MemoryHandle hmem;
        private readonly Memory<byte> packet;
        private readonly byte* pPacket0;
        private byte* pPacket;
        private uint packetLen;

        private WinDivertParseResult current;
        public WinDivertParseResult Current => current;
        object IEnumerator.Current => current;

        internal WinDivertPacketEnumerator(Memory<byte> packet)
        {
            hmem = packet.Pin();
            this.packet = packet;
            pPacket0 = (byte*)hmem.Pointer;
            pPacket = pPacket0;
            packetLen = (uint)packet.Length;
            current = new WinDivertParseResult();
        }

        public bool MoveNext()
        {
            var ipv4Hdr = (WinDivertIPv4Hdr*)null;
            var ipv6Hdr = (WinDivertIPv6Hdr*)null;
            var protocol = (byte)0;
            var icmpv4Hdr = (WinDivertICMPv4Hdr*)null;
            var icmpv6Hdr = (WinDivertICMPv6Hdr*)null;
            var tcpHdr = (WinDivertTCPHdr*)null;
            var udpHdr = (WinDivertUDPHdr*)null;
            var pData = (byte*)null;
            var dataLen = (uint)0;
            var pNext = (byte*)null;
            var nextLen = (uint)0;

            var success = NativeMethods.WinDivertHelperParsePacket(pPacket, packetLen, &ipv4Hdr, &ipv6Hdr, &protocol, &icmpv4Hdr, &icmpv6Hdr, &tcpHdr, &udpHdr, (void**)&pData, &dataLen, (void**)&pNext, &nextLen);
            if (!success) return false;

            current.Packet = pNext != null
                ? packet[(int)(pPacket - pPacket0)..(int)(pNext - pPacket0)]
                : packet[(int)(pPacket - pPacket0)..(int)(pPacket + packetLen - pPacket0)];
            current.IPv4Hdr = ipv4Hdr;
            current.IPv6Hdr = ipv6Hdr;
            current.Protocol = protocol;
            current.ICMPv4Hdr = icmpv4Hdr;
            current.ICMPv6Hdr = icmpv6Hdr;
            current.TCPHdr = tcpHdr;
            current.UDPHdr = udpHdr;
            current.Data = pData != null && dataLen > 0
                ? packet[(int)(pData - pPacket0)..(int)(pData + dataLen - pPacket0)]
                : Memory<byte>.Empty;

            pPacket = pNext;
            packetLen = nextLen;
            return true;
        }

        public void Reset()
        {
            pPacket = pPacket0;
            packetLen = (uint)packet.Length;
            current = new WinDivertParseResult();
        }

        public void Dispose() => hmem.Dispose();
    }

    public unsafe struct WinDivertParseResult
    {
        public Memory<byte> Packet;
        public WinDivertIPv4Hdr* IPv4Hdr;
        public WinDivertIPv6Hdr* IPv6Hdr;
        public byte Protocol;
        public WinDivertICMPv4Hdr* ICMPv4Hdr;
        public WinDivertICMPv6Hdr* ICMPv6Hdr;
        public WinDivertTCPHdr* TCPHdr;
        public WinDivertUDPHdr* UDPHdr;
        public Memory<byte> Data;
    }

    public class WinDivertInvalidFilterException : ArgumentException
    {
        public string FilterErrorStr;
        public uint FilterErrorPos;

        public WinDivertInvalidFilterException(string errorStr, uint errorPos, string? paramName) : base(errorStr, paramName)
        {
            FilterErrorStr = errorStr;
            FilterErrorPos = errorPos;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IPv4Addr : IEquatable<IPv4Addr>
    {
        internal uint Raw;

        public static unsafe IPv4Addr Parse(string addrStr)
        {
            var addr = new IPv4Addr();
            var success = NativeMethods.WinDivertHelperParseIPv4Address(addrStr, &addr.Raw);
            if (!success) throw new Win32Exception();
            return addr;
        }

        public override unsafe string ToString()
        {
            var buffer = (Span<byte>)stackalloc byte[32];
            var success = false;
            fixed (byte* pBuffer = buffer) success = NativeMethods.WinDivertHelperFormatIPv4Address(Raw, pBuffer, (uint)buffer.Length);
            if (!success) throw new Win32Exception();

            var strlen = buffer.IndexOf((byte)0);
            return Encoding.ASCII.GetString(buffer[..strlen]);
        }

        public static bool operator ==(IPv4Addr left, IPv4Addr right) => left.Equals(right);
        public static bool operator !=(IPv4Addr left, IPv4Addr right) => !left.Equals(right);

        public bool Equals(IPv4Addr addr) => Raw == addr.Raw;

        public override bool Equals(object? obj)
        {
            if (obj is IPv4Addr ipv4Addr) return Equals(ipv4Addr);
            return base.Equals(obj);
        }

        public override int GetHashCode() => base.GetHashCode();
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NetworkIPv4Addr : IEquatable<NetworkIPv4Addr>
    {
        internal uint Raw;

        public override string ToString() => ((IPv4Addr)this).ToString();

        public static bool operator ==(NetworkIPv4Addr left, NetworkIPv4Addr right) => left.Equals(right);
        public static bool operator !=(NetworkIPv4Addr left, NetworkIPv4Addr right) => !left.Equals(right);

        public bool Equals(NetworkIPv4Addr addr) => Raw == addr.Raw;

        public static implicit operator NetworkIPv4Addr(IPv4Addr addr) => new()
        {
            Raw = NativeMethods.WinDivertHelperHtonl(addr.Raw),
        };

        public static implicit operator IPv4Addr(NetworkIPv4Addr addr) => new()
        {
            Raw = NativeMethods.WinDivertHelperNtohl(addr.Raw),
        };

        public override bool Equals(object? obj)
        {
            if (obj is NetworkIPv4Addr addr) return Equals(addr);
            return base.Equals(obj);
        }

        public override int GetHashCode() => base.GetHashCode();
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IPv6Addr : IEquatable<IPv6Addr>
    {
        internal fixed uint Raw[4];

        public static IPv6Addr Parse(string addrStr)
        {
            var addr = new IPv6Addr();
            var success = NativeMethods.WinDivertHelperParseIPv6Address(addrStr, addr.Raw);
            if (!success) throw new Win32Exception();
            return addr;
        }

        public override string ToString()
        {
            var buffer = (Span<byte>)stackalloc byte[64];
            var success = false;
            fixed (uint* addr = Raw) fixed (byte* pBuffer = buffer)
            {
                success = NativeMethods.WinDivertHelperFormatIPv6Address(addr, pBuffer, (uint)buffer.Length);
            }
            if (!success) throw new Win32Exception();

            var strlen = buffer.IndexOf((byte)0);
            return Encoding.ASCII.GetString(buffer[..strlen]);
        }

        public static bool operator ==(IPv6Addr left, IPv6Addr right) => left.Equals(right);
        public static bool operator !=(IPv6Addr left, IPv6Addr right) => !left.Equals(right);

        public bool Equals(IPv6Addr addr)
        {
            return Raw[0] == addr.Raw[0]
                && Raw[1] == addr.Raw[1]
                && Raw[2] == addr.Raw[2]
                && Raw[3] == addr.Raw[3];
        }

        public override bool Equals(object? obj)
        {
            if (obj is IPv6Addr ipv6Addr) return Equals(ipv6Addr);
            return base.Equals(obj);
        }

        public override int GetHashCode() => base.GetHashCode();
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct NetworkIPv6Addr : IEquatable<NetworkIPv6Addr>
    {
        internal fixed uint Raw[4];

        public override string ToString() => ((IPv6Addr)this).ToString();

        public static bool operator ==(NetworkIPv6Addr left, NetworkIPv6Addr right) => left.Equals(right);
        public static bool operator !=(NetworkIPv6Addr left, NetworkIPv6Addr right) => !left.Equals(right);

        public bool Equals(NetworkIPv6Addr addr)
        {
            return Raw[0] == addr.Raw[0]
                && Raw[1] == addr.Raw[1]
                && Raw[2] == addr.Raw[2]
                && Raw[3] == addr.Raw[3];
        }

        public static implicit operator NetworkIPv6Addr(IPv6Addr addr)
        {
            var naddr = new NetworkIPv6Addr();
            NativeMethods.WinDivertHelperHtonIPv6Address(addr.Raw, naddr.Raw);
            return naddr;
        }

        public static implicit operator IPv6Addr(NetworkIPv6Addr addr)
        {
            var haddr = new IPv6Addr();
            NativeMethods.WinDivertHelperNtohIPv6Address(addr.Raw, haddr.Raw);
            return haddr;
        }

        public override bool Equals(object? obj)
        {
            if (obj is NetworkIPv6Addr addr) return Equals(addr);
            return base.Equals(addr);
        }

        public override int GetHashCode() => base.GetHashCode();
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NetworkUInt16 : IEquatable<NetworkUInt16>
    {
        private readonly ushort raw;

        private NetworkUInt16(ushort raw) => this.raw = raw;
        public static implicit operator NetworkUInt16(ushort x) => new(NativeMethods.WinDivertHelperHtons(x));
        public static implicit operator ushort(NetworkUInt16 x) => NativeMethods.WinDivertHelperNtohs(x.raw);
        public static bool operator ==(NetworkUInt16 left, NetworkUInt16 right) => left.Equals(right);
        public static bool operator !=(NetworkUInt16 left, NetworkUInt16 right) => !left.Equals(right);
        public bool Equals(NetworkUInt16 x) => raw == x.raw;

        public override bool Equals(object? obj)
        {
            if (obj is NetworkUInt16 x) return Equals(x);
            return base.Equals(obj);
        }

        public override int GetHashCode() => base.GetHashCode();
        public override string ToString() => ((ushort)this).ToString();
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NetworkUInt32 : IEquatable<NetworkUInt32>
    {
        private readonly uint raw;

        private NetworkUInt32(uint raw) => this.raw = raw;
        public static implicit operator NetworkUInt32(uint x) => new(NativeMethods.WinDivertHelperHtonl(x));
        public static implicit operator uint(NetworkUInt32 x) => NativeMethods.WinDivertHelperNtohl(x.raw);
        public static bool operator ==(NetworkUInt32 left, NetworkUInt32 right) => left.Equals(right);
        public static bool operator !=(NetworkUInt32 left, NetworkUInt32 right) => !left.Equals(right);
        public bool Equals(NetworkUInt32 x) => raw == x.raw;

        public override bool Equals(object? obj)
        {
            if (obj is NetworkUInt32 x) return Equals(x);
            return base.Equals(obj);
        }

        public override int GetHashCode() => base.GetHashCode();
        public override string ToString() => ((uint)this).ToString();
    }

    internal static class NativeMethods
    {
        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern unsafe IntPtr WinDivertOpen(byte* filter, WinDivert.Layer layer, short priority, WinDivert.Flag flags);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern unsafe bool WinDivertRecvEx(IntPtr handle, void* packet, uint packetLen, uint* recvLen, ulong flags, WinDivertAddress* addr, uint* addrLen, NativeOverlapped* overlapped);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern unsafe bool WinDivertSendEx(IntPtr handle, void* packet, uint packetLen, uint* sendLen, ulong flags, WinDivertAddress* addr, uint addrLen, NativeOverlapped* overlapped);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern bool WinDivertSetParam(IntPtr handle, WinDivert.Param param, ulong value);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern bool WinDivertGetParam(IntPtr handle, WinDivert.Param param, out ulong value);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern bool WinDivertShutdown(IntPtr handle, WinDivert.ShutdownHow how);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern bool WinDivertClose(IntPtr handle);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = false)]
        public static extern unsafe bool WinDivertHelperParsePacket(void* packet, uint packetLen, WinDivertIPv4Hdr** ipv4Hdr, WinDivertIPv6Hdr** ipv6Hdr, byte* protocol, WinDivertICMPv4Hdr** icmpv4Hdr, WinDivertICMPv6Hdr** icmpv6Hdr, WinDivertTCPHdr** tcpHdr, WinDivertUDPHdr** udpHdr, void** data, uint* dataLen, void** next, uint* nextLen);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern unsafe bool WinDivertHelperParseIPv4Address(string addrStr, uint* addr);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern unsafe bool WinDivertHelperParseIPv6Address(string addrStr, uint* addr);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern unsafe bool WinDivertHelperFormatIPv4Address(uint addr, byte* buffer, uint buflen);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = true)]
        public static extern unsafe bool WinDivertHelperFormatIPv6Address(uint* addr, byte* buffer, uint buflen);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = false)]
        public static extern unsafe bool WinDivertHelperCalcChecksums(void* packet, uint packetLen, WinDivertAddress* addr, WinDivert.ChecksumFlag flags);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = false)]
        public static extern unsafe bool WinDivertHelperCompileFilter(string filter, WinDivert.Layer layer, byte* fobj, uint fobjLen, byte** errorStr, uint* errorPos);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = false)]
        public static extern ushort WinDivertHelperNtohs(ushort x);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = false)]
        public static extern ushort WinDivertHelperHtons(ushort x);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = false)]
        public static extern uint WinDivertHelperNtohl(uint x);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = false)]
        public static extern uint WinDivertHelperHtonl(uint x);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = false)]
        public static extern unsafe void WinDivertHelperNtohIPv6Address(uint* inAddr, uint* outAddr);

        [DllImport("WinDivert.dll", ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true, PreserveSig = true, SetLastError = false)]
        public static extern unsafe void WinDivertHelperHtonIPv6Address(uint* inAddr, uint* outAddr);
    }

    [StructLayout(LayoutKind.Explicit)]
    public unsafe struct WinDivertAddress
    {
        [FieldOffset(0)] public long Timestamp;
        [FieldOffset(8)] private byte byteLayer;
        [FieldOffset(9)] private byte byteEvent;
        [FieldOffset(10)] private byte flags;

        [FieldOffset(16)] public WinDivertDataNetwork Network;
        [FieldOffset(16)] public WinDivertDataFlow Flow;
        [FieldOffset(16)] public WinDivertDataSocket Socket;
        [FieldOffset(16)] public WinDivertDataReflect Reflect;
        [FieldOffset(16)] private fixed byte reserved[64];

        public WinDivert.Layer Layer
        {
            get => (WinDivert.Layer)byteLayer;
            set => byteLayer = (byte)value;
        }

        public WinDivert.Event Event
        {
            get => (WinDivert.Event)byteEvent;
            set => byteEvent = (byte)value;
        }

        public bool Sniffed
        {
            get => GetFlag(1 << 0);
            set => SetFlag(1 << 0, value);
        }

        public bool Outbound
        {
            get => GetFlag(1 << 1);
            set => SetFlag(1 << 1, value);
        }

        public bool Loopback
        {
            get => GetFlag(1 << 2);
            set => SetFlag(1 << 2, value);
        }

        public bool Impostor
        {
            get => GetFlag(1 << 3);
            set => SetFlag(1 << 3, value);
        }

        public bool IPv6
        {
            get => GetFlag(1 << 4);
            set => SetFlag(1 << 4, value);
        }

        public bool IPChecksum
        {
            get => GetFlag(1 << 5);
            set => SetFlag(1 << 5, value);
        }

        public bool TCPChecksum
        {
            get => GetFlag(1 << 6);
            set => SetFlag(1 << 6, value);
        }

        public bool UDPChecksum
        {
            get => GetFlag(1 << 7);
            set => SetFlag(1 << 7, value);
        }

        private bool GetFlag(byte bit) => (flags & bit) != 0;

        private void SetFlag(byte bit, bool val)
        {
            if (val) flags = (byte)(flags | bit);
            else flags = (byte)((flags | bit) ^ bit);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertDataNetwork
    {
        public uint IfIdx;
        public uint SubIfIdx;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertDataFlow
    {
        public ulong EndpointId;
        public ulong ParentEndpointId;
        public uint ProcessId;
        public IPv6Addr LocalAddr;
        public IPv6Addr RemoteAddr;
        public ushort LocalPort;
        public ushort RemotePort;
        public byte Protocol;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertDataSocket
    {
        public ulong EndpointId;
        public ulong ParentEndpointId;
        public uint ProcessId;
        public IPv6Addr LocalAddr;
        public IPv6Addr RemoteAddr;
        public ushort LocalPort;
        public ushort RemotePort;
        public byte Protocol;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertDataReflect
    {
        public long Timestamp;
        public uint ProcessId;
        public WinDivert.Layer Layer;
        public ulong Flags;
        public short Priority;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertIPv4Hdr
    {
        public byte HdrLengthOff0;
        public byte TOS;
        public NetworkUInt16 Length;
        public NetworkUInt16 Id;
        public ushort FragOff0;
        public byte TTL;
        public byte Protocol;
        public ushort Checksum;
        public NetworkIPv4Addr SrcAddr;
        public NetworkIPv4Addr DstAddr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertIPv6Hdr
    {
        public uint FlowLabelOff0;
        public NetworkUInt16 Length;
        public byte NextHdr;
        public byte HopLimit;
        public NetworkIPv6Addr SrcAddr;
        public NetworkIPv6Addr DstAddr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertICMPv4Hdr
    {
        public byte Type;
        public byte Code;
        public ushort Checksum;
        public uint Body;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertICMPv6Hdr
    {
        public byte Type;
        public byte Code;
        public ushort Checksum;
        public uint Body;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertTCPHdr
    {
        public NetworkUInt16 SrcPort;
        public NetworkUInt16 DstPort;
        public NetworkUInt32 SeqNum;
        public NetworkUInt32 AckNum;
        public ushort FinOff0;
        public NetworkUInt16 Window;
        public ushort Checksum;
        public NetworkUInt16 UrgPtr;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinDivertUDPHdr
    {
        public NetworkUInt16 SrcPort;
        public NetworkUInt16 DstPort;
        public NetworkUInt16 Length;
        public ushort Checksum;
    }
}
