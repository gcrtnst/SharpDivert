/*
 * SafeHandleReferenceTests.cs
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
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SharpDivert;

namespace SharpDivertTests
{
    [TestClass]
    public class SafeHandleReferenceTests
    {
        [TestMethod]
        public void Ctor_NullHandle()
        {
            var invalid = (IntPtr)(-1);
            using var href = new SafeHandleReference(null, invalid);
            Assert.AreEqual(invalid, href.RawHandle);
        }

        [TestMethod]
        public void Ctor_ValidHandle()
        {
            using var handle = new SafeTestHandle();
            using var href = new SafeHandleReference(handle, (IntPtr)(-1));

            Assert.AreEqual(handle.DangerousGetHandle(), href.RawHandle);

            handle.Dispose();
            Assert.IsFalse(handle.Released);
        }

        [TestMethod]
        public void Dispose_CallOnce()
        {
            var handle = new SafeTestHandle();
            using (handle)
            {
                using var href = new SafeHandleReference(handle, (IntPtr)(-1));
            }
            Assert.IsTrue(handle.Released);
        }

        [TestMethod]
        public void Dispose_CallThreeTimes()
        {
            using var handle = new SafeTestHandle();
            using var href = new SafeHandleReference(handle, (IntPtr)(-1));
            href.Dispose();
            href.Dispose();
        }
    }

    internal class SafeTestHandle : SafeHandle
    {
        public bool Released = false;
        public override bool IsInvalid => false;

        public SafeTestHandle() : base((IntPtr)1, true) { }

        protected override bool ReleaseHandle()
        {
            Released = true;
            return true;
        }
    }
}
