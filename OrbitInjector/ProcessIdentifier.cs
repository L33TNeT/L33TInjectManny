using System;
namespace CSGOInjector
{
	public class ProcessIdentifier
	{
		private static IntPtr proc_handle = null;

		public ProcessIdentifier(IntPtr procHandle)
		{
			proc_handle = procHandle;
		}
        public static IntPtr getRemoteAddress(byte[] matching_bytes)
        {
			int x;

        }
    }
}
