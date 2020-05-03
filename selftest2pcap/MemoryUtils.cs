using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace selftest2pcap
{
    public static class MemoryUtils
    {
        public static byte[] GetBytes<T>(this T s) where T : struct
        {
            int size;
            byte[] result;
            IntPtr p;

            size = Marshal.SizeOf(typeof(T));
            result = new byte[size];
            p = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr<T>(s, p, true);
                Marshal.Copy(p, result, 0, size);
            }
            catch
            {
                result = null;
            }
            finally
            {
                Marshal.FreeHGlobal(p);
            }
            return result;
        }

        public static T GetStruct<T>(this byte[] array) where T : struct
        {
            int size;
            T result;
            IntPtr p;

            size = Marshal.SizeOf(typeof(T));
            p = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.Copy(array, 0, p, size);
                result = (T)Marshal.PtrToStructure(p, typeof(T));
            }
            catch
            {
                result = default(T);
            }
            finally
            {
                Marshal.FreeHGlobal(p);
            }
            return result;
        }

        public static string GetString<T>(this Encoding enc, T source) where T : struct
        {
            byte[] buffer;
            int len;

            buffer = source.GetBytes();
            if (buffer != null)
            {
                len = buffer.Length;
                for (int i = 0; i < buffer.Length; i++)
                {
                    if (buffer[i] == 0)
                    {
                        len = i;
                        break;
                    }
                }
                if (len > 0)
                {
                    return enc.GetString(buffer, 0, len);
                }
            }

            return "";
        }
    }
}
