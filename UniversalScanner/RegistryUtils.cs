using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UniversalScanner
{
    public static class RegistryUtils
    {
        public static RegistryKey openOrCreate(this RegistryKey key, string path)
        {
            RegistryKey result;

            result = key.OpenSubKey(path, true);
            if (result == null)
            {
                result = key.CreateSubKey(path);
            }

            return result;
        }

        public static string readString(this RegistryKey key, string variable)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(String))
                return "";

            return (string)result;
        }

        public static void writeString(this RegistryKey key, string variable, string value)
        {
            key.SetValue(variable, value, RegistryValueKind.String);
        }

        public static byte[] readBinary(this RegistryKey key, string variable)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(byte[]))
                return new byte[0];

            return (byte[])result;
        }

        public static void writeBinary(this RegistryKey key, string variable, byte[] value)
        {
            key.SetValue(variable, value, RegistryValueKind.Binary);
        }

        public static int readInteger(this RegistryKey key, string variable)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(Int32))
                return 0;

            return (int)result;
        }

        public static void writeInteger(this RegistryKey key, string variable, int value)
        {
            key.SetValue(variable, value, RegistryValueKind.DWord);
        }

        public static bool readBool(this RegistryKey key, string variable)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(Int32))
                return false;

            return ((int)result) != 0;
        }

        public static void writeBool(this RegistryKey key, string variable, bool value)
        {
            key.SetValue(variable, (value ? 1 : 0), RegistryValueKind.DWord);
        }

        public static long readLong(this RegistryKey key, string variable)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(Int64))
                return 0;

            return (long)result;
        }

        public static void writeLong(this RegistryKey key, string variable, long value)
        {
            key.SetValue(variable, value, RegistryValueKind.QWord);
        }

        public static string[] readText(this RegistryKey key, string variable)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(String[]))
                return new string[0];

            return (string[])result;
        }

        public static void writeText(this RegistryKey key, string variable, string[] value)
        {
            key.SetValue(variable, value, RegistryValueKind.MultiString);
        }
    }
}
