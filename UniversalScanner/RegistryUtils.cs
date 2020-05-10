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

        public static string readString(this RegistryKey key, string variable, string defaultValue = "")
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(String))
                return defaultValue;

            return (string)result;
        }

        public static void writeString(this RegistryKey key, string variable, string value)
        {
            key.SetValue(variable, value, RegistryValueKind.String);
        }

        public static byte[] readBinary(this RegistryKey key, string variable, byte[] defaultValue = null)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(byte[]))
                return (defaultValue != null ? defaultValue : new byte[0]);

            return (byte[])result;
        }

        public static void writeBinary(this RegistryKey key, string variable, byte[] value)
        {
            key.SetValue(variable, value, RegistryValueKind.Binary);
        }

        public static int readInt(this RegistryKey key, string variable, int defaultValue = 0)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(Int32))
                return defaultValue;

            return (int)result;
        }

        public static void writeInt(this RegistryKey key, string variable, int value)
        {
            key.SetValue(variable, value, RegistryValueKind.DWord);
        }

        public static uint readUInt(this RegistryKey key, string variable, uint defaultValue = 0)
        {
            return (uint)readInt(key, variable, (int)defaultValue);
        }

        public static void writeUInt(this RegistryKey key, string variable, uint value)
        {
            writeInt(key, variable, (int)value);
        }

        public static bool readBool(this RegistryKey key, string variable, bool defaultValue = false)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(Int32))
                return defaultValue;

            return ((int)result) != 0;
        }

        public static void writeBool(this RegistryKey key, string variable, bool value)
        {
            key.SetValue(variable, (value ? 1 : 0), RegistryValueKind.DWord);
        }

        public static long readLong(this RegistryKey key, string variable, long defaultValue = 0)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(Int64))
                return defaultValue;

            return (long)result;
        }

        public static void writeLong(this RegistryKey key, string variable, long value)
        {
            key.SetValue(variable, value, RegistryValueKind.QWord);
        }

        public static ulong readULong(this RegistryKey key, string variable, ulong defaultValue = 0)
        {
            return (ulong)readLong(key, variable, (long)defaultValue);
        }

        public static void writeULong(this RegistryKey key, string variable, ulong value)
        {
            writeLong(key, variable, (long)value);
        }

        public static string[] readText(this RegistryKey key, string variable, string[] defaultValue = null)
        {
            object result;

            result = key.GetValue(variable);
            if (result == null || result.GetType() != typeof(String[]))
                return (defaultValue == null ? defaultValue : new string[0]);

            return (string[])result;
        }

        public static void writeText(this RegistryKey key, string variable, string[] value)
        {
            key.SetValue(variable, value, RegistryValueKind.MultiString);
        }
    }
}
