// --------------------------------------------------------------------------------------------------------------------
// <copyright file="AzFilesSmbMI.cs" company="Microsoft Corporation.">
//   All rights reserved.
// </copyright>
// <summary>
//   AzFilesSmbMI is a library that provides methods to manage Azure Files SMB authentication using Managed Identities or OAuth tokens.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace Microsoft.Azure.Files
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Reflection;
    using System.Runtime.InteropServices;

    public class AzFilesSmbMI
    {
        // Pre-load the native DLL matching the running process architecture so an AnyCPU host
        // (which may run as x64 or ARM64) always binds to the correct native build.
        static AzFilesSmbMI()
        {
            NativeLibraryLoader.EnsureLoaded();
        }

        [DllImport("AzFilesSmbMI.dll", SetLastError = false,
                CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int SmbSetCredential(
                        string FileEndpointUri,
                        string OAuthToken,
                        string ClientId,
                        [MarshalAs(UnmanagedType.U8)] out ulong ExpiryInSeconds);

        [DllImport("AzFilesSmbMI.dll", SetLastError = false,
            CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int SmbRefreshCredential(
                    string FileEndpointUri,
                    string ClientId);

        [DllImport("AzFilesSmbMI.dll", SetLastError = false,
            CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int SmbWaitForRefreshFailure(
                    string FileEndpointUri,
                    uint TimeoutMilliseconds);

        [DllImport("AzFilesSmbMI.dll", SetLastError = false,
            CharSet = CharSet.Unicode, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int SmbClearCredential(
                    string FileEndpointUri);

        private static class NativeLibraryLoader
        {
            private const string NativeDllName = "AzFilesSmbMI.dll";
            private static readonly object SyncRoot = new object();
            private static bool loaded;

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern IntPtr LoadLibrary(string lpFileName);

            internal static void EnsureLoaded()
            {
                if (loaded)
                {
                    return;
                }

                lock (SyncRoot)
                {
                    if (loaded)
                    {
                        return;
                    }

                    string rid;
                    switch (RuntimeInformation.ProcessArchitecture)
                    {
                        case Architecture.Arm64:
                            rid = "win-arm64";
                            break;
                        case Architecture.X64:
                            rid = "win-x64";
                            break;
                        case Architecture.X86:
                            rid = "win-x86";
                            break;
                        default:
                            loaded = true;
                            return;
                    }

                    string arch = rid.Substring("win-".Length);

                    foreach (string root in GetProbeRoots())
                    {
                        string[] candidates =
                        {
                            Path.Combine(root, "runtimes", rid, "native", NativeDllName),
                            Path.Combine(root, arch, NativeDllName),
                        };

                        foreach (string candidate in candidates)
                        {
                            if (File.Exists(candidate) && LoadLibrary(candidate) != IntPtr.Zero)
                            {
                                loaded = true;
                                return;
                            }
                        }
                    }

                    // Fall back to default resolution (native DLL alongside the assembly).
                    loaded = true;
                }
            }

            private static IEnumerable<string> GetProbeRoots()
            {
                yield return AppDomain.CurrentDomain.BaseDirectory;

                string assemblyDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
                if (!string.IsNullOrEmpty(assemblyDir))
                {
                    yield return assemblyDir;
                }
            }
        }
    }
}