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
    using System.Runtime.InteropServices;

    public class AzFilesSmbMI
    {
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
        public static extern int SmbClearCredential(
                    string FileEndpointUri);
    }
}