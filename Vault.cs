using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Win2FA
{
    public class VaultEntry
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Issuer { get; set; } = "";
        public string AccountName { get; set; } = "";
        public string Base32Secret { get; set; } = "";
        public int Digits { get; set; } = 6;
        public int Period { get; set; } = 30;
    }

    public static class Vault
    {
        private static readonly string VaultPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Win2FA",
            "vault.db"
        );

        public static void SaveEntries(List<VaultEntry> entries)
        {
            string json = JsonConvert.SerializeObject(entries, Formatting.Indented);
            byte[] plainBytes = Encoding.UTF8.GetBytes(json);

            // Windows DPAPI Encryption (Tied to the user account, highly secure)
            byte[] encryptedBytes = ProtectedData.Protect(
                plainBytes,
                null,
                DataProtectionScope.CurrentUser
            );

            string? dir = Path.GetDirectoryName(VaultPath);
            if (dir != null) Directory.CreateDirectory(dir);

            File.WriteAllBytes(VaultPath, encryptedBytes);
        }

        public static List<VaultEntry> LoadEntries()
        {
            if (!File.Exists(VaultPath)) return new List<VaultEntry>();

            try
            {
                byte[] encryptedBytes = File.ReadAllBytes(VaultPath);
                byte[] plainBytes = ProtectedData.Unprotect(
                    encryptedBytes,
                    null,
                    DataProtectionScope.CurrentUser
                );

                string json = Encoding.UTF8.GetString(plainBytes);
                return JsonConvert.DeserializeObject<List<VaultEntry>>(json) ?? new List<VaultEntry>();
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("DPAPI Unprotect failed: " + ex.Message);
                return new List<VaultEntry>();
            }
        }
    }
}
