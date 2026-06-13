using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Win2FA
{
    public class OtpAccount
    {
        public string Issuer { get; set; } = "Unknown";
        public string AccountName { get; set; } = "Unknown";
        public string Secret { get; set; } = ""; // Plain Base32 key
    }

    public static class GoogleAuthParser
    {
        public static List<OtpAccount> ParseMigrationUri(string uri)
        {
            var accounts = new List<OtpAccount>();
            if (string.IsNullOrEmpty(uri) || !uri.StartsWith("otpauth-migration://offline", StringComparison.OrdinalIgnoreCase))
                return accounts;

            // Extract 'data' query parameter
            int dataIndex = uri.IndexOf("data=");
            if (dataIndex < 0) return accounts;

            string dataEncoded = uri.Substring(dataIndex + 5);
            int ampIndex = dataEncoded.IndexOf('&');
            if (ampIndex >= 0) dataEncoded = dataEncoded.Substring(0, ampIndex);

            string dataDecoded = Uri.UnescapeDataString(dataEncoded);
            byte[] rawProto = Convert.FromBase64String(dataDecoded);

            return ParseProtobuf(rawProto);
        }

        private static List<OtpAccount> ParseProtobuf(byte[] rawProto)
        {
            var accounts = new List<OtpAccount>();
            using (var ms = new MemoryStream(rawProto))
            {
                while (ms.Position < ms.Length)
                {
                    int header = ReadVarint(ms);
                    int wireType = header & 0x07;
                    int fieldNumber = header >> 3;

                    if (fieldNumber == 1 && wireType == 2) // repeated OtpParameters otp_parameters = 1;
                    {
                        int length = ReadVarint(ms);
                        byte[] nestedBytes = new byte[length];
                        ms.Read(nestedBytes, 0, length);
                        var acct = ParseOtpParameters(nestedBytes);
                        if (acct != null && !string.IsNullOrEmpty(acct.Secret))
                        {
                            accounts.Add(acct);
                        }
                    }
                    else
                    {
                        SkipField(ms, wireType);
                    }
                }
            }
            return accounts;
        }

        private static OtpAccount? ParseOtpParameters(byte[] bytes)
        {
            var acct = new OtpAccount();
            using (var ms = new MemoryStream(bytes))
            {
                while (ms.Position < ms.Length)
                {
                    int header = ReadVarint(ms);
                    int wireType = header & 0x07;
                    int fieldNumber = header >> 3;

                    if (fieldNumber == 1 && wireType == 2) // bytes secret = 1;
                    {
                        int length = ReadVarint(ms);
                        byte[] secretBytes = new byte[length];
                        ms.Read(secretBytes, 0, length);
                        acct.Secret = Base32Encode(secretBytes);
                    }
                    else if (fieldNumber == 2 && wireType == 2) // string name = 2;
                    {
                        int length = ReadVarint(ms);
                        byte[] nameBytes = new byte[length];
                        ms.Read(nameBytes, 0, length);
                        acct.AccountName = Encoding.UTF8.GetString(nameBytes);
                    }
                    else if (fieldNumber == 3 && wireType == 2) // string issuer = 3;
                    {
                        int length = ReadVarint(ms);
                        byte[] issuerBytes = new byte[length];
                        ms.Read(issuerBytes, 0, length);
                        acct.Issuer = Encoding.UTF8.GetString(issuerBytes);
                    }
                    else
                    {
                        SkipField(ms, wireType);
                    }
                }
            }

            if (acct.Issuer == "Unknown" && acct.AccountName.Contains(":"))
            {
                var parts = acct.AccountName.Split(':');
                acct.Issuer = parts[0].Trim();
                acct.AccountName = parts[1].Trim();
            }

            return acct;
        }

        private static int ReadVarint(MemoryStream ms)
        {
            int result = 0;
            int shift = 0;
            while (true)
            {
                int b = ms.ReadByte();
                if (b < 0) throw new EndOfStreamException();
                result |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }
            return result;
        }

        private static void SkipField(MemoryStream ms, int wireType)
        {
            switch (wireType)
            {
                case 0: // Varint
                    ReadVarint(ms);
                    break;
                case 1: // 64-bit
                    ms.Seek(8, SeekOrigin.Current);
                    break;
                case 2: // Length-delimited
                    int length = ReadVarint(ms);
                    ms.Seek(length, SeekOrigin.Current);
                    break;
                case 5: // 32-bit
                    ms.Seek(4, SeekOrigin.Current);
                    break;
                default:
                    throw new InvalidDataException("Unsupported wire type: " + wireType);
            }
        }

        private static string Base32Encode(byte[] bytes)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var sb = new StringBuilder();
            int bitBuffer = 0;
            int bitBufferLength = 0;

            foreach (byte b in bytes)
            {
                bitBuffer = (bitBuffer << 8) | b;
                bitBufferLength += 8;

                while (bitBufferLength >= 5)
                {
                    int index = (bitBuffer >> (bitBufferLength - 5)) & 0x1F;
                    sb.Append(alphabet[index]);
                    bitBufferLength -= 5;
                }
            }

            if (bitBufferLength > 0)
            {
                int index = (bitBuffer << (5 - bitBufferLength)) & 0x1F;
                sb.Append(alphabet[index]);
            }

            return sb.ToString();
        }
    }
}
