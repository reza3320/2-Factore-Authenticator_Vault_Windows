using System;
using System.Security.Cryptography;
using System.Text;

namespace Win2FA
{
    public static class Totp
    {
        public static string GeneratePin(byte[] secret, long timeStep = 30, int digits = 6)
        {
            long counter = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / timeStep;
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }

            using (var hmac = new HMACSHA1(secret))
            {
                byte[] hash = hmac.ComputeHash(counterBytes);
                int offset = hash[hash.Length - 1] & 0x0F;
                int binary = ((hash[offset] & 0x7F) << 24) |
                             ((hash[offset + 1] & 0xFF) << 16) |
                             ((hash[offset + 2] & 0xFF) << 8) |
                             (hash[offset + 3] & 0xFF);

                int password = binary % (int)Math.Pow(10, digits);
                return password.ToString().PadLeft(digits, '0');
            }
        }

        public static byte[] Base32Decode(string base32)
        {
            if (string.IsNullOrEmpty(base32)) return Array.Empty<byte>();

            base32 = base32.Trim().ToUpperInvariant().Replace(" ", "");
            int outLength = base32.Length * 5 / 8;
            byte[] result = new byte[outLength];

            int byteIndex = 0;
            int bitBuffer = 0;
            int bitBufferLength = 0;

            foreach (char c in base32)
            {
                int charVal = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".IndexOf(c);
                if (charVal < 0) continue; // Skip padding or invalid characters

                bitBuffer = (bitBuffer << 5) | charVal;
                bitBufferLength += 5;

                if (bitBufferLength >= 8)
                {
                    result[byteIndex++] = (byte)((bitBuffer >> (bitBufferLength - 8)) & 0xFF);
                    bitBufferLength -= 8;
                }
            }

            return result;
        }
    }
}
