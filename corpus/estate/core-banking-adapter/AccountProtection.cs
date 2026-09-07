using System;
using System.Security.Cryptography;

namespace Meridian.CoreBanking
{
    /// <summary>Account number protection in the .NET core banking adapter.</summary>
    public static class AccountProtection
    {
        public static RSA CreateAccountSigningKey() => RSA.Create(2048);

        public static ECDsa CreateStatementSigningKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

        public static byte[] EncryptAccountNumber(byte[] plaintext, byte[] key, byte[] iv)
        {
            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            using var encryptor = aes.CreateEncryptor(key, iv);
            return encryptor.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        // Statement checksum from the mainframe era.
        public static byte[] StatementChecksum(byte[] statement)
        {
            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(statement);
        }
    }
}
