using System.IO;
using System.Security.Cryptography;
using System.Text;
using System;

public static class SJEncryption
{
    static string passPhase = "Pas5pr@se";
    static string saltValue = "S@1tValue";
    static string hassAlgorithm = "MD5";
    static int passworditerations = 2;
    static string initVector = "@1B2c3D4e5F6g7H8";
    public static string Decrypt(this string cipherText)
    {
        byte[] Key = Encoding.ASCII.GetBytes(initVector);
        byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

        byte[] _cipherText = Convert.FromBase64String(cipherText.Replace(' ', '+'));

        PasswordDeriveBytes password = new PasswordDeriveBytes(passPhase, saltValueBytes, hassAlgorithm, passworditerations);

        byte[] IV = password.GetBytes(16);

        string plaintext = null;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(_cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        return plaintext;
    }

    public static string Encrypt(this string plainText)
    {
        byte[] Key = Encoding.ASCII.GetBytes(initVector);
        byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

        PasswordDeriveBytes password = new PasswordDeriveBytes(passPhase, saltValueBytes, hassAlgorithm, passworditerations);

        byte[] IV = password.GetBytes(16);

        byte[] encrypted;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        string cipherText = Convert.ToBase64String(encrypted);
        return cipherText;
    }
}