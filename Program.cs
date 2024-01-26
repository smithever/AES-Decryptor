using System;
using System.IO;
using System.Security.Cryptography;

namespace Decyption
{
    class Program
    {
        static void Main(string[] args)
        {
            string inputFile = @"C:\FileToEncrypt.txt";
            string outputFile = @"C:\EncryptedOutputFile.txt";
            string password = "YourAESEncryptionPassword";

            FileDecrypt(inputFile, outputFile, password);

        }

        private static void FileDecrypt(string inputFile, string outputFile, string password)
        {

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);

            Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;

            //Create the Key
            byte[] passwordBytes = System.Text.Encoding.ASCII.GetBytes(password);
            var sha = SHA256.Create();
            var KeyData = sha.ComputeHash(passwordBytes);
            var size = (aes.KeySize / 8);
            byte[] key = new byte[size];
            Array.Copy(KeyData, key, size);

            aes.Key = key;

            //Create the IV
            var ivSize = (aes.BlockSize / 8);
            byte[] ivData = new byte[ivSize];
            Array.Copy(KeyData, ivData, ivSize);
            aes.IV = ivData;

            var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            CryptoStream cs = new CryptoStream(fsCrypt, aes.CreateDecryptor(), CryptoStreamMode.Read);
            FileStream fsOut = new FileStream(outputFile, FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (CryptographicException ex_CryptographicException)
            {
                Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();
            }
        }

    }
}