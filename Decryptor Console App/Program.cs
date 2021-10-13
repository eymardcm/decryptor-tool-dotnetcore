using System;
using Chilkat;

namespace Decryptor_Console_App
{
    class Program
    {
        static void Main(string[] args)
        {
            bool showMenu = true;
            while (showMenu)
            {
                showMenu = MainMenu();
            }

        }

        private static bool MainMenu()
        {

            Console.Clear();
            Console.WriteLine("Choose an option:");
            Console.WriteLine("1) Encrypt");
            Console.WriteLine("2) Decrypt");
            Console.WriteLine("3) Base64 Encode an encryption key");
            Console.WriteLine("4) Exit");
            Console.Write("\r\nSelect an option: ");

            switch (Console.ReadLine())
            {
                case "1":
                    Encrypt();
                    return true;
                case "2":
                    Decrypt();
                    return true;
                case "3":
                    Base64Encode();
                    return true;
                case "4":
                    return false;
                default:
                    return true;
            }
        }

        static void Decrypt()
        {
            SecuredData.Clear();

            Console.WriteLine("\nEnter the securedData you want decrypted:");
            SecuredData.CipherText = Console.ReadLine().ToString();

            Console.WriteLine("\nEnter the base64-encoded 256-bit encryption key that was used to encrypt the data (aka: The Wrapping Key):");
            SecuredData.Base64EncodedAESWrappingKey = Console.ReadLine().ToString();

            Console.WriteLine($"{Environment.NewLine}Here is your decrypted data:");
            Console.WriteLine($"{SecuredData.Decrypt()}");

            Console.WriteLine("\nPress any key to continue, or [Ctrl + c] to exit.\n");
            Console.ReadKey();
        }

        static void Encrypt()
        {
            Console.WriteLine($"{Environment.NewLine}Enter the data you want to encrypt, then press the <Enter> key:");
            var data = Console.ReadLine();
            Console.WriteLine($"{Environment.NewLine}Enter a 32 bytes (256-bit) AES Wrapping Key:"); // this should NOT be base64 encoded
            var aesWrappingKey = Console.ReadLine();

            Chilkat.Jwe jwe = new Chilkat.Jwe();

            // First build the JWE Protected Header: 

            Chilkat.JsonObject jweProtHdr = new Chilkat.JsonObject();
            jweProtHdr.AppendString("alg", "A256GCMKW");
            jweProtHdr.AppendString("enc", "A256GCM");
            // the iv should be 16 random chars.
            Chilkat.Prng prng = new Chilkat.Prng();
            jweProtHdr.AppendString("iv", prng.RandomString(16, true, true, true));
            jwe.SetProtectedHeader(jweProtHdr);

            // Given that we have 256-bit AES, our key should be 32 bytes.
            // The ascii string here is 32 bytes, therefore the 2nd arg is "ascii" to use these
            // ascii chars directly as the key.
            jwe.SetWrappingKey(0, aesWrappingKey, "ascii");

            // Encrypt and return the JWE:
            string strJwe = jwe.Encrypt(data, "utf-8");
            if (jwe.LastMethodSuccess != true)
            {
                Console.WriteLine(jwe.LastErrorText);
                return;
            }
            else
            {
                // Show the JWE we just created:
                Console.WriteLine($"{Environment.NewLine}Here is your securedData:");
                Console.WriteLine($"{strJwe} {Environment.NewLine}");

            }

            Console.WriteLine("\nPress any key to continue, or [Ctrl + c] to exit.\n");
            Console.ReadKey();

        }

        public static void Base64Encode()
        {
            Console.WriteLine($"{Environment.NewLine}Enter the 32 bytes (256-bit) AES Wrapping Key you want to encode:");
            var plainTextBytes = System.Text.Encoding.ASCII.GetBytes(Console.ReadLine());


            Console.WriteLine($"{Environment.NewLine}Here is your base64Encoded key:");
            Console.WriteLine($"{Convert.ToBase64String(plainTextBytes)}");

            Console.WriteLine($"{Environment.NewLine}Press any key to continue, or [Ctrl + c] to exit.\n");
            Console.ReadKey();

        }
    }

    public struct SecuredData
    {
        public static string CipherText;                    // this is the value of securedData
        public static string Base64EncodedAESWrappingKey;   // this is the b64Encoded 256-bit encryption key    
        public static string Decrypt()
        {
            bool success;

            Jwe jwe = new Jwe();

            //  1. Load the JWE..
            success = jwe.LoadJwe(CipherText);
            if (success != true) return jwe.LastErrorText;

            //  2. Set the AES wrap key for the recipient index.
            jwe.SetWrappingKey(0, Base64EncodedAESWrappingKey, "base64url");
            if (jwe.LastMethodSuccess != true) return jwe.LastErrorText;

            //  3. Decrypt       
            return jwe.Decrypt(0, "ascii");

        }
        public static void Clear()
        {
            CipherText = string.Empty;
            Base64EncodedAESWrappingKey = string.Empty;
        }
    }
}
