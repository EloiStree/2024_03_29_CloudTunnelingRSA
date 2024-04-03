using Nethereum.Signer;
using System;
using System.IO;
using System.Numerics;
using System.Security;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        try
        {
            // Ethereum address of the signer
            string signerAddress = "0xYourSignerAddress";

            // Message to verify
            string message = "Hello, Ethereum!";

            // Signature to verify
            string signature = "YourSignature";

            // Verify the signature
            var signer = new EthereumMessageSigner();
            var verified = signer.Verify(message, signature, signerAddress);

            if (verified)
            {
                Console.WriteLine("The message has been signed by the specified address.");
            }
            else
            {
                Console.WriteLine("The message has not been signed by the specified address.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }
}



using Nethereum.Signer;
using System;
using System.IO;
using System.Numerics;
using System.Security;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        try
        {
            // Ethereum address and private key
            string address = "Your Ethereum Address";
            string privateKey = "Your Ethereum Private Key";

            // Message to sign
            string message = "Hello, Ethereum!";

            // Convert private key string to SecureString for security
            using (SecureString securePrivateKey = new SecureString())
            {
                foreach (char c in privateKey)
                {
                    securePrivateKey.AppendChar(c);
                }

                // Initialize the signer
                var signer = new EthereumMessageSigner();

                // Sign the message
                var signature = signer.EncodeUTF8AndSign(message, securePrivateKey);

                Console.WriteLine("Signature: " + signature);

                // Save the signature to a file
                string fileName = "signature.txt";
                File.WriteAllText(fileName, signature);
                Console.WriteLine("Signature saved to: " + fileName);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }
}
