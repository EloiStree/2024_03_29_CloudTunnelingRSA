﻿using System;
using System.Net.WebSockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

class WebSocketClient
{
    private const string ServerUri = "ws://81.240.94.97:2501";
    public static string m_privateKey = "<RSAKeyValue><Modulus>vP7yDAkjkLrO7zqlaOlVpi3h7knD2xU4voEj3w9aJ9Pm/J0WADOOpnGcBc25VI7yuZuJZjsLuK9dz6aFVQR2+ZpT7H1aD/7qgXG10eIrOSu41ZIpcO26VDFcfsX1as7kmAQmLqFFTzcL2Yzv5Vz3982QeFy5Sx4MIRa26fbrKOE=</Modulus><Exponent>AQAB</Exponent><P>x5+b84t6DU7dmRnZbg6nK5eLyGseIyDVodarQ8f7C4kCTfgYG7WW89X1cU//jMsj3mjQntOjJF2BkhtX/HWO0w==</P><Q>8l77YEBBJiLo6yuFDZLWRyjYJsEvuE3/MQvSwXtY2Hb7BM+ynhIcncs6jGmUuSSNoXhQ877CeD2sOJbGV+Ng+w==</Q><DP>J98nZRO8wx+3fzb8iNEAbuKMFvHeSSHrybF478bny7wH687b8dzpU7aumX1jC5ofhfLliHO5KDBNCwPPJSvN5Q==</DP><DQ>OzKVxUmMYAswxpfHlKwjqBfCy5xt0l9CkDEqFdXRunU9FEzCfLdBxAyqTTdQevQBn8mqRA54ozO1B9FTuo2v1w==</DQ><InverseQ>K+5TNsF1zM4SeFX8Pd7OcsB3yYP0VkCCawyeQxjm3GQbQd805JnqCoaAnAiuM5N49jonQXuJMjYqgxT0JWh2VA==</InverseQ><D>oJ3J9pCNuSIJWyXsDQy/zUqRB4GJAVc3si7t3VOeutpLI8QcPm+Se8FxZz0+k64oebTFQCxN+daPUzmhdm8k6+OqoYV/gHCrWbEQMAKkavT3rxtlJbkWkFgqNxmMQA2/2feC0ESbavtZemBLOP7p+VVr/cYu6DzpUNr5+FVhD0E=</D></RSAKeyValue>";
    public static string m_publicKey = "<RSAKeyValue><Modulus>vP7yDAkjkLrO7zqlaOlVpi3h7knD2xU4voEj3w9aJ9Pm/J0WADOOpnGcBc25VI7yuZuJZjsLuK9dz6aFVQR2+ZpT7H1aD/7qgXG10eIrOSu41ZIpcO26VDFcfsX1as7kmAQmLqFFTzcL2Yzv5Vz3982QeFy5Sx4MIRa26fbrKOE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

    static byte[] SignData(byte[] data, RSAParameters privateKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(privateKey);
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
    static bool VerifySignature(byte[] data, byte[] signature, RSAParameters publicKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(publicKey);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }

    public async Task ConnectAndRun()
    {
        // Create a new instance of the RSA algorithm
        using (RSA rsag = RSA.Create())
        {
            // Generate a 1024-bit RSA key pair
            rsag.KeySize = 1024;

            // Export the private key in PKCS#8 format
            string privateKey = rsag.ToXmlString(true);
            string publicKey = rsag.ToXmlString(false);

            Console.WriteLine("Generated random key if you need");
            // Print the generated keys
            Console.WriteLine("Private Key:");
            Console.WriteLine("-----------------------------------------------------------------");
            Console.WriteLine(privateKey);
            Console.WriteLine("-----------------------------------------------------------------");
            Console.WriteLine();
            Console.WriteLine("Public Key:");
            Console.WriteLine("-----------------------------------------------------------------");
            Console.WriteLine(publicKey);
            Console.WriteLine("-----------------------------------------------------------------");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine();
        }

        



        while (true)
        {
            using (ClientWebSocket webSocket = new ClientWebSocket())
            {
                try
                {
                    Console.WriteLine($"Connecting to server: {ServerUri}");
                    await webSocket.ConnectAsync(new Uri(ServerUri), CancellationToken.None);

                    Task.Run(() => ReceiveMessages(webSocket));
                    while (webSocket.State == WebSocketState.Open)
                    {

                        if (true)
                        {
                            RSA rsa = RSA.Create();
                            
                            rsa.KeySize = 1024;
                            rsa.FromXmlString(m_privateKey);
                            RSAParameters privateKey = rsa.ExportParameters(true);
                            RSAParameters publicKey = rsa.ExportParameters(false);
                                
                            string dateTime = DateTime.UtcNow.ToString("yyyyMMddHHmm");
                            byte[] data = Encoding.UTF8.GetBytes(dateTime);
                            byte[] signature = SignData(data, privateKey);
                            var signatureBase64 = Convert.ToBase64String(signature);
                            string sent = "RSA:" + signatureBase64;
                            byte[] signatureBytes = Encoding.UTF8.GetBytes(sent);
                            Console.WriteLine($"Sent message to server: {sent}");
                            Console.WriteLine($"Sent message to server: {dateTime}");
                            await webSocket.SendAsync(new ArraySegment<byte>(signatureBytes), WebSocketMessageType.Text, true, CancellationToken.None);
                            // create a signe message
                            byte[] b = Encoding.UTF8.GetBytes(dateTime);
                            await webSocket.SendAsync(new ArraySegment<byte>(b), WebSocketMessageType.Text, true, CancellationToken.None);

                            await Task.Delay(3000);
                        }
                        //if (true)
                        //{
                        //    RSA rsa = RSA.Create();
                        //    rsa.FromXmlString(m_privateKey);
                        //    string dateTime = DateTime.UtcNow.ToString("yyyyMMddHHmm");
                        //    byte[] data = Encoding.UTF8.GetBytes(dateTime);
                        //    byte[] encryptedData = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                        //    var encryptedData64 = Convert.ToBase64String(encryptedData);
                        //    string sent = "RSA:" + encryptedData64;
                        //    byte[] textAsUTF8 = Encoding.UTF8.GetBytes(sent);
                        //    Console.WriteLine($"Sent message to server: {sent}");
                        //    await webSocket.SendAsync(new ArraySegment<byte>(textAsUTF8), WebSocketMessageType.Text, true, CancellationToken.None);
                        //    // create a signe message
                        //    Console.WriteLine($"Sent message to server: {dateTime}");
                        //    byte[] b = Encoding.UTF8.GetBytes(dateTime);
                        //    await webSocket.SendAsync(new ArraySegment<byte>(b), WebSocketMessageType.Text, true, CancellationToken.None);

                        //    await Task.Delay(3000);
                        //}



                        // create a signe message
                        string message = $"Client message at {DateTime.Now}";
                        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                        await webSocket.SendAsync(new ArraySegment<byte>(messageBytes), WebSocketMessageType.Text, true, CancellationToken.None);
                        await Task.Delay(3000);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"WebSocket error: {ex.Message}");
                    Console.WriteLine("Reconnecting in 5 seconds...");
                    await Task.Delay(5000);
                }
            }
        }
    }

    private async Task ReceiveMessages(ClientWebSocket webSocket)
    {
        byte[] buffer = new byte[4096];

        try
        {
            while (webSocket.State == WebSocketState.Open)
            {
                WebSocketReceiveResult result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

                if (result.MessageType == WebSocketMessageType.Text)
                {
                    string receivedMessage = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    Console.WriteLine($"Received message from server: {receivedMessage}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"WebSocket error: {ex.Message}");

            // Handle reconnection logic
            Console.WriteLine("Reconnecting in 5 seconds...");
            await Task.Delay(5000);
        }
    }
}

class Program
{
    static async Task Main(string[] args)
    {
        WebSocketClient client = new WebSocketClient();
        await client.ConnectAndRun();

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}