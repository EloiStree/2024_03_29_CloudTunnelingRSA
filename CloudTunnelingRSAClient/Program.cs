using System;
using System.Drawing;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using NBitcoin.Secp256k1;
using Nethereum.Hex.HexConvertors.Extensions;
using Nethereum.Signer;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;

using SixLabors.ImageSharp.Processing;

class WebSocketClient
{
    private const string m_serverUri = "ws://81.240.94.97:2501";
    public static string m_privateKey = "<RSAKeyValue><Modulus>vP7yDAkjkLrO7zqlaOlVpi3h7knD2xU4voEj3w9aJ9Pm/J0WADOOpnGcBc25VI7yuZuJZjsLuK9dz6aFVQR2+ZpT7H1aD/7qgXG10eIrOSu41ZIpcO26VDFcfsX1as7kmAQmLqFFTzcL2Yzv5Vz3982QeFy5Sx4MIRa26fbrKOE=</Modulus><Exponent>AQAB</Exponent><P>x5+b84t6DU7dmRnZbg6nK5eLyGseIyDVodarQ8f7C4kCTfgYG7WW89X1cU//jMsj3mjQntOjJF2BkhtX/HWO0w==</P><Q>8l77YEBBJiLo6yuFDZLWRyjYJsEvuE3/MQvSwXtY2Hb7BM+ynhIcncs6jGmUuSSNoXhQ877CeD2sOJbGV+Ng+w==</Q><DP>J98nZRO8wx+3fzb8iNEAbuKMFvHeSSHrybF478bny7wH687b8dzpU7aumX1jC5ofhfLliHO5KDBNCwPPJSvN5Q==</DP><DQ>OzKVxUmMYAswxpfHlKwjqBfCy5xt0l9CkDEqFdXRunU9FEzCfLdBxAyqTTdQevQBn8mqRA54ozO1B9FTuo2v1w==</DQ><InverseQ>K+5TNsF1zM4SeFX8Pd7OcsB3yYP0VkCCawyeQxjm3GQbQd805JnqCoaAnAiuM5N49jonQXuJMjYqgxT0JWh2VA==</InverseQ><D>oJ3J9pCNuSIJWyXsDQy/zUqRB4GJAVc3si7t3VOeutpLI8QcPm+Se8FxZz0+k64oebTFQCxN+daPUzmhdm8k6+OqoYV/gHCrWbEQMAKkavT3rxtlJbkWkFgqNxmMQA2/2feC0ESbavtZemBLOP7p+VVr/cYu6DzpUNr5+FVhD0E=</D></RSAKeyValue>";
    public static string m_publicKey = "<RSAKeyValue><Modulus>vP7yDAkjkLrO7zqlaOlVpi3h7knD2xU4voEj3w9aJ9Pm/J0WADOOpnGcBc25VI7yuZuJZjsLuK9dz6aFVQR2+ZpT7H1aD/7qgXG10eIrOSu41ZIpcO26VDFcfsX1as7kmAQmLqFFTzcL2Yzv5Vz3982QeFy5Sx4MIRa26fbrKOE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

    public static byte[] SignData(byte[] data, RSAParameters privateKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(privateKey);
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
    public static bool VerifySignature(byte[] data, byte[] signature, RSAParameters publicKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(publicKey);
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }


    public static Queue<string> m_toSendToTheServerUTF8 = new Queue<string>();
    public static Queue<byte[]> m_toSendToTheServerBytes = new Queue<byte[]>();

    public async Task ConnectAndRun()
    {
        //// Create a new instance of the RSA algorithm
        //using (RSA rsag = RSA.Create())
        //{
        //    // Generate a 1024-bit RSA key pair
        //    rsag.KeySize = 1024;

        //    // Export the private key in PKCS#8 format
        //    string privateKey = rsag.ToXmlString(true);
        //    string publicKey = rsag.ToXmlString(false);

        //    Console.WriteLine("Generated random key if you need");
        //    // Print the generated keys
        //    Console.WriteLine("Private Key:");
        //    Console.WriteLine("-----------------------------------------------------------------");
        //    Console.WriteLine(privateKey);
        //    Console.WriteLine("-----------------------------------------------------------------");
        //    Console.WriteLine();
        //    Console.WriteLine("Public Key:");
        //    Console.WriteLine("-----------------------------------------------------------------");
        //    Console.WriteLine(publicKey);
        //    Console.WriteLine("-----------------------------------------------------------------");
        //    Console.WriteLine();
        //    Console.WriteLine();
        //    Console.WriteLine();
        //}

        



        while (true)
        {
            using (ClientWebSocket webSocket = new ClientWebSocket())
            {
                try
                {
                    m_messageToSignedReceived = "";
                    m_connectionEstablishedAndVerified = false;
                    Console.WriteLine($"Connecting to server: {m_serverUri}");
                    await webSocket.ConnectAsync(new Uri(m_serverUri), CancellationToken.None);

                    Task.Run(() => ReceiveMessages(webSocket));





                    while (webSocket.State == WebSocketState.Open)
                    {

                        if (!m_connectionEstablishedAndVerified)
                        {
                            byte[] b = Encoding.UTF8.GetBytes("Hello");
                            await webSocket.SendAsync(new ArraySegment<byte>(b), WebSocketMessageType.Text, true, CancellationToken.None);

                            while (m_messageToSignedReceived.Length == 0)
                            {
                                await Task.Delay(20);
                            }



                            RSA rsa = RSA.Create();

                            rsa.KeySize = 1024;
                            rsa.FromXmlString(m_privateKey);
                            RSAParameters privateKey = rsa.ExportParameters(true);
                            RSAParameters publicKey = rsa.ExportParameters(false);

                            string messageToSigne = m_messageToSignedReceived;
                            byte[] data = Encoding.UTF8.GetBytes(messageToSigne);
                            byte[] signature = SignData(data, privateKey);
                            var signatureBase64 = Convert.ToBase64String(signature);
                            string sent = "RSA:" + signatureBase64;
                            byte[] signatureBytes = Encoding.UTF8.GetBytes(sent);
                            Console.WriteLine($"Sent message to server: {sent}");
                            Console.WriteLine($"Sent message to server: {messageToSigne}");
                            await webSocket.SendAsync(new ArraySegment<byte>(signatureBytes), WebSocketMessageType.Text, true, CancellationToken.None);
                            // create a signe message
                            byte[] bb = Encoding.UTF8.GetBytes(messageToSigne);
                            await webSocket.SendAsync(new ArraySegment<byte>(bb), WebSocketMessageType.Text, true, CancellationToken.None);

                            while (!m_connectionEstablishedAndVerified)
                            {
                                await Task.Delay(20);
                            }

                        }
                        


                        while (m_toSendToTheServerUTF8.Count > 0)
                        {
                            byte[] messageBytes = Encoding.UTF8.GetBytes(m_toSendToTheServerUTF8.Dequeue());
                            await webSocket.SendAsync(new ArraySegment<byte>(messageBytes), WebSocketMessageType.Text, true, CancellationToken.None);
                        } while (m_toSendToTheServerBytes.Count > 0)
                        {
                            byte[] messageBytes = m_toSendToTheServerBytes.Dequeue();
                            await webSocket.SendAsync(new ArraySegment<byte>(messageBytes), WebSocketMessageType.Text, true, CancellationToken.None);
                        }
                        await Task.Delay(1);
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

    public static string m_messageToSignedReceived = "";
    public static bool m_connectionEstablishedAndVerified = false;
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
                    if (!m_connectionEstablishedAndVerified) { 
                        if (receivedMessage.Contains("SIGNEHERE:"))
                        {
                            m_messageToSignedReceived = receivedMessage.Replace("SIGNEHERE:", "");
                        }
                        if(receivedMessage.Contains("RSA:Verified"))
                        {
                            m_connectionEstablishedAndVerified = true;
                        }
                    }

                    if(receivedMessage.StartsWith("UDPT:"))
                    {
                        string whatToSend = receivedMessage.Substring("UDPT:".Length);
                        int index= whatToSend.IndexOf(":");
                        if (index > -1) { 
                            string type = whatToSend.Substring(0, index);
                            string data = whatToSend.Substring(index + 1);
                            if (int.TryParse(type, out int port))
                            {
                                //Send UDP data as text to localhost:port
                                Console.WriteLine($"Sending UDP data to localhost:{port}");
                                UdpClient udpClient = new UdpClient();
                                await udpClient.SendAsync(Encoding.UTF8.GetBytes(data), data.Length, "localhost", port);
                                udpClient.Close();
                            }
                            else {
                                foreach (var item in m_broadcastPort)
                                {
                                    UdpClient udpClient = new UdpClient();
                                    await udpClient.SendAsync(Encoding.UTF8.GetBytes(data), data.Length, "localhost", item);
                                    udpClient.Close();
                                }
                            }
                        }
                    }

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

    public static List<int> m_broadcastPort = new List<int>();
}

class Program
{
    static async Task Main(string[] args)
    {

        //Read a file name PrivateKey.txt and PublicKey.txt
        string path = Directory.GetCurrentDirectory();
        Console.WriteLine("Current Path:"+path);
        if (!File.Exists("KeyPair/RSA_PRIVATE_XML.txt"))
        {
            Directory.CreateDirectory("KeyPair");
            using (RSA rsa = RSA.Create())
            {
                rsa.KeySize = 1024;
                File.WriteAllText("KeyPair/RSA_PRIVATE_XML.txt", rsa.ToXmlString(true));
                File.WriteAllText("KeyPair/RSA_PUBLIC_XML.txt", rsa.ToXmlString(false));



                Console.WriteLine("Not Private key found. Random Generated for you in PrivateKey.txt.");
                Console.WriteLine("Never share your private key.");
            }
        }
       
        string privateKey = File.ReadAllText("KeyPair/RSA_PRIVATE_XML.txt");
        string publicKey = File.ReadAllText("KeyPair/RSA_PUBLIC_XML.txt");
        WebSocketClient.m_publicKey = publicKey;
        WebSocketClient.m_privateKey = privateKey;

        Console.WriteLine("PUBLIC KEY USE:");
        Console.WriteLine("---------------------");
        Console.WriteLine(publicKey);
        Console.WriteLine("---------------------");

        //example of sending data to local ports when broadcast all.
        WebSocketClient.m_broadcastPort.Add(5505);
        WebSocketClient.m_broadcastPort.Add(5506);

        Task.Run(async () =>
        {
            while (true)
            {
                await Task.Delay(30000);
                WebSocketClient.m_toSendToTheServerUTF8.Enqueue($"CLIENTTIME:{DateTime.UtcNow.ToString("yyyyMMddhhmmss")}");
            }
        });
        WebSocketClient client = new WebSocketClient();
        await client.ConnectAndRun();



        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}



public class PemToXmlConverter
{


    public void Generate1024RsaKey(out string privateXmlKey, out string publicXmlKey, out string privatePem, out string publicPem)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.KeySize = 1024;
            privateXmlKey = rsa.ToXmlString(true);
            publicXmlKey = rsa.ToXmlString(false);
            privatePem = rsa.ExportRSAPrivateKeyPem();
            publicPem = rsa.ExportRSAPublicKeyPem();
        }
    }
    public void GenerateEthereumKey(out string privateKeyEthereum, out string publicKeyEthereum, out string address)
    {

        var ecKey = EthECKey.GenerateKey();
        privateKeyEthereum = ecKey.GetPrivateKeyAsBytes().ToHex();
        publicKeyEthereum = ecKey.GetPubKey().ToHex();
        address = ecKey.GetPublicAddress();
    }


    public static string ConvertPrivateKey(string pemPrivateKey)
    {
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(pemPrivateKey);
        RSAParameters parameters = rsa.ExportParameters(true);

        XmlDocument xmlDoc = new XmlDocument();
        XmlElement root = xmlDoc.CreateElement("RSAKeyValue");
        xmlDoc.AppendChild(root);

        XmlElement modulus = xmlDoc.CreateElement("Modulus");
        modulus.InnerText = Convert.ToBase64String(parameters.Modulus);
        root.AppendChild(modulus);

        XmlElement exponent = xmlDoc.CreateElement("Exponent");
        exponent.InnerText = Convert.ToBase64String(parameters.Exponent);
        root.AppendChild(exponent);

        XmlElement p = xmlDoc.CreateElement("P");
        p.InnerText = Convert.ToBase64String(parameters.P);
        root.AppendChild(p);

        XmlElement q = xmlDoc.CreateElement("Q");
        q.InnerText = Convert.ToBase64String(parameters.Q);
        root.AppendChild(q);

        XmlElement dp = xmlDoc.CreateElement("DP");
        dp.InnerText = Convert.ToBase64String(parameters.DP);
        root.AppendChild(dp);

        XmlElement dq = xmlDoc.CreateElement("DQ");
        dq.InnerText = Convert.ToBase64String(parameters.DQ);
        root.AppendChild(dq);

        XmlElement inverseQ = xmlDoc.CreateElement("InverseQ");
        inverseQ.InnerText = Convert.ToBase64String(parameters.InverseQ);
        root.AppendChild(inverseQ);

        XmlElement d = xmlDoc.CreateElement("D");
        d.InnerText = Convert.ToBase64String(parameters.D);
        root.AppendChild(d);

        return xmlDoc.OuterXml;
    }

    public static string ConvertPublicKey(string pemPublicKey)
    {
        RSA rsa = RSA.Create();
        rsa.ImportFromPem(pemPublicKey);
        RSAParameters parameters = rsa.ExportParameters(false);

        XmlDocument xmlDoc = new XmlDocument();
        XmlElement root = xmlDoc.CreateElement("RSAKeyValue");
        xmlDoc.AppendChild(root);

        XmlElement modulus = xmlDoc.CreateElement("Modulus");
        modulus.InnerText = Convert.ToBase64String(parameters.Modulus);
        root.AppendChild(modulus);

        XmlElement exponent = xmlDoc.CreateElement("Exponent");
        exponent.InnerText = Convert.ToBase64String(parameters.Exponent);
        root.AppendChild(exponent);

        return xmlDoc.OuterXml;
    }
}