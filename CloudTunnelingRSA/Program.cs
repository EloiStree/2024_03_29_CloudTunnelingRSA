﻿using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System;
using System.Security.Cryptography.Xml;
using static WebSocketServer;
using System.Security.Cryptography.X509Certificates;


public class QuickTest
{

    public static string m_publicKey = "<RSAKeyValue><Modulus>vP7yDAkjkLrO7zqlaOlVpi3h7knD2xU4voEj3w9aJ9Pm/J0WADOOpnGcBc25VI7yuZuJZjsLuK9dz6aFVQR2+ZpT7H1aD/7qgXG10eIrOSu41ZIpcO26VDFcfsX1as7kmAQmLqFFTzcL2Yzv5Vz3982QeFy5Sx4MIRa26fbrKOE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

    public static string m_tunnelToSigneMessage = Guid.NewGuid().ToString();

    public static bool m_isRsaValidated = false;
    internal static bool m_saidHello;
    internal static bool m_waitForSigneMessage;
}

public class HideWindow
{

    // Import the ShowWindow function from user32.dll
    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private const int SW_MINIMIZE = 6;
    public static void MinimizeConsoleWindow()
    {
        IntPtr handle = Process.GetCurrentProcess().MainWindowHandle;
        ShowWindow(handle, SW_MINIMIZE);
    }
}

class WebSocketServer
{

    public class AppConfig
    {

        public int m_portOfServer = 2501;
        public int m_portToListen = 2502;
        public bool m_useRebroadcastLastMessage = false;
        public bool m_displayIpAddresses = true;
        public bool m_useConsolePrint = false;
        public bool m_valueTypeIsByte = true;

        public static AppConfig Configuration = new AppConfig();
    }

    private const int BufferSize = 4096;
    private HttpListener httpListener;
    private UdpClient udpListener;
    private readonly ConcurrentDictionary<string, WebSocket> connectedClients = new ConcurrentDictionary<string, WebSocket>();


    public async Task Start(string httpListenerPrefix, int udpListenerPort)
    {
        httpListener = new HttpListener();
        httpListener.Prefixes.Add(httpListenerPrefix);
        httpListener.Start();

        udpListener = new UdpClient(udpListenerPort);
        Console.WriteLine($"UDP listener is running on port {udpListenerPort}");

        Console.WriteLine("WebSocket server is running...");

        // Start a background task to broadcast messages every 1 second
        //if (AppConfig.Configuration.m_useRebroadcastLastMessage)

        //    Task.Run(() => broad());
        // Start a background task to listen for UDP messages
        Task.Run(() => ListenForUdpMessages());

        while (true)
        {
            HttpListenerContext context = await httpListener.GetContextAsync();
            if (context.Request.IsWebSocketRequest)
            {
                ProcessWebSocketRequest(context);
            }
            else
            {
                context.Response.StatusCode = 400;
                context.Response.Close();
            }
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
    private async void ProcessWebSocketRequest(HttpListenerContext context)
    {
        HttpListenerWebSocketContext webSocketContext = await context.AcceptWebSocketAsync(subProtocol: null);

        WebSocket webSocket = webSocketContext.WebSocket;
        string clientId = Guid.NewGuid().ToString(); // Assign a unique identifier to each client

        Console.WriteLine($"Hello  message from {clientId}");

        connectedClients.TryAdd(clientId, webSocket);

        try
        {
            byte[] buffer = new byte[BufferSize];

            while (webSocket.State == WebSocketState.Open)
            {
                WebSocketReceiveResult result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

                if (result.MessageType == WebSocketMessageType.Text)
                {
                    string receivedMessage = Encoding.UTF8.GetString(buffer, 0, result.Count);
                    if (AppConfig.Configuration.m_useConsolePrint)
                        Console.WriteLine($"Received message from {clientId}: {receivedMessage}");

                    if (receivedMessage.Length == 5 && receivedMessage.IndexOf("Hello") == 0)
                    {
                        QuickTest.m_saidHello = false;
                        QuickTest.m_waitForSigneMessage = false;
                        QuickTest.m_isRsaValidated = false;
                    }

                    if (!QuickTest.m_isRsaValidated)
                    {

                        if (receivedMessage.Length == 5 && receivedMessage.IndexOf("Hello") == 0)
                        {
                            QuickTest.m_saidHello = true;
                            QuickTest.m_waitForSigneMessage = true;
                            QuickTest.m_isRsaValidated = false;
                            byte[] reply = Encoding.UTF8.GetBytes("SIGNEHERE:" + QuickTest.m_tunnelToSigneMessage);
                            await webSocket.SendAsync(new ArraySegment<byte>(reply), WebSocketMessageType.Text, true, CancellationToken.None);
                        }
                        else if (QuickTest.m_saidHello && QuickTest.m_waitForSigneMessage)
                        {

                            RSA rsa = RSA.Create();

                            rsa.KeySize = 1024;
                            rsa.FromXmlString(QuickTest.m_publicKey);
                            RSAParameters publicKey = rsa.ExportParameters(false);

                            string encryptMessage = receivedMessage.Substring("RSA:".Length);
                            Console.WriteLine("Message to verified:" + encryptMessage);
                            byte[] encryptedData = Convert.FromBase64String(encryptMessage);
                            bool isVerified = VerifySignature(Encoding.UTF8.GetBytes(QuickTest.m_tunnelToSigneMessage), encryptedData, publicKey);
                            // console write is verified
                            Console.WriteLine("Is verified: " + isVerified);
                            Console.WriteLine("");
                            Console.WriteLine("");

                            if (isVerified)
                            {
                                QuickTest.m_waitForSigneMessage = false;
                                QuickTest.m_isRsaValidated = true;
                                byte[] reply = Encoding.UTF8.GetBytes("RSA:Verified");
                                await webSocket.SendAsync(new ArraySegment<byte>(reply), WebSocketMessageType.Text, true, CancellationToken.None);
                                reply = Encoding.UTF8.GetBytes("Congratulation. Welcome to the server. Make yourself as at your home. :)\n\n\n");
                                await webSocket.SendAsync(new ArraySegment<byte>(reply), WebSocketMessageType.Text, true, CancellationToken.None);
                            }
                            else
                            {


                                byte[] reply = Encoding.UTF8.GetBytes("Signature non validie !!!");
                                await webSocket.SendAsync(new ArraySegment<byte>(reply), WebSocketMessageType.Text, true, CancellationToken.None);

                                await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None);
                                webSocket.Dispose();
                            }
                        }
                        else
                        {
                            byte[] reply = Encoding.UTF8.GetBytes("You must say 'Hello'." +
                                " You will receive a 'SIGNEHERE:' message." +
                                " Signe it with your RSA key. Wait the 'RSA:Verified'." +
                                " Any other situation is consider as spam, fail or DOS and lead to disconnection.");
                            await webSocket.SendAsync(new ArraySegment<byte>(reply), WebSocketMessageType.Text, true, CancellationToken.None);

                            await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None);
                            webSocket.Dispose();
                        }

                    }
                    else
                    {

                        Console.WriteLine("Valide message: " + receivedMessage);
                    }

                    // You can handle the received message here if needed
                }
                else if (result.MessageType == WebSocketMessageType.Close)
                {
                    connectedClients.TryRemove(clientId, out _);
                    await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"WebSocket error for client {clientId}: {ex.Message}");
        }
    }


    private async Task ListenForUdpMessages()
    {
        while (true)
        {
            UdpReceiveResult result = await udpListener.ReceiveAsync();

            if (AppConfig.Configuration.m_valueTypeIsByte)
            {
                byte[] byteToBroadcast = result.Buffer;
                TimeWatch.Start();

                if (AppConfig.Configuration.m_useConsolePrint)

                    Console.WriteLine($"Byte Received lenght: {byteToBroadcast.Length}");

                // Broadcast the UDP message to connected WebSocket clients
                foreach (var client in connectedClients)
                {
                    try
                    {
                        if (client.Value.State == WebSocketState.Open)
                        {

                            await client.Value.SendAsync(new ArraySegment<byte>(byteToBroadcast), WebSocketMessageType.Binary, true, CancellationToken.None);
                        }
                        else
                        {
                            // Remove disconnected client
                            connectedClients.TryRemove(client.Key, out _);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to send UDP message to client {client.Key}: {ex.Message}");
                    }
                }
                TimeWatch.End();
                if (AppConfig.Configuration.m_useConsolePrint)

                    Console.WriteLine($"TimeWatch (Read and push): {TimeWatch.GetSeconds()}");
            }
            else
            {
                string udpMessage = Encoding.UTF8.GetString(result.Buffer);
                TimeWatch.Start();

                if (AppConfig.Configuration.m_useConsolePrint)

                    Console.WriteLine($"Received UDP message: {udpMessage}");

                // Broadcast the UDP message to connected WebSocket clients
                foreach (var client in connectedClients)
                {
                    try
                    {
                        if (client.Value.State == WebSocketState.Open)
                        {
                            byte[] udpMessageBytes = Encoding.UTF8.GetBytes(udpMessage);
                            await client.Value.SendAsync(new ArraySegment<byte>(udpMessageBytes), WebSocketMessageType.Text, true, CancellationToken.None);
                        }
                        else
                        {
                            // Remove disconnected client
                            connectedClients.TryRemove(client.Key, out _);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to send UDP message to client {client.Key}: {ex.Message}");
                    }
                }
                TimeWatch.End();
                if (AppConfig.Configuration.m_useConsolePrint)

                    Console.WriteLine($"TimeWatch (Read and push): {TimeWatch.GetSeconds()}");
            }


        }
    }

    public void Stop()
    {
        httpListener.Stop();
        httpListener.Close();
        udpListener.Close();
    }
}

public class TimeWatch
{
    public static DateTime m_startTime;
    public static DateTime m_endTime;

    public static void Start() { m_startTime = DateTime.Now; }
    public static void End() { m_endTime = DateTime.Now; }
    public static double GetSeconds() { return (m_endTime - m_startTime).TotalSeconds; }
}


class Program
{
    public static string m_configFileRelativePath = "ConfigBroadcaster.json";
    static async Task Main(string[] args)
    {
        if (!Directory.Exists("KeyPair"))
            Directory.CreateDirectory("KeyPair");

        if (!File.Exists("KeyPair/PublicKey.txt"))
        {
            File.WriteAllText("KeyPair/PublicKey.txt", QuickTest.m_publicKey);
        }

        QuickTest.m_publicKey = File.ReadAllText("KeyPair/PublicKey.txt");




        if (!File.Exists(m_configFileRelativePath))
            File.WriteAllText(m_configFileRelativePath, JsonConvert.SerializeObject(AppConfig.Configuration));

        string configUsed = File.ReadAllText(m_configFileRelativePath);
        Console.WriteLine(configUsed);
        AppConfig.Configuration = JsonConvert.DeserializeObject<AppConfig>(configUsed);


        if (AppConfig.Configuration.m_displayIpAddresses)
            NetworkInfo.DisplayConnectedLocalIPs();


        HideWindow.MinimizeConsoleWindow();
        string httpListenerPrefix = $"http://*:{AppConfig.Configuration.m_portOfServer}/";
        int udpListenerPort = AppConfig.Configuration.m_portToListen;

        WebSocketServer server = new WebSocketServer();
        await server.Start(httpListenerPrefix, udpListenerPort);

        Console.WriteLine("Press any key to stop the server...");
        Console.ReadKey();

        server.Stop();
    }
}
