using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using CSD.Key;
using CSD.AES_Alghoritm;
using System.Numerics;
using System.IO;

namespace CSD.Communication
{
    public class Server
    {
        private readonly TcpListener listener;
        private readonly byte[] readBuffer = new byte[1024];

        private bool started;

        public Server()
        {
            var ipEndPoint = new IPEndPoint(IPAddress.Any, 8888);
            listener = new TcpListener(ipEndPoint);
        }

        public void Start()
        {
            if (started) return;

            started = true;
            listener.Start();
            Thread serverThread = new Thread(Run);
            serverThread.Start();
        }

        private void Run()
        {

            while (started)
            {
                var handler = listener.AcceptTcpClient();
                var stream = handler.GetStream();
                var aes = AcceptConection(stream);

                var clientHandlerThread = new Thread(() => { HandleClient(handler, stream); });
                clientHandlerThread.Start();

            }

        }
        public void Stop()
        {
            listener.Stop();
            started = false;
        }

        private void HandleClient(TcpClient handler, NetworkStream stream)
        {
            Console.WriteLine("Connected");
            while(started)
            {
                var recived = stream.Read(readBuffer);

                string message = AES.Decrypt(readBuffer.Take(recived).ToArray());

                if (message.Split(' ')[0] == "-sm")
                {
                    message = message.Substring(4);
                    Console.WriteLine("Recived: " + message);
                }
                else
                {
                    var path = message.Split(" ")[1].Split("\\");
                    var filePath = path[path.Length - 1].Replace("\0","");

                    Console.WriteLine("Reciving file: " +  filePath);

                    using var file = File.OpenWrite(filePath);
                    if(file == null)
                    {
                        Console.WriteLine("Cannot open file!");
                        return;
                    }

                    while(true)
                    {
                        int recv = stream.Read(readBuffer);
                        var mess = AES.Decrypt_Bytes(readBuffer.Take(recv).ToArray());

                        if (recv < 1024)
                        {
                            file.Write(mess, 0, mess.Length);
                            break;
                        }

                        file.Write(mess, 0, mess.Length);
                    }

                    Console.WriteLine("Recived");
                }

            }
        }

        private AES AcceptConection(NetworkStream stream)
        {
            var recived = stream.Read(readBuffer);

            var keyAgreement = new Key_agreement();

            stream.Write(keyAgreement.publicKey.ToByteArray(), 0, keyAgreement.publicKey.ToByteArray().Length);
            stream.Flush();

            keyAgreement.Agreement(new BigInteger(readBuffer.Take(recived).ToArray()));

            AES aes = new AES(keyAgreement.communicationKey);
            //Console.WriteLine(BitConverter.ToString(AES.key));

            return aes;
        }
    }

}