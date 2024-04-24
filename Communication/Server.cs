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

            while (true)
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
            while(true)
            {
                var recived = stream.Read(readBuffer);

                string message = AES.Decrypt(readBuffer.Take(recived).ToArray());

                if(message.Split(' ')[0] == "-sm")
                {
                    message = message.Substring(3);
                    Console.WriteLine();
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