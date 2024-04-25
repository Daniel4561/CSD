using CSD.AES_Alghoritm;
using CSD.Key;
using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CSD.Communication
{
    public class Client
    {
        private TcpClient tcpClient;
        private NetworkStream stream;
        private AES aes;

        private readonly IPEndPoint endPoint;
        
        private readonly byte[] readBuffer = new byte[1024];

        private readonly int port = 8888;

        public Client()
        {
            endPoint = new IPEndPoint(new IPAddress(new byte[] { 192, 168, 124, 5 }), port);
        }

        public void Connect()
        {
            tcpClient = new TcpClient();
            tcpClient.Connect(endPoint);

            stream = tcpClient.GetStream();

            // Receive public parameters from client
            var keyAgreement = new Key_agreement();

            stream.Write(keyAgreement.publicKey.ToByteArray(), 0, keyAgreement.publicKey.ToByteArray().Length);
            stream.Flush();

            int recived = stream.Read(readBuffer);

            keyAgreement.Agreement(new BigInteger(readBuffer.Take(recived).ToArray()));

            aes = new AES(keyAgreement.communicationKey);
            //Console.WriteLine(BitConverter.ToString(AES.key));
        }

        public void SendMessage(string message)
        {
            if (tcpClient == null || stream == null || aes == null) return;

            var bytes = AES.Encrypt(message);
            stream.Write(bytes);
        }

        public void SendFile(string path)
        {
            using var file = File.OpenRead(path);

            if(file == null)
            {
                Console.WriteLine("No such file!");
                return;
            }

            var buffer = new byte[1024];
            var readed = file.Read(buffer, 0, buffer.Length);

            while(readed != 0)
            {
                var encoded = AES.Encrypt(buffer.Take(readed).ToArray());
                stream.Write(encoded);
                readed = file.Read(buffer, 0, buffer.Length);
            }

        }

        public void Stop()
        {
            stream.Close();
            tcpClient.Close();
        }
    }
}
