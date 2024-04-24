using CSD.AES_Alghoritm;
using CSD.Key;
using System;
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
            endPoint = new IPEndPoint(new IPAddress(new byte[] { 192, 168, 1, 103 }), port);
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
            Console.WriteLine(BitConverter.ToString(AES.key));
        }

        public void SendMessage(string message)
        {
            if (tcpClient == null || stream == null || aes == null) return;

            var bytes = AES.Encrypt(message);
            stream.Write(bytes);
            stream.Flush();
        }

        public void Stop()
        {
            stream.Close();
            tcpClient.Close();
        }
    }
}
