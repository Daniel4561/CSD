using CSD.Communication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CSD
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var server = new Server();
            server.Start();

            var client = new Client();

            client.Connect();

            string message = Console.ReadLine();

            client.SendMessage(message);
        }
    }
}
