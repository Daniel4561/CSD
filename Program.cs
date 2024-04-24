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
            string help = "-sm [message] to send messege\n-sf [filePath] send file\n";
            string unkCommand = "Unknown Command";
            var server = new Server();
            server.Start();

            var client = new Client();

            client.Connect();

            while (true)
            {
                string command = Console.ReadLine();
                if (command == "-h" || command == "/h" || command == "/?")
                    Console.WriteLine(help);
                else
                {
                    if (command.Split(' ')[0] == "-sm")
                    {
                        client.SendMessage(command);
                    }
                    else
                    {
                        if(command.Split(" ")[0] == "-sf")
                        {
                            client.SendMessage(command);
                            client.SendFile(command.Split(' ')[1]);
                        }
                        else
                            Console.WriteLine(unkCommand);
                    }
                }
            }
        }
    }
}
