using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CSD.Key
{
    public class Key_Generator
    {
        public static byte[] GenerateRandomKey(int keySize)
        {
            byte[] key = new byte[keySize];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            return key;
        }
    }
}
