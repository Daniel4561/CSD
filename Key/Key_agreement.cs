using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CSD.Key
{
    public class Key_agreement
    {
        private readonly BigInteger prime = BigInteger.Parse("191084770079676860731293364209784482007092682817527956783792656278547449213");
        private readonly BigInteger generator = 5;

        public byte[] communicationKey = new byte[16];
        public BigInteger publicKey;

        private BigInteger aliceSecret;
        public Key_agreement()
        {
            aliceSecret = new BigInteger(Key_Generator.GenerateRandomKey(16)) & BigInteger.Parse("7fffffffffffffffffffffffffffffff", NumberStyles.AllowHexSpecifier);
            publicKey = BigInteger.ModPow(generator, aliceSecret, prime);
        }
        public void Agreement(BigInteger bobPublic)
        {

            BigInteger sharedSecret = BigInteger.ModPow(bobPublic, aliceSecret, prime);

            Array.Copy(sharedSecret.ToByteArray(), sharedSecret.ToByteArray().Length - 16, communicationKey, 0, 16);
        }
    }
}
