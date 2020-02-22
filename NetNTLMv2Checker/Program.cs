using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace NetNTLMv2Checker
{
   
    public class IMChecker
    {
        /* Designed to allow for checking a password locally against the output from Internal Monologue (netNTLMv2 Response) */
        public IMChecker(string netNTLMv2Response)
        {
            originalMessage = netNTLMv2Response;
            parseOriginal();
        }

        private void parseOriginal()
        {
            String[] separators = { ":" };
            String[] strlist = originalMessage.Split(separators, 5, StringSplitOptions.RemoveEmptyEntries);

            username = strlist[0];
            target = strlist[1];
            serverChallenge = utils.StringToByteArray(strlist[2]);
            netNtlmv2ResponseOriginal = utils.StringToByteArray(strlist[3]);
            blob = utils.StringToByteArray(strlist[4]);

        }

        public bool checkPassword(string password)
        {
            byte[] ntlmv2ResponseHash = new byte[16];
            ntlmv2ResponseHash = ntlm.getNTLMv2Response(target, username, password, serverChallenge, blob);
            Console.WriteLine("Response Hash: " + utils.ByteArrayToString(ntlmv2ResponseHash));
            Console.WriteLine("Original Hash: " + utils.ByteArrayToString(netNtlmv2ResponseOriginal));
            return ntlmv2ResponseHash.SequenceEqual(netNtlmv2ResponseOriginal);
        }

        public string originalMessage { get; set; }
        private string username { get; set; }
        private string target { get; set; }
        private byte[] serverChallenge { get; set; }
       
        private byte[] blob { get; set; }
        private byte[] netNtlmv2ResponseOriginal { get; set; }
    }
}
