# Local NetNTLMv2 Checker #

__Summary__

__NB__: This is __NOT__ a netNTLMv2 password cracking tool. For large scale dictionary or brute-force attacks a tool such as John or hashcat is recomended.
 
Check collected cleartext passwords against a netNTLMv2 Response. Designed to process the output from Internal Monologue. This allows verification of cleartext passwords without attempting authentication.

## Usage ##
```c#
string netNTLMv2Response = "user::DOMAIN:0123456789abcdef:cbabbca713eb795d04c97abc01ee4983:01010000000000000090d336b734c301ffffff00112233440000000002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d000000000000000000";
IMChecker checker = new IMChecker(netNTLMv2Response);
Console.WriteLine("password: " + checker.checkPassword("password")); // False
Console.WriteLine("SecREt01: " + checker.checkPassword("SecREt01")); // True
```  

## NTLMv2 Response Message ##

This primarily refereneces an excellent [article](http://davenport.sourceforge.net/ntlm.html#theLmv2Response) by Eric Glass on sourceforge and Microsoft's MSD NTML [documentation](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4). 
Infomration here will touch on the netNTLMv2 Repsonse (Type 3) message. For a more complete understanding of the protocol please read the article and documentation. 

__Overview__

1. NTLM hash is obtained (MD4 of user's password).
2. Unicode uppercase username is concatenated  with the domain or severname (this would normally be provided in the server response message - Type 2).
3. The NTLMv2 Hash is calulated from the HMAC_MD5 of these values, using the NTLM hash (see 1.) as the key giving a 16-byte (128-bit) hash (_see [HMAC](https://en.wikipedia.org/wiki/HMAC#Design_principles) for more details on the difference between MD5_).
4. The NTLMv2 hash is concatenated  with some _"random"_ data called the _blob_ (In this usecase we are not concerned with the structure of the _blob_ howerver, it is important in the protocol as it prevents attackers creating rainbow tables for precomputed passwords).
5. The HMAC_MD5 is calulated of the NTLMv2 Hash and _blob_ resulting in the final NTLMv2 Response (this is what we see in a netNTLMv2 Response Message).

### netNTLMv2 ###

When netNTLMv2 Response Messages (Type 3) are captured they will be in the following format.

`USERNAME::DOMAIN:SERVER_CHALLENGE:NTLMv2 Response:Blob`

Once captured the type 3 message above can be used, along with a supplied password, to generated a new NTLMv2 Response and the values compared. If a brute-force or dicationary approach is required a tool such as John or Hashcat is more appropriate.

## Credits ##
- C# MD4 Algorithm [novotnyllc](https://github.com/novotnyllc/cifs/blob/master/Cifs/MD4.cs)