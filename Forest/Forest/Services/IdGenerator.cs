using System;
using System.Security.Cryptography;
using System.Text;

public class IdGenerator
{    
    public static string GeneratePublicUserId(string seed, string salt = null)
    {
        string raw = seed + "|" + salt; //The raw, will be used for creating hash
        
        var sha256 = SHA256.Create(); //SHA256
        byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(raw)); //Byte array of the hash
        
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant(); //Converting bytes to string
    }
    public static bool VerifyId(string id, string seed, string salt = "")
    {
        string expectedId = GeneratePublicUserId(seed, salt); //Generating public user ID from setted data
        
        return string.Equals(id, expectedId, StringComparison.OrdinalIgnoreCase); //Verifing user's ID and expected ID
    }
}