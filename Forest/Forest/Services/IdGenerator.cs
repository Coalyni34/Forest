using System;
using System.Security.Cryptography;
using System.Text;

public class IdGenerator
{    
    public static string GenerateUserId(string seed, string salt = null)
    {
        string raw = seed + "|" + salt;
        
        var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(raw));
        
        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
    }
    public static bool VerifyId(string id, string seed, string salt = "")
    {
        string expectedId = GenerateUserId(seed, salt);
        
        return string.Equals(id, expectedId, StringComparison.OrdinalIgnoreCase);
    }
}