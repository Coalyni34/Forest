using System;
using System.IO;
using System.Security.Cryptography;

public class UserService
{
    private readonly static string UserInfoPath = "MainFolder/UserInfo/ContactInfo/";
    public static class UserCreator
    {
        public static void WriteUserInfo(Contact user)
        {
            var json = ContactService.ContactSerializer.SerializeContact(user);
            if(!File.Exists($"{user.PublicId}.json"))
            {
                File.WriteAllText(UserInfoPath, json);
            }
        }
        public static Contact CreateUserInfo(string name, bool isPublic)
        {
            string publicId = GenerateDeterministicPublicId(name, DateTime.UtcNow.Ticks.ToString());
            string privateId = GenerateRandomPrivateId();
            return new Contact(name, isPublic, publicId, privateId);
        }
        private static string GenerateRandomPrivateId()
        {
            byte[] randomBytes = new byte[32]; 
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            
            var Id = string.Empty;
            foreach(var b in randomBytes)
            {
                Id += b.ToString();
            }
            return Id;
        }

        private static string GenerateDeterministicPublicId(string seed, string salt)
        {
            return IdGenerator.GenerateUserId(seed, salt);
        }
    }
}