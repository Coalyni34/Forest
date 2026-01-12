using System;
using System.IO;

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
            return new Contact(name, isPublic, publicId);
        }

        private static string GenerateDeterministicPublicId(string seed, string salt)
        {
            return IdGenerator.GeneratePublicUserId(seed, salt);
        }
    }
}