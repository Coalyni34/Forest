using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Data.SqlTypes;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Chaos.NaCl;
public class EncryptionService
{  
    public class EncryptedMessagePacket
    {
        public string ChatId { get; set; }
        public string SenderId { get; set; }
        public ulong MessageId { get; set; }

        public DateTime SentAt { get; set; }
        public MessageType MessageType { get; set; }

        public byte[] Ciphertext { get; set; }
        public byte[] Nonce { get; set; }
        public byte[] AuthTag { get; set; }
        public byte[] Signature { get; set; }

        public string ToJson() => JsonSerializer.Serialize(this);
        public static EncryptedMessagePacket FromJson(string json) => JsonSerializer.Deserialize<EncryptedMessagePacket>(json);
    }
    public class ChatSession
    {
        public string ChatId { get; set; }
        public byte[] RootKey { get; set; }
        public byte[] ChatSalt { get; set; }

        public string SelfId { get; set; }
        public string PeerId { get; set; }
        public byte[] PeerPublicKey { get; set; }

        public ulong NextMessageId { get; set; }
    }
    public class MessageEncoder
    {
        public (EncryptedMessagePacket packet, Message message) EncryptMessage(
            Message message, 
            ChatSession session,
            byte[] senderPrivateKey)
        {
            ValidateParameters(message, session, senderPrivateKey);

            if (message.Id == 0)
            {
                message.Id = session.NextMessageId;
                session.NextMessageId++;
            }

            if (string.IsNullOrEmpty(message.SenderId))
            {
                message.SenderId = session.SelfId;
            }

            message.SentAt = DateTime.UtcNow;

            string messageJson = SerializeMessage(message);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(messageJson);

            var (messageKey, messageNonce) = DeriveMessageKey(
                session.RootKey,
                session.ChatSalt,
                message.Id
            ); 

            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] authTag = new byte[16];

            using (var aes = new AesGcm(messageKey))
            {
                aes.Encrypt(messageNonce, plaintextBytes, ciphertext, authTag);
            }

            byte[] signature = SignMessageData(
                session.ChatId,
                message.Id,
                ciphertext,
                authTag,
                messageNonce,
                senderPrivateKey
            );

            var encryptedPacket = new EncryptedMessagePacket
            {
                ChatId = session.ChatId,
                SenderId = message.SenderId,
                MessageId = message.Id,
                SentAt = message.SentAt,
                MessageType = message.MessageType,
                Ciphertext = ciphertext,
                Nonce = messageNonce,
                AuthTag = authTag,
                Signature = signature        
            };

            return (encryptedPacket, message);
        }
        public (EncryptedMessagePacket packet, Message message) EncryptTextMessage(
            string text,
            ChatSession session,
            byte[] senderPrivateKey,
            ulong? messageId = null
        )
        {
            var message = new Message(
                Id: messageId ?? 0,
                SenderId: session.SelfId,
                Data: Encoding.UTF8.GetBytes(text),
                IsDownloaded: false,
                MessageType: MessageType.Text,
                MediaSourcePath: new List<string>()
            );

            return EncryptMessage(message, session,  senderPrivateKey);
        }
        public (EncryptedMessagePacket packet, Message message) EncryptMediaMessage(
            MessageType mediaType,
            string magnetLink,
            string description,
            ChatSession session,
            byte[] senderPrivateKey,
            ulong? messageId = null
        )
        {
            var message = new Message(
                Id: messageId ?? 0,
                SenderId: session.SelfId,
                Data: Encoding.UTF8.GetBytes(description),
                IsDownloaded: false,
                MessageType: mediaType,
                MediaSourcePath: new List<string> { magnetLink }
            );

            return EncryptMessage(message, session, senderPrivateKey);
        }
        public (EncryptedMessagePacket, Message mesage) EncryptMessageWithId(
            Message message,
            ChatSession session,
            byte[] senderPrivateKey
        )
        {
            if(message.Id == 0)
            {
                throw new ArgumentException("ID can't be null");
            }

            return EncryptMessage(message, session, senderPrivateKey);
        }
        
        public Message DecryptMessage(
            EncryptedMessagePacket packet,
            ChatSession session
        )
        {
            ValidatePacket(packet);

            if (!VerifyMessageSignature(packet, session.PeerPublicKey))
            {
                throw new CryptographicException(
                    $"Wrong signature of the message: \n{packet.MessageId}\nThe message is maybe a fake."
                );
            }

            var (expectedKey, expectedNonce) = DeriveMessageKey(
                session.RootKey,
                session.ChatSalt,
                packet.MessageId
            );

            if (!packet.Nonce.SequenceEqual(expectedNonce))
            {
                throw new CryptographicException(
                    $"Wrong nonce for the message:\n{packet.MessageId}\nThe message is maybe a fake"
                );
            }

            byte[] plaintextBytes = new byte[packet.Ciphertext.Length];

            using (var aes = new AesGcm(expectedKey))
            {
                try
                {
                    aes.Decrypt(
                        packet.Nonce,
                        packet.Ciphertext,
                        packet.AuthTag,
                        plaintextBytes
                    );
                }
                catch (CryptographicException ex)
                {
                    throw new CryptographicException(
                        $"Couldn't decrypt the message:\n{packet.MessageId}\n"
                        + $"Data is damaged or a key is not correct.", ex
                    );
                }
            }

            Message message;
            try
            {
                string messageJson = Encoding.UTF8.GetString(plaintextBytes);
                message = DeserializeMessage(messageJson);
            }
            catch(JsonException ex)
            {
                throw new CryptographicException(
                    $"Couldn't deserialize a decrypted message:\n{packet.MessageId}\n", ex
                );
            }

            ValidateDecryptedMessage(message, packet);

            message.IsDownloaded = true;

            if (message.Id >= session.NextMessageId)
            {
                session.NextMessageId = message.Id + 1;
            }

            return message;
        } 
        public Message DecryptMessageFromJson(
            string encryptedJson,
            ChatSession session
        )
        {
            var packet = EncryptedMessagePacket.FromJson(encryptedJson);
            return DecryptMessage(packet, session);
        }

        public bool VerifySignatureOnly(
            EncryptedMessagePacket packet,
            byte[] senderPublicKey
        )
        {
            try
            {
                return VerifyMessageSignature(packet, senderPublicKey);
            }
            catch
            {
                return false;
            }
        }
        
        private (byte[] key, byte[] nonce) DeriveMessageKey(
            byte[] rootkey,
            byte[] chatSalt,
            ulong messageId
        )
        {
            var hkdf = new HMACSHA256(rootkey);

            byte[] idBytes = BitConverter.GetBytes(messageId);
            byte[] hkdfSalt = new byte[chatSalt.Length + idBytes.Length];
            Buffer.BlockCopy(chatSalt, 0, hkdfSalt, 0, chatSalt.Length);
            Buffer.BlockCopy(idBytes, 0, hkdfSalt, chatSalt.Length, idBytes.Length);

            byte[] prk = hkdf.ComputeHash(hkdfSalt);
            byte[] info = Encoding.UTF8.GetBytes("FOREST_MESSAGE_KEY_V1");
            byte[] keyMaterial = hkdf.ComputeHash(prk.Concat(info).ToArray());

            byte[] key = new byte[32];
            byte[] nonce = new byte[12];
            Buffer.BlockCopy(keyMaterial, 0, key, 0, 32);
            Buffer.BlockCopy(keyMaterial, 32, nonce, 0, 12);

            return (key, nonce);
        }
        private byte[] SignMessageData(
            string chatId,
            ulong messageId,
            byte[] ciphertext,
            byte[] authTag,
            byte[] nonce,
            byte[] senderPrivateKey
        )
        {
            byte[] chatIdBytes = Encoding.UTF8.GetBytes(chatId);
            byte[] idBytes = BitConverter.GetBytes(messageId);

            byte[] dataToSign = new byte[
                chatIdBytes.Length + 
                idBytes.Length +
                ciphertext.Length +
                authTag.Length + 
                nonce.Length
            ];

            int offset = 0;
            Buffer.BlockCopy(chatIdBytes, 0, dataToSign, offset, chatIdBytes.Length);
            offset += chatIdBytes.Length;

            Buffer.BlockCopy(idBytes, 0, dataToSign, offset, idBytes.Length);
            offset += idBytes.Length;

            Buffer.BlockCopy(ciphertext, 0, dataToSign, offset, ciphertext.Length);
            offset += ciphertext.Length;

            Buffer.BlockCopy(authTag, 0, dataToSign, offset, authTag.Length);
            offset += authTag.Length;

            Buffer.BlockCopy(nonce, 0, dataToSign, offset, nonce.Length);

            return Ed25519.Sign(dataToSign, senderPrivateKey);
        }
        private bool VerifyMessageSignature(
            EncryptedMessagePacket packet,
            byte[] senderPublicKey
        )
        {
            try
            {
                byte[] chatIdBytes = Encoding.UTF8.GetBytes(packet.ChatId);
                byte[] idBytes = BitConverter.GetBytes(packet.MessageId);

                byte[] dataToVerify = new byte[
                    chatIdBytes.Length + 
                    idBytes.Length + 
                    packet.Ciphertext.Length +
                    packet.AuthTag.Length + 
                    packet.Nonce.Length
                ];

                int offset = 0;
                Buffer.BlockCopy(chatIdBytes, 0, dataToVerify, offset, chatIdBytes.Length);
                offset += chatIdBytes.Length;

                Buffer.BlockCopy(idBytes, 0, dataToVerify, offset, idBytes.Length);
                offset += idBytes.Length;

                Buffer.BlockCopy(packet.Ciphertext, 0, dataToVerify, offset, packet.Ciphertext.Length);
                offset += packet.Ciphertext.Length;

                Buffer.BlockCopy(packet.AuthTag, 0, dataToVerify, offset, packet.AuthTag.Length);
                offset += packet.AuthTag.Length;

                Buffer.BlockCopy(packet.Nonce, 0, dataToVerify, offset, packet.Nonce.Length);

                return Ed25519.Verify(packet.Signature, dataToVerify, senderPublicKey);       
            }
            catch
            {
                return false;
            }
        }

        private void ValidateParameters(Message message, ChatSession session, byte[] senderPrivateKey)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (session == null) throw new ArgumentNullException(nameof(session));
            if (senderPrivateKey == null || senderPrivateKey.Length != 64)
            { throw new ArgumentException("PrivateKey must be 64 byte", nameof(senderPrivateKey)); }
            
            if (message.Data == null)
            { throw new ArgumentNullException("Message.Data can't be null"); }

            if (message.MediaSourcePath == null)
            { message.MediaSourcePath = new List<string>(); }
        }
        private void ValidatePacket(EncryptedMessagePacket packet)
        {
            if (packet == null) throw new ArgumentNullException(nameof(packet));
            if (string.IsNullOrEmpty(packet.ChatId))
            { throw new ArgumentException("ChatId can't be null"); }
            if (string.IsNullOrEmpty(packet.SenderId))
            { throw new ArgumentException("SenderId can't be null"); }
            if (packet.Ciphertext == null || packet.Ciphertext.Length == 0)
            { throw new ArgumentException("Ciphertext can't be null"); }
            if (packet.Nonce == null || packet.Nonce.Length != 12)
            { throw new ArgumentException("Nonce must be 12 bytes"); }
            if (packet.AuthTag == null || packet.AuthTag.Length != 16)
            { throw new ArgumentException("AuthTag must be 16 bytes"); }
            if (packet.Signature == null || packet.Signature.Length == 0)
            { throw new ArgumentException("Signature can't be null"); }
        }
        private void ValidateDecryptedMessage(Message message, EncryptedMessagePacket packet)
        {
            if (message == null)
            { throw new CryptographicException("Decoded message is null"); }
            if (message.SenderId != packet.SenderId)
            {
                throw new CryptographicException(
                    $"Sender's ID is not the same: message = {message.SenderId}, packet = {packet.SenderId}"
                );
            }
            if (message.MessageType != packet.MessageType)
            {
                throw new CryptographicException(
                    $"MessageType is not the same: message = {message.MessageType}, packet = {packet.MessageType}"
                );
            }
            if (message.Id != packet.MessageId)
            {
                throw new CryptographicException(
                    $"Sender's ID is not the same: message = {message.Id}, packet = {message.Id}"
                );
            }
            
            TimeSpan age = DateTime.UtcNow - message.SentAt;
            if (age > TimeSpan.FromHours(24))
            {
                throw new CryptographicException(
                    $"Message too old: {age.TotalHours:F1} hours. Maximum 24 hours."
                );
            }
        }
        
        private string SerializeMessage(Message message)
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = false,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            return JsonSerializer.Serialize(message, options);
        }
        private Message DeserializeMessage(string json)
        {
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true                
            };

            return JsonSerializer.Deserialize<Message>(json, options);
        }
    }
    public class CryptoKeysGenerator
    {
        public class KeyPair
        {
            public byte[] PublicKey { get; set; } = new byte[32];
            public byte[] PrivateKey { get; set; } = new byte[64];

            public byte[] EncryptionPrivateKey { get; set; } = new byte[32];
            public byte[] EncryptionPublicKey { get; set; } = new byte[32];

            public string MnemonicPhrase { get; set; }
            public DateTime GenerateAt { get; set; } = DateTime.UtcNow;

            public string PublicKeyBase64 => Convert.ToBase64String(PublicKey);
            public string EncryptionPublicKeyBase64 => Convert.ToBase64String(EncryptionPublicKey);
        }
        
        public static KeyPair GenerateNewKeyPair()
        {
            byte[] ed25519Seed = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(ed25519Seed);
            }

            Ed25519.KeyPairFromSeed(out byte[] ed25519PublicKey, out byte[] ed25519PrivateKey, ed25519Seed);

            byte[] x25519PrivateKey = new byte[32];
            byte[] x25519PublicKey = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(x25519PrivateKey);
            }

            x25519PrivateKey = Ed25519.ExpandedPrivateKeyFromSeed(ed25519Seed).Take(32).ToArray();
            x25519PublicKey = MontgomeryCurve25519.GetPublicKey(x25519PrivateKey);

            return new KeyPair
            {
                PublicKey = ed25519PublicKey,
                PrivateKey = ed25519PrivateKey,
                EncryptionPrivateKey = x25519PrivateKey,
                EncryptionPublicKey = x25519PublicKey,
                MnemonicPhrase = null
            };
        }
        public static KeyPair GenerateFromMnemonic(string mnemonicPhrase, string passphrase = "")
        {
            byte[] masterSeed = DeriveSeedFromMnemonic(mnemonicPhrase, passphrase);
            
            byte[] ed25519Seed = masterSeed.Take(32).ToArray();

            Ed25519.KeyPairFromSeed(out byte[] ed25519PublicKey, out byte[] ed25519PrivateKey, ed25519Seed);

            byte[] x25519PrivateKey = Ed25519.ExpandedPrivateKeyFromSeed(ed25519Seed).Take(32).ToArray();
            byte[] x25519PublicKey = MontgomeryCurve25519.GetPublicKey(x25519PrivateKey);

            return new KeyPair
            {
                PublicKey = ed25519PublicKey,
                PrivateKey = ed25519PrivateKey,
                EncryptionPrivateKey = x25519PrivateKey,
                EncryptionPublicKey = x25519PublicKey,
                MnemonicPhrase = mnemonicPhrase
            };
        }

        private static byte [] DeriveSeedFromMnemonic(string mnemonicPhrase, string passphrase)
        {
            string normalizedPhrase = mnemonicPhrase.Trim().ToLowerInvariant().Replace("  ", " ");

            string salt = $"FOREST_MNEMONIC_SALT|{passphrase}";

            var pbkdf2 = new Rfc2898DeriveBytes(
                normalizedPhrase,
                Encoding.UTF8.GetBytes(salt),
                2048
            );

            return pbkdf2.GetBytes(64);
        }
        public static byte[] SignData(byte[] data, KeyPair keyPair)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (keyPair?.PrivateKey == null) throw new ArgumentNullException(nameof(keyPair));

            return Ed25519.Sign(data, keyPair.PrivateKey);
        }
        public static bool VerifySignature(byte[] data, byte[] signature, byte[] publicKey)
        {
            if (data == null || signature == null || publicKey == null) { return false; }

            try
            {
                return Ed25519.Verify(signature, data, publicKey);
            }
            catch
            {
                return false;
            }
        }
        public static byte[] ComputeSharedSecret(byte[] myPrivateKey, byte[] peerPublicKey)
        {
            if (myPrivateKey.Length != 32 || peerPublicKey.Length != 32)
            { throw new ArgumentException ("Keys must have 32 bytes"); }

            try
            {
                return MontgomeryCurve25519.KeyExchange(peerPublicKey, myPrivateKey);
            }
            catch
            {
                throw new CryptographicException("ECDH Error");
            }
        }
        public static string ExportKeyPair(KeyPair keyPair, string encryptionPassword)
        {
            var exportData = new
            {
                Version = "1.0",
                PublicKey = Convert.ToBase64String(keyPair.PublicKey),
                EncryptedPrivateKey = EncryptPrivateKey(keyPair.PrivateKey, encryptionPassword),

                EncryptionPublicKey = Convert.ToBase64String(keyPair.EncryptionPublicKey),
                GeneratedAt = keyPair.GenerateAt.ToString("o")
            };

            return JsonSerializer.Serialize(exportData, new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }
        private static string EncryptPrivateKey(byte[] privateKey, string password)
        {
            byte[] salt = new byte[16];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);

            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000);
            byte[] key = pbkdf2.GetBytes(32);

            using var aes = new AesGcm(key);
            byte[] nonce = new byte[12];            
            rng.GetBytes(nonce);
            byte[] ciphertext = new byte[privateKey.Length];
            byte[] tag = new byte[16];

            aes.Encrypt(nonce, privateKey, ciphertext, tag);

            byte[] result = new byte[salt.Length + nonce.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, result, salt.Length, nonce.Length);
            Buffer.BlockCopy(ciphertext, 0, result, salt.Length + nonce.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, result, salt.Length + nonce.Length + ciphertext.Length, tag.Length);

            return Convert.ToBase64String(result);
        }
    }
    public class PhrasesGenerator
    {
        public static string WebPath = "https://people.sc.fsu.edu/~jburkardt/datasets/words/anagram_dictionary.txt";
        public static string LocalDictionaryPath = "MainFolder/UserInfo/Security/Mnemonic/BaseDictionary/mnemonicdictionary.txt";
        public static string LocalBaseMnemonicPhrasePath = "MainFolder/UserInfo/Security/Mnemonic/";
        public static short WordsCount = 24;
        public PhrasesGenerator()
        {

        }
        public static void CreateMnemonicDictionary()
        {
            try
            {
                var folderName = "MainFolder/UserInfo/Security/Mnemonic/BaseDictionary";
                if (!Directory.Exists(folderName))
                {
                    Directory.CreateDirectory(folderName);
                    if (!File.Exists(LocalDictionaryPath))
                    {
                        var webClient = new WebClient();
                        var dictionary = webClient.DownloadString(WebPath);
                        File.WriteAllText(LocalDictionaryPath, dictionary);
                    }
                }
                else
                {
                    if (!File.Exists(LocalDictionaryPath))
                    {
                        var webClient = new WebClient();
                        var dictionary = webClient.DownloadString(WebPath);
                        File.WriteAllText(LocalDictionaryPath, dictionary);
                    }
                }
            }
            catch (Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
            }
        }
        public static void WriteSecureMnemonicPhraseString(string folderName, string fileName)
        {
            var phrase = CreateSecureMnemonicPhraseString().Split(' ');

            var basefolderpath = "MainFolder/UserInfo/Security/Mnemonic";
            var fullPath = $"{basefolderpath}/{folderName}/{fileName}";

            if(!Directory.Exists($"{basefolderpath}/{folderName}"))
            {
                Directory.CreateDirectory($"{basefolderpath}/{folderName}");
                if(!File.Exists(fullPath))
                {
                    File.WriteAllText(fullPath, JsonSerializer.Serialize(phrase));
                }
            }
            else
            {
                if(!File.Exists(fullPath))
                {
                    File.WriteAllText(fullPath, JsonSerializer.Serialize(phrase));
                }
            }
        }
        public static string CreateSecureMnemonicPhraseString()
        {
            try
            {
                var dictionary = File.ReadAllLines(LocalDictionaryPath);

                var words = new List<string>(WordsCount); 

                using (var rng = RandomNumberGenerator.Create())
                {
                    byte[] randomBuffer = new byte[WordsCount * 4];
                    rng.GetBytes(randomBuffer);

                    for (int i = 0; i < WordsCount; i++)
                    {
                        uint randomNumber = BitConverter.ToUInt32(randomBuffer, i * 4);
                        int index = (int)(randomNumber % (uint)dictionary.Length);
                        words.Add(dictionary[index]);
                    }
                }

                return string.Join(" ", words);
            }
            catch (Exception e)
            {
                var logger = new ErrorManager();
                logger.LogError(e.ToString());
                return null;
            }
        }

        public static string CreateChecksum(string phrase)
        {
            var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(phrase));

            string checksum = BitConverter.ToString(hash, 0, 2)
                .Replace("-", "")
                .ToLower();

            return $"{checksum}";
        }
        public static bool CheckUpCheckSum(string phrase, string checksum)
        {
            if (CreateChecksum(phrase) == checksum)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}