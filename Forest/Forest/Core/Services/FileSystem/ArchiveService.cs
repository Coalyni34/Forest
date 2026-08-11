using System;
using System.Threading.Tasks;

namespace ForestMSG.Core.Services.FileSystem
{
    public class ArchiveService
    {
        public async Task<byte[]> CreateEncryptedArchiveAsync(string folderPath, byte[] archiveKey)
        {
            throw new Exception();
            // 1. Создаём ZIP папки
            // 2. Шифруем ZIP (AES-GCM) с archiveKey
            // 3. Возвращаем byte[]
        }

        public async Task ExtractEncryptedArchiveAsync(byte[] encryptedData, byte[] archiveKey, string extractPath)
        {
            // 1. Расшифровываем
            // 2. Распаковываем ZIP
        }
    }
}