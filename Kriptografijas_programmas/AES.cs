using System;
using System.Text;
using System.Security.Cryptography; // Tiek lietots tikai, lai ģenerētu atslēgas, ērtībai (Uzdevuma nosacījumos šo atslēgu jāvada patstāvīgi, bet programmā ir iespējams to ģenerēt automātiski).

internal static class AES
{
    public static int Run()
    {
        Console.WriteLine("AES-128");
        Console.WriteLine();

        byte[] key = ReadKeyHexOrGenerate();
        var aes = new Aes128(key);

        byte[]? lastResult = null;

        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Komandas:");
            Console.WriteLine("  E - Šifrēt");
            Console.WriteLine("  D - Atšifrēt");
            Console.WriteLine("  R - Izmantot pēdējo rezultātu kā ievadi");
            Console.WriteLine("  K - Mainīt/ģenerēt atslēgu");
            Console.WriteLine("  T - Tests (FIPS-197 tests)");
            Console.WriteLine("  Q - Beigt");
            Console.Write("> ");

            string? cmd = Console.ReadLine();
            if (cmd == null) continue;
            cmd = cmd.Trim();

            if (cmd.Equals("Q", StringComparison.OrdinalIgnoreCase))
                return 0;

            if (cmd.Equals("T", StringComparison.OrdinalIgnoreCase))
            {
                SelfTest();
                continue;
            }

            if (cmd.Equals("K", StringComparison.OrdinalIgnoreCase))
            {
                key = ReadKeyHexOrGenerate();
                aes = new Aes128(key);
                Console.WriteLine("Atslēga uzstādīta.");
                continue;
            }

            if (cmd.Equals("R", StringComparison.OrdinalIgnoreCase))
            {
                if (lastResult == null)
                {
                    Console.WriteLine("Nav iepriekšēja rezultāta.");
                    continue;
                }

                Console.WriteLine("Pēdējais rezultāts (HEX):");
                Console.WriteLine(BytesToHex(lastResult));
                Console.WriteLine("Ko darīt ar šo bloku? [E] šifrēt, [D] atšifrēt, jebkas cits — atcelt");
                Console.Write("> ");
                string? sub = Console.ReadLine()?.Trim();
                if (sub == null) continue;

                if (sub.Equals("E", StringComparison.OrdinalIgnoreCase))
                {
                    lastResult = aes.EncryptBlock(lastResult);
                    PrintResult(lastResult, "Nošifrētais bloks");
                }
                else if (sub.Equals("D", StringComparison.OrdinalIgnoreCase))
                {
                    lastResult = aes.DecryptBlock(lastResult);
                    PrintResult(lastResult, "Atšifrētais bloks");
                }
                else
                {
                    Console.WriteLine("Atcelts.");
                }

                continue;
            }

            if (cmd.Equals("E", StringComparison.OrdinalIgnoreCase) ||
                cmd.Equals("D", StringComparison.OrdinalIgnoreCase))
            {
                bool encrypt = cmd.Equals("E", StringComparison.OrdinalIgnoreCase);

                byte[] block = ReadBlockHexOrText();
                lastResult = encrypt ? aes.EncryptBlock(block) : aes.DecryptBlock(block);

                PrintResult(lastResult, encrypt ? "Nošifrētais bloks" : "Atšifrētais bloks");
                continue;
            }

            Console.WriteLine("Nederīga komanda.");
        }
    }

    private static byte[] ReadKeyHexOrGenerate()
    {
        while (true)
        {
            Console.WriteLine("Atslēga: [H] ievadīt 32-hex, [G] ģenerēt automātiski (128-bit)");
            Console.Write("> ");
            string? mode = Console.ReadLine();
            if (mode == null) continue;

            mode = mode.Trim();

            if (mode.Equals("H", StringComparison.OrdinalIgnoreCase))
            {
                byte[] k = ReadHexBytesExact("128 bitu atslēga (32 hex): ", 16);
                Console.WriteLine("Atslēga (HEX):");
                Console.WriteLine(BytesToHex(k));
                return k;
            }

            if (mode.Equals("G", StringComparison.OrdinalIgnoreCase))
            {
                byte[] k = GenerateRandomKey16();
                Console.WriteLine("Ģenerētā atslēga (HEX):");
                Console.WriteLine(BytesToHex(k));
                return k;
            }

            Console.WriteLine("Nederīga izvēle. Ievadiet H vai G.");
        }
    }

    private static byte[] GenerateRandomKey16()
    {
        // Atslēgu ģenerēšanai (neietekmē AES algoritma realizāciju, atslēgu var ievadīt arī manuāli).
        byte[] key = new byte[16];
        RandomNumberGenerator.Fill(key);
        return key;
    }

    private static byte[] ReadBlockHexOrText()
    {
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Ievades veids datu blokam: [H] 32-hex (16 baiti) vai [T] teksts (UTF-8 -> 16 baiti)");
            Console.Write("> ");
            string? mode = Console.ReadLine();
            if (mode == null) continue;

            mode = mode.Trim();

            if (mode.Equals("H", StringComparison.OrdinalIgnoreCase))
                return ReadHexBytesExact("128 bitu datu bloks (32 hex): ", 16);

            if (mode.Equals("T", StringComparison.OrdinalIgnoreCase))
            {
                Console.Write("Teksts: ");
                string? text = Console.ReadLine();
                if (text == null) continue;

                try
                {
                    byte[] block = TextTo16Bytes(text);
                    Console.WriteLine("Teksta HEX (ievades bloks):");
                    Console.WriteLine(BytesToHex(block));
                    return block;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Kļūda: " + ex.Message);
                    continue;
                }
            }

            Console.WriteLine("Nederīga izvēle. Ievadiet H vai T.");
        }
    }

    private static byte[] TextTo16Bytes(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);

        if (bytes.Length > 16)
            throw new ArgumentException($"Teksts aizņem {bytes.Length} baitus, bet bloks ir tikai 16 baiti.");

        byte[] block = new byte[16];
        Buffer.BlockCopy(bytes, 0, block, 0, bytes.Length); 
        return block;
    }

    private static void PrintResult(byte[] block16, string title)
    {
        Console.WriteLine();
        Console.WriteLine(title + " (32 hex):");
        Console.WriteLine(BytesToHex(block16));

        string asText = TryDecodeUtf8(block16);
        if (asText.Length > 0)
        {
            Console.WriteLine("Rezultāts kā UTF-8:");
            Console.WriteLine(asText);
        }
    }

    private static string TryDecodeUtf8(byte[] block16)
    {
        int len = block16.Length;
        while (len > 0 && block16[len - 1] == 0x00) len--;
        if (len == 0) return "";

        string s;
        try
        {
            s = Encoding.UTF8.GetString(block16, 0, len);
        }
        catch
        {
            return "";
        }

        int bad = 0;
        foreach (char ch in s)
        {
            if (char.IsControl(ch) && ch != '\r' && ch != '\n' && ch != '\t')
                bad++;
        }

        return bad == 0 ? s : "";
    }

    private static byte[] ReadHexBytesExact(string prompt, int byteCount)
    {
        int hexLen = byteCount * 2;

        while (true)
        {
            Console.Write(prompt);
            string? s = Console.ReadLine();
            if (s == null) continue;

            s = s.Trim().Replace(" ", "");

            if (s.Length != hexLen)
            {
                Console.WriteLine($"Jābūt tieši {hexLen} hex simboliem (šobrīd: {s.Length}).");
                continue;
            }

            try
            {
                return HexToBytes(s);
            }
            catch
            {
                Console.WriteLine("Nederīgs hex. Atļauti tikai 0-9, a-f, A-F.");
            }
        }
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex.Length % 2 != 0) throw new FormatException("Hex garumam jābūt pāra skaitlim.");
        byte[] result = new byte[hex.Length / 2];

        for (int i = 0; i < result.Length; i++)
        {
            int hi = HexNibble(hex[2 * i]);
            int lo = HexNibble(hex[2 * i + 1]);
            result[i] = (byte)((hi << 4) | lo);
        }

        return result;
    }

    private static int HexNibble(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new FormatException("Nederīgs hex simbols.");
    }

    private static string BytesToHex(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 2);
        foreach (byte b in data) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    private static void SelfTest()
    {
        // FIPS-197 zināmais AES-128 tests:
        // Key:       000102030405060708090a0b0c0d0e0f
        // Plaintext: 00112233445566778899aabbccddeeff
        // Cipher:    69c4e0d86a7b0430d8cdb78070b4c55a
        byte[] key = HexToBytes("000102030405060708090a0b0c0d0e0f");
        byte[] pt = HexToBytes("00112233445566778899aabbccddeeff");
        byte[] exp = HexToBytes("69c4e0d86a7b0430d8cdb78070b4c55a");

        var aes = new Aes128(key);
        byte[] ct = aes.EncryptBlock(pt);
        byte[] dec = aes.DecryptBlock(ct);

        Console.WriteLine();
        Console.WriteLine("SelfTest (FIPS-197):");
        Console.WriteLine("CT  = " + BytesToHex(ct));
        Console.WriteLine("EXP = " + BytesToHex(exp));
        Console.WriteLine("DEC = " + BytesToHex(dec));

        bool ok1 = ByteArraysEqual(ct, exp);
        bool ok2 = ByteArraysEqual(dec, pt);

        Console.WriteLine(ok1 && ok2 ? "OK" : "FAIL");
    }

    private static bool ByteArraysEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }
}
