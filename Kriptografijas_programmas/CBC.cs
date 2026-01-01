using System.Text;
using System.Security.Cryptography; // Tiek lietots tikai, lai ģenerētu atslēgas, ērtībai (Uzdevuma nosacījumos šo atslēgu jāvada patstāvīgi, bet programmā ir iespējams to ģenerēt automātiski).


internal static class CBC
{
    public static int Run()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("AES-128 CBC");
        Console.WriteLine();

        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Komandas:");
            Console.WriteLine("  E - Šifrēt (CBC)");
            Console.WriteLine("  D - Atšifrēt (CBC)");
            Console.WriteLine("  T - AES self-tests (FIPS-197 1 bloks)");
            Console.WriteLine("  Q - Beigt");
            Console.Write("> ");

            string? cmd = Console.ReadLine()?.Trim();
            if (string.IsNullOrEmpty(cmd)) continue;

            if (cmd.Equals("Q", StringComparison.OrdinalIgnoreCase)) return 0;

            try
            {
                if (cmd.Equals("T", StringComparison.OrdinalIgnoreCase))
                {
                    AesSelfTest();
                    continue;
                }

                if (cmd.Equals("E", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] key = ReadKeyHexOrGenerate();
                    byte[] iv = ReadIvHexOrGenerate();

                    string inPath = ReadFilePath("Norādiet šifrējamā faila atrašānās vietu (ceļu uz failu): ");
                    string outPath = ReadOutFilePath("Norādiet vietu un faila nosaukumu, kur saglabāt nošifrēto failu: ");

                    var aes = new Aes128(key);
                    CbcFileCipher.EncryptFile(aes, iv, inPath, outPath);

                    Console.WriteLine("Veiksmīgi! Atrodas: " + outPath);
                    continue;
                }

                if (cmd.Equals("D", StringComparison.OrdinalIgnoreCase))
                {
                    byte[] key = ReadKeyHexOrGenerate();

                    string inPath = ReadFilePath("Norādiet atšifrējamā faila atrašānās vietu (ceļu uz failu): ");
                    string outPath = ReadOutFilePath("Norādiet vietu un faila nosaukumu, kur saglabāt atšifrēto failu: ");

                    var aes = new Aes128(key);
                    CbcFileCipher.DecryptFile(aes, inPath, outPath);

                    Console.WriteLine("Veiksmīgi! Atrodas: " + outPath);
                    continue;
                }

                Console.WriteLine("Nederīga ievade.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Kļūda: " + ex.Message);
            }
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
                byte[] k = new byte[16];
                RandomNumberGenerator.Fill(k);
                Console.WriteLine("Ģenerēta atslēga (HEX):");
                Console.WriteLine(BytesToHex(k));
                return k;
            }

            Console.WriteLine("Nederīga izvēle. Ievadi H vai G.");
        }
    }

    private static byte[] ReadIvHexOrGenerate()
    {
        while (true)
        {
            Console.WriteLine("IV: [H] ievadīt 32-hex, [G] ģenerēt automātiski (128-bit)");
            Console.Write("> ");
            string? mode = Console.ReadLine();
            if (mode == null) continue;

            mode = mode.Trim();

            if (mode.Equals("H", StringComparison.OrdinalIgnoreCase))
            {
                byte[] iv = ReadHexBytesExact("128 bitu inicializācijas vektors IV (32 hex): ", 16);
                Console.WriteLine("IV (HEX):");
                Console.WriteLine(BytesToHex(iv));
                return iv;
            }

            if (mode.Equals("G", StringComparison.OrdinalIgnoreCase))
            {
                byte[] iv = new byte[16];
                RandomNumberGenerator.Fill(iv);
                Console.WriteLine("Ģenerēts IV (HEX):");
                Console.WriteLine(BytesToHex(iv));
                return iv;
            }

            Console.WriteLine("Nederīga izvēle. Ievadi H vai G.");
        }
    }

    private static void AesSelfTest()
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
        Console.WriteLine("AES SelfTest (FIPS-197):");
        Console.WriteLine("CT  = " + BytesToHex(ct));
        Console.WriteLine("EXP = " + BytesToHex(exp));
        Console.WriteLine("DEC = " + BytesToHex(dec));
        Console.WriteLine(ByteArraysEqual(ct, exp) && ByteArraysEqual(dec, pt) ? "OK" : "FAIL");
    }

    private static string ReadFilePath(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            string? p = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(p)) continue;

            p = p.Trim().Trim('"');
            if (!File.Exists(p))
            {
                Console.WriteLine("Fails neeksistē: " + p);
                continue;
            }
            return p;
        }
    }

    private static string ReadOutFilePath(string prompt)
    {
        while (true)
        {
            Console.Write(prompt);
            string? p = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(p)) continue;

            p = p.Trim().Trim('"');
            string? dir = Path.GetDirectoryName(Path.GetFullPath(p));
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Console.WriteLine("Mape neeksistē: " + dir);
                continue;
            }
            return p;
        }
    }

    private static byte[] ReadHexBytesExact(string prompt, int byteCount)
    {
        int hexLen = byteCount * 2;

        while (true)
        {
            Console.Write(prompt);
            string? s = Console.ReadLine();
            if (s == null) continue;

            s = s.Trim().Replace(" ", "").Replace("\t", "");
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
                Console.WriteLine("Nederīgs hex. Atļauti ir tikai 0-9, a-f, A-F.");
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

    private static bool ByteArraysEqual(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }
}

internal static class CbcFileCipher
{
    private const int BlockSize = 16;

    public static void EncryptFile(Aes128 aes, byte[] iv16, string plaintextPath, string ciphertextPath)
    {
        if (iv16 == null) throw new ArgumentNullException(nameof(iv16));
        if (iv16.Length != BlockSize) throw new ArgumentException("IV jābūt 16 baitiem (128-bit).");

        using FileStream fin = File.OpenRead(plaintextPath);
        using FileStream fout = File.Create(ciphertextPath);

        // C0 = IV
        fout.Write(iv16, 0, BlockSize);

        byte[] prev = (byte[])iv16.Clone();

        long len = fin.Length;
        long fullBlocks = len / BlockSize;
        int rem = (int)(len % BlockSize);

        byte[] plain = new byte[BlockSize];
        byte[] xored = new byte[BlockSize];

        for (long i = 0; i < fullBlocks; i++)
        {
            ReadExact(fin, plain, BlockSize);
            XorBlock(plain, prev, xored);
            byte[] c = aes.EncryptBlock(xored);
            fout.Write(c, 0, BlockSize);
            prev = c;
        }

        if (rem > 0)
        {
            Array.Clear(plain, 0, BlockSize);
            ReadExact(fin, plain, rem);

            int padLen = BlockSize - rem;
            for (int i = rem; i < BlockSize; i++) plain[i] = (byte)padLen;

            XorBlock(plain, prev, xored);
            byte[] c = aes.EncryptBlock(xored);
            fout.Write(c, 0, BlockSize);
        }
        else
        {
            Array.Fill(plain, (byte)BlockSize);
            XorBlock(plain, prev, xored);
            byte[] c = aes.EncryptBlock(xored);
            fout.Write(c, 0, BlockSize);
        }
    }

    public static void DecryptFile(Aes128 aes, string ciphertextPath, string plaintextPath)
    {
        using FileStream fin = File.OpenRead(ciphertextPath);
        using FileStream fout = File.Create(plaintextPath);

        if (fin.Length < BlockSize * 2)
            throw new InvalidDataException("Nošifrētais fails ir par īsu: jābūt vismaz IV + 1 datu blokam (>=32 baiti).");

        if (fin.Length % BlockSize != 0)
            throw new InvalidDataException("Nošifrētā faila garumam ir jādalās ar 16 (baitiem) bez atlikuma.");

        long totalBlocks = fin.Length / BlockSize;
        long dataBlocks = totalBlocks - 1;

        byte[] prev = new byte[BlockSize];
        ReadExact(fin, prev, BlockSize); // C0 = IV

        byte[] c = new byte[BlockSize];

        for (long i = 1; i <= dataBlocks; i++)
        {
            ReadExact(fin, c, BlockSize);

            byte[] dec = aes.DecryptBlock(c);
            byte[] p = XorNew(dec, prev);

            if (i < dataBlocks)
            {
                fout.Write(p, 0, BlockSize);
            }
            else
            {
                int outLen = RemovePkcs7Padding(p);
                fout.Write(p, 0, outLen);
            }

            Buffer.BlockCopy(c, 0, prev, 0, BlockSize);
        }
    }

    private static void ReadExact(Stream s, byte[] buf, int count)
    {
        int off = 0;
        while (off < count)
        {
            int n = s.Read(buf, off, count - off);
            if (n <= 0) throw new EndOfStreamException("Negaidītas beigas failā.");
            off += n;
        }
    }

    private static void XorBlock(byte[] a16, byte[] b16, byte[] dst16)
    {
        for (int i = 0; i < BlockSize; i++)
            dst16[i] = (byte)(a16[i] ^ b16[i]);
    }

    private static byte[] XorNew(byte[] a16, byte[] b16)
    {
        var out16 = new byte[BlockSize];
        for (int i = 0; i < BlockSize; i++)
            out16[i] = (byte)(a16[i] ^ b16[i]);
        return out16;
    }

    private static int RemovePkcs7Padding(byte[] lastPlain16)
    {
        if (lastPlain16.Length != BlockSize)
            throw new ArgumentException("Blokam jābūt 16 baitiem.");

        int pad = lastPlain16[BlockSize - 1];
        if (pad < 1 || pad > BlockSize)
            throw new InvalidDataException("Nederīgs padding (pēdējā baita vērtība ārpus 1..16).");

        for (int i = BlockSize - pad; i < BlockSize; i++)
            if (lastPlain16[i] != (byte)pad)
                throw new InvalidDataException("Nederīgs padding (nepareizi aizpildīti pēdējie baiti).");

        return BlockSize - pad;
    }
}