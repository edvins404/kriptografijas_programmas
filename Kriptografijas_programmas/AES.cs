using System;
using System.Text;
using System.Security.Cryptography; // Tiek lietots tikai, lai ģenerētu atslēgu ērtībai (Uzdevuma nosacījumos šo atslēgu jāvada patstāvīgi, bet programmā ir iespējams to ģenerēt automātiski).

internal static class Program
{
    public static int Main()
    {
        Console.WriteLine("AES-128 (1 bloks) — šifrēt/atšifrēt vienā sesijā ar to pašu atslēgu");
        Console.WriteLine("Ievade blokam: HEX (32 hex) vai TEKSTS (UTF-8).");
        Console.WriteLine("Atslēgu var ievadīt manuāli vai ģenerēt automātiski.");
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
                Console.WriteLine("Ko darīt ar šo bloku? [E] šifrēt / [D] atšifrēt / jebkas cits — atcelt");
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
            throw new ArgumentException($"Teksts UTF-8 aizņem {bytes.Length} baitus, bet bloks ir tikai 16 baiti.");

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

internal sealed class Aes128
{
    private const int Nr = 10;  
    private readonly byte[] _roundKeys; 

    public Aes128(byte[] key16)
    {
        if (key16 == null) throw new ArgumentNullException(nameof(key16));
        if (key16.Length != 16) throw new ArgumentException("Atslēgai jābūt 16 baitiem (128-bit).");
        _roundKeys = ExpandKey(key16);
    }

    public byte[] EncryptBlock(byte[] input16)
    {
        if (input16 == null) throw new ArgumentNullException(nameof(input16));
        if (input16.Length != 16) throw new ArgumentException("Blokam jābūt 16 baitiem (128-bit).");

        byte[,] state = ToState(input16);

        AddRoundKey(state, 0);

        for (int round = 1; round <= Nr - 1; round++)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, round);
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, Nr);

        return FromState(state);
    }

    public byte[] DecryptBlock(byte[] input16)
    {
        if (input16 == null) throw new ArgumentNullException(nameof(input16));
        if (input16.Length != 16) throw new ArgumentException("Blokam jābūt 16 baitiem (128-bit).");

        byte[,] state = ToState(input16);

        AddRoundKey(state, Nr);

        for (int round = Nr - 1; round >= 1; round--)
        {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, round);
            InvMixColumns(state);
        }

        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, 0);

        return FromState(state);
    }

    private static byte[,] ToState(byte[] input)
    {
        var s = new byte[4, 4];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                s[r, c] = input[r + 4 * c];
        return s;
    }

    private static byte[] FromState(byte[,] state)
    {
        var output = new byte[16];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                output[r + 4 * c] = state[r, c];
        return output;
    }

    private void AddRoundKey(byte[,] state, int round)
    {
        int offset = round * 16;
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                state[r, c] ^= _roundKeys[offset + (r + 4 * c)];
    }

    private static void SubBytes(byte[,] state)
    {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r, c] = SBox[state[r, c]];
    }

    private static void InvSubBytes(byte[,] state)
    {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r, c] = InvSBox[state[r, c]];
    }

    private static void ShiftRows(byte[,] state)
    {
        for (int r = 1; r < 4; r++)
        {
            byte[] tmp = new byte[4];
            for (int c = 0; c < 4; c++) tmp[c] = state[r, c];
            for (int c = 0; c < 4; c++) state[r, c] = tmp[(c + r) & 3];
        }
    }

    private static void InvShiftRows(byte[,] state)
    {
        for (int r = 1; r < 4; r++)
        {
            byte[] tmp = new byte[4];
            for (int c = 0; c < 4; c++) tmp[c] = state[r, c];
            for (int c = 0; c < 4; c++) state[r, c] = tmp[(c - r + 4) & 3];
        }
    }

    private static void MixColumns(byte[,] s)
    {
        for (int c = 0; c < 4; c++)
        {
            byte a0 = s[0, c], a1 = s[1, c], a2 = s[2, c], a3 = s[3, c];

            s[0, c] = (byte)(GfMul(a0, 0x02) ^ GfMul(a1, 0x03) ^ a2 ^ a3);
            s[1, c] = (byte)(a0 ^ GfMul(a1, 0x02) ^ GfMul(a2, 0x03) ^ a3);
            s[2, c] = (byte)(a0 ^ a1 ^ GfMul(a2, 0x02) ^ GfMul(a3, 0x03));
            s[3, c] = (byte)(GfMul(a0, 0x03) ^ a1 ^ a2 ^ GfMul(a3, 0x02));
        }
    }

    private static void InvMixColumns(byte[,] s)
    {
        for (int c = 0; c < 4; c++)
        {
            byte a0 = s[0, c], a1 = s[1, c], a2 = s[2, c], a3 = s[3, c];

            s[0, c] = (byte)(GfMul(a0, 0x0e) ^ GfMul(a1, 0x0b) ^ GfMul(a2, 0x0d) ^ GfMul(a3, 0x09));
            s[1, c] = (byte)(GfMul(a0, 0x09) ^ GfMul(a1, 0x0e) ^ GfMul(a2, 0x0b) ^ GfMul(a3, 0x0d));
            s[2, c] = (byte)(GfMul(a0, 0x0d) ^ GfMul(a1, 0x09) ^ GfMul(a2, 0x0e) ^ GfMul(a3, 0x0b));
            s[3, c] = (byte)(GfMul(a0, 0x0b) ^ GfMul(a1, 0x0d) ^ GfMul(a2, 0x09) ^ GfMul(a3, 0x0e));
        }
    }

    private static byte GfMul(byte a, byte b)
    {
        int p = 0;
        int aa = a;
        int bb = b;

        for (int i = 0; i < 8; i++)
        {
            if ((bb & 1) != 0) p ^= aa;

            bool hi = (aa & 0x80) != 0;
            aa = (aa << 1) & 0xFF;
            if (hi) aa ^= 0x1B;
            bb >>= 1;
        }

        return (byte)p;
    }

    private static byte[] ExpandKey(byte[] key16)
    {
        byte[] expanded = new byte[176];
        Buffer.BlockCopy(key16, 0, expanded, 0, 16);

        int bytesGenerated = 16;
        int rconIter = 1;
        byte[] temp = new byte[4];

        while (bytesGenerated < expanded.Length)
        {
            for (int i = 0; i < 4; i++)
                temp[i] = expanded[bytesGenerated - 4 + i];

            if (bytesGenerated % 16 == 0)
            {
                RotWord(temp);
                SubWord(temp);
                temp[0] ^= Rcon[rconIter++];
            }

            for (int i = 0; i < 4; i++)
            {
                expanded[bytesGenerated] = (byte)(expanded[bytesGenerated - 16] ^ temp[i]);
                bytesGenerated++;
            }
        }

        return expanded;
    }

    private static void RotWord(byte[] w)
    {
        byte t = w[0];
        w[0] = w[1];
        w[1] = w[2];
        w[2] = w[3];
        w[3] = t;
    }

    private static void SubWord(byte[] w)
    {
        for (int i = 0; i < 4; i++)
            w[i] = SBox[w[i]];
    }

    private static readonly byte[] Rcon =
    {
        0x00,
        0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36
    };

    private static readonly byte[] SBox =
    {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    private static readonly byte[] InvSBox =
    {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };
}
