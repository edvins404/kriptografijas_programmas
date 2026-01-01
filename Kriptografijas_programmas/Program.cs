using System;

internal static class Program
{
    public static int Main(string[] args)
    {
        while (true)
        {
            Console.WriteLine("Izvēlies ko palaist:");
            Console.WriteLine("1 - AES (1 bloks)");
            Console.WriteLine("2 - AES-CBC (fails)");
            Console.WriteLine("Q - iziet");
            Console.Write("> ");

            string? choice = Console.ReadLine()?.Trim();

            if (string.Equals(choice, "1", StringComparison.OrdinalIgnoreCase))
                return AES.Run();

            if (string.Equals(choice, "2", StringComparison.OrdinalIgnoreCase))
                return CBC.Run();

            if (string.Equals(choice, "Q", StringComparison.OrdinalIgnoreCase))
                return 0;

            Console.WriteLine("Nederīga izvēle. Mēģini vēlreiz.\n");
        }
    }
}
