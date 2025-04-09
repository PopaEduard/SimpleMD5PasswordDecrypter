using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

class Decryptor
{
    private readonly char[] characters = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()".ToCharArray(); // Caracterele din care poate fi facuta o parola
    private char[] password = new char[4]; // Cautam parole de lungime 4

    public void bruteForceDecryption(int k, string encryptedPass, CancellationTokenSource tokenSource) // Functia de decriptare / backtracking
    {
        if (tokenSource.Token.IsCancellationRequested) // Verificare daca oprim thread-ul
            return;

        if (k < password.Length) // Daca nu s-a ajuns la o solutie facem backtracking
        {
            for (int i = 0; i < characters.Length; i++)
            {
                if (tokenSource.Token.IsCancellationRequested)
                    return;

                password[k] = characters[i]; // Generare parole
                bruteForceDecryption(k + 1, encryptedPass, tokenSource);
            }
        }
        else
        {
            string generatedPassword = new string(password);
            string generatedHash = CreateMD5Hash(generatedPassword); // Daca avem o parola completa, o criptam cu md5

            if (generatedHash == encryptedPass) // Comparam parolele criptare si daca sunt la fel, afisam parola
            {
                Console.WriteLine($"Password found: {generatedPassword}");
                tokenSource.Cancel(); // Oprim thread-ul, deci si rularea backtracking-ului
                return;
            }
        }
    }

    public string CreateMD5Hash(string password) // Functia pentru criptat folosind md5
    {
        using (MD5 md5 = MD5.Create())
        {
            byte[] data = Encoding.ASCII.GetBytes(password);
            byte[] hashBytes = md5.ComputeHash(data);

            StringBuilder sBuilder = new StringBuilder();
            foreach (byte b in hashBytes)
                sBuilder.Append(b.ToString("x2"));

            return sBuilder.ToString();
        }
    }
}

class ParallelDecryptor
{
    private Thread[] threads;
    private CancellationTokenSource[] tokenSources; // Variabile de oprire pentru fiecare thread
    private int numThreads;
    private string[] encryptedPasswords;

    public ParallelDecryptor(int numThreads, string[] encryptedPasswords)
    {
        this.encryptedPasswords = encryptedPasswords;
        this.numThreads = numThreads;

        threads = new Thread[numThreads];
        tokenSources = new CancellationTokenSource[numThreads];
    }

    private void initThreads()
    {
        for (int i = 0; i < numThreads; i++)
        {
            tokenSources[i] = new CancellationTokenSource();
            int index = i;
            threads[i] = new Thread(() =>
            {
                Decryptor decryptor = new Decryptor();
                decryptor.bruteForceDecryption(0, encryptedPasswords[index], tokenSources[index]); // Crearea si executarea fiecarui thread cu functia de decriptare
            });
        }
    }

    private void startThreads() // Activarea thread-urilor
    {
        for (int i = 0; i < numThreads; i++)
            threads[i].Start();
    }

    private void stopThreads() // Oprirea thread-urilor
    {
        for (int i = 0; i < numThreads; i++)
            threads[i].Join();
    }

    public void ParallelDecryptionTime() // Masurarea timpului de decriptare
    {
        Stopwatch watch = Stopwatch.StartNew();

        initThreads();
        startThreads();
        stopThreads();

        watch.Stop();
        var elapsed = watch.Elapsed;

        Console.WriteLine($"Elapsed time for parallel implementation of decryption: {elapsed}");
    }
}


class SerialDecryptor
{
    private Decryptor decryptor;
    private string[] encryptedPasswords;

    public SerialDecryptor(string[] encryptedPasswords)
    {
        this.decryptor = new Decryptor();
        this.encryptedPasswords = encryptedPasswords;
    }

    private void SerialDecryption() // Decriptarea seriala a parolelor
    {
        foreach (string pass in encryptedPasswords)
        {
            CancellationTokenSource tokenSource = new CancellationTokenSource();
            decryptor.bruteForceDecryption(0, pass, tokenSource);
        }
    }

    public void SerialDecryptionTime() // Masurearea timpului de decriptare seriala
    {
        Stopwatch watch = Stopwatch.StartNew();

        SerialDecryption();

        watch.Stop();
        var elapsed = watch.Elapsed;

        Console.WriteLine($"Elapsed time for serial implementation of decryption: {elapsed}");
    }
}

class MainProgram
{
    static string[] encryptedPasswords = new string[]{"56aed7e7485ff03d5605b885b86e947e", "e26026b73cdc3b59012c318ba26b5518", "9de37a0627c25684fdd519ca84073e34"};

    public static void Main(string[] args)
    {
        SerialDecryptor serialDecryptor = new SerialDecryptor(encryptedPasswords);
        serialDecryptor.SerialDecryptionTime();

        Console.WriteLine();

        ParallelDecryptor parallelDecryptor = new ParallelDecryptor(encryptedPasswords.Length, encryptedPasswords);
        parallelDecryptor.ParallelDecryptionTime();
    }
}
