#include <stdlib.h>
#include <iostream>
#include <cassert>
#include <random>
using namespace std;

// Function to calculate gcd
long long gcd(long long a, long long b)
{
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

// Function to calculate lcm
long long lcm(long long a, long long b)
{
    return (a * b) / gcd(a, b);
}

// Function to calculate power with modulus
long long power(long long x, long long y, long long p)
{
    long long res = 1;
    x = x % p;

    while (y > 0)
    {
        if (y & 1)
            res = (res * x) % p;
        y = y >> 1;
        x = (x * x) % p;
    }
    return res;
}

// Function to implement the Extended Euclidean Algorithm
long long extended_gcd(long long a, long long b, long long& x, long long& y)
{
    if (b == 0)
    {
        x = 1;
        y = 0;
        return a;
    }
    long long x1, y1;
    long long d = extended_gcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - y1 * (a / b);
    return d;
}

// Function to calculate modular multiplicative inverse using Extended Euclidean Algorithm
long long modInverse(long long a, long long m)
{
    long long x, y;
    long long g = extended_gcd(a, m, x, y);
    if (g != 1)
        return -1; // inverse doesn't exist
    else
    {
        // m is added to handle negative x
        long long res = (x % m + m) % m;
        return res;
    }
}

struct PaillierKeyGenerator
{
    long long p, q, n, lambda, g, mu;
    PaillierKeyGenerator(long long p_, long long q_)
    {
        p = p_;
        q = q_;
        n = p * q;
        lambda = lcm(p - 1, q - 1);
        g = n + 1;
        mu = modInverse(lambda, n);
        // cout << mu * lambda % n << endl;
        assert(mu * lambda % n == 1);
    }
    void print()
    {
        cout << "Public Key: (N, g) = (" << n << ", " << g << ")" << endl;
        cout << "Private Key: (lambda, mu) = (" << lambda << ", " << mu << ")" << endl;
    }
};

struct CryptoNumber
{
    long long cipher_text;
    long long n_square;

    CryptoNumber(long long cipher_text_, long long n_square_)
    {
        cipher_text = cipher_text_;
        n_square = n_square_;
    }
    CryptoNumber() = default;

    CryptoNumber operator+(CryptoNumber other)
    {
        long long sum_ciphertext = (cipher_text * other.cipher_text) % n_square;
        return CryptoNumber(sum_ciphertext, n_square);
    }

    CryptoNumber operator*(long long other)
    {
        long long mul_cipher_text = power(cipher_text, other, n_square);
        return CryptoNumber(mul_cipher_text, n_square);
    }

    friend CryptoNumber operator*(long long other, CryptoNumber crypto_number)
    {
        return crypto_number * other;
    }
};
// 创建一个随机数生成器
std::mt19937 rng(std::random_device{}());
struct Paillier
{
    enum CIPHER_MODE
    {
        ENCRYPT,
        DECRYPT
    };
    CIPHER_MODE mode;
    long long n, g, lambda, mu;
    long long n_square;
    Paillier(long long n_, long long g_, long long lambda_, long long mu_, CIPHER_MODE mode_)
    {
        n = n_;
        g = g_;
        lambda = lambda_;
        mu = mu_;
        mode = mode_;
        n_square = n * n;
        // cout << "n_square = " << n_square << endl;
    }
    long long fn_L(long long x)
    {
        return (x - 1) / n;
    }

    CryptoNumber encrypt(long long m)
    {
        if (mode != ENCRYPT)
        {
            cout << "Error: Wrong mode!" << endl;
            return CryptoNumber(-1, -1);
        }
        std::uniform_int_distribution<long long> dist(0, n);
        long long r = dist(rng);
        while (gcd(r, n) != 1)
        {
            r = dist(rng);
        }
        long long tmp = power(r, n * lambda, n_square);
        // cout << "tmp = " << tmp << endl;
        long long cipher_text = ((n * m + 1) % n_square * power(r, n, n_square)) % n_square;
        return CryptoNumber(cipher_text, n_square);
    }

    long long decrypt(CryptoNumber crypto_number)
    {
        if (mode != DECRYPT)
        {
            cout << "Error: Wrong mode!" << endl;
            return -1;
        }
        long long x = power(crypto_number.cipher_text, lambda, n_square);
        long long L = fn_L(x);
        long long plain_text = (L * mu) % n;
        return plain_text;
    }
};
#include <chrono>
#include <omp.h>
struct Test
{
    Paillier encrypt_cipher;
    Paillier decrypt_cipher;
    const int tests_num = 10;
    Test(long long n_, long long g_, long long lambda_, long long mu_) : encrypt_cipher(n_, g_, 0, 0, Paillier::ENCRYPT), decrypt_cipher(n_, g_, lambda_, mu_, Paillier::DECRYPT) {}


    void test_encrypt_decrypt(long long* message, long long m_size)
    {
        long long* cipher_text = new long long[m_size];
        long long* plain_text = new long long[m_size];
        //warm up   ------------------------------------------------
#pragma omp parallel for schedule(static)
        for (int i = 0; i < m_size; i++)
        {
            cipher_text[i] = encrypt_cipher.encrypt(message[i]).cipher_text;
            plain_text[i] = decrypt_cipher.decrypt(CryptoNumber(cipher_text[i], encrypt_cipher.n_square));
            // test encrypt and decrypt
            if (message[i] != plain_text[i])
            {
                cout << "i = " << i << endl;
                cout << "message = " << message[i] << endl;
                cout << "plain_text = " << plain_text[i] << endl;
                assert(false);
            }
        }
        cout << "test_encrypt_decrypt passed" << endl;
        //warm up end  ------------------------------------------------

        auto start = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < tests_num; j++)
        {
#pragma omp parallel for schedule(static)
            for (int i = 0; i < m_size; i++)
            {
                cipher_text[i] = encrypt_cipher.encrypt(message[i]).cipher_text;
            }
        }
        auto encrypt_stop = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < tests_num; j++)
        {
#pragma omp parallel for schedule(static)
            for (int i = 0; i < m_size; i++)
            {
                plain_text[i] = decrypt_cipher.decrypt(CryptoNumber(cipher_text[i], encrypt_cipher.n_square));
            }
        }
        auto decrypt_stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> encrypt_diff = encrypt_stop - start;
        std::chrono::duration<double> decrypt_diff = decrypt_stop - encrypt_stop;
        cout << "encrypt costs " << encrypt_diff.count() / tests_num << " seconds" << endl;
        cout << "decrypt costs " << decrypt_diff.count() / tests_num << " seconds" << endl;
        delete[] cipher_text;
        delete[] plain_text;
    }


    void test_homomorphic_add(long long* message1, long long* message2, long long m_size)
    {
        CryptoNumber* cipher_text1 = new CryptoNumber[m_size];
        CryptoNumber* cipher_text2 = new CryptoNumber[m_size];
        CryptoNumber* cipher_text = new CryptoNumber[m_size];
        long long* plain_text = new long long[m_size];
        //warm up   ------------------------------------------------
#pragma omp parallel for schedule(static)
        for (int i = 0; i < m_size; i++)
        {
            cipher_text1[i] = encrypt_cipher.encrypt(message1[i]);
            cipher_text2[i] = encrypt_cipher.encrypt(message2[i]);
            cipher_text[i] = cipher_text1[i] + cipher_text2[i];
            plain_text[i] = decrypt_cipher.decrypt(cipher_text[i]);
            // test encrypt and decrypt
            if ((message1[i] + message2[i]) % encrypt_cipher.n != plain_text[i])
            {
                cout << "i = " << i << endl;
                cout << "message1 = " << message1[i] << endl;
                cout << "message2 = " << message2[i] << endl;
                cout << "plain_text = " << plain_text[i] << endl;
                assert(false);
            }
        }
        cout << "test_homomorphic_add passed" << endl;
        //warm up end  ------------------------------------------------

        auto start = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < tests_num; j++)
        {
#pragma omp parallel for schedule(static)
            for (int i = 0; i < m_size; i++)
            {
                cipher_text[i] = cipher_text1[i] + cipher_text2[i];
            }
        }
        auto add_stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff = add_stop - start;
        cout << "homomorphic add costs " << diff.count() / tests_num << " seconds" << endl;

        delete[] cipher_text1;
        delete[] cipher_text2;
        delete[] cipher_text;
        delete[] plain_text;
    }


    void test_homomorphic_mul(long long* message, long long* scalars, long long m_size)
    {
        CryptoNumber* cipher_text = new CryptoNumber[m_size];
        long long* plain_text = new long long[m_size];
        //warm up   ------------------------------------------------
#pragma omp parallel for schedule(static)
        for (int i = 0; i < m_size; i++)
        {
            cipher_text[i] = encrypt_cipher.encrypt(message[i]);
            cipher_text[i] = cipher_text[i] * scalars[i];
            plain_text[i] = decrypt_cipher.decrypt(cipher_text[i]);
            // test encrypt and decrypt
            if (message[i] * scalars[i] % encrypt_cipher.n != plain_text[i])
            {
                cout << "i = " << i << endl;
                cout << "message = " << message[i] << endl;
                cout << "scalars = " << scalars[i] << endl;
                cout << "plain_text = " << plain_text[i] << endl;
                assert(false);
            }
        }
        cout << "test_homomorphic_mul passed" << endl;
        //warm up end  ------------------------------------------------

        auto start = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < tests_num; j++)
        {
#pragma omp parallel for schedule(static)
            for (int i = 0; i < m_size; i++)
            {
                cipher_text[i] = cipher_text[i] * scalars[i];
            }
        }
        auto mul_stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff = mul_stop - start;
        cout << "homomorphic mul costs " << diff.count() / tests_num << " seconds" << endl;

        delete[] cipher_text;
        delete[] plain_text;
    }

};

int main()
{
    long long p = 251; // for simplicity, we select p as 3
    long long q = 211; // for simplicity, we select q as 5

    PaillierKeyGenerator keygen(p, q);
    // keygen.print();
    const long long max_m_size = 409600000;



#ifdef _OPENMP
    //set number of threads for OpenMP
    omp_set_num_threads(64);
#endif
    Paillier encryptor(keygen.n, keygen.g, 0, 0, Paillier::ENCRYPT);
    Paillier decryptor(keygen.n, keygen.g, keygen.lambda, keygen.mu, Paillier::DECRYPT);

    Test test(keygen.n, keygen.g, keygen.lambda, keygen.mu);
    long long* message1 = new long long[max_m_size];
    long long* message2 = new long long[max_m_size];
    long long* scalars = new long long[max_m_size];

    std::uniform_int_distribution<long long> dist(0, encryptor.n - 1);
#pragma omp parallel for schedule(static)
    for (int i = 0; i < max_m_size; i++)
        message1[i] = dist(rng);
#pragma omp parallel for schedule(static)
    for (int i = 0; i < max_m_size; i++)
        message2[i] = dist(rng);
#pragma omp parallel for schedule(static)
    for (int i = 0; i < max_m_size; i++)
        scalars[i] = dist(rng);

    // test.test_encrypt_decrypt(message1, m_size);
    // test.test_homomorphic_add(message1, message2, m_size);
    // test.test_homomorphic_mul(message1, scalars, m_size);

    // test over different m_size
    const int m_size_list[] = { 100000, 200000, 400000, 800000, 1600000, 3200000, 6400000, 12800000, 25600000, 51200000, 102400000, 204800000, 409600000 };

    for (int i = 0; i < 13; i++)
    {
        int m_size = m_size_list[i];
        cout << "m_size = " << m_size << endl;
        test.test_encrypt_decrypt(message1, m_size);
        test.test_homomorphic_add(message1, message2, m_size);
        test.test_homomorphic_mul(message1, scalars, m_size);
    }



    delete[] message1;
    delete[] message2;
    delete[] scalars;
    return 0;
}
