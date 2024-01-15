#include <iostream>
#include <stdio.h>
#include <curand.h>
#include <curand_kernel.h>
#include <assert.h>
#include <chrono>
#include <random>

using namespace std;
__device__ long long power(long long x, long long y, long long p)
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


__device__ long long gcd_device(long long a, long long b) {
    long long tmp;
    while (b != 0) {
        tmp = a % b;
        a = b;
        b = tmp;
    }
    return a;
}


__global__ void encryptKernel(long long n, long long lambda, long long n_square, long long* messages, curandState* globalState, long long* cipher_texts, int n_size) {
    int index = threadIdx.x + blockIdx.x * blockDim.x;
    if (index < n_size)
    {
        curandState localState = globalState[index];
        long long r = curand(&localState) % n;
        while (gcd_device(r, n) != 1) {
            r = curand(&localState) % n;
        }
        globalState[index] = localState;
        long long tmp = power(r, n * lambda, n_square);
        long long cipher_text = ((n * messages[index] + 1) % n_square * power(r, n, n_square)) % n_square;
        cipher_texts[index] = cipher_text;
    }
}


__global__ void decryptKernel(long long n, long long lambda, long long n_square, long long mu, long long* cipher_texts, long long* plain_texts, int n_size)
{
    int index = threadIdx.x + blockIdx.x * blockDim.x;
    if (index < n_size)
    {
        long long x = power(cipher_texts[index], lambda, n_square);
        long long L = (x - 1) / n;
        plain_texts[index] = (L * mu) % n;
    }
}

__global__ void setup_kernel(curandState* state, unsigned long seed) {
    int id = threadIdx.x + blockIdx.x * blockDim.x;
    curand_init(seed, id, 0, &state[id]);
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
    long long gcd_host(long long a, long long b) {
        if (b == 0)
            return a;
        return gcd_host(b, a % b);
    }


    // Function to calculate lcm
    long long lcm(long long a, long long b)
    {
        return (a * b) / gcd_host(a, b);
    }
    // Function to implement the Extended Euclidean Algorithm

    long long modInverse(long long a, long long messages)
    {
        long long x, y;
        long long g = extended_gcd(a, messages, x, y);
        if (g != 1)
            return -1; // inverse doesn't exist
        else
        {
            // messages is added to handle negative x
            long long res = (x % messages + messages) % messages;
            return res;
        }
    }

    // Function to calculate modular multiplicative inverse using Extended Euclidean Algorithm
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


    void print()
    {
        cout << "Public Key: (N, g) = (" << n << ", " << g << ")" << endl;
        cout << "Private Key: (lambda, mu) = (" << lambda << ", " << mu << ")" << endl;
    }
};
const int batch_size = 1024;

__global__ void Crypto_add_kernel(long long n_square, long long* cipher_texts, long long* cipher_texts2, long long* cipher_texts3, int n_size)
{
    int index = threadIdx.x + blockIdx.x * blockDim.x;
    if (index < n_size)
    {
        cipher_texts3[index] = (cipher_texts[index] * cipher_texts2[index]) % n_square;
    }
}

__global__ void Crypto_mul_kernel(long long n_square, long long* cipher_text, long long* result_cipher_text, long long* scalars, int n_size)
{
    int index = threadIdx.x + blockIdx.x * blockDim.x;
    if (index < n_size)
    {
        result_cipher_text[index] = power(cipher_text[index], scalars[index], n_square);
    }
}

struct Test
{
    const int tests_num = 1;
    PaillierKeyGenerator generator;
    Test(PaillierKeyGenerator generator_) : generator(generator_) {    }
    void test_encrypt_decrypt(long long* messages, long long m_size)
    {
        long long* d_messages;
        long long* d_cipher_texts;
        long long* cipher_texts = new long long[m_size];
        long long* d_plain_texts;
        long long* plain_texts = new long long[m_size];
        cudaMalloc(&d_messages, m_size * sizeof(long long));
        cudaMalloc(&d_cipher_texts, m_size * sizeof(long long));
        cudaMalloc(&d_plain_texts, m_size * sizeof(long long));

        curandState* devStates;
        cudaMalloc(&devStates, m_size * sizeof(curandState));
        setup_kernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (devStates, time(0));

        cudaMemcpy(d_messages, messages, m_size * sizeof(long long), cudaMemcpyHostToDevice);
        encryptKernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n, generator.lambda, generator.n * generator.n, d_messages, devStates, d_cipher_texts, m_size);
        cudaMemcpy(cipher_texts, d_cipher_texts, m_size * sizeof(long long), cudaMemcpyDeviceToHost);

        cudaMemcpy(d_cipher_texts, cipher_texts, m_size * sizeof(long long), cudaMemcpyHostToDevice);
        decryptKernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n, generator.lambda, generator.n * generator.n, generator.mu, d_cipher_texts, d_plain_texts, m_size);
        cudaMemcpy(plain_texts, d_plain_texts, m_size * sizeof(long long), cudaMemcpyDeviceToHost);

        // test encrypt and decrypt
        for (int i = 0; i < m_size; i++)
        {
            // cout << messages[i] << " " << plain_texts[i] << " " << endl;
            if (messages[i] != plain_texts[i])
            {
                cout << "Error: " << messages[i] << " " << plain_texts[i] << endl;
            }
        }
        // warm up end ------------------------------------------------

        auto start = chrono::high_resolution_clock::now();
        int test_id;
        for (test_id = 0; test_id < tests_num; test_id++)
        {
            // encrypt
            cudaMemcpy(d_messages, messages, m_size * sizeof(long long), cudaMemcpyHostToDevice);
            encryptKernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n, generator.lambda, generator.n * generator.n, d_messages, devStates, d_cipher_texts, m_size);
            cudaMemcpy(cipher_texts, d_cipher_texts, m_size * sizeof(long long), cudaMemcpyDeviceToHost);
        }
        auto encrypt_stop = chrono::high_resolution_clock::now();

        for (test_id = 0; test_id < tests_num; test_id++)
        {
            // decrypt
            cudaMemcpy(d_cipher_texts, cipher_texts, m_size * sizeof(long long), cudaMemcpyHostToDevice);
            decryptKernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n, generator.lambda, generator.n * generator.n, generator.mu, d_cipher_texts, d_plain_texts, m_size);
            cudaMemcpy(plain_texts, d_plain_texts, m_size * sizeof(long long), cudaMemcpyDeviceToHost);
        }
        auto decrypt_stop = chrono::high_resolution_clock::now();

        std::chrono::duration<double> encrypt_diff = encrypt_stop - start;
        std::chrono::duration<double> decrypt_diff = decrypt_stop - encrypt_stop;
        cout << "encrypt costs " << encrypt_diff.count() / tests_num << " seconds" << endl;
        cout << "decrypt costs " << decrypt_diff.count() / tests_num << " seconds" << endl;



        // free memory
        cudaFree(d_messages);
        cudaFree(d_cipher_texts);
        cudaFree(d_plain_texts);
        cudaFree(devStates);
        delete[] cipher_texts;
        delete[] plain_texts;
    }

    void test_homomorphic_add(long long* message1, long long* message2, long long m_size)
    {
        long long* d_messages1;
        long long* d_messages2;
        long long* d_cipher_texts1;
        long long* d_cipher_texts2;
        long long* d_cipher_texts3;
        long long* d_plain_texts;
        long long* plain_texts = new long long[m_size];
        cudaMalloc(&d_messages1, m_size * sizeof(long long));
        cudaMalloc(&d_messages2, m_size * sizeof(long long));
        cudaMalloc(&d_cipher_texts1, m_size * sizeof(long long));
        cudaMalloc(&d_cipher_texts2, m_size * sizeof(long long));
        cudaMalloc(&d_cipher_texts3, m_size * sizeof(long long));
        cudaMalloc(&d_plain_texts, m_size * sizeof(long long));

        curandState* devStates;
        cudaMalloc(&devStates, m_size * sizeof(curandState));
        setup_kernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (devStates, time(0));

        //warm up   ------------------------------------------------
        cudaMemcpy(d_messages1, message1, m_size * sizeof(long long), cudaMemcpyHostToDevice);
        cudaMemcpy(d_messages2, message2, m_size * sizeof(long long), cudaMemcpyHostToDevice);
        encryptKernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n, generator.lambda, generator.n * generator.n, d_messages1, devStates, d_cipher_texts1, m_size);
        encryptKernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n, generator.lambda, generator.n * generator.n, d_messages2, devStates, d_cipher_texts2, m_size);

        Crypto_add_kernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n * generator.n, d_cipher_texts1, d_cipher_texts2, d_cipher_texts3, m_size);
        decryptKernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n, generator.lambda, generator.n * generator.n, generator.mu, d_cipher_texts3, d_plain_texts, m_size);
        cudaMemcpy(plain_texts, d_plain_texts, m_size * sizeof(long long), cudaMemcpyDeviceToHost);

        // test homomorphic add
        for (int i = 0; i < m_size; i++)
        {
            // cout << messages[i] << " " << plain_texts[i] << " " << endl;
            if ((message1[i] + message2[i]) % generator.n != plain_texts[i])
            {
                cout << "i: " << i << endl;
                cout << "add Error: " << message1[i] << " " << message2[i] << " " << plain_texts[i] << endl;
                return;
            }
        }
        // warm up end ------------------------------------------------

        long long* cipher_texts3 = new long long[m_size];
        auto start = chrono::high_resolution_clock::now();
        int test_id;
        for (test_id = 0; test_id < tests_num; test_id++)
        {
            cudaMemcpy(d_messages1, message1, m_size * sizeof(long long), cudaMemcpyHostToDevice);
            cudaMemcpy(d_messages2, message2, m_size * sizeof(long long), cudaMemcpyHostToDevice);
            Crypto_add_kernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n * generator.n, d_cipher_texts1, d_cipher_texts2, d_cipher_texts3, m_size);
            cudaMemcpy(cipher_texts3, d_cipher_texts3, m_size * sizeof(long long), cudaMemcpyDeviceToHost);
        }
        auto stop = chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff = stop - start;
        cout << "homomorphic add costs " << diff.count() / tests_num << " seconds" << endl;

        // free memory
        cudaFree(d_messages1);
        cudaFree(d_messages2);
        cudaFree(d_cipher_texts1);
        cudaFree(d_cipher_texts2);
        cudaFree(d_cipher_texts3);
        cudaFree(d_plain_texts);
        cudaFree(devStates);
        delete[] cipher_texts3;
        delete[] plain_texts;
    }

    void test_homomorphic_mul(long long* message, long long* scalars, long long m_size)
    {
        long long* d_messages;
        long long* d_scalars;
        long long* d_cipher_texts;
        long long* d_plain_texts;
        long long* plain_texts = new long long[m_size];
        cudaMalloc(&d_messages, m_size * sizeof(long long));
        cudaMalloc(&d_scalars, m_size * sizeof(long long));
        cudaMalloc(&d_cipher_texts, m_size * sizeof(long long));
        cudaMalloc(&d_plain_texts, m_size * sizeof(long long));

        curandState* devStates;
        cudaMalloc(&devStates, m_size * sizeof(curandState));
        setup_kernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (devStates, time(0));

        //warm up   ------------------------------------------------
        cudaMemcpy(d_messages, message, m_size * sizeof(long long), cudaMemcpyHostToDevice);
        cudaMemcpy(d_scalars, scalars, m_size * sizeof(long long), cudaMemcpyHostToDevice);
        encryptKernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n, generator.lambda, generator.n * generator.n, d_messages, devStates, d_cipher_texts, m_size);
        Crypto_mul_kernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n * generator.n, d_cipher_texts, d_cipher_texts, d_scalars, m_size);
        decryptKernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n, generator.lambda, generator.n * generator.n, generator.mu, d_cipher_texts, d_plain_texts, m_size);
        cudaMemcpy(plain_texts, d_plain_texts, m_size * sizeof(long long), cudaMemcpyDeviceToHost);

        // test homomorphic mul
        for (int i = 0; i < m_size; i++)
        {
            // cout << messages[i] << " " << plain_texts[i] << " " << endl;
            if ((message[i] * scalars[i]) % generator.n != plain_texts[i])
            {
                cout << "mul Error: " << message[i] << " " << scalars[i] << " " << plain_texts[i] << endl;
                return;
            }
        }
        // warm up end ------------------------------------------------

        long long* cipher_texts = new long long[m_size];
        auto start = chrono::high_resolution_clock::now();
        int test_id;
        for (test_id = 0; test_id < tests_num; test_id++)
        {
            cudaMemcpy(d_messages, message, m_size * sizeof(long long), cudaMemcpyHostToDevice);
            cudaMemcpy(d_scalars, scalars, m_size * sizeof(long long), cudaMemcpyHostToDevice);
            Crypto_mul_kernel << <(m_size + batch_size - 1) / batch_size, batch_size >> > (generator.n * generator.n, d_cipher_texts, d_cipher_texts, d_scalars, m_size);
            cudaMemcpy(cipher_texts, d_cipher_texts, m_size * sizeof(long long), cudaMemcpyDeviceToHost);
        }
        auto stop = chrono::high_resolution_clock::now();
        std::chrono::duration<double> diff = stop - start;
        cout << "homomorphic mul costs " << diff.count() / tests_num << " seconds" << endl;

        // free memory
        cudaFree(d_messages);
        cudaFree(d_scalars);
        cudaFree(d_cipher_texts);
        cudaFree(d_plain_texts);
        cudaFree(devStates);
        delete[] cipher_texts;
        delete[] plain_texts;
    }
};

int main()
{
    // test encryptKernel 
    long long p = 251; // for simplicity, we select p as 251
    long long q = 211; // for simplicity, we select q as 211
    const int max_size = 51200000;
    const int m_size_list[] = { 100000, 200000, 400000, 800000, 1600000, 3200000, 6400000, 12800000, 25600000, 51200000 };

    PaillierKeyGenerator keygen(p, q);
    keygen.print();

    long long n = keygen.n;

    //encrypt   
    long long* messages1 = new long long[max_size];
    long long* messages2 = new long long[max_size];
    long long* scalars = new long long[max_size];

    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<long long> dist(0, n - 1);

    cout << "begin generate random numbers" << endl;
    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < max_size; i++)
        messages1[i] = dist(rng);
    for (int i = 0; i < max_size; i++)
        messages2[i] = dist(rng);
    for (int i = 0; i < max_size; i++)
        scalars[i] = dist(rng);
    auto stop = chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff = stop - start;
    cout << "generate random numbers costs " << diff.count() << " seconds" << endl;
    Test test(keygen);
    cout << "begin test" << endl;
    // test.test_encrypt_decrypt(messages1, m_size);
    // test.test_homomorphic_add(messages1, messages2, m_size);
    // test.test_homomorphic_mul(messages1, scalars, m_size);
    // for (int i = 0; i < 15; i++)
    for (int i = 0; i < 10; i++)
    {
        int m_size = m_size_list[i];
        cout << "m_size: " << m_size << endl;
        test.test_encrypt_decrypt(messages1, m_size);
        test.test_homomorphic_add(messages1, messages2, m_size);
        test.test_homomorphic_mul(messages1, scalars, m_size);
    }

    cout << "end test" << endl;


    delete[] messages1;
    delete[] messages2;
    delete[] scalars;
    return 0;
}