#include <iostream>
#include <cstring>
#include<cmath>
#include <fstream>
#include <sstream>
#include "structures.h"
using namespace std;

/* Used in Round() and serves as the final round during decryption
 * SubRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
 * So basically does the same as AddRoundKey in the encryption
 */
void SubRoundKey(unsigned char *state, unsigned char *roundKey)
{
	for (int i = 0; i < 16; i++)
	{
		state[i] ^= roundKey[i];
	}
}

/* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
 * Unmixes the columns by reversing the effect of MixColumns in encryption
 */
void InverseMixColumns(unsigned char *state)
{
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
	tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
	tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
	tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

	tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
	tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
	tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
	tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

	tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
	tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
	tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
	tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

	tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
	tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
	tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
	tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

	for (int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}
}

// Shifts rows right (rather than left) for decryption
void ShiftRows(unsigned char *state)
{
	unsigned char tmp[16];

	/* Column 1 */
	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	/* Column 2 */
	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	/* Column 3 */
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	/* Column 4 */
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

	for (int i = 0; i < 16; i++)
	{
		state[i] = tmp[i];
	}
}

/* Perform substitution to each of the 16 bytes
 * Uses inverse S-box as lookup table
 */
void SubBytes(unsigned char *state)
{
	for (int i = 0; i < 16; i++)
	{ // Perform substitution to each of the 16 bytes
		state[i] = inv_s[state[i]];
	}
}

/* Each round operates on 128 bits at a time
 * The number of rounds is defined in AESDecrypt()
 * Not surprisingly, the steps are the encryption steps but reversed
 */
void Round(unsigned char *state, unsigned char *key)
{
	SubRoundKey(state, key);
	InverseMixColumns(state);
	ShiftRows(state);
	SubBytes(state);
}

// Same as Round() but no InverseMixColumns
void InitialRound(unsigned char *state, unsigned char *key)
{
	SubRoundKey(state, key);
	ShiftRows(state);
	SubBytes(state);
}

/* The AES decryption function
 * Organizes all the decryption steps long long into one function
 */
void AESDecrypt(unsigned char *encryptedMessage, unsigned char *expandedKey, unsigned char *decryptedMessage)
{
	unsigned char state[16]; // Stores the first 16 bytes of encrypted message

	for (int i = 0; i < 16; i++)
	{
		state[i] = encryptedMessage[i];
	}

	InitialRound(state, expandedKey + 160);

	int numberOfRounds = 9;

	for (int i = 8; i >= 0; i--)
	{
		Round(state, expandedKey + (16 * (i + 1)));
	}

	SubRoundKey(state, expandedKey); // Final round

	// Copy decrypted state to buffer
	for (int i = 0; i < 16; i++)
	{
		decryptedMessage[i] = state[i];
	}
}
int check_prime(long long int n)
{
	long long int i;
	for (i = 2; i <= n / 2; i++)
	{
		if (n % i == 0)
		{
			return 1;
		}
	}
	return 0;
}
long long int compute(long long int a, long long int m, long long int n)
{
	long long int r;
	long long int y = 1;

	while (m > 0)
	{
		r = m % 2;
		if (r == 1)
		{
			y = (y * a) % n;
		}
		a = a * a % n;
		m = m / 2;
	}

	return y;
}
long long int gcd(long long int a, long long int h)
{
	long long int temp;
	while (1)
	{
		temp = a % h;
		if (temp == 0)
			return h;
		a = h;
		h = temp;
	}
}
void decryption()
{
	cout<<"Decryption\n";
	long long int i = 0, j, d, n, l = 0, m = 0;
	cout<<"Enter n:";
	cin>>n;
	getchar();
	cout<<"Enter the private key:";
	cin>>d;
	getchar();
	long long int C1[100];
	// scanf("%[^\n]s",C);
	string C;
	ifstream plfile;
	plfile.open("Key_Cipher.txt", ios::in | ios::binary);

	if (plfile.is_open())
	{
		getline(plfile, C); // The first line of file is the plalong long intext
		plfile.close();
	}

	else
		cout << "Unable to open file";
	while (5)
	{
		long long int y = 0;
		while (C[m] != ' ' && C[m] != '\0')
		{
			y = (y * 10) + (C[m] - 48);
			m++;
		}
		m++;
		C1[l] = y;
		if (m >= C.length())
		{
			break;
		}
		l++;
	}
	cout<<"Decrypted Text is:\n";
	for (j = 0; j <= l; j++)
	{
		C1[j] = compute(C1[j], d, n);
		cout<<C1[j]<<" ";
	}
	ofstream outfile;
	outfile.open("Key_Cipher.txt", ios::out | ios::binary);
	if (outfile.is_open())
	{
		for (int i = 0; i <= l; i++)
		{
			outfile << C1[i];
			outfile << " ";
		}
		outfile.close();
		cout<<("Wrote Decrypted text to file Key_Cipher.txt\n");
	}
}

void key_generation()
{
	cout << "Key Generation:\n";
	long long int n, phi, e = 2, k = 0, d;
	long long int p,q;
	double msg;
	p=rand();
	q=rand();
	p=p*(100);
	q=q*(10);
	//cout << "Enter the Two Prime Numbers p & q:\n";
	while (5)
	{
	a:
		//cout << "Enter p:";
		//cin >> p;
		p=p+1;
		if (check_prime(p) == 1)//||//p<1000000000)
		{
			//cout << "Invalid input Enter again\n";
			goto a;
		}
	b:
		//cout << "Enter q:";
		//cin >> q;
		q=q+1;
		if (check_prime(q) == 1)//||q<1000000000)
		{
			//cout << "Invalid input Enter again\n";
			goto b;
		}
		break;
	}
	n = p * q;
	phi = (p - 1) * (q - 1);
	while (5) // Public key Generation
	{
		e = (rand() % phi - 2) + 2;
		if (gcd(e, phi) == 1)
			break; // Public Key Found Hence Leave
	}
	while ((1 + (k * phi)) % e != 0)
	{
		k++;
	}
	d = (1 + (k * phi)) / e; // Private Key Generation
	cout << "n=" << n << "\nPublic Key e=" << e << "\nPrivate key d=" << d << "\n";
	// msg = compute(c, d, n); //Decryption Using Private Key
	// prlong long intf("\nDecrypted text=%.lf", msg);
	return;
}
int main()
{

	// Read in the message from message.aes
	string msgstr;
	ifstream infile;
	key_generation();
	decryption();
	infile.open("message.aes", ios::in | ios::binary);

	if (infile.is_open())
	{
		getline(infile, msgstr); // The first line of file is the message
		cout << "Read in encrypted message from message.aes" << endl;
		infile.close();
	}

	else
		cout << "Unable to open file";

	char *msg = new char[msgstr.size() + 1];

	strcpy(msg, msgstr.c_str());

	int n = strlen((const char *)msg);

	unsigned char *encryptedMessage = new unsigned char[n];
	for (int i = 0; i < n; i++)
	{
		encryptedMessage[i] = (unsigned char)msg[i];
	}

	// Free memory
	delete[] msg;

	// Read in the key
	string keystr;
	ifstream keyfile;
	keyfile.open("Key_Cipher.txt", ios::in | ios::binary);

	if (keyfile.is_open())
	{
		getline(keyfile, keystr); // The first line of file should be the key
		cout << "Read in the 128-bit key from Key_Cipher.txt" << endl;
		keyfile.close();
	}

	else
		cout << "Unable to open file";

	istringstream hex_chars_stream(keystr);
	unsigned char key[16];
	int i = 0;
	unsigned int c;
	while (hex_chars_stream >> hex >> c)
	{
		key[i] = c;
		i++;
	}

	unsigned char expandedKey[176];

	KeyExpansion(key, expandedKey);

	int messageLen = strlen((const char *)encryptedMessage);

	unsigned char *decryptedMessage = new unsigned char[messageLen];

	for (int i = 0; i < messageLen; i += 16)
	{
		AESDecrypt(encryptedMessage + i, expandedKey, decryptedMessage + i);
	}

	cout << "Decrypted message in hex:" << endl;
	for (int i = 0; i < messageLen; i++)
	{
		cout << hex << (int)decryptedMessage[i];
		cout << " ";
	}
	cout << endl;
	cout << "Decrypted message: " << endl;
	for (int i = 0; i < messageLen; i++)
	{
		cout << decryptedMessage[i];
	}
	cout << endl;

	return 0;
}