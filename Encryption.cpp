/*
 * main.cpp
 *
 *  Created on: Mar 21, 2021
 *      Author: padmapriyapatta
 */


#include <iostream>
#include "KeyExpansion.h"
#include "Decryption.h"

using namespace std;


int numberOfRounds = 10;
//Forward Rijndael S-box
unsigned char s[256] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

//Multiply by 2 for MixColumns
unsigned char mul2[] =
{
	0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
	0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
	0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
	0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
	0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
	0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
	0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
	0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
	0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
	0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
	0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
	0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
	0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
	0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
	0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
	0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};

//Multiply by 3 for MixColumns
unsigned char mul3[] =
{
	0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
	0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
	0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
	0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
	0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
	0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
	0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
	0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
	0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
	0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
	0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
	0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
	0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
	0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
	0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
	0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a
};

void AddRoundKey(unsigned char * state, unsigned char * roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

void SubBytes(unsigned char * state) {
	for (int i = 0; i < 16; i++) {
		state[i] = s[state[i]];
	}

	//SBox shift to make cryptographically strong
//	unsigned char temp[256];
//	for(int i = 0; i < 16; i++) {
//		temp[16*i + 0] = s[16*i + 1];
//		temp[16*i + 1] = s[16*i + 2];
//		temp[16*i + 2] = s[16*i + 3];
//		temp[16*i + 3] = s[16*i + 4];
//		temp[16*i + 4] = s[16*i + 5];
//		temp[16*i + 5] = s[16*i + 6];
//		temp[16*i + 6] = s[16*i + 7];
//		temp[16*i + 7] = s[16*i + 8];
//		temp[16*i + 8] = s[16*i + 9];
//		temp[16*i + 9] = s[16*i + 10];
//		temp[16*i + 10] = s[16*i + 11];
//		temp[16*i + 11] = s[16*i + 12];
//		temp[16*i + 12] = s[16*i + 13];
//		temp[16*i + 13] = s[16*i + 14];
//		temp[16*i + 14] = s[16*i + 15];
//		temp[16*i + 15] = s[16*i + 0];
//	}
//
//	for (int i = 0; i < 256; i++) {
//		s[i] = temp[i];
//	}
}

void ShiftRows(unsigned char * state) {
	unsigned char temp[16];

	temp[0] = state[0];
	temp[1] = state[5];
	temp[2] = state[10];
	temp[3] = state[15];

	/* Column 2 */
	temp[4] = state[4];
	temp[5] = state[9];
	temp[6] = state[14];
	temp[7] = state[3];

	/* Column 3 */
	temp[8] = state[8];
	temp[9] = state[13];
	temp[10] = state[2];
	temp[11] = state[7];

	/* Column 4 */
	temp[12] = state[12];
	temp[13] = state[1];
	temp[14] = state[6];
	temp[15] = state[11];

	for (int i = 0; i < 16; i++) {
		state[i] = temp[i];
	}
}

void MixColumns(unsigned char * state) {
	unsigned char temp[16];

	temp[0] = (unsigned char) mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
	temp[1] = (unsigned char) state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
	temp[2] = (unsigned char) state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
	temp[3] = (unsigned char) mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

	temp[4] = (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
	temp[5] = (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
	temp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
	temp[7] = (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

	temp[8] = (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
	temp[9] = (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
	temp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
	temp[11] = (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

	temp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
	temp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
	temp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
	temp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

	for (int i = 0; i < 16; i++) {
		state[i] = temp[i];
	}
}

void Round(unsigned char * state, unsigned char * key) {
	SubBytes(state);
	ShiftRows(state);
	MixColumns(state);
	AddRoundKey(state, key);
}

void FinalRound(unsigned char * state, unsigned char * key) {
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, key);
}

void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
	unsigned char state[16];

	for (int i = 0; i < 16; i++) {
		state[i] = message[i];
	}

	AddRoundKey(state, expandedKey);

	for (int i = 0; i < numberOfRounds - 1; i++) {
		Round(state, expandedKey + (16 * (i+1)));
	}

	FinalRound(state, expandedKey + 160);

	for (int i = 0; i < 16; i++) {
		encryptedMessage[i] = state[i];
	}
}

//ECB mode of operation
void AESEncryptECB(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * encryptedMessage) {
	for(int i = 0; i < paddedMessageLength; i+= 16) {
		AESEncrypt(paddedMessage + i, expandedKey, encryptedMessage + i);
	}
}

//CBC mode of operation
void AESEncryptCBC(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * iv, unsigned char * encryptedMessage) {
	unsigned char *block = new unsigned char[16];

	memcpy(block, iv, 16);
	for(int i = 0; i < paddedMessageLength; i += 16) {
		for(int j = 0; j < 16; j++) {
			block[j] ^= (paddedMessage + i)[j];
		}
		AESEncrypt(block, expandedKey, encryptedMessage + i);
		memcpy(block, encryptedMessage + i, 16);
	}

	delete[] block;
}

//CFB mode of operation
void AESEncryptCFB(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * iv, unsigned char * encryptedMessage) {
	unsigned char *block = new unsigned char[16];
	unsigned char *encryptedBlock = new unsigned char[16];

	memcpy(block, iv, 16);
	for(int i = 0; i < paddedMessageLength; i += 16) {
		AESEncrypt(block, expandedKey, encryptedBlock);
		for(int j = 0; j < 16; j++) {
			(encryptedMessage + i)[j] = (encryptedBlock)[j] ^ (paddedMessage + i)[j];
		}
		memcpy(block, encryptedMessage + i, 16);
	}

	delete[] block;
	delete[] encryptedBlock;
}

//OFB mode of operation
void AESEncryptOFB(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * iv, unsigned char * encryptedMessage) {
	unsigned char *block = new unsigned char[16];

	memcpy(block, iv, 16);
	for(int i = 0; i < paddedMessageLength; i += 16) {
		AESEncrypt(block, expandedKey, encryptedMessage + i);
		memcpy(block, encryptedMessage + i, 16);
		for(int j = 0; j < 16; j++) {
			(encryptedMessage + i)[j] ^= (paddedMessage + i)[j];
		}
	}

	delete[] block;
}

//CTR mode of operation
void AESEncryptCTR(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * iv, unsigned char * encryptedMessage) {
	unsigned char *block = new unsigned char[16];

	memcpy(block, iv, 16);
	for(int i = 0; i < paddedMessageLength; i += 16) {
		AESEncrypt(block, expandedKey, encryptedMessage + i);
		for (unsigned int i = 1; i <= strlen((char *)block); ++i) {
		    unsigned int index = strlen((char *)block) - i;
		    block[index]++;
		    if (block[index] != 0) {
		      break;
		    }
		  }
		memcpy(block, block, 16);
		for(int j = 0; j < 16; j++) {
			(encryptedMessage + i)[j] ^= (paddedMessage + i)[j];
		}
	}
	delete[] block;
}

//Linear Congruential Generator
unsigned long rand(unsigned long seed, long a, long c, long m) {
	//Secure coding practice to avoid unsigned integer wrapping
	if (a * seed < ULLONG_MAX && a*seed + c < ULLONG_MAX) {
		//Secure coding practice to avoid divide by zero errors
		if(m == 0) {
			m = rand();
		}
	} else {
		seed = seed % m;
	}
	seed = fmod(a*seed + c,m);
	return seed;
}

void lfsr(unsigned char * seed) {
	for(int i = 64; i > 0; i--) {
		seed[i] = seed[i-1];
	}
	seed[0] = seed[63] ^ seed[62] ^ seed[60] ^ seed[59];
}

void decimalToHexadecimal(unsigned long dec, unsigned char * hexaDec)
{
    int i = 0;
    while (dec != 0) {
        int temp = 0;
        temp = dec % 16;
        if(temp < 10) {
        	hexaDec[i] = temp + 48;
            i++;
        } else {
            hexaDec[i] = temp + 55;
            i++;
        }
        dec = dec / 16;
    }
}

void hexaDecimalToBinary(unsigned char * hexaDec, unsigned char * binary) {
	for(int i=0; i< 16; i++) {
		switch(hexaDec[i]) {
	    case '0':
	    	strcat((char *) binary, "0000");
	        break;
	    case '1':
	        strcat((char *) binary, "0001");
	        break;
	    case '2':
	    	strcat((char *) binary, "0010");
	    	break;
	    case '3':
	    	strcat((char *) binary, "0011");
	    	break;
	    case '4':
	    	strcat((char *) binary, "0100");
	    	break;
	    case '5':
	    	strcat((char *) binary, "0101");
	    	break;
	    case '6':
	    	strcat((char *) binary, "0110");
	    	break;
	    case '7':
	    	strcat((char *) binary, "0111");
	    	break;
	    case '8':
	    	strcat((char *) binary, "1000");
	    	break;
	    case '9':
	    	strcat((char *) binary, "1001");
	    	break;
	    case 'A':
	    case 'a':
	    	strcat((char *) binary, "1010");
	    	break;
	    case 'B':
	    case 'b':
	    	strcat((char *) binary, "1011");
	    	break;
	    case 'C':
	    case 'c':
	    	strcat((char *) binary, "1100");
	    	break;
	    case 'D':
	    case 'd':
	    	strcat((char *) binary, "1101");
	    	break;
	    case 'E':
	    case 'e':
	    	strcat((char *) binary, "1110");
	    	break;
	    case 'F':
	    case 'f':
	    	strcat((char *) binary, "1111");
	    	break;
	    default:
	    	break;
		}
	}
}

void binaryToHexaDecimal(unsigned char * binary, unsigned char * hexaDec) {
	for(int i=0; i<16; i++) {
		char temp[4];
		temp[0] = binary[4*i + 0];
		temp[1] = binary[4*i + 1];
		temp[2] = binary[4*i + 2];
		temp[3] = binary[4*i + 3];
		int decNum = ((temp[0]-48) * pow(2,0))+ ((temp[1]-48) * pow(2,1)) + ((temp[2]-48) * pow(2,2)) + ((temp[3]-48) * pow(2,3));

		switch(decNum) {
		case 0:
			hexaDec[i] = '0';
			break;
		case 1:
			hexaDec[i] = '1';
			break;
		case 2:
			hexaDec[i] = '2';
			break;
		case 3:
			hexaDec[i] = '3';
			break;
		case 4:
			hexaDec[i] = '4';
			break;
		case 5:
			hexaDec[i] = '5';
			break;
		case 6:
			hexaDec[i] = '6';
			break;
		case 7:
			hexaDec[i] = '7';
			break;
		case 8:
			hexaDec[i] = '8';
			break;
		case 9:
			hexaDec[i] = '9';
			break;
		case 10:
			hexaDec[i] = (char)'A';
			break;
		case 11:
			hexaDec[i] = (char)'B';
			break;
		case 12:
			hexaDec[i] = (char)'C';
			break;
		case 13:
			hexaDec[i] = (char)'D';
			break;
		case 14:
			hexaDec[i] = (char)'E';
			break;
		case 15:
			hexaDec[i] = (char)'F';
			break;
		default:
			hexaDec[i] = (char)'0';
			break;
		}
	}
}
int main() {

	char plainText[1024];
	//Get plain text
	cout << "Enter the message to be encrypted:" << endl;
	cin.getline(plainText, sizeof(plainText));

	int sizeOfKey;

	cout << "Enter option for size of key" << endl;
	cout << "128 bits" << endl;
	cout << "192 bits" << endl;
	cout << "256 bits" << endl;

	cin >> sizeOfKey;

	unsigned char * key;
	switch (sizeOfKey) {
	case 1:
		key = new unsigned char[16];
		numberOfRounds = 10;
		break;
	case 2:
		key = new unsigned char[24];
		numberOfRounds = 12;
		break;
	case 3:
		key = new unsigned char[32];
		numberOfRounds = 14;
		break;
	}
	unsigned long seed = 958736124345165312;
	long a = 166455762553123415;
	long c = 1013904287909231234;
	long m = pow(2,64);

	seed = rand(seed, a, c, m);
	decimalToHexadecimal(seed, key);

	unsigned long lfsr_seed;
	unsigned char * lfsr_key = new unsigned char[16];
	seed = rand(seed, a, c, m);
	lfsr_seed = seed;
	decimalToHexadecimal(lfsr_seed, lfsr_key);
	unsigned char * lfsr_binary = new unsigned char [128];
	hexaDecimalToBinary(lfsr_key, lfsr_binary);
	lfsr(lfsr_binary);
	binaryToHexaDecimal(lfsr_binary, lfsr_key);

	switch (sizeOfKey) {
		case 1:
			break;
		case 2:
			for(int i = 16; i < 24; i++) {
				key[i] = lfsr_key[i - 16];
			}
			break;
		case 3:
			for(int i = 16; i < 32; i++) {
				key[i] = lfsr_key[i - 16];
			}
			break;
	}
	cout << "Key: ";
	for (int j = 0; j < 32; j++) {
		cout << key[j];
	}
	cout << endl;

	unsigned char iv[16];
	seed = rand(seed, a, c, m);
	cout << "IV: ";
	decimalToHexadecimal(seed, iv);
	for (int j = 0; j < 16; j++) {
		cout << iv[j];
	}
	cout << endl;

	//Padding message
	int messageLength = strlen((const char *)plainText);
	int paddedMessageLength = messageLength;
	if ((paddedMessageLength % 16) != 0) {
		paddedMessageLength = (paddedMessageLength / 16 + 1) * 16;
	}
	unsigned char * paddedMessage = new unsigned char[paddedMessageLength];
	unsigned char * encryptedMessage = new unsigned char[paddedMessageLength];
	for (int i = 0; i< paddedMessageLength; i++) {
		if (i < messageLength) {
			paddedMessage[i] = plainText[i];
		} else {
			paddedMessage[i] = 0;
		}
	}

	//Key expansion
	unsigned char expandedKey[176];
	KeyExpansion(key, expandedKey);

	//Encryption
	int modeOfOp = 0;
	cout << "Enter option for mode of operation" << endl;
	cout << "1. ECB" << endl;
	cout << "2. CBC" << endl;
	cout << "3. CFB" << endl;
	cout << "4. OFB" << endl;
	cout << "5. CTR" << endl;

	cin >> modeOfOp;

	//All cases handled according to secure coding practices
	switch(modeOfOp) {
	case 2:
		AESEncryptCBC(paddedMessage, paddedMessageLength, expandedKey, iv, encryptedMessage);
		break;
	case 3:
		AESEncryptCFB(paddedMessage, paddedMessageLength, expandedKey, iv, encryptedMessage);
		paddedMessageLength = messageLength;
		break;
	case 4:
		AESEncryptOFB(paddedMessage, paddedMessageLength, expandedKey, iv, encryptedMessage);
		paddedMessageLength = messageLength;
		break;
	case 5:
		AESEncryptCTR(paddedMessage, paddedMessageLength, expandedKey, iv, encryptedMessage);
		paddedMessageLength = messageLength;
		break;
	case 1:
	default:
		AESEncryptECB(paddedMessage, paddedMessageLength, expandedKey, encryptedMessage);
		break;
	}

	cout << "Encrypted message:" << endl;
	for (int i = 0; i < paddedMessageLength; i++) {
		cout << hex << (int) encryptedMessage[i];
		cout << " ";
	}
	cout << endl;

	//Decryption
	Decryption decrypt = Decryption();
	unsigned char * decryptedMessage = new unsigned char[paddedMessageLength];
	switch(modeOfOp) {
	case 1:
		decrypt.AESDecryptECB(encryptedMessage, paddedMessageLength, expandedKey, decryptedMessage, numberOfRounds);
		break;
	case 2:
		decrypt.AESDecryptCBC(encryptedMessage, paddedMessageLength, expandedKey, iv, decryptedMessage, numberOfRounds);
		break;
	case 3:
		decrypt.AESDecryptCFB(encryptedMessage, paddedMessageLength, expandedKey, iv, decryptedMessage, numberOfRounds);
		break;
	case 4:
		decrypt.AESDecryptOFB(encryptedMessage, paddedMessageLength, expandedKey, iv, decryptedMessage, numberOfRounds);
		break;
	case 5:
		decrypt.AESDecryptCTR(encryptedMessage, paddedMessageLength, expandedKey, iv, decryptedMessage, numberOfRounds);
		break;
	}

	cout << "Decrypted message:" << endl;
	for (int i = 0; i < paddedMessageLength; i++) {
		cout << decryptedMessage[i];
	}
	cout << endl;
}
