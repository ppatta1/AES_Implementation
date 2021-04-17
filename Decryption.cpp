/*
 * Decryption.cpp
 *
 *  Created on: Apr 12, 2021
 *      Author: padmapriyapatta
 */
#include <iostream>
#include "Decryption.h"

using namespace std;

Decryption::Decryption() {

}

Decryption::~Decryption() {
	// TODO Auto-generated destructor stub
}

unsigned char inv_s[] ={
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

void Decryption::SubRoundKey(unsigned char * state, unsigned char * roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

void Decryption::InverseMixColumns(unsigned char * state) {
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

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

void Decryption::InvShiftRows(unsigned char * state) {
	unsigned char tmp[16];

	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}

void Decryption::InvSubBytes(unsigned char * state) {

	//SBox shift to make cryptographically strong
//	unsigned char temp[256];
//	for(int i = 0; i < 16; i++) {
//		temp[16*i + 0] = inv_s[16*i + 1];
//		temp[16*i + 1] = inv_s[16*i + 2];
//		temp[16*i + 2] = inv_s[16*i + 3];
//		temp[16*i + 3] = inv_s[16*i + 4];
//		temp[16*i + 4] = inv_s[16*i + 5];
//		temp[16*i + 5] = inv_s[16*i + 6];
//		temp[16*i + 6] = inv_s[16*i + 7];
//		temp[16*i + 7] = inv_s[16*i + 8];
//		temp[16*i + 8] = inv_s[16*i + 9];
//		temp[16*i + 9] = inv_s[16*i + 10];
//		temp[16*i + 10] = inv_s[16*i + 11];
//		temp[16*i + 11] = inv_s[16*i + 12];
//		temp[16*i + 12] = inv_s[16*i + 13];
//		temp[16*i + 13] = inv_s[16*i + 14];
//		temp[16*i + 14] = inv_s[16*i + 15];
//		temp[16*i + 15] = inv_s[16*i + 0];
//	}
//
//	for (int i = 0; i < 256; i++) {
//		inv_s[i] = temp[i];
//	}

	for (int i = 0; i < 16; i++) {
		state[i] = inv_s[state[i]];
	}


//	for(int i = 0; i < 16; i++) {
//		tmp[16*i + 0] = inv_s[16*i + 15];
//		tmp[16*i + 1] = inv_s[16*i + 0];
//		tmp[16*i + 2] = inv_s[16*i + 1];
//		tmp[16*i + 3] = inv_s[16*i + 2];
//		tmp[16*i + 4] = inv_s[16*i + 3];
//		tmp[16*i + 5] = inv_s[16*i + 4];
//		tmp[16*i + 6] = inv_s[16*i + 5];
//		tmp[16*i + 7] = inv_s[16*i + 6];
//		tmp[16*i + 8] = inv_s[16*i + 7];
//		tmp[16*i + 9] = inv_s[16*i + 8];
//		tmp[16*i + 10] = inv_s[16*i + 9];
//		tmp[16*i + 11] = inv_s[16*i + 10];
//		tmp[16*i + 12] = inv_s[16*i + 11];
//		tmp[16*i + 13] = inv_s[16*i + 12];
//		tmp[16*i + 14] = inv_s[16*i + 13];
//		tmp[16*i + 15] = inv_s[16*i + 14];
//	}
}

void Decryption::DecryptRound(unsigned char * state, unsigned char * key) {
	SubRoundKey(state, key);
	InverseMixColumns(state);
	InvShiftRows(state);
	InvSubBytes(state);
}

// Same as Round() but no InverseMixColumns
void Decryption::DecryptInitialRound(unsigned char * state, unsigned char * key) {
	SubRoundKey(state, key);
	InvShiftRows(state);
	InvSubBytes(state);
}

void Decryption::AESDecrypt(unsigned char * encryptedMessage, unsigned char * expandedKey, unsigned char * decryptedMessage, int numberOfRounds) {
	unsigned char state[16]; // Stores the first 16 bytes of original message

	for (int i = 0; i < 16; i++) {
		state[i] = encryptedMessage[i];
	}

	DecryptInitialRound(state, expandedKey + 160);

	numberOfRounds = numberOfRounds -1;
	for (int i = numberOfRounds - 1; i >=0; i--) {
		DecryptRound(state, expandedKey + (16 * (i+1)));
	}

	SubRoundKey(state, expandedKey);

	// Copy encrypted state to buffer
	for (int i = 0; i < 16; i++) {
		decryptedMessage[i] = state[i];
	}
}

void Decryption::AESDecryptECB(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * decryptedMessage, int numberOfRounds) {
	for(int i = 0; i < paddedMessageLength; i+= 16) {
		AESDecrypt(paddedMessage + i, expandedKey, decryptedMessage + i, numberOfRounds);
	}
}

void Decryption::AESDecryptCBC(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * iv, unsigned char * decryptedMessage, int numberOfRounds) {
	unsigned char *block = new unsigned char[16];
	memcpy(block, iv, 16);
	for(int i = 0; i < paddedMessageLength; i += 16) {
		AESDecrypt(paddedMessage + i, expandedKey, decryptedMessage + i, numberOfRounds);
		for(int j = 0; j < 16; j++) {
			(decryptedMessage + i)[j] ^= (block)[j];
		}
		memcpy(block, paddedMessage + i, 16);
	}

	delete[] block;
}

void Decryption::AESDecryptCFB(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * iv, unsigned char * decryptedMessage, int numberOfRounds) {
	unsigned char *block = new unsigned char[16];
	unsigned char *decryptedBlock = new unsigned char[16];

	memcpy(block, iv, 16);
	for(int i = 0; i < paddedMessageLength; i += 16) {
		AESDecrypt(block, expandedKey, decryptedMessage + i, numberOfRounds);
		for(int j = 0; j < 16; j++) {
			(decryptedMessage + i)[j] = (decryptedMessage + i)[j] ^ (paddedMessage + i)[j];
		}
		memcpy(block, paddedMessage + i, 16);
	}

	delete[] block;
	delete[] decryptedBlock;
}

void Decryption::AESDecryptOFB(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * iv, unsigned char * decryptedMessage, int numberOfRounds) {
	unsigned char *block = new unsigned char[16];
	unsigned char *decryptedBlock = new unsigned char[16];

	memcpy(block, iv, 16);
	for(int i = 0; i < paddedMessageLength; i += 16) {
		AESDecrypt(block, expandedKey, decryptedBlock, numberOfRounds);
		memcpy(block, decryptedBlock, 16);
		for(int j = 0; j < 16; j++) {
			(decryptedMessage + i)[j] = decryptedBlock[j] ^ (paddedMessage + i)[j];
		}

	}

	delete[] block;
	delete[] decryptedBlock;
}

void Decryption::AESDecryptCTR(unsigned char * paddedMessage, int paddedMessageLength, unsigned char * expandedKey, unsigned char * iv, unsigned char * decryptedMessage, int numberOfRounds) {
	unsigned char *block = new unsigned char[16];

	memcpy(block, iv, 16);
	for(int i = 0; i < paddedMessageLength; i += 16) {
		AESDecrypt(block, expandedKey, decryptedMessage + i, numberOfRounds);
		for (unsigned int i = 1; i <= strlen((char *)block); ++i) {
		    unsigned int index = strlen((char *)block) - i;
		    block[index]++;
		    if (block[index] != 0) {
		      break;
		    }
		}
		memcpy(block, block, 16);
		for(int j = 0; j < 16; j++) {
			(decryptedMessage + i)[j] ^= (paddedMessage + i)[j];
		}
	}

	delete[] block;
}

