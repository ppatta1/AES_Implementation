/*
 * KeyExpansion.cpp
 *
 *  Created on: Apr 12, 2021
 *      Author: padmapriyapatta
 */

#include "KeyExpansion.h"

KeyExpansion::KeyExpansion() {

}

KeyExpansion::~KeyExpansion() {
}

void KeyExpansion::KeyExpansionCore(unsigned char * inputKey, unsigned char rconIteration) {
	// Rotate left
	unsigned char temp = inputKey[0];
	inputKey[0] = inputKey[1];
	inputKey[1] = inputKey[2];
	inputKey[2] = inputKey[3];
	inputKey[3] = temp;

	// S-box 4 bytes
	inputKey[0] = s_box[inputKey[0]];
	inputKey[1] = s_box[inputKey[1]];
	inputKey[2] = s_box[inputKey[2]];
	inputKey[3] = s_box[inputKey[3]];

	// RCon
	inputKey[0] ^= rcon[rconIteration];
}

KeyExpansion::KeyExpansion(unsigned char key[16], unsigned char expandedKeys[176]) {
	for(int i = 0; i < 16; i++) {
		expandedKeys[i] = key[i];
	}

	int bytesGenerated = 16;
	int rconIteration = 1;
	unsigned char tempCore[4];

	while (bytesGenerated < 176) {
		for(int i = 0; i < 4; i++) {
			tempCore[i] = expandedKeys[i + bytesGenerated - 4];
		}

		if (bytesGenerated % 16 == 0) {
			KeyExpansionCore(tempCore, rconIteration++);
		}

		for(unsigned char a = 0; a < 4; a++) {
			expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - 16] ^ tempCore[a];
			bytesGenerated++;
		}
	}
}

//Dynamic Key Dependent SBox
void KeyExpansion::dynamicSBox(unsigned char s[256], unsigned char inv_s[256]) {
//	unsigned char temp[256];
//	int i =0, k = 1, l = 1;
//	temp[1] = (keys[1] + keys[2]) % 256;
//	s[1] = temp[1];
//	while(k < 256) {
//		i = i+1;
//		int m = 1 + (k + i*l)%176;
//		temp[i+1] = (temp[i] + keys[m])%256;
//		l =0;
//		for(int j = 1; j<=k; j++) {
//			if (temp[i+1] != s[j]) {
//				l++;
//			}
//		}
//		if (l == k) {
//			s[k+1] = temp[i+1];
//		}
//		k++;
//	};
//	for(int i =0; i < 256; i++) {
//		inv_s[s[i]+1] = i-1;
//	}
}

