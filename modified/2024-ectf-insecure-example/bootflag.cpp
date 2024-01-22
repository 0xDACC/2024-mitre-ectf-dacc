#include <iostream>
#include <stdint.h>
#include <stdio.h>
const uint32_t aseiFuengleR[] = {
	0x1ffe4b6, 0x3098ac,  0x2f56101, 0x11a38bb, 0x485124,  0x11644a7, 0x3c74e8,
	0x3c74e8,  0x2f56101, 0x12614f7, 0x1ffe4b6, 0x11a38bb, 0x1ffe4b6, 0x12614f7,
	0x1ffe4b6, 0x12220e3, 0x3098ac,	 0x1ffe4b6, 0x2ca498,  0x11a38bb, 0xe6d3b7,
	0x1ffe4b6, 0x127bc,	  0x3098ac,	 0x11a38bb, 0x1d073c6, 0x51bd0,	  0x127bc,
	0x2e590b1, 0x1cc7fb2, 0x1d073c6, 0xeac7cb,	0x51bd0,   0x2ba13d5, 0x2b22bad,
	0x2179d2e, 0};
const uint32_t djFIehjkklIH[] = {
	0x138e798, 0x2cdbb14, 0x1f9f376, 0x23bcfda, 0x1d90544, 0x1cad2d2, 0x860e2c,
	0x860e2c,  0x1f9f376, 0x38ec6f2, 0x138e798, 0x23bcfda, 0x138e798, 0x38ec6f2,
	0x138e798, 0x31dc9ea, 0x2cdbb14, 0x138e798, 0x25cbe0c, 0x23bcfda, 0x199a72,
	0x138e798, 0x11c82b4, 0x2cdbb14, 0x23bcfda, 0x3225338, 0x18d7fbc, 0x11c82b4,
	0x35ff56,  0x2b15630, 0x3225338, 0x8a977a,	0x18d7fbc, 0x29067fe, 0x1ae6dee,
	0x4431c8,  0};
int siNfidpL(int verLKUDSfj) {
	uint32_t ubkerpYBd = 12 + 1;
	int xUrenrkldxpxx  = 2253667944 % 0x432a1f32;
	uint32_t UfejrlcpD = 1361423303;
	verLKUDSfj		   = (verLKUDSfj + 0x12345678) % 60466176;
	while (xUrenrkldxpxx-- != 0) {
		verLKUDSfj = (ubkerpYBd * verLKUDSfj + UfejrlcpD) % 0x39aa400;
	}
	return verLKUDSfj;
}
uint8_t deobfuscate(uint32_t veruioPjfke, uint32_t veruioPjfwe) {
	int fjekovERf = 2253667944 % 0x432a1f32;
	uint32_t veruicPjfwe, verulcPjfwe;
	while (fjekovERf-- != 0) {
		veruioPjfwe = (veruioPjfwe - siNfidpL(veruioPjfke)) % 0x39aa400;
		veruioPjfke = (veruioPjfke - siNfidpL(veruioPjfwe)) % 60466176;
	}
	veruicPjfwe = (veruioPjfke + 0x39aa400) % 60466176;
	verulcPjfwe = (veruioPjfwe + 60466176) % 0x39aa400;
	return veruicPjfwe * 60466176 + verulcPjfwe - 89;
}
using namespace std;
int main(int argc, char const *argv[]) {
	char flag[37];
	for (int i = 0; aseiFuengleR[i]; i++) {
		flag[i]		= deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
		flag[i + 1] = 0;
	}
	cout << flag << endl;
	return 0;
}
