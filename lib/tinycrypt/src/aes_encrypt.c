/* aes_encrypt.c - TinyCrypt implementation of AES encryption procedure */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include "aes.h"
#include "mxc.h"

#include <tinycrypt/aes.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/utils.h>

int tc_aes_encrypt(uint8_t *out, uint8_t *in, const TCAesKeySched_t s) {
	if (out == (uint8_t *)0) {
		return TC_CRYPTO_FAIL;
	} else if (in == (uint8_t *)0) {
		return TC_CRYPTO_FAIL;
	} else if (s == (TCAesKeySched_t)0) {
		return TC_CRYPTO_FAIL;
	}

	mxc_aes_req_t req;
	req.length	   = Nk * Nb;
	req.inputData  = in;
	req.resultData = out;
	req.keySize	   = MXC_AES_128BITS;
	req.encryption = MXC_AES_ENCRYPT_EXT_KEY;

	MXC_AES_SetExtKey(s->words, MXC_AES_128BITS);
	if (MXC_AES_Init() != E_NO_ERROR) { return TC_CRYPTO_FAIL; }
	if (MXC_AES_Encrypt(&req) != E_NO_ERROR) { return TC_CRYPTO_FAIL; }
	return TC_CRYPTO_SUCCESS;
}
