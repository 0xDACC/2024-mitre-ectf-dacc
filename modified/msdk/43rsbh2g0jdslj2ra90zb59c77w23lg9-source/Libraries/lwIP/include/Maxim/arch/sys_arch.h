/*
 * @file sys_arch.h
 *
 ******************************************************************************
 * Copyright (C) 2019 Maxim Integrated Products, Inc., All rights Reserved.
 *
 * This software is protected by copyright laws of the United States and
 * of foreign countries. This material may also be protected by patent laws
 * and technology transfer regulations of the United States and of foreign
 * countries. This software is furnished under a license agreement and/or a
 * nondisclosure agreement and may only be used or reproduced in accordance
 * with the terms of those agreements. Dissemination of this information to
 * any party or parties not specified in the license agreement and/or
 * nondisclosure agreement is expressly prohibited.
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL MAXIM INTEGRATED BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Except as contained in this notice, the name of Maxim Integrated
 * Products, Inc. shall not be used except as stated in the Maxim Integrated
 * Products, Inc. Branding Policy.
 *
 * The mere transfer of this software does not imply any licenses
 * of trade secrets, proprietary technology, copyrights, patents,
 * trademarks, maskwork rights, or any other form of intellectual
 * property whatsoever. Maxim Integrated Products, Inc. retains all
 * ownership rights.
 ******************************************************************************
 */
#ifndef LIBRARIES_LWIP_INCLUDE_MAXIM_ARCH_SYS_ARCH_H_
#define LIBRARIES_LWIP_INCLUDE_MAXIM_ARCH_SYS_ARCH_H_

#define SYS_MBOX_NULL   NULL
#define SYS_SEM_NULL    NULL

typedef void *sys_prot_t;
typedef void *sys_mutex_t;
typedef void *sys_sem_t;
typedef void *sys_mbox_t;
typedef void *sys_thread_t;

#define sys_arch_mbox_tryfetch(mbox, msg) sys_arch_mbox_fetch(mbox, msg, 1)

#endif // LIBRARIES_LWIP_INCLUDE_MAXIM_ARCH_SYS_ARCH_H_
