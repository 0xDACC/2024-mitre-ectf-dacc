################################################################################
 # Copyright (C) 2023 Maxim Integrated Products, Inc., All Rights Reserved.
 #
 # Permission is hereby granted, free of charge, to any person obtaining a
 # copy of this software and associated documentation files (the "Software"),
 # to deal in the Software without restriction, including without limitation
 # the rights to use, copy, modify, merge, publish, distribute, sublicense,
 # and/or sell copies of the Software, and to permit persons to whom the
 # Software is furnished to do so, subject to the following conditions:
 #
 # The above copyright notice and this permission notice shall be included
 # in all copies or substantial portions of the Software.
 #
 # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 # OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 # MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 # IN NO EVENT SHALL MAXIM INTEGRATED BE LIABLE FOR ANY CLAIM, DAMAGES
 # OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 # ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 # OTHER DEALINGS IN THE SOFTWARE.
 #
 # Except as contained in this notice, the name of Maxim Integrated
 # Products, Inc. shall not be used except as stated in the Maxim Integrated
 # Products, Inc. Branding Policy.
 #
 # The mere transfer of this software does not imply any licenses
 # of trade secrets, proprietary technology, copyrights, patents,
 # trademarks, maskwork rights, or any other form of intellectual
 # property whatsoever. Maxim Integrated Products, Inc. retains all
 # ownership rights.
 #
 ###############################################################################

# The build directory
ifeq "$(BUILD_DIR)" ""
BUILD_DIR=$(CURDIR)/build
endif

# Create output object file names
SRCS_NOPATH := $(foreach NAME,$(SRCS),$(basename $(notdir $(NAME))).c)
BINS_NOPATH := $(foreach NAME,$(BINS),$(basename $(notdir $(NAME))).bin)
OBJS_NOPATH := $(SRCS_NOPATH:.c=.o)
OBJS_NOPATH += $(BINS_NOPATH:.bin=.o)
OBJS        := $(OBJS_NOPATH:%.o=$(BUILD_DIR)/%.o)
OBJS        += $(PROJ_OBJS)

################################################################################
# Goals

# The default goal, which causes the example to be built.
.DEFAULT_GOAL :=
.PHONY: all
all: mkbuildir
all: ${BUILD_DIR}/${PROJECT}.elf
all: project_defines

# Goal to build for release without debug
.PHONY: release
release: mkbuildir
release: ${BUILD_DIR}/${PROJECT}.elf
release: ${BUILD_DIR}/${PROJECT}.srec
release: ${BUILD_DIR}/${PROJECT}.hex
release: ${BUILD_DIR}/${PROJECT}.bin
release: ${BUILD_DIR}/${PROJECT}.dasm

# The goal to build as a library
.PHONY: lib
lib: mkbuildir
lib: ${BUILD_DIR}/${PROJECT}.a

# The goal to create the target directory.
.PHONY: mkbuildir
mkbuildir:
	@mkdir -p ${BUILD_DIR}

# The goal to clean out all the build products.
.PHONY: clean
clean:
	@rm -rf ${BUILD_DIR} ${wildcard *~}

${BUILD_DIR}/${PROJECT}.elf: ${LIBS} ${OBJS} ${LINKERFILE}
${BUILD_DIR}/${PROJECT}.a: ${OBJS}

# Create a goal to exercise the library build dependencies
.PHONY: FORCE
FORCE:

# Include the automatically generated dependency files.
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${BUILD_DIR}/*.d} __dummy__
endif

################################################################################
# Get the operating system name.  If this is Cygwin, the .d files will be
# munged to convert c: into /cygdrive/c so that "make" will be happy with the
# auto-generated dependencies. Also if this is Cygwin, file paths for ARM GCC
# will be converted from /cygdrive/c to C:.
################################################################################
UNAME := $(shell uname -s)
ifneq ($(findstring CYGWIN, $(UNAME)), )
CYGWIN=True
endif

ifneq ($(findstring MSYS, $(UNAME)), )
MSYS=True
endif

# Set the toolchain prefix.  Top-level makefiles can specify ARM_PREFIX or
# PREFIX directly.  ARM_PREFIX is given to improve dual-core projects
ifeq "$(ARM_PREFIX)" ""
PREFIX ?= arm-none-eabi
else
PREFIX ?= $(ARM_PREFIX)
endif

# Set absolute path to tools if TOOL_DIR is specified
ifneq "$(TOOL_DIR)" ""
PREFIX=$(TOOL_DIR)/$(PREFIX)
endif

# The command for calling the compiler.
CC=${PREFIX}-gcc
CXX=${PREFIX}-g++

# Discover if we are using GCC > 4.8.0
GCCVERSIONGTEQ4 := $(shell expr `$(CC) -dumpversion | cut -f1 -d.` \> 4)
ifeq "$(GCCVERSIONGTEQ4)" "0"
GCCVERSIONGTEQ4 := $(shell expr `$(CC) -dumpversion | cut -f1 -d.` \>= 4)
ifeq "$(GCCVERSIONGTEQ4)" "1"
GCCVERSIONGTEQ4 := $(shell expr `$(CC) -dumpversion | cut -f2 -d.` \>= 8)
endif

endif

# The flags passed to the assembler.
AFLAGS=-mthumb         \
       -mcpu=cortex-m4 \
       -MD
ifneq "$(HEAP_SIZE)" ""
AFLAGS+=-D__HEAP_SIZE=$(HEAP_SIZE)
endif
ifneq "$(STACK_SIZE)" ""
AFLAGS+=-D__STACK_SIZE=$(STACK_SIZE)
endif
ifneq "$(SRAM_SIZE)" ""
AFLAGS+=-D__SRAM_SIZE=$(SRAM_SIZE)
endif
AFLAGS+=$(PROJ_AFLAGS)

ifeq "$(MXC_OPTIMIZE_CFLAGS)" ""
# Default is optimize for size
MXC_OPTIMIZE_CFLAGS = -Os
endif

# Float ABI options:
# See https://gcc.gnu.org/onlinedocs/gcc/ARM-Options.html (-mfloat-abi)
# Specifies which floating-point ABI to use. Permissible values are: ‘soft’, ‘softfp’ and ‘hard’.

# Specifying ‘soft’ causes GCC to generate output containing library calls for floating-point
# operations. ‘softfp’ allows the generation of code using hardware floating-point
# instructions, but still uses the soft-float calling conventions. ‘hard’ allows generation of
# floating-point instructions and uses FPU-specific calling conventions.

# The default depends on the specific target configuration. Note that the hard-float and
# soft-float ABIs are not link-compatible; you must compile your entire program with the same
# ABI, and link with a compatible set of libraries.
ifeq "$(MFLOAT_ABI)" ""
MFLOAT_ABI = softfp
endif

# (deprecated) MFLOAT_FLAGS
ifneq "$(MFLOAT_FLAGS)" ""
$(warning MFLOAT_FLAGS has been deprecated!  Please use MFLOAT_ABI instead.)
MFLOAT_ABI = $(MFLOAT_FLAGS) # Copy over to new option for backwards compatability
endif

# Option for setting the FPU to use
MFPU ?= fpv4-sp-d16

# (deprecated) MFPU_FLAGS
# The old option implied multiple values could be set, so it was renamed to MFPU
ifneq "$(MFPU_FLAGS)" ""
$(warning MFPU_FLAGS has been deprecated!  Used MFPU instead.)
MFPU := $(MFPU_FLAGS) # Copy over to the new option for backwards compatability
endif

# The flags passed to the compiler.
# fno-isolate-erroneous-paths-dereference disables the check for pointers with the value of 0
#  add this below when arm-none-eabi-gcc version is past 4.8 -fno-isolate-erroneous-paths-dereference                                \

# Universal optimization flags added to all builds
DEFAULT_OPTIMIZE_FLAGS ?= -ffunction-sections -fdata-sections -fsingle-precision-constant
DEFAULT_WARNING_FLAGS ?= -Wall -Wno-format -Wdouble-promotion

CFLAGS=-mthumb                                                                 \
       -mcpu=cortex-m4                                                         \
       -mfloat-abi=$(MFLOAT_ABI)                                               \
       -mfpu=$(MFPU)                                                           \
       -Wa,-mimplicit-it=thumb                                                 \
       $(MXC_OPTIMIZE_CFLAGS)   											   \
       $(DEFAULT_OPTIMIZE_FLAGS)   										       \
       $(DEFAULT_WARNING_FLAGS)   										       \
       -MD                                                                     \
       -c

# The flags passed to the C++ compiler.
CXXFLAGS := $(CFLAGS)
CXXFLAGS += \
	-fno-rtti				\
	-fno-exceptions				\
	-std=c++11				\

# On GCC version > 4.8.0 use the -fno-isolate-erroneous-paths-dereference flag
ifeq "$(GCCVERSIONGTEQ4)" "1"
CFLAGS += -fno-isolate-erroneous-paths-dereference
endif

ifneq "$(TARGET)" ""
CFLAGS+=-DTARGET=$(TARGET)
endif

ifneq "$(TARGET_REV)" ""
CFLAGS+=-DTARGET_REV=$(TARGET_REV)
endif

# Exclude debug for 'release' builds
ifneq (${MAKECMDGOALS},release)
ifneq (${DEBUG},0)
CFLAGS+=-g3 -ggdb -DDEBUG
endif
endif

CFLAGS+=$(PROJ_CFLAGS)
CXXFLAGS+=$(CFLAGS)

# The command for calling the library archiver.
AR=${PREFIX}-ar

# The command for calling the linker.
LD=${PREFIX}-gcc

# The flags passed to the linker.
LDFLAGS=-mthumb                                                                \
        -mcpu=cortex-m4                                                        \
        -mfloat-abi=$(MFLOAT_ABI)                                              \
        -mfpu=$(MFPU)                                                          \
        -Xlinker --gc-sections                                                 \
	-Xlinker -Map -Xlinker ${BUILD_DIR}/$(PROJECT).map
LDFLAGS+=$(PROJ_LDFLAGS)

# Include math library
STD_LIBS=-lc -lm

# Determine if any C++ files are in the project sources, and add libraries as appropriate
ifneq "$(findstring .cpp, ${SRCS})" ""
STD_LIBS+=-lsupc++ -lstdc++
endif

# Finally, resolve any newlib system calls with libnosys
STD_LIBS+=-lnosys

PROJ_LIBS:=$(addprefix -l, $(PROJ_LIBS))

# The command for extracting images from the linked executables.
OBJCOPY=${PREFIX}-objcopy
OBJDUMP=${PREFIX}-objdump

ifeq "$(CYGWIN)" "True"
fixpath=$(shell echo $(1) | sed -r 's/\/cygdrive\/([A-Na-n])/\U\1:/g' )
else
fixpath=$(1)
endif

# Add the include file paths to AFLAGS and CFLAGS.
AFLAGS+=${patsubst %,-I%,$(call fixpath,$(IPATH))}
CFLAGS+=${patsubst %,-I%,$(call fixpath,$(IPATH))}
CXXFLAGS+=${patsubst %,-I%,$(call fixpath,$(IPATH))}
ifneq ($(MSYS),)
# 2-27-2023:  This workaround was added to resolve a linker bug introduced
# when we started using ln_args.txt.  The GCC linker expects C:/-like paths
# on Windows if arguments are passed in from a text file.  However, ln_args
# is parsed through a regex that misses the edge case -L/C/Path/... because
# of the leading "-L".  We use cygpath here to handle that edge case before
# parsing ln_args.txt.
LDFLAGS+=${patsubst %,-L%,$(shell cygpath -m $(LIBPATH))}
else
LDFLAGS+=${patsubst %,-L%,$(call fixpath,$(LIBPATH))}
endif

# Add an option for stripping unneeded symbols from archive files
STRIP_LIBRARIES ?= 0
# The command for stripping objects.
STRIP = $(PREFIX)-strip

################################################################################
# The rule for building the object file from each C source file.
${BUILD_DIR}/%.o: %.c $(PROJECTMK)
	@if [ 'x${ECLIPSE}' != x ]; 																			\
	then 																									\
		echo ${CC} ${CFLAGS} -o $(call fixpath,${@}) $(call fixpath,${<}) | sed 's/-I\/\(.\)\//-I\1:\//g' ; \
	elif [ 'x${VERBOSE}' != x ];                                               								\
	then 																									\
	    echo ${CC} ${CFLAGS} -o $(call fixpath,${@}) $(call fixpath,${<});     								\
	else                                                                       								\
	    echo "  CC    ${<}";                                                   								\
	fi
	@${CC} ${CFLAGS} -o $(call fixpath,${@}) $(call fixpath,${<})
ifeq "$(CYGWIN)" "True"
	@sed -i -r -e 's/([A-Na-n]):/\/cygdrive\/\L\1/g' -e 's/\\([A-Za-z])/\/\1/g' ${@:.o=.d}
endif

# The rule to build an object file from a C++ source file
${BUILD_DIR}/%.o: %.cpp $(PROJECTMK)
	@if [ 'x${ECLIPSE}' != x ]; 																			\
	then 																									\
		echo ${CXX} ${CXXFLAGS} -o $(call fixpath,${@}) $(call fixpath,${<}) | sed 's/-I\/\(.\)\//-I\1:\//g' ; \
	elif [ 'x${VERBOSE}' != x ];                                               								\
	then 																									\
	    echo ${CXX} ${CXXFLAGS} -o $(call fixpath,${@}) $(call fixpath,${<});     								\
	else                                                                       								\
	    echo "  CXX    ${<}";                                                   								\
	fi
	@${CXX} ${CXXFLAGS} -o $(call fixpath,${@}) $(call fixpath,${<})
ifeq "$(CYGWIN)" "True"
	@sed -i -r -e 's/([A-Na-n]):/\/cygdrive\/\L\1/g' -e 's/\\([A-Za-z])/\/\1/g' ${@:.o=.d}
endif

# The rule for building the object file from each assembly source file.
${BUILD_DIR}/%.o: %.S $(PROJECTMK)
	@if [ 'x${VERBOSE}' = x ];                                                   \
	 then                                                                        \
	     echo "  AS    ${<}";                                                    \
	 else                                                                        \
	     echo ${CC} ${AFLAGS} -o $(call fixpath,${@}) -c $(call fixpath,${<});   \
	 fi
	@${CC} ${AFLAGS} -o $(call fixpath,${@}) -c $(call fixpath,${<})
ifeq "$(CYGWIN)" "True"
	@sed -i -r -e 's/([A-Na-n]):/\/cygdrive\/\L\1/g' -e 's/\\([A-Za-z])/\/\1/g' ${@:.o=.d}
endif

# The rule for creating an object library.
${BUILD_DIR}/%.a: $(PROJECTMK)
	@echo -cr $(call fixpath,${@}) $(call fixpath,${^})                          \
	| sed -r -e 's/ \/([A-Za-z])\// \1:\//g' > ${BUILD_DIR}/ar_args.txt
	@if [ 'x${VERBOSE}' = x ];                                                   \
	 then                                                                        \
	     echo "  AR    ${@}";                                                    \
	 else                                                                        \
	     echo ${AR} -cr $(call fixpath,${@}) $(call fixpath,${^});               \
	 fi
	@${AR} @${BUILD_DIR}/ar_args.txt
ifeq ($(STRIP_LIBRARIES),1)
	@if [ 'x${ECLIPSE}' != x ];                                                 \
	 then                                                                       \
	    echo ${STRIP} $(call fixpath,${@}) | sed 's/-I\/\(.\)\//-I\1:\//g' ;    \
	elif [ 'x${VERBOSE}' != x ];                                                \
	then                                                                        \
	    echo ${STRIP} --strip-unneeded $(call fixpath,${@});                    \
	elif [ 'x${QUIET}' != x ];                                                  \
	then                                                                        \
	    :;                                                                      \
	else                                                                        \
	    echo "  STRIP ${@}";                                                    \
	fi
	@${STRIP} --strip-unneeded $(call fixpath,${@})
endif

# The rule for building the object file from binary source file.
# Resulting object will have the following symbols
# _binary_<file_name>_bin_start
# _binary_<file_name>_bin_end
# _binary_<file_name>_bin_size
${BUILD_DIR}/%.o: %.bin $(PROJECTMK)
	@if [ 'x${VERBOSE}' = x ];                                                  \
	then                                                                        \
	    echo "  CP    ${<}";                                                    \
	elif [ 'x${QUIET}' != x ];                                                  \
	then 																		\
		:;																		\
	else 																		\
	    echo ${OBJCOPY} -I binary -B arm -O elf32-littlearm --rename-section    \
	    .data=.text $(call fixpath,${<}) $(call fixpath,${@});                  \
	fi
	@${OBJCOPY} -I binary -B arm -O elf32-littlearm --rename-section            \
	.data=.text $(call fixpath,${<}) $(call fixpath,${@})
ifeq "$(CYGWIN)" "True"
	@sed -i -r -e 's/([A-Na-n]):/\/cygdrive\/\L\1/g' -e 's/\\([A-Za-z])/\/\1/g' ${@:.o=.d}
endif

# The rule for linking the application.
${BUILD_DIR}/%.elf: $(PROJECTMK)
	@echo -T $(call fixpath,${LINKERFILE})                                       \
	      --entry ${ENTRY}                                                       \
	      $(call fixpath,${LDFLAGS})                                             \
	      -o $(call fixpath,${@})                                                \
	      $(call fixpath,$(filter %.o, ${^}))                                    \
	      -Xlinker --start-group                                                 \
	      $(call fixpath,$(filter %.a, ${^}))                                    \
	      ${PROJ_LIBS}                                                           \
	      ${STD_LIBS}                                                            \
	      -Xlinker --end-group                                                   \
	      | sed -r -e 's/ \/([A-Za-z])\// \1:\//g' > ${BUILD_DIR}/ln_args.txt	
	@if [ 'x${VERBOSE}' = x ];                                                   \
	then                                                                         \
	    echo "  LD    ${@} ${LNK_SCP}";                                      \
	else                                                                         \
	    echo ${LD} -T $(call fixpath,${LINKERFILE})                          \
	        --entry ${ENTRY}                                             \
	        $(call fixpath,${LDFLAGS})                                   \
	        -o $(call fixpath,${@})                                      \
	        $(call fixpath,$(filter %.o, ${^}))                          \
	        -Xlinker --start-group                                       \
	        $(call fixpath,$(filter %.a, ${^}))                          \
	        ${PROJ_LIBS}                                                 \
	        ${STD_LIBS}                                                  \
	        -Xlinker --end-group;                                        \
	    echo ${LD} @${BUILD_DIR}/ln_args.txt;                                \
	fi
	@${LD} @${BUILD_DIR}/ln_args.txt

# Create S-Record output file
%.srec: %.elf
	@if [ 'x${VERBOSE}' = x ];                                                   \
	 then                                                                        \
	     echo "Creating ${@}";                                                   \
	 else                                                                        \
	     echo ${OBJCOPY} -O srec $(call fixpath,${<}) $(call fixpath,${@});      \
	 fi
	@$(OBJCOPY) -O srec $< $(call fixpath,${@})

# Create Intex Hex output file
%.hex: %.elf
	@if [ 'x${VERBOSE}' = x ];                                                   \
	 then                                                                        \
	     echo "Creating ${@}";                                                   \
	 else                                                                        \
	     echo ${OBJCOPY} -O ihex $(call fixpath,${<}) $(call fixpath,${@});      \
	 fi
	@$(OBJCOPY) -O ihex $< $(call fixpath,${@})

# Create binary output file
%.bin: %.elf
	@if [ 'x${VERBOSE}' = x ];                                                   \
	 then                                                                        \
	     echo "Creating ${@}";                                                   \
	 else                                                                        \
	     echo ${OBJCOPY} -O binary $(call fixpath,${<}) $(call fixpath,${@});    \
	 fi
	@$(OBJCOPY) -O binary $< $(call fixpath,${@})

# Create disassembly file
%.dasm: %.elf
	@if [ 'x${VERBOSE}' = x ];                                                   \
	 then                                                                        \
	     echo "Creating ${@}";                                                   \
	 else                                                                        \
	     echo $(OBJDUMP) -S $(call fixpath,${<}) $(call fixpath,${@});        \
	 fi
	@$(OBJDUMP) -S $< > $(call fixpath,${@})

################################################################################
.PHONY: debug
debug:
	@echo CYGWIN = ${CYGWIN}
	@echo
	@echo CC = ${CC}
	@echo
	@echo AS = ${AS}
	@echo
	@echo LD = ${LD}
	@echo
	@echo TARGET = ${TARGET}
	@echo
	@echo BOARD = ${BOARD}
	@echo
	@echo BUILD_DIR = ${BUILD_DIR}
	@echo
	@echo SRCS = ${SRCS}
	@echo
	@echo SRCS_NOPATH = ${SRCS_NOPATH}
	@echo
	@echo OBJS_NOPATH = ${OBJS_NOPATH}
	@echo
	@echo OBJS = ${OBJS}
	@echo
	@echo LIBS = ${LIBS}
	@echo
	@echo VPATH = ${VPATH}
	@echo
	@echo IPATH = ${IPATH}
	@echo
	@echo CFLAGS = ${CFLAGS}
	@echo
	@echo AFLAGS = ${AFLAGS}
	@echo
	@echo LDFLAGS = ${LDFLAGS}

################################################################################
# Add a rule for generating a header file containing compiler definitions
# that come from the build system and compiler itself.  This generates a
# "project_defines.h" header file inside the build directory that can be
# force included by VS Code to improve the intellisense engine.
.PHONY: project_defines
project_defines: $(BUILD_DIR)/project_defines.h
$(BUILD_DIR)/project_defines.h: mkbuildir
	$(file > $(BUILD_DIR)/empty.c,)
	$(file > $(BUILD_DIR)/project_defines.h,// This is a generated file that's used to detect definitions that have been set by the compiler and build system.)
	@$(CC) -E -P -dD $(BUILD_DIR)/empty.c $(CFLAGS) >> $(BUILD_DIR)/project_defines.h
	@rm $(BUILD_DIR)/empty.c
	@rm empty.d