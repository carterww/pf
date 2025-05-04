CC = clang
BUILD_DIR = build
LIB_DIR = lib
INCLUDE = -I.

PREFIX = /usr/local
LIBRARY = $(PREFIX)/lib
HEADER = $(PREFIX)/include

C_FLAGS = -std=c99 -O2 -masm=intel -fPIC -Werror -Wall -Wextra -Wpedantic -Wno-unused -Wfloat-equal \
	  -Wdouble-promotion -Wformat=2 -Wformat-security -Wstack-protector \
	  -Walloca -Wvla -Wcast-qual -Wconversion -Wformat-signedness -Wshadow \
	  -Wstrict-overflow=4 -Wundef -Wstrict-prototypes -Wswitch-default \
	  -Wswitch-enum -Wnull-dereference -Wmissing-include-dirs -Warray-bounds \
	  -Warray-bounds-pointer-arithmetic -Wassign-enum \
	  -Wbad-function-cast -Wconditional-uninitialized -Wformat-type-confusion \
	  -Widiomatic-parentheses -Wimplicit-fallthrough -Wloop-analysis \
	  -Wpointer-arith -Wshift-sign-overflow -Wshorten-64-to-32 \
	  -Wtautological-constant-in-range-compare -Wunreachable-code-aggressive \
	  -Wthread-safety -Wthread-safety-beta -Wcomma \
	  -fstack-protector-strong -fstack-clash-protection \
	  -D_FORTIFY_SOURCE=2 -fsanitize=bounds -fsanitize-undefined-trap-on-error \
	  -fsanitize=undefined -fno-omit-frame-pointer -fsanitize=safe-stack \
	  $(INCLUDE)

LD_FLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code

TARGET = libpf.so
TARGET_VERSION = libpf.so.0.1.0
TARGET_MAJOR = libpf.so.0
SRCS = pf.c pf_tables.c
OBJS = $(patsubst %.c,build/%.o,$(SRCS))

LIB_OUT = $(LIB_DIR)/$(TARGET)

all: lib_so

lib_so: $(LIB_OUT)

$(LIB_OUT): $(LIB_DIR) $(OBJS)
	$(CC) $(C_FLAGS) $(LD_FLAGS) -shared $(OBJS) -o $@

build/%.o: %.c $(BUILD_DIR)
	$(CC) $(C_FLAGS) -c $< -o $@

$(BUILD_DIR) $(LIB_DIR):
	@mkdir $@

clean:
	@rm -rf bin build

install:
	cp $(LIB_OUT) $(LIBRARY)/$(TARGET_VERSION)
	ln -sf $(TARGET_VERSION) $(LIBRARY)/$(TARGET_MAJOR)
	ln -sf $(TARGET_VERSION) $(LIBRARY)/$(TARGET)
	chmod 755 $(LIBRARY)/$(TARGET_VERSION)     \
		  $(LIBRARY)/$(TARGET_MAJOR)       \
		  $(LIBRARY)/$(TARGET)
	cp pf.h $(HEADER)/pf.h
	cp pf_hw_timer.h $(HEADER)/pf_hw_timer.h

uninstall:
	rm $(LIBRARY)/$(TARGET)
	rm $(LIBRARY)/$(TARGET_MAJOR)
	rm $(LIBRARY)/$(TARGET_VERSION)
	rm $(HEADER)/pf.h
	rm $(HEADER)/pf_hw_timer.h

.PHONY: all lib_so clean install uninstall
