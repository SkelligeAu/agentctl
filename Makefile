CC      ?= cc
CFLAGS  ?= -std=c99 -Wall -Wextra -Wpedantic -O2 \
           -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -D_GNU_SOURCE
LDFLAGS ?=

BINS = agentctl agentd reviewer-agent fanout-agent psa broker-test broker-fault broker-concurrency
TESTS = tests/test_ipc_msg_trunc tests/test_ipc_msg_ctrunc tests/test_cloexec tests/phase1-probe tests/crash-agent
LIBOBJS = common.o ipc.o broker.o profiles.o tasks.o enforcement.o
LIB = libagentctl.a
FUZZ_CC ?= clang
FUZZ_CFLAGS ?= -std=c99 -O1 -g -fno-omit-frame-pointer \
	-fsanitize=fuzzer,address,undefined \
	-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
	-D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -D_GNU_SOURCE
FUZZ_TARGETS = tests/fuzz/fuzz-broker tests/fuzz/fuzz-ipc

AR ?= ar

all: $(LIB) $(BINS) $(TESTS)

$(LIB): $(LIBOBJS)
	$(AR) rcs $@ $(LIBOBJS)

tests: $(TESTS)

fuzz: $(FUZZ_TARGETS)

tests/fuzz/fuzz-broker: tests/fuzz/fuzz_broker.c broker.c broker.h common.h
	$(FUZZ_CC) $(FUZZ_CFLAGS) -I. -o $@ tests/fuzz/fuzz_broker.c broker.c

tests/fuzz/fuzz-ipc: tests/fuzz/fuzz_ipc.c ipc.c ipc.h common.c common.h \
		broker.c broker.h profiles.c profiles.h tasks.c tasks.h \
		enforcement.c enforcement.h
	$(FUZZ_CC) $(FUZZ_CFLAGS) -I. -o $@ tests/fuzz/fuzz_ipc.c \
		ipc.c common.c broker.c profiles.c tasks.c enforcement.c

agentctl: agentctl.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ agentctl.o $(LIBOBJS)

agentd: agentd.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ agentd.o $(LIBOBJS)

reviewer-agent: reviewer-agent.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ reviewer-agent.o $(LIBOBJS)

fanout-agent: fanout-agent.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ fanout-agent.o $(LIBOBJS)

psa: psa.o $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ psa.o $(LIBOBJS)

broker-test: examples/broker-test.c $(LIBOBJS)
	$(CC) $(CFLAGS) -I. $(LDFLAGS) -o $@ examples/broker-test.c $(LIBOBJS)

broker-fault: examples/broker-fault.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ examples/broker-fault.c

broker-concurrency: examples/broker-concurrency.c $(LIBOBJS)
	$(CC) $(CFLAGS) -I. $(LDFLAGS) -o $@ examples/broker-concurrency.c $(LIBOBJS)

tests/test_ipc_msg_trunc: tests/test_ipc_msg_trunc.c $(LIBOBJS)
	$(CC) $(CFLAGS) -I. $(LDFLAGS) -o $@ tests/test_ipc_msg_trunc.c $(LIBOBJS)

tests/test_ipc_msg_ctrunc: tests/test_ipc_msg_ctrunc.c $(LIBOBJS)
	$(CC) $(CFLAGS) -I. $(LDFLAGS) -o $@ tests/test_ipc_msg_ctrunc.c $(LIBOBJS)

tests/test_cloexec: tests/test_cloexec.c $(LIBOBJS)
	$(CC) $(CFLAGS) -I. $(LDFLAGS) -o $@ tests/test_cloexec.c $(LIBOBJS)

tests/phase1-probe: tests/phase1-probe.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tests/phase1-probe.c

tests/crash-agent: tests/crash-agent.c $(LIBOBJS)
	$(CC) $(CFLAGS) -I. $(LDFLAGS) -o $@ tests/crash-agent.c $(LIBOBJS)

agentctl.o: agentctl.c common.h profiles.h tasks.h enforcement.h
	$(CC) $(CFLAGS) -c -o $@ agentctl.c

agentd.o: agentd.c common.h profiles.h tasks.h enforcement.h
	$(CC) $(CFLAGS) -c -o $@ agentd.c

reviewer-agent.o: reviewer-agent.c common.h profiles.h tasks.h
	$(CC) $(CFLAGS) -c -o $@ reviewer-agent.c

fanout-agent.o: fanout-agent.c common.h profiles.h tasks.h
	$(CC) $(CFLAGS) -c -o $@ fanout-agent.c

psa.o: psa.c common.h profiles.h tasks.h enforcement.h
	$(CC) $(CFLAGS) -c -o $@ psa.c

common.o: common.c common.h
	$(CC) $(CFLAGS) -c -o $@ common.c

ipc.o: ipc.c ipc.h common.h
	$(CC) $(CFLAGS) -c -o $@ ipc.c

broker.o: broker.c broker.h common.h
	$(CC) $(CFLAGS) -c -o $@ broker.c

profiles.o: profiles.c profiles.h common.h
	$(CC) $(CFLAGS) -c -o $@ profiles.c

tasks.o: tasks.c tasks.h common.h profiles.h
	$(CC) $(CFLAGS) -c -o $@ tasks.c

enforcement.o: enforcement.c enforcement.h common.h profiles.h
	$(CC) $(CFLAGS) -c -o $@ enforcement.c

clean:
	rm -f $(BINS) $(TESTS) $(FUZZ_TARGETS) $(LIB) agentctl.o agentd.o reviewer-agent.o fanout-agent.o psa.o common.o ipc.o broker.o profiles.o tasks.o enforcement.o

.PHONY: all clean tests fuzz
