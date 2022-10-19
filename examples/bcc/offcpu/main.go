package main

import (
	"bytes"
	"encoding/binary"
	nlog "github.com/abc463774475/my_tool/n_log"
	"github.com/iovisor/gobpf/bcc"
	"os"
	"os/signal"
	"regexp"
)

const source string = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MINBLOCK_US MINBLOCK_US_VALUEULL
#define MAXBLOCK_US MAXBLOCK_US_VALUEULL


struct key_t {
	u64 pid;
	u64 tid;
    int user_stack_id;
	int kernel_stack_id;
	char name[TASK_COMM_LEN];
};

BPF_HASH(counts, struct key_t);
BPF_HASH(start, u32);
BPF_STACK_TRACE(stack_traces, STACK_STORAGE_SIZE);

struct warn_event_t {
	u32 pid;
	u32 tid;
	u32 t_start;
	u32 t_end;
};
BPF_PERF_OUTPUT(warn_events);

int oncpu(struct pt_regs *ctx, struct task_struct *prev) {
	u32 pid =  prev->pid;
	u32 tid =  prev->tgid;
	u64 ts, *tsp;
	
	// record previous thread sleep time
	if ((THREAD_FILTER) && (STATE_FILTER)) {
		ts = bpf_ktime_get_ns();
		start.update(&pid, &ts);
	}
	
	// get the current thread start time
	pid = bpf_get_current_pid_tgid();
	tid = pid >> 32;
    // lookup the current process start time
	tsp = start.lookup(&pid);
	if (tsp == 0) {
		return 0;
	}

	// calculate the current thread delta time
	u64 t_start = *tsp;
	u64 t_end = bpf_ktime_get_ns();
	start.delete(&pid);
	
	if (t_start > t_end) {
       struct warn_event_t event = {
			.pid = pid, 
			.tid = tid, 
			.t_start = t_start, 
			.t_end = t_end};
		// there is a bug in bcc, cur time is less than start time.
		warn_events.perf_submit(ctx, &event, sizeof(event));
		return 0;
	}
	u64 delta = t_end - t_start;
	delta /= 1000;
	if (delta < MINBLOCK_US || delta > MAXBLOCK_US) {
		return 0;
	}

	// create a key map to store the thread info
	struct key_t key = {};
	key.pid = pid;
	key.tid = tid;
	key.user_stack_id = USER_STACK_GET;
	key.kernel_stack_id = KERNEL_STACK_GET;
	bpf_get_current_comm(&key.name, sizeof(key.name));
	counts.increment(key, delta);
	return 0;	
`

var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

type WarnEvent struct {
	Pid    uint32
	Tid    uint32
	TStart uint32
	TEnd   uint32
}

func main() {
	nlog.Info("start")
	m := bcc.NewModule(source, []string{
		"-DTHREAD_FILTER=pid == 999",
		"-DSTATE_FILTER=prev->STATE_FAILED == 0",
		"-DMINBLOCK_US_VALUEULL=1000000",
		"-DMAXBLOCK_US_VALUEULL=100000000",
		"-DSTACK_STORAGE_SIZE=10240",
		"-DUSER_STACK_GET=stack_traces.get_stackid(ctx, BPF_F_REUSE_STACKID)",
		"-DKERNEL_STACK_GET=stack_traces.get_stackid(ctx, 0)",
	})
	defer m.Close()

	startKprobe, err := m.LoadKprobe("oncpu")
	if err != nil {
		nlog.Erro("Failed to load oncpu: %s", err)
		return
	}

	err = m.AttachKprobe("finish_task_switch", startKprobe, -1)
	if err != nil {
		nlog.Erro("Failed to attach oncpu: %s", err)
		return
	}

	table := bcc.NewTable(m.TableId("warn_events"), m)

	channel := make(chan []byte)
	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		nlog.Erro("Failed to init perf map: %s", err)
		return
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event WarnEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				nlog.Erro("Failed to decode received data: %s", err)
				continue
			}
			nlog.Info("warn event: %+v", event)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
