package main

import "C"
import (
	"bytes"
	"encoding/binary"
	nlog "github.com/abc463774475/my_tool/n_log"
	bpf "github.com/iovisor/gobpf/bcc"
	"os"
	"os/signal"
)

const source string = `
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
	u64 stack_id;
	u32 pid;
	char comm[TASK_COMM_LEN];
};

BPF_STACK_TRACE(stack_traces, 1024);
BPF_PERF_OUTPUT(events);

void trace_stack(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid();
	//FILTER
	struct data_t data = {};
	data.stack_id = stack_traces.get_stackid(ctx, 0);
	
	u64 user_stack_id = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);
	u64 user_stack_id1 = stack_traces.get_stackid(ctx, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);

	data.pid = pid;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	events.perf_submit(ctx, &data, sizeof(data));
	bpf_trace_printk("stack_id: %llu user_stackid %llu 2 %llu\n", data.stack_id, user_stack_id, user_stack_id1);
}
`

type data struct {
	StackID uint64
	Pid     uint32
	Comm    [16]byte
}

func main() {
	nlog.Info("start")
	//pid := 22943
	m := bpf.NewModule(source, []string{
		//fmt.Sprintf("-DFILTER=if (pid != %v) { return; }", pid),
		//"-DTASK_COMM_LEN=256",
	})
	defer m.Close()

	f, err := m.LoadUprobe("trace_stack")
	if err != nil {
		nlog.Erro("load kprobe failed: %v", err)
		return
	}

	fnName := "/home/hxd/work/c++/test/b.out"

	nlog.Info("fnName: %v", fnName)
	err = m.AttachUprobe(fnName, "p3", f, -1)
	if err != nil {
		nlog.Erro("attach kprobe failed: %v", err)
		return
	}

	nlog.Info("end")

	table := bpf.NewTable(m.TableId("events"), m)
	channel := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		nlog.Erro("init perf map failed: %v", err)
		return
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event data
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				nlog.Erro("failed to decode received data: %v", err)
				continue
			}
			nlog.Info("pid %v comm %v stack_id %v", event.Pid, string(event.Comm[:]), event.StackID)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
