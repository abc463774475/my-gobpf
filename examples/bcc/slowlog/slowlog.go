package main

import "C"
import (
	"bytes"
	"encoding/binary"
	nlog "github.com/abc463774475/my_tool/n_log"
	bpf "github.com/iovisor/gobpf/bcc"
	"os"
	"os/signal"
	"regexp"
)

const source string = `
#include <uapi/linux/ptrace.h>

struct start_t{
	u64 ts;
	char query[QUERY_MAX];
};

struct data_t{
	u64 pid;
	u64 ts;
	u64 delta;
	
	char query[QUERY_MAX];
};

BPF_HASH(start_tmp, u32, struct start_t);
BPF_PERF_OUTPUT (events);

int do_start (struct pt_regs *ctx, char *szQuery) {
	// Return: current->tgid << 32 | current->pid maybe not right?
	u32 tid = bpf_get_current_pid_tgid();
	struct start_t start = {};
	start.ts = bpf_ktime_get_ns();
	//bpf_usdt_readarg (1, ctx, &start.query);
	//char sz1[64];
	int ret = 0;
	//ret = bpf_probe_read(&sz1,sizeof(sz1),(void*)PT_REGS_PARM1(ctx));  bpf_probe_read_user_str
	ret = bpf_probe_read_user(&(start.query), sizeof(start.query), (void*)PT_REGS_PARM1(ctx));
	start_tmp.update(&tid, &start);
	
	//start.query = sz1;
	bpf_trace_printk("start %s %d \n", szQuery, szQuery[0]);
	bpf_trace_printk("start111 %s ret %d\n", start.query, ret);		
	return 0;
}

int do_done(struct pt_regs *ctx){
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = (u32)pid_tgid ;
	
	struct start_t *sp;
	sp = start_tmp.lookup (&tid);
	bpf_trace_printk("done1  sp %p\n",sp);
	if (sp == 0) {
		return 0;
	}

	u64 delta = bpf_ktime_get_ns() - sp->ts;
	bpf_trace_printk("done2  delta %lld\n",delta);
	if (delta > MIN_NS) {
		struct data_t data = {.pid = pid, .ts = sp->ts, .delta = delta};
		bpf_probe_read_user(&data.query, sizeof(data.query), (void *)sp->query);
		events.perf_submit (ctx, &data, sizeof(data));
		
		bpf_trace_printk("done3\n");
	}
	
	start_tmp.delete(&tid) ;
	bpf_trace_printk("done4\n");
	return 0;
}

`

var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

type endEvent struct {
	Pid   uint64
	Ts    uint64
	Delta uint64
	Query [64]byte
}

func main() {
	nlog.Info("start")
	m := bpf.NewModule(source, []string{"-DQUERY_MAX=64", "-DMIN_NS=100000000"})
	defer m.Close()

	nlog.Info("load start")
	fPath := `/home/hxd/work/c++/test/b.out`

	{
		startUprobe, err := m.LoadUprobe("do_start")
		if err != nil {
			nlog.Erro("err %v", err)
			return
		}

		err = m.AttachUprobe(fPath, "start111", startUprobe, -1)
		if err != nil {
			nlog.Erro("err %v", err)
			return
		}
	}
	{
		doneUprobe, err := m.LoadUprobe("do_done")
		if err != nil {
			nlog.Erro("err %v", err)
			return
		}

		err = m.AttachUprobe(fPath, "end111", doneUprobe, -1)
		if err != nil {
			nlog.Erro("err %v", err)
			return
		}
	}

	table := bpf.NewTable(m.TableId("events"), m)
	channel := make(chan []byte)
	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		nlog.Erro("err %v", err)
		return
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event endEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				nlog.Erro("err %v", err)
				continue
			}
			str := string(event.Query[:bytes.IndexByte(event.Query[:], 0)])
			nlog.Info("\npid %d ts %d delta %d query %s  %v ",
				event.Pid, event.Ts, event.Delta, str, len(str))
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
