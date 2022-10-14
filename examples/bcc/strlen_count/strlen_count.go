// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>

struct key_t {
	char c[80];
};

BPF_HASH(counts, struct key_t);
BPF_PERF_ARRAY(clk, MAX_CPUS);

int count(struct pt_regs *ctx, int i, long j,int *k) {
	bpf_trace_printk("111111  i %d j %ld  k %d\n",i,j,*k);
	if (!PT_REGS_PARM1(ctx))
		return 0;
	char sz1[64];
	int ret = 0;
	ret = bpf_probe_read(&sz1,sizeof(sz1),(void*)PT_REGS_PARM2(ctx));
	bpf_trace_printk ("sz %ld  %s  max \n", PT_REGS_PARM2(ctx),sz1);
	return 0;
}
`

var ansiEscape = regexp.MustCompile(`[[:cntrl:]]`)

func main() {
	pid := flag.Int("pid", -1, "attach to pid, default is all processes")
	flag.Parse()
	m := bpf.NewModule(source, []string{"-DMAX_CPUS=10"})
	defer m.Close()

	strlenUprobe, err := m.LoadUprobe("count")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load uprobe count: %s\n", err)
		os.Exit(1)
	}

	err = m.AttachUprobe("/home/hxd/work/c++/test/a.out", "f111", strlenUprobe, *pid)
	// m.AttachUretprobe()

	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach uprobe to strlen: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("counts"), m)

	fmt.Println("Tracing strlen()... hit Ctrl-C to end.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	fmt.Printf("%10s %s\n", "COUNT", "STRING")
	for it := table.Iter(); it.Next(); {
		k := ansiEscape.ReplaceAll(it.Key(), []byte{})
		v := binary.LittleEndian.Uint64(it.Leaf())
		fmt.Printf("%10d \"%s\"\n", v, k)
	}
}
