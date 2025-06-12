package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strconv"
)

var (
	flagSyscalls = flag.String("e", "", "only trace specified syscalls")
	flagOutput   = flag.String("o", "/data/stracefile.json", "json output file")
	flagTimeout  = flag.Int64("t", 10, "strace timeout (secs)")
)

var (
	// -f trace child processes
	// -T time spent in each syscall
	// -ttt timestamp of each event (microseconds)
	// -qq don't display process exit status
	defaultStraceArgs = []string{"-f", "-T", "-ttt", "-yy", "-qq"}
)

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] command\n", path.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Parse()

	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// run strace
	userStraceArgs := []string{}
	if *flagSyscalls != "" {
		userStraceArgs = append(userStraceArgs, "-e", *flagSyscalls)
	}

	// support attach pid
	args := flag.Args()
	pid := 0
	if len(args) == 1 {
		pid_, err := strconv.Atoi(args[0])
		if err == nil {
			userStraceArgs = append(userStraceArgs, "-p", args[0])
			args = args[1:]
			pid = pid_
		}
	}
	userStraceArgs = append(userStraceArgs, args...)

	tmp, err := os.CreateTemp("", "stracefile")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	defaultStraceArgs = append(defaultStraceArgs, "-o", tmp.Name())

	strace := Strace{
		DefaultArgs: defaultStraceArgs,
		UserArgs:    userStraceArgs,
		Timeout:     *flagTimeout,
	}
	strace.Run()

	var events []*Event
	//add meta events
	metaEvents, err := GetProcessThreadsMetadata(pid)
	if err == nil {
		for i := range metaEvents {
			events = append(events, &metaEvents[i])
		}
	}

	// parse results
	preserved := make(map[string]*Event) // [pid+syscall]*Event
	scanner := bufio.NewScanner(tmp)

	for scanner.Scan() {
		e := NewEvent(scanner.Text())
		// fix pid when attach
		if pid != 0 {
			e.Pid = pid
		}

		switch {
		case e.Cat == "unfinished":
			k := strconv.Itoa(e.Tid) + e.Name
			preserved[k] = e
			break
		case e.Cat == "detached":
			k := strconv.Itoa(e.Tid) + e.Name
			p := preserved[k]
			e.Args.First = p.Args.First
			events = append(events, e)
			delete(preserved, k)
			break
		case e.Cat == "other":
			break
		default:
			events = append(events, e)
		}
	}
	// add any unfinished/preserved traces to events
	for _, p := range preserved {
		p.Ph = "i" // instant event
		events = append(events, p)
	}

	// save results
	te := TraceEvents{events}
	te.Save(*flagOutput)

	fmt.Printf("[+] Trace file saved to: %s\n", *flagOutput)
	fmt.Printf("[+] Analyze results: %s\n", "https://ui.perfetto.dev/")

}
