package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	reSuccessful = `^(\d+) +(\d+\.\d+) +(\w+)+((?:\(\)|\(.+\))) +\= (\d+) +<(.+)>`         // pid,ts,syscall,args,returnValue,duration
	reFailed     = `^(\d+) +(\d+\.\d+) +(\w+)+((?:\(\)|\(.+\))) +\= (\-.+) +<(.+)>`        // pid,ts,syscall,args,returnValue,duration
	reUnfinished = `^(\d+) +(\d+\.\d+) +(\w+)+(.+)<unfinished ...>`                        // pid,ts,syscall,args
	reDetached   = `^(\d+) +(\d+\.\d+) <... +(\w+) resumed>+((?:.|.+\))) +\= (.+) +<(.+)>` // pid,ts,syscall,args,returnValue,duration

	regexpSuccessful = regexp.MustCompile(reSuccessful)
	regexpFailed     = regexp.MustCompile(reFailed)
	regexpUnfinished = regexp.MustCompile(reUnfinished)
	regexpDetached   = regexp.MustCompile(reDetached)
)

type Event struct {
	fullTrace string
	Name      string `json:"name"`
	Cat       string `json:"cat"`
	Ph        string `json:"ph"`
	Pid       int    `json:"pid"`
	Tid       int    `json:"tid"`
	Ts        int    `json:"ts"`
	Dur       int    `json:"dur,omitempty"`
	Args      Args   `json:"args"`
}

type Args struct {
	First       string `json:"first,omitempty"`
	Second      string `json:"second,omitempty"`
	ReturnValue string `json:"returnValue,omitempty"`
	DetachedDur int    `json:"detachedDur,omitempty"`
	Name        string `json:"name,omitempty"`
}

func NewEvent(content string) *Event {
	event := Event{fullTrace: content}
	event.getType()
	event.addFields()
	return &event
}

func (e *Event) getType() {
	if m, _ := regexp.MatchString(reSuccessful, e.fullTrace); m {
		e.Cat = "successful"
	} else if m, _ := regexp.MatchString(reFailed, e.fullTrace); m {
		e.Cat = "failed"
	} else if m, _ := regexp.MatchString(reUnfinished, e.fullTrace); m {
		e.Cat = "unfinished"
	} else if m, _ := regexp.MatchString(reDetached, e.fullTrace); m {
		e.Cat = "detached"
	} else {
		e.Cat = "other"
	}
}

func (e *Event) addFields() {
	groups := e.getReGroups()
	if len(groups) != 0 {
		e.Name = groups[3]
		e.Ts = convertTS(groups[2])
		e.Pid = convertID(groups[1])
		e.Tid = convertID(groups[1])
		e.Args.First = groups[4]
		switch e.Cat {
		case "successful", "failed":
			e.Ph = "X"
			e.Dur = convertTS(groups[6])
			e.Args.First = groups[4]
			e.Args.ReturnValue = groups[5]
		case "detached":
			e.Ph = "X"
			e.Dur = convertTS(groups[6])
			e.Args.Second = groups[4]
			e.Args.ReturnValue = groups[5]
		case "unfinished":
			e.Args.First = groups[4]
			e.Ph = "B"
		}
	}
}

func (e Event) getReGroups() []string {
	switch e.Cat {
	case "successful":
		return regexpSuccessful.FindAllStringSubmatch(e.fullTrace, -1)[0]
	case "failed":
		return regexpFailed.FindAllStringSubmatch(e.fullTrace, -1)[0]
	case "unfinished":
		return regexpUnfinished.FindAllStringSubmatch(e.fullTrace, -1)[0]
	case "detached":
		return regexpDetached.FindAllStringSubmatch(e.fullTrace, -1)[0]
	}
	return []string{}
}

type TraceEvents struct {
	Event []*Event `json:"traceEvents"`
}

func (te TraceEvents) Save(output string) {
	b, err := json.MarshalIndent(te.Event, "", " ")
	if err != nil {
		log.Fatalf("[!] Error encoding events to JSON: %s\n", err)
	}
	if err = ioutil.WriteFile(output, b, 0644); err != nil {
		log.Fatalf("[!] Error creating JSON file: %s\n", err)
	}
}

func convertID(id string) int {
	i, err := strconv.Atoi(id)
	if err != nil {
		log.Fatal(err)
	}
	return i
}

func convertTS(ts string) int {
	s := strings.Split(ts, ".")
	c := s[0] + s[1]
	i, err := strconv.Atoi(c)
	if err != nil {
		log.Fatal(err)
	}
	return i
}

func GetProcessThreadsMetadata(pid int) ([]Event, error) {
	threadsDir := fmt.Sprintf("/proc/%d/task", pid)
	tids, err := ioutil.ReadDir(threadsDir)
	if err != nil {
		return nil, err
	}

	var events []Event
	for _, tidEntry := range tids {
		tidStr := tidEntry.Name()
		tid, err := strconv.Atoi(tidStr)
		if err != nil {
			continue
		}
		commPath := filepath.Join(threadsDir, tidStr, "comm")
		data, err := ioutil.ReadFile(commPath)
		if err != nil {
			continue
		}
		threadName := strings.TrimSpace(string(data))

		event := Event{
			Name: "thread_name",
			Ph:   "M",
			Pid:  pid,
			Tid:  tid,
		}
		event.Args.Name = threadName
		events = append(events, event)
	}
	return events, nil
}
