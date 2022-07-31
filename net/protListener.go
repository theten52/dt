package main

/**
 * golang实现netstat -ntlp命令功能
 * netstat 工作原理：
 * 1. 通过读取/proc/net/tcp 、/proc/net/tcp6文件，获取socket本地地址，本地端口，远程地址，远程端口，状态，inode等信息
 * 2. 接着扫描所有/proc/[pid]/fd目录下的的socket文件描述符，建立inode到进程pid映射
 * 3. 根据pid读取/proc/[pid]/cmdline文件，获取进程命令和启动参数
 * 4. 根据2,3步骤，即可以获得1中对应socket的相关进程信息
 *
 */

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
)

// @see https://github.com/torvalds/linux/blob/master/include/net/tcp_states.h
const (
	TCP_ESTABLISHED = iota + 1
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
	//TCP_NEW_SYN_RECV
	//TCP_MAX_STATES
)

var states = map[int]string{
	TCP_ESTABLISHED: "ESTABLISHED",
	TCP_SYN_SENT:    "SYN_SENT",
	TCP_SYN_RECV:    "SYN_RECV",
	TCP_FIN_WAIT1:   "FIN_WAIT1",
	TCP_FIN_WAIT2:   "FIN_WAIT2",
	TCP_TIME_WAIT:   "TIME_WAIT",
	TCP_CLOSE:       "CLOSE",
	TCP_CLOSE_WAIT:  "CLOSE_WAIT",
	TCP_LAST_ACK:    "LAST_ACK",
	TCP_LISTEN:      "LISTEN",
	TCP_CLOSING:     "CLOSING",
	//TCP_NEW_SYN_RECV: "NEW_SYN_RECV",
	//TCP_MAX_STATES:   "MAX_STATES",
}

type socketEntry struct {
	id      int
	srcIP   net.IP
	srcPort int
	dstIP   net.IP
	dstPort int
	state   string

	txQueue       int
	rxQueue       int
	timer         int8
	timerDuration time.Duration
	rto           time.Duration // retransmission timeout
	uid           int
	uname         string
	timeout       time.Duration
	inode         string
}

const (
	tcpfile    = "/proc/net/tcp"
	passwdfile = "/etc/passwd"
)

var systemUsers map[string]string

func main() {
	f, err := os.Open(tcpfile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	bf := bufio.NewReader(f)
	lines := make([]string, 0)
	for {
		line, err := bf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		lines = append(lines, line)
	}

	sockEntrys := make([]*socketEntry, 0, len(lines))
	for i := 1; i < len(lines); i++ {
		se, err := parseRawSocketEntry(lines[i])
		if err != nil {
			log.Fatal(err)
		}
		sockEntrys = append(sockEntrys, se)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Proto", "Recv-Q", "Send-Q", "Local Address",
		"Foreign Address", "State", "PID/Program name"})
	for _, se := range sockEntrys {
		foreignAddr := fmt.Sprintf("%s:%d", se.dstIP, se.dstPort)
		if se.dstPort == 0 {
			foreignAddr = fmt.Sprintf("%s:*", se.dstIP)
		}
		v := []string{
			"tcp",
			fmt.Sprintf("%d", se.rxQueue),
			fmt.Sprintf("%d", se.txQueue),
			fmt.Sprintf("%s:%d", se.srcIP, se.srcPort),
			foreignAddr,
			se.state,
			fmt.Sprintf("%s(%d)", se.uname, se.uid),
		}
		table.Append(v)
	}
	table.SetBorder(false)
	table.SetAutoFormatHeaders(false)
	table.SetColumnSeparator("")
	table.SetHeaderLine(false)
	table.Render()
}

// @todo 遍历所有/proc/pid/fd目录，找到进程信息
func parseRawSocketEntry(entry string) (*socketEntry, error) {
	se := &socketEntry{}
	entrys := strings.Split(strings.TrimSpace(entry), " ")
	entryItems := make([]string, 0, 17)
	for _, ent := range entrys {
		if ent == "" {
			continue
		}
		entryItems = append(entryItems, ent)
	}

	id, err := strconv.Atoi(string(entryItems[0][:len(entryItems[0])-1]))
	if err != nil {
		return nil, err
	}
	se.id = id                                     // sockect entry id
	localAddr := strings.Split(entryItems[1], ":") // 本地ip
	se.srcIP = parseHexBigEndianIPStr(localAddr[0])
	port, err := strconv.ParseInt(localAddr[1], 16, 32) // 本地port
	if err != nil {
		return nil, err
	}
	se.srcPort = int(port)

	remoteAddr := strings.Split(entryItems[2], ":") // 远程ip
	se.dstIP = parseHexBigEndianIPStr(remoteAddr[0])
	port, err = strconv.ParseInt(remoteAddr[1], 16, 32) // 远程port
	if err != nil {
		return nil, err
	}
	se.dstPort = int(port)

	state, _ := strconv.ParseInt(entryItems[3], 16, 32) // socket 状态
	se.state = states[int(state)]

	tcpQueue := strings.Split(entryItems[4], ":")
	tQueue, err := strconv.ParseInt(tcpQueue[0], 16, 32) // 发送队列数据长度
	if err != nil {
		return nil, err
	}
	se.txQueue = int(tQueue)
	sQueue, err := strconv.ParseInt(tcpQueue[1], 16, 32) // 接收队列数据长度
	if err != nil {
		return nil, err
	}
	se.rxQueue = int(sQueue)

	se.uid, err = strconv.Atoi(entryItems[7]) // socket uid
	if err != nil {
		return nil, err
	}
	se.uname = systemUsers[entryItems[7]] // socket user name
	se.inode = entryItems[9]              // socket inode
	return se, nil
}

// hexIP是网络字节序/大端法转换成的16进制的字符串
func parseHexBigEndianIPStr(hexIP string) net.IP {
	b := []byte(hexIP)
	for i, j := 1, len(b)-2; i < j; i, j = i+2, j-2 { // 反转字节，转换成小端法
		b[i], b[i-1], b[j], b[j+1] = b[j+1], b[j], b[i-1], b[i]
	}
	l, _ := strconv.ParseInt(string(b), 16, 64)
	return net.IPv4(byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
}

func init() {
	initSystemUsersInfo()
}

// 读取/etc/passwd获取uid => uname 的映射
// /etc/passwd的文件结构： 用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录Shell
func initSystemUsersInfo() {
	f, err := os.Open(passwdfile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	systemUsers = make(map[string]string)
	bf := bufio.NewReader(f)
	for {
		line, err := bf.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatal(err)
		}
		items := strings.Split(line, ":")
		systemUsers[items[2]] = items[0]
	}
}
