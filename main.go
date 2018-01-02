/*
	Author        : tuxpy
	Email         : q8886888@qq.com.com
	Create time   : 2017-10-25 10:57:30
	Filename      : main.go
	Description   :
*/

package main

import (
	"fmt"
	"hosts"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"utils"

	"github.com/bogdanovich/dns_resolver"
	fastping "github.com/lujinda/go-fastping"
)

const (
	TIMEOUT_DELAY       = 99999.9
	DEFAULT_DNS_SERVERS = "168.126.63.1, 168.126.63.2, 168.95.1.1, 168.95.192.1, 203.80.96.10, 114.114.114.114, 8.8.8.8"
)

func Ping(ip string) float64 {
	var cost float64
	p := fastping.NewPinger()
	p.MaxRTT = 1 * time.Second
	p.Size = 64

	ra, err := net.ResolveIPAddr("ip4:icmp", ip)
	utils.CheckErrorPanic(err)
	p.AddIPAddr(ra)
	p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		cost = float64(rtt / time.Millisecond)
	}
	p.OnIdle = func() {
		Log(fmt.Sprintf("Ping %s timeout", ip))
		cost = TIMEOUT_DELAY
		time.Sleep(3 * time.Second)
	}

	if err = p.Run(); err != nil {
		cost = TIMEOUT_DELAY
		Log(fmt.Sprintf("Ping %s go wrong. %s", ip, err))
		time.Sleep(3 * time.Second)
	}

	return cost
}

type IPDelaySorter struct {
	IPS       []string
	DelayByIP map[string]float64
}

type Host struct {
	Name        string
	IPBlackList []string
}

func NewIPDelaySroter(IPS []string) *IPDelaySorter {
	return &IPDelaySorter{
		IPS:       IPS,
		DelayByIP: make(map[string]float64),
	}
}

func (sorter *IPDelaySorter) Len() int {
	return len(sorter.IPS)
}

func (sorter *IPDelaySorter) GetDelay(ip string) float64 {
	if delay, ok := sorter.DelayByIP[ip]; ok {
		return delay

	}
	ping_count := 5
	delaies := []float64{}

	var max, current, delaies_count, delay float64
	for i := 0; i < ping_count; i++ {
		current = Ping(ip)
		if max < current {
			max = current
		}
		delaies = append(delaies, current)
	}

	for _, delay = range delaies {
		delaies_count += delay
	}
	// 减去max值 再算平均值, 相当于变向地实现了"允许超时一次"
	avg_delay := (delaies_count - max) / float64(ping_count-1)
	sorter.DelayByIP[ip] = avg_delay
	Log(fmt.Sprintf("IP: %s, Delay: %.2f", ip, avg_delay))
	return delay
}

func (sorter *IPDelaySorter) Less(i, j int) bool {
	return sorter.GetDelay(sorter.IPS[i]) < sorter.GetDelay(sorter.IPS[j])
}

func (sorter *IPDelaySorter) Swap(i, j int) {
	sorter.IPS[i], sorter.IPS[j] = sorter.IPS[j], sorter.IPS[i]
}

func (sorter *IPDelaySorter) BestIP() string {
	sort.Sort(sorter)
	return sorter.IPS[0]
}

func Log(s string) {
	if os.Getenv("DEBUG") != "" {
		log.Println(s)
	}
}

func GetDNSServers() []string {
	var dns_servers = strings.Split(DEFAULT_DNS_SERVERS, ",")

	var dns_servers_from_env = strings.TrimSpace(os.Getenv("DNS"))
	if dns_servers_from_env != "" {
		dns_servers = strings.Split(dns_servers_from_env, ",")
	}

	for index, dns_server := range dns_servers {
		dns_servers[index] = strings.TrimSpace(dns_server)
	}
	return dns_servers
}

func GetHosts() []Host {
	hosts := []Host{}
	content, err := ioutil.ReadFile(os.Args[1])
	utils.CheckErrorPanic(err)

	for _, line := range strings.Split(string(content), "\n") {
		line_parts := strings.Fields(strings.TrimSpace(line))
		if len(line) == 0 {
			continue
		}
		ip_blacklist := []string{}
		host := Host{
			Name: line_parts[0],
		}
		if len(line_parts) > 1 {
			for _, desc := range line_parts[1:] {
				if desc[0] == '!' {
					ip_blacklist = append(ip_blacklist, desc[1:])
				}
			}
		}
		host.IPBlackList = ip_blacklist
		hosts = append(hosts, host)
	}
	return hosts
}

func HostName2IPS(hostname string) []string {
	var resolver *dns_resolver.DnsResolver
	var ips []string = []string{}

	for _, dns_server := range GetDNSServers() {
		resolver = dns_resolver.New([]string{dns_server})
		ips_data, _ := resolver.LookupHost(hostname)
		Log(fmt.Sprintf("server: %s, hostname: %s nslookup result: ", dns_server, hostname))
		for _, ip_data := range ips_data {
			Log(fmt.Sprintf("\t%s", ip_data))
			if utils.FindString(ips, ip_data.String()) == -1 {
				ips = append(ips, ip_data.String())
			}
		}
	}
	return ips
}

func MatchIP(ips []string, ip string) bool {
	for _, _ip := range ips {
		if _ip == ip {
			return true
		}
		if _ip[len(_ip)-1] == '.' && strings.HasPrefix(ip, _ip) { // 如果黑名单ip写得是.结尾的话, 则采取头部匹配。如1.1. 可匹配1.1.1.1
			return true
		}
	}
	return false
}

func Run() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, r)
			os.Stderr.Sync()
		}
	}()
	for _, host := range GetHosts() {
		ips := HostName2IPS(host.Name)

		if len(ips) == 0 {
			Log(fmt.Sprintf("%s no available ip", host.Name))
			continue
		}

		exists_hosts_item := hosts.ReadOne(host.Name)
		if exists_hosts_item != nil && utils.FindString(ips, exists_hosts_item.IP) == -1 {
			Log(fmt.Sprintf("hostname %s ip %s from hosts", host.Name, exists_hosts_item.IP))
			ips = append(ips, exists_hosts_item.IP)
		}

		final_ips := []string{}
		for _, ip := range ips {
			if MatchIP(host.IPBlackList, ip) {
				Log(fmt.Sprintf("hostname %s ip %s in blacklist", host.Name, ip))

			} else {
				final_ips = append(final_ips, ip)
			}
		}
		if len(final_ips) == 0 {
			Log(fmt.Sprintf("%s no available ip", host.Name))
			continue
		}
		ips = final_ips

		sorter := NewIPDelaySroter(ips)
		best_ip := sorter.BestIP()
		hosts.Bind(best_ip, host.Name)
		Log(fmt.Sprintf("%s best ip is %s", host.Name, best_ip))

		Log("")
	}
}

func main() {
	interval, _ := strconv.Atoi(os.Getenv("INTERVAL"))
	if interval > 0 {
		for {
			Run()
			time.Sleep(time.Duration(interval) * time.Second)
		}

	} else {
		Run()
	}
}
