/*
	Author        : tuxpy
	Email         : q8886888@qq.com.com
	Create time   : 2017-10-24 18:40:22
	Filename      : main.go
	Description   :
*/

package hosts

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"utils"
)

const HOSTS_PATH = "/etc/hosts"

type HostItem struct {
	IP       string
	HostName string
	Comment  string
	RawLine  string
	Updated  bool
}

func (item *HostItem) HasValue() bool {
	return item.IP != "" && item.HostName != ""
}

func (item *HostItem) Update(ip string) {
	item.Updated = true
	item.IP = ip
	reg := regexp.MustCompile("\\[update time:.+?\\]\\s*$")
	new_comment := fmt.Sprintf("[update time: %s]", time.Now().Format("2006-01-02 15:04:05"))
	if reg.MatchString(item.RawLine) {
		item.Comment = reg.ReplaceAllString(item.Comment, new_comment)

	} else {
		item.Comment += " " + new_comment
	}
}

func (item *HostItem) String() string {
	if item.HasValue() {
		return fmt.Sprintf("%s %s #%s", item.IP, item.HostName, item.Comment)

	} else {
		return item.RawLine
	}
}

func ReadOne(hostname string) *HostItem {
	for _, item := range Read() {
		if item.HostName == hostname {
			return item
		}
	}
	return nil
}

func Read() []*HostItem {
	hosts_items := []*HostItem{}
	content, err := ioutil.ReadFile(HOSTS_PATH)
	utils.CheckErrorPanic(err)

	lines := strings.FieldsFunc(string(content), func(c rune) bool {
		return strings.ContainsAny(string(c), "\r\n")
	})

	var comment string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		hosts_item := &HostItem{
			RawLine: line,
		}
		hosts_items = append(hosts_items, hosts_item)
		if line == "" {
			continue
		}
		line_parts := strings.SplitN(line, "#", 2)
		item_line := line_parts[0]
		if len(line_parts) == 2 {
			comment = line_parts[1]
		} else {
			comment = ""
		}
		hosts_item.Comment = comment

		item_parts := strings.Fields(item_line)
		if len(item_parts) != 2 {
			continue
		}

		hosts_item.IP = item_parts[0]
		hosts_item.HostName = item_parts[1]
	}
	return hosts_items

}

func Write(hosts_items []*HostItem) {
	temp_file := filepath.Join(os.TempDir(), ".hosts")
	writer, err := os.Create(temp_file)
	utils.CheckErrorPanic(err)
	defer func() {
		writer.Close()
	}()

	for _, hosts_item := range hosts_items {
		_, err := writer.WriteString(hosts_item.String() + "\n")
		utils.CheckErrorPanic(err)
	}
	utils.CheckErrorPanic(os.Rename(temp_file, HOSTS_PATH))
}

func Bind(ip, hostname string) error {
	if ip != "" {
		_, err := net.ResolveIPAddr("ip4", ip)
		if err != nil {
			return err
		}
	}

	var exists bool

	hosts_items := Read()
	for _, hosts_item := range hosts_items {
		if hosts_item.HostName == hostname {
			hosts_item.Update(ip)
			exists = true
		}
	}

	if !exists {
		new_hosts_item := &HostItem{
			HostName: hostname,
		}
		new_hosts_item.Update(ip)
		hosts_items = append(hosts_items, new_hosts_item)
	}

	Write(hosts_items)
	return nil
}

func init() {
	supported_os := []string{"linux", "darwin"}
	current_os := runtime.GOOS
	if utils.FindString(supported_os, current_os) < 0 {
		panic(fmt.Errorf("not supported os: %s", strings.Join(supported_os, ", ")))
	}
}
