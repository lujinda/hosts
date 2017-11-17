/*
	Author        : tuxpy
	Email         : q8886888@qq.com.com
	Create time   : 2017-10-24 19:02:58
	Filename      : hosts_test.go
	Description   :
*/

package hosts

import (
	"fmt"
	"testing"
)

func TestWrite(t *testing.T) {
	Bind("1.1.1.1", "www.aa.com")
}

func TestRead(t *testing.T) {
	fmt.Printf("%#v\n", Read())
}

func TestReadOne(t *testing.T) {
	fmt.Printf("%#v\n", ReadOne("www.amazon.com"))
}
