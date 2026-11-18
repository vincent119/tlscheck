package app

import (
	"os"
	"os/exec"
	"testing"
)

func TestSettingsDisconnectProcessHelper(t *testing.T) {
	if os.Getenv("TLSCHECK_DISCONNECT_TEST_HELPER") != "1" {
		return
	}
	os.Exit(New().Run(t.Context(), []string{"--settings"}, os.Stdout, os.Stderr))
}
func TestSettingsTerminalDisconnectExits(t *testing.T) {
	script := `import os,pty,select,subprocess,sys,time
master,slave=pty.openpty()
p=subprocess.Popen([sys.argv[1],"-test.run=^TestSettingsDisconnectProcessHelper$"],stdin=slave,stderr=slave,stdout=subprocess.PIPE)
os.close(slave)
try:
 data=b"";deadline=time.monotonic()+5
 while b"tlscheck" not in data and time.monotonic()<deadline:
  ready,_,_=select.select([master],[],[],.1)
  if ready:data+=os.read(master,4096)
 assert b"tlscheck" in data,"menu missing"
 os.close(master);master=-1
 out,_=p.communicate(timeout=2)
 assert p.returncode==2 and out==b"",(p.returncode,out)
finally:
 if master>=0:os.close(master)
 if p.poll() is None:p.kill();p.wait()
`
	cmd := exec.CommandContext(t.Context(), "python3", "-c", script, os.Args[0])
	cmd.Env = append(os.Environ(), "TLSCHECK_DISCONNECT_TEST_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
}
