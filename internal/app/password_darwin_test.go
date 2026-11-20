package app

import (
	"os"
	"os/exec"
	"testing"

	"github.com/vincent119/tlscheck/internal/i18n"
)

func TestPasswordPromptProcessHelper(t *testing.T) {
	if os.Getenv("TLSCHECK_PASSWORD_PTY_HELPER") != "1" {
		return
	}
	password, err := askPassword(t.Context(), os.Stderr, i18n.New("en"), 0)
	clear(password)
	if err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
func TestPasswordTerminalHidesInputAndRestoresMode(t *testing.T) {
	script := `import os,pty,select,subprocess,sys,time,termios
for value,expected in [(b'S12_NO_ECHO_CANARY\r',0),(b'\x03',2),(b'\x04',2)]:
 master,slave=pty.openpty();before=termios.tcgetattr(slave)
 p=subprocess.Popen([sys.argv[1],'-test.run=^TestPasswordPromptProcessHelper$'],stdin=slave,stderr=slave,stdout=subprocess.PIPE)
 try:
  data=b'';deadline=time.monotonic()+5
  while b'(hidden): ' not in data and time.monotonic()<deadline:
   ready,_,_=select.select([master],[],[],.1)
   if ready:data+=os.read(master,4096)
  assert b'(hidden): ' in data,'password prompt missing'
  os.write(master,value);out,_=p.communicate(timeout=3)
  while select.select([master],[],[],0)[0]:data+=os.read(master,4096)
  assert p.returncode==expected and out==b'','incorrect exit or stdout'
  assert b'S12_NO_ECHO_CANARY' not in data,'password echoed'
  after=termios.tcgetattr(slave)
  # PENDIN 是核心的待重送輸入狀態，不是呼叫端設定；其餘模式位元及控制字元必須完全復原。
  before[3]&=~termios.PENDIN;after[3]&=~termios.PENDIN
  assert after==before,('terminal mode not restored',[(i,before[i],after[i]) for i in range(len(before)) if before[i]!=after[i]])
 finally:
  if p.poll() is None:p.kill();p.wait()
  os.close(master);os.close(slave)
`
	cmd := exec.CommandContext(t.Context(), "python3", "-c", script, os.Args[0])
	cmd.Env = append(os.Environ(), "TLSCHECK_PASSWORD_PTY_HELPER=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("密碼終端回歸失敗", err, string(out))
	}
}
