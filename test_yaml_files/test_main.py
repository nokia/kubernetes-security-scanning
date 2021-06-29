import sys
sys.path.append('../utils')
import time
from runshell import run_shell_cmd

def main():
  commands = ["kubectl apply -f ./privileged.yaml" , 
  "kubectl apply -f ./host-path.yaml",
  "kubectl apply -f ./host-pid.yaml",
  "kubectl apply -f ./root-user.yaml"]

# ToDo: image-pull.yaml, net_raw, container_sandbox

  for i in commands:
    time.sleep(5)
    print(run_shell_cmd(i))

if __name__ == '__main__':
    main()