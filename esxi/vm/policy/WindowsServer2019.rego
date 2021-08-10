package main

deny_vm_Win2019_cpu[msg] {
  vm := input.VirtualMachines[0]
  vm.Name == "WindowsServer2019"
  ret := object.get(vm.Config.Hardware,"NumCPU",false)
  ret != 2
  msg := sprintf("%s is misconfigration. CPU core should be set 2.", [vm.Name])
}
