package main

deny_vm_Win2019_CPU[msg] {
  vm := input.VirtualMachines[0]
  vm.Name == "WindowsServer2019"
  ret := object.get(vm.Config.Hardware,"NumCPU",false)
  ret != 2
  msg := sprintf("%s is misconfigration. CPU core should be set 2.", [vm.Name])
}

deny_vm_Win2019_Socket[msg] {
  vm := input.VirtualMachines[0]
  vm.Name == "WindowsServer2019"
  ret := object.get(vm.Config.Hardware,"NumCoresPerSocket",false)
  ret != 1
  msg := sprintf("%s is misconfigration. Socket should be set 1.", [vm.Name])
}

deny_vm_Win2019_MemoryMB[msg] {
  vm := input.VirtualMachines[0]
  vm.Name == "WindowsServer2019"
  ret := object.get(vm.Config.Hardware,"MemoryMB",false)
  ret != 2048
  msg := sprintf("%s is misconfigration. Memory should be set 2048MB.", [vm.Name])
}
