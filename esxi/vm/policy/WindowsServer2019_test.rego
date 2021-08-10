package main

test_correct_vm_Win2019_NumCPU {
  msg := "WindowsServer2019 is misconfigration. CPU core should be set 2."
  not deny_vm_Win2019_CPU[msg] with input as {
  "VirtualMachines": [
    {
      "Name": "WindowsServer2019",
      "Config": {
        "Hardware": {
          "NumCPU": 2,
          "NumCoresPerSocket": 1,
          "MemoryMB": 2048
        }}}]}
}

test_incorrect_vm_Win2019_NumCPU {
  msg := "WindowsServer2019 is misconfigration. CPU core should be set 2."
  deny_vm_Win2019_CPU[msg] with input as {
  "VirtualMachines": [
    {
      "Name": "WindowsServer2019",
      "Config": {
        "Hardware": {
          "NumCPU": 1,
          "NumCoresPerSocket": 1,
          "MemoryMB": 2048
        }}}]}
}

test_incorrect_empty_vm_Win2019_NumCPU {
  msg := "WindowsServer2019 is misconfigration. CPU core should be set 2."
  deny_vm_Win2019_CPU[msg] with input as {
  "VirtualMachines": [
    {
      "Name": "WindowsServer2019",
      "Config": {
        "Hardware": {
          "NumCoresPerSocket": 1,
          "MemoryMB": 2048
        }}}]}
}
