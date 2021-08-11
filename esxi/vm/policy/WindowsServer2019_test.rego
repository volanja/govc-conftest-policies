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

test_correct_vm_Win2019_NumCoresPerSocket {
  msg := "WindowsServer2019 is misconfigration. Socket should be set 1."
  not deny_vm_Win2019_Socket[msg] with input as {
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

test_incorrect_vm_Win2019_NumCoresPerSocket {
  msg := "WindowsServer2019 is misconfigration. Socket should be set 1."
  deny_vm_Win2019_Socket[msg] with input as {
  "VirtualMachines": [
    {
      "Name": "WindowsServer2019",
      "Config": {
        "Hardware": {
          "NumCPU": 2,
          "NumCoresPerSocket": 4,
          "MemoryMB": 2048
        }}}]}
}

test_incorrect_empty_vm_Win2019_NumCoresPerSocket {
  msg := "WindowsServer2019 is misconfigration. Socket should be set 1."
  deny_vm_Win2019_Socket[msg] with input as {
  "VirtualMachines": [
    {
      "Name": "WindowsServer2019",
      "Config": {
        "Hardware": {
          "NumCPU": 2,
          "MemoryMB": 2048
        }}}]}
}

test_correct_vm_Win2019_MemoryMB {
  msg := "WindowsServer2019 is misconfigration. Memory should be set 2048MB."
  not deny_vm_Win2019_MemoryMB[msg] with input as {
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

test_incorrect_vm_Win2019_MemoryMB {
  msg := "WindowsServer2019 is misconfigration. Memory should be set 2048MB."
  deny_vm_Win2019_MemoryMB[msg] with input as {
  "VirtualMachines": [
    {
      "Name": "WindowsServer2019",
      "Config": {
        "Hardware": {
          "NumCPU": 2,
          "NumCoresPerSocket": 1,
          "MemoryMB": 1024
        }}}]}
}

test_incorrect_empty_vm_Win2019_MemoryMB {
  msg := "WindowsServer2019 is misconfigration. Memory should be set 2048MB."
  deny_vm_Win2019_MemoryMB[msg] with input as {
  "VirtualMachines": [
    {
      "Name": "WindowsServer2019",
      "Config": {
        "Hardware": {
          "NumCPU": 2,
          "NumCoresPerSocket": 1,
        }}}]}
}
