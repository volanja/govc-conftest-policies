package main

test_correct_product_name {
  msg := "Product name is VMware ESXi"
  not deny_incorrect_product_name[msg] with input as {"About": { "Name": "VMware ESXi", "Build": "14320388"}}
}

test_incorrect_product_name {
  msg := "Product name is VMware ESXi"
  deny_incorrect_product_name[msg] with input as {"About": { "Name": "VMware ESX", "Build": "14320388"}}
}

test_product_name_is_not_set {
  msg := "Product name is VMware ESXi"
  deny_incorrect_product_name[msg] with input as {"About": { "Build": "14320388"}}
}

test_correct_esxi_version_same_version {
  msg := "ESXi version should be greater than 14320388"
  not deny_esxi_version[msg] with input as {
  "About": {
    "Name": "VMware ESXi",
    "FullName": "VMware ESXi 6.7.0 build-14320388",
    "Vendor": "VMware, Inc.",
    "Version": "6.7.0",
    "Build": "14320388",
  }}
}

# 15018017 is ESXi 6.7 EP 13
test_correct_esxi_version_greater_version {
  msg := "ESXi version should be greater than 14320388"
  not deny_esxi_version[msg] with input as {
  "About": {
    "Name": "VMware ESXi",
    "FullName": "VMware ESXi 6.7.0 build-15018017",
    "Vendor": "VMware, Inc.",
    "Version": "6.7.0",
    "Build": "15018017",
  }}
}

test_incorrect_esxi_version {
  msg := "ESXi version should be greater than 14320388"
  deny_esxi_version[msg] with input as {
  "About": {
    "Name": "VMware ESXi",
    "FullName": "VMware ESXi 6.7.0 build-13981272",
    "Vendor": "VMware, Inc.",
    "Version": "6.7.0",
    "Build": "13981272",
  }}
}
