package main

deny_incorrect_product_name[msg] {
  not input.About.Name == "VMware ESXi"
  msg := "Product name is VMware ESXi"
}

deny_esxi_version[msg] {
  # to_number is string to numeric
  actual_version := to_number(input.About.Build)
  # 14320388 is ESXi 6.7 Update 3
  # see https://kb.vmware.com/s/article/2143832
  actual_version < 14320388
  msg := "ESXi version should be greater than 14320388"
}
