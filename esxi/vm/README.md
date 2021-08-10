# Example : vm.info WindowsServer2019

## Target: actual machines

```
$ conftest govc vm.info WindowsServer2019
Testing vm.info WindowsServer2019

1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions
```

## Target: local files

```
$ conftest test data/WindowsServer2019.json

1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions
```

# Unit Test

```
$ conftest verify

3 tests, 3 passed, 0 warnings, 0 failures, 0 exceptions, 0 skipped
```

