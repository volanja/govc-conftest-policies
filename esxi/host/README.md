# Example : host.info

## Target: actual machines

```
$ conftest govc host.info
Testing host.info

32 tests, 32 passed, 0 warnings, 0 failures, 0 exceptions
```

## Target: local files

```
$ conftest test data/host.json

32 tests, 32 passed, 0 warnings, 0 failures, 0 exceptions
```

# Unit Test

```
$ conftest verify

50 tests, 50 passed, 0 warnings, 0 failures, 0 exceptions, 0 skipped
```

