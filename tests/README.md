# Running tests


Run tests in root folder using:
`poetry run python3 -m unittest`

Run integration test in root folder (probably only works on POSIX OSs):
`poetry run python3 -m tests.integration -d <mcu> -c <clock in MHz>`
