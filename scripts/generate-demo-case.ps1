param(
    [string]$Out = "demo-output/artifacts",
    [string]$Source = "testdata/demo-case"
)

$ErrorActionPreference = "Stop"

go run ./scripts/generate_demo_case.go -source $Source -out $Out
