# smoke_test lambda

Runs on the ASG **launch** lifecycle hook. While the new backend instance is in
`Pending:Wait` (not in the target group yet), it drives **SSM RunCommand** to
curl the app on `127.0.0.1` from *inside the instance*, then decides:

- **pass** → `CompleteLifecycleAction(CONTINUE)` → instance joins the target group
- **fail** → revert `docker_sha` SSM parameter to the previous version,
  optionally cancel the running instance refresh,
  `CompleteLifecycleAction(ABANDON)` → ASG terminates + replaces the instance

The handler **always** completes the lifecycle action before returning; any
unexpected error ends in `ABANDON` (fail-safe).

## Why SSM RunCommand instead of a direct HTTP call

The function does not open a network connection to the instance's private IP
itself — it sends a shell script (`curl ... 127.0.0.1:$APP_PORT...`) to the
instance via `ssm:SendCommand` and reads the result back via
`ssm:GetCommandInvocation`. That means:

- The Lambda does **not** need to run inside the VPC (no ENI, no VPC config,
  no security-group rule letting the Lambda reach the backend SG).
- The instance only needs the SSM Agent registered (already true — it uses
  the `AmazonSSMManagedInstanceCore` managed policy for its instance profile).
- The first attempts against a brand-new instance may fail with
  "instance never registered with the SSM agent" until the agent finishes its
  initial check-in — the handler retries `send_command` until that clears or
  the smoke budget runs out.

## Runtime

- `python3.12`, handler `handler.lambda_handler`
- No dependencies to package — `boto3` + stdlib only
- Does **not** need to run in the VPC

## IAM (execution role)

- `AWSLambdaBasicExecutionRole` (managed) — CloudWatch Logs
- `autoscaling:CompleteLifecycleAction`, `autoscaling:RecordLifecycleActionHeartbeat`
- `ssm:GetParameter`, `ssm:PutParameter` on the `docker_sha` parameter
- `ssm:SendCommand` on the `AWS-RunShellScript` document and the account's
  EC2 instances
- `ssm:GetCommandInvocation` (requires `resources = ["*"]`)
- `autoscaling:DescribeInstanceRefreshes`, `autoscaling:CancelInstanceRefresh`
  (only if `CANCEL_INSTANCE_REFRESH=true`)

## Environment variables

| var | default | meaning |
|---|---|---|
| `DOCKER_SHA_PARAM` | *(required for revert)* | name of the `docker_sha` SSM parameter |
| `APP_PORT` | `8080` | backend port (checked over `127.0.0.1` on the instance) |
| `HEALTH_PATH` | `/actuator/health` | Spring health endpoint |
| `REQUIRED_COMPONENTS` | `db,redis` | health components that must be `UP` |
| `EXTRA_CHECK_PATH` | `/api/auth/login` | deeper check through MVC+security+DB (`""` disables) |
| `EXTRA_CHECK_METHOD` | `POST` | |
| `EXTRA_CHECK_BODY` | bad-creds JSON | request body for the deeper check |
| `EXTRA_CHECK_MAX_STATUS` | `499` | any status ≤ this = "app is serving"; 5xx / conn error = fail |
| `POLL_INTERVAL_SECONDS` | `10` | wait between attempts (and between SSM registration retries) |
| `HTTP_TIMEOUT_SECONDS` | `5` | curl's own `--max-time` on the instance |
| `HEARTBEAT_EVERY_SECONDS` | `120` | how often to send `RecordLifecycleActionHeartbeat` |
| `FINISH_MARGIN_SECONDS` | `45` | budget reserved at the end for revert + complete |
| `MAX_SMOKE_SECONDS` | `0` | hard cap on the smoke phase; `0` = use the Lambda budget |
| `CANCEL_INSTANCE_REFRESH` | `false` | also cancel the in-progress instance refresh on failure |

## Sizing

The smoke budget is `Lambda timeout − FINISH_MARGIN_SECONDS`. Set the Lambda
`timeout` to cover worst-case cloud-init (apt + docker + fluent-bit) + app
startup + SSM agent registration — e.g. `600`. The hook's `heartbeat_timeout`
can stay small (e.g. `180`) because the handler sends heartbeats while it
waits. Each check attempt costs one SSM RunCommand round-trip (send +
dispatch + poll), which typically adds a few seconds of latency over a direct
HTTP call — accounted for by `HTTP_TIMEOUT_SECONDS` / `POLL_INTERVAL_SECONDS`.
