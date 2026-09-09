"""
ASG launch lifecycle-hook smoke test.

Triggered by an EventBridge rule matching:
    source      = ["aws.autoscaling"]
    detail-type = ["EC2 Instance-launch Lifecycle Action"]

While a new backend instance sits in Pending:Wait (outside the target group,
no production traffic), this function drives SSM RunCommand to curl the app
*locally on the instance* (over 127.0.0.1) and decides whether the instance
is allowed into service.

    pass  -> CompleteLifecycleAction(CONTINUE)  -> ASG registers it in the TG
    fail  -> revert the docker_sha SSM parameter to the previous version,
             (optionally) cancel the running instance refresh,
             CompleteLifecycleAction(ABANDON)   -> ASG terminates + replaces it

The function ALWAYS completes the lifecycle action before returning. Any
unexpected error results in ABANDON (fail-safe: never let an unverified
instance take traffic).

Using SSM RunCommand instead of a direct HTTP call means the function does
NOT need to run inside the VPC or have network line-of-sight to the
instance's private IP — it only needs ssm:SendCommand / GetCommandInvocation,
and the instance only needs the SSM agent (already required for
AmazonSSMManagedInstanceCore).

Required IAM permissions (execution role, see modules/compute/smoke-test.tf)
------------------------------------------------------------------------------
Trust policy:
    sts:AssumeRole                          principal: lambda.amazonaws.com

Managed policy attachment:
    arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
        -> logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
           (writes this function's own CloudWatch log group)

Inline policy statements:
    AllowRevertSSMDocker
        ssm:GetParameter, ssm:GetParameters, ssm:PutParameter
        resource: aws_ssm_parameter.docker_sha.arn
        -> read/rewrite the docker_sha parameter (and its previous version,
           read via "<name>:<version>") when the smoke test fails

    AllowLifecycleActions
        autoscaling:CompleteLifecycleAction
        autoscaling:RecordLifecycleActionHeartbeat
        resource: "*"
        -> resolve/heartbeat/complete the ASG launch lifecycle hook

    AllowSendRunCommand
        ssm:SendCommand
        resources:
            arn:aws:ec2:<region>:<account_id>:instance/*
            arn:aws:ssm:<region>::document/AWS-RunShellScript
        -> deliver the curl script to the new instance

    AllowReadRunCommandResult
        ssm:GetCommandInvocation
        resource: "*"   (this action does not support resource-level scoping)
        -> poll the RunCommand invocation for its status/stdout

    Optional, only if CANCEL_INSTANCE_REFRESH=true:
        autoscaling:DescribeInstanceRefreshes
        autoscaling:CancelInstanceRefresh
        resource: "*"

Resource-based policy (on the function itself, not the role):
    lambda:InvokeFunction                   principal: events.amazonaws.com
        -> lets the EventBridge rule (aws_cloudwatch_event_rule.asg_hook)
           invoke this function

Not an IAM permission of the Lambda, but a hard prerequisite on the target
side: the EC2 instance's own instance profile must carry
arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore so its SSM Agent is
registered and reachable by SendCommand/GetCommandInvocation.

Runtime: python3.12, no external packages (boto3 + stdlib only).
"""

import base64
import binascii
import json
import logging
import os
import re
import time

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

asg = boto3.client("autoscaling")
ssm = boto3.client("ssm")

# ---------------------------------------------------------------------------
# Config (all overridable via Lambda environment variables)
# ---------------------------------------------------------------------------
APP_PORT = int(os.environ.get("APP_PORT", "8080"))
HEALTH_PATH = os.environ.get("HEALTH_PATH", "/actuator/health")
# Spring health components that must report "UP" (not just the top-level status).
REQUIRED_COMPONENTS = [
    c.strip() for c in os.environ.get("REQUIRED_COMPONENTS", "db,redis").split(",") if c.strip()
]

# Optional deeper check: a real request through the full MVC + security + DB path.
# Default: POST /api/auth/login with bad-but-well-formed credentials -> expect 401
# (proves controller -> service -> repository -> Postgres actually works).
EXTRA_CHECK_PATH = os.environ.get("EXTRA_CHECK_PATH", "/api/auth/login")
EXTRA_CHECK_METHOD = os.environ.get("EXTRA_CHECK_METHOD", "POST").upper()
EXTRA_CHECK_BODY = os.environ.get(
    "EXTRA_CHECK_BODY",
    json.dumps({"email": "smoke-test@invalid.local", "password": "smoke-test-invalid"}),
)
# Any HTTP response with status <= this value counts as "the app is serving".
# A 5xx or a connection error is a failure.
EXTRA_CHECK_MAX_STATUS = int(os.environ.get("EXTRA_CHECK_MAX_STATUS", "499"))

POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))
HTTP_TIMEOUT_SECONDS = int(os.environ.get("HTTP_TIMEOUT_SECONDS", "5"))
HEARTBEAT_EVERY_SECONDS = int(os.environ.get("HEARTBEAT_EVERY_SECONDS", "120"))
# Safety margin kept free at the end of the Lambda budget so we always have
# time to revert SSM + complete the lifecycle action.
FINISH_MARGIN_SECONDS = int(os.environ.get("FINISH_MARGIN_SECONDS", "45"))
# Optional hard cap on the smoke phase, independent of the Lambda timeout.
MAX_SMOKE_SECONDS = int(os.environ.get("MAX_SMOKE_SECONDS", "0"))  # 0 = use Lambda budget

# How long an individual SSM RunCommand invocation is allowed to run on the
# instance (the SSM document-level timeout, not the Lambda's own budget).
SSM_COMMAND_TIMEOUT_SECONDS = max(30, HTTP_TIMEOUT_SECONDS + 15)

DOCKER_SHA_PARAM = os.environ.get("DOCKER_SHA_PARAM", "")
CANCEL_INSTANCE_REFRESH = os.environ.get("CANCEL_INSTANCE_REFRESH", "false").lower() == "true"


# ---------------------------------------------------------------------------
# SSM RunCommand transport
# ---------------------------------------------------------------------------
_STATUS_RE = re.compile(r"SMOKE_HTTP_CODE=(\d+)")
# Body travels as base64 on its own line(s) — deliberately NOT text between
# newline-anchored markers. curl writes the response body with no trailing
# newline, so a plain "cat file; echo END_MARKER" merges the last line of the
# body with the marker (e.g. "...}SMOKE_BODY_END") and a "\n"-anchored regex
# never matches, leaving the body empty. Base64 sidesteps that entirely.
_BODY_RE = re.compile(r"SMOKE_BODY_BASE64_START\n(.*?)\nSMOKE_BODY_BASE64_END", re.DOTALL)


def _build_curl_script(method, path, body):
    """Build a shell script that curls the app on localhost and prints the
    status code + base64-encoded response body wrapped in markers we can
    parse back out of SSM's StandardOutputContent."""
    url = f"http://127.0.0.1:{APP_PORT}{path}"
    lines = ["set +e"]
    data_arg = ""
    if body is not None:
        lines.append(f"cat > /tmp/smoke_body.$$ <<'SMOKE_BODY_EOF'\n{body}\nSMOKE_BODY_EOF")
        data_arg = "--data @/tmp/smoke_body.$$ -H 'Content-Type: application/json'"
    lines.append(
        f"CODE=$(curl -s -S -o /tmp/smoke_out.$$ -w '%{{http_code}}' "
        f"-X {method} {data_arg} --max-time {HTTP_TIMEOUT_SECONDS} '{url}')"
    )
    lines.append('[ -z "$CODE" ] && CODE=000')
    lines.append('echo "SMOKE_HTTP_CODE=$CODE"')
    lines.append("echo SMOKE_BODY_BASE64_START")
    lines.append("base64 -w0 /tmp/smoke_out.$$ 2>/dev/null")
    lines.append("echo")  # force a newline after the (unterminated) base64 blob
    lines.append("echo SMOKE_BODY_BASE64_END")
    lines.append("rm -f /tmp/smoke_out.$$ /tmp/smoke_body.$$ 2>/dev/null")
    return "\n".join(lines)


def send_and_wait(instance_id, script, deadline):
    """Deliver `script` to `instance_id` via SSM RunCommand and block until it
    finishes. Retries send_command while the instance hasn't registered with
    the SSM agent yet (InvalidInstanceId is expected for the first ~30-60s of
    a fresh instance's life)."""
    while True:
        try:
            resp = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": [script]},
                TimeoutSeconds=SSM_COMMAND_TIMEOUT_SECONDS,
            )
            command_id = resp["Command"]["CommandId"]
            break
        except ssm.exceptions.InvalidInstanceId:
            if time.time() >= deadline:
                raise RuntimeError("instance never registered with the SSM agent")
            time.sleep(min(POLL_INTERVAL_SECONDS, max(1, deadline - time.time())))

    # Give the agent a moment to pick the command up before the first poll.
    time.sleep(2)
    while True:
        try:
            inv = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        except ssm.exceptions.InvocationDoesNotExist:
            if time.time() >= deadline:
                raise RuntimeError("ssm command invocation never appeared")
            time.sleep(2)
            continue

        status = inv["Status"]
        if status not in ("Pending", "InProgress", "Delayed"):
            return {
                "status": status,
                "stdout": inv.get("StandardOutputContent", ""),
                "stderr": inv.get("StandardErrorContent", ""),
            }

        if time.time() >= deadline:
            raise RuntimeError(f"ssm command timed out waiting for completion (status={status})")
        time.sleep(2)


def curl_via_ssm(instance_id, method, path, body, deadline):
    """Run curl against the app's localhost endpoint on `instance_id` via SSM
    RunCommand. Returns (status_code, body_text). Raises RuntimeError if the
    command could not be delivered/executed at all."""
    script = _build_curl_script(method, path, body)
    invocation = send_and_wait(instance_id, script, deadline)

    if invocation["status"] != "Success":
        detail = invocation["stderr"].strip() or invocation["stdout"].strip()
        raise RuntimeError(f"ssm command {invocation['status']}: {detail[:300]}")

    stdout = invocation["stdout"]
    status_match = _STATUS_RE.search(stdout)
    if not status_match:
        raise RuntimeError(f"could not parse curl status from ssm output: {stdout[:300]}")

    status = int(status_match.group(1))
    if status == 0:
        raise RuntimeError("curl on instance failed to connect (000)")

    body_match = _BODY_RE.search(stdout)
    if body_match:
        b64 = body_match.group(1).replace("\n", "").strip()
        try:
            text = base64.b64decode(b64).decode("utf-8", "replace") if b64 else ""
        except (binascii.Error, ValueError):
            text = ""
    else:
        text = ""
    return status, text


# ---------------------------------------------------------------------------
# App-level checks
# ---------------------------------------------------------------------------
def check_health(instance_id, deadline):
    try:
        status, text = curl_via_ssm(instance_id, "GET", HEALTH_PATH, None, deadline)
    except RuntimeError as e:
        return False, f"health: {e}"

    if status != 200:
        return False, f"health: HTTP {status} ({text[:200]})"

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False, f"health: non-JSON body ({text[:200]})"

    if payload.get("status") != "UP":
        return False, f"health: status={payload.get('status')} ({text[:300]})"

    components = payload.get("components", {})
    for name in REQUIRED_COMPONENTS:
        comp_status = components.get(name, {}).get("status")
        if comp_status != "UP":
            return False, f"health: component '{name}' status={comp_status}"

    return True, "health: UP"


def check_extra(instance_id, deadline):
    if not EXTRA_CHECK_PATH:
        return True, "extra: skipped"

    body = EXTRA_CHECK_BODY if EXTRA_CHECK_METHOD in ("POST", "PUT", "PATCH") else None
    try:
        status, text = curl_via_ssm(instance_id, EXTRA_CHECK_METHOD, EXTRA_CHECK_PATH, body, deadline)
    except RuntimeError as e:
        return False, f"extra: {e}"

    if status > EXTRA_CHECK_MAX_STATUS:
        return False, f"extra: HTTP {status} ({text[:200]})"

    return True, f"extra: HTTP {status} (ok)"


# ---------------------------------------------------------------------------
# AWS helpers
# ---------------------------------------------------------------------------
def send_heartbeat(asg_name, hook_name, instance_id):
    try:
        asg.record_lifecycle_action_heartbeat(
            AutoScalingGroupName=asg_name,
            LifecycleHookName=hook_name,
            InstanceId=instance_id,
        )
        log.info("heartbeat sent")
    except Exception as e:  # never let a heartbeat failure abort the smoke test
        log.warning("heartbeat failed: %s", e)


def complete_lifecycle(asg_name, hook_name, token, instance_id, result):
    log.info("CompleteLifecycleAction: %s for %s", result, instance_id)
    kwargs = dict(
        AutoScalingGroupName=asg_name,
        LifecycleHookName=hook_name,
        LifecycleActionResult=result,
        InstanceId=instance_id,
    )
    if token:
        kwargs["LifecycleActionToken"] = token
    asg.complete_lifecycle_action(**kwargs)


def revert_docker_sha():
    """Roll the docker_sha SSM parameter back to its previous version's value.

    Idempotent: if the parameter already holds the previous value (e.g. another
    concurrent invocation reverted it), this does nothing.
    """
    if not DOCKER_SHA_PARAM:
        log.warning("DOCKER_SHA_PARAM not set — skipping SSM revert")
        return

    current = ssm.get_parameter(Name=DOCKER_SHA_PARAM)["Parameter"]
    version = current["Version"]
    current_value = current["Value"]

    if version <= 1:
        log.warning("docker_sha is at version %s — nothing to revert to", version)
        return

    previous = ssm.get_parameter(Name=f"{DOCKER_SHA_PARAM}:{version - 1}")["Parameter"]
    previous_value = previous["Value"]

    if previous_value == current_value:
        log.info("docker_sha already equals previous value (%s) — no revert needed", current_value)
        return

    ssm.put_parameter(
        Name=DOCKER_SHA_PARAM,
        Value=previous_value,
        Type="String",
        Overwrite=True,
    )
    log.info("reverted docker_sha: %s -> %s", current_value, previous_value)


def cancel_instance_refresh(asg_name):
    if not CANCEL_INSTANCE_REFRESH:
        return
    try:
        in_progress = asg.describe_instance_refreshes(AutoScalingGroupName=asg_name)[
            "InstanceRefreshes"
        ]
        if any(r["Status"] in ("Pending", "InProgress", "Cancelling") for r in in_progress):
            asg.cancel_instance_refresh(AutoScalingGroupName=asg_name)
            log.info("requested cancellation of the in-progress instance refresh")
    except Exception as e:
        log.warning("could not cancel instance refresh: %s", e)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def lambda_handler(event, context):
    log.info("event: %s", json.dumps(event))
    detail = event["detail"]

    asg_name = detail["AutoScalingGroupName"]
    hook_name = detail["LifecycleHookName"]
    instance_id = detail["EC2InstanceId"]
    token = detail.get("LifecycleActionToken")
    transition = detail.get("LifecycleTransition", "")

    # Defensive: this function only handles the launch transition.
    if transition != "autoscaling:EC2_INSTANCE_LAUNCHING":
        log.info("ignoring transition %s -> CONTINUE", transition)
        complete_lifecycle(asg_name, hook_name, token, instance_id, "CONTINUE")
        return {"result": "CONTINUE", "reason": f"unhandled transition {transition}"}

    # Hard deadline: leave FINISH_MARGIN_SECONDS for revert + complete.
    budget = context.get_remaining_time_in_millis() / 1000.0 - FINISH_MARGIN_SECONDS
    if MAX_SMOKE_SECONDS > 0:
        budget = min(budget, MAX_SMOKE_SECONDS)
    deadline = time.time() + budget
    log.info("smoke budget: %.0fs (via SSM RunCommand on %s)", budget, instance_id)

    try:
        last_heartbeat = time.time()
        last_reason = "no attempts made"
        attempt = 0

        while time.time() < deadline:
            attempt += 1

            if time.time() - last_heartbeat >= HEARTBEAT_EVERY_SECONDS:
                send_heartbeat(asg_name, hook_name, instance_id)
                last_heartbeat = time.time()

            ok, reason = check_health(instance_id, deadline)
            if ok:
                ok, reason = check_extra(instance_id, deadline)
            last_reason = reason

            if ok:
                log.info("smoke PASSED on attempt %s: %s", attempt, reason)
                complete_lifecycle(asg_name, hook_name, token, instance_id, "CONTINUE")
                return {"result": "CONTINUE", "instance": instance_id, "attempts": attempt}

            log.info("attempt %s not ready: %s", attempt, reason)
            time.sleep(POLL_INTERVAL_SECONDS)

        # Budget exhausted without a passing check -> roll back and reject.
        log.error("smoke FAILED for %s: %s", instance_id, last_reason)
        revert_docker_sha()
        cancel_instance_refresh(asg_name)
        complete_lifecycle(asg_name, hook_name, token, instance_id, "ABANDON")
        return {"result": "ABANDON", "instance": instance_id, "reason": last_reason}

    except Exception as e:
        # Fail-safe: anything unexpected -> do not let the instance into service.
        log.exception("unexpected error, abandoning instance %s", instance_id)
        try:
            revert_docker_sha()
            cancel_instance_refresh(asg_name)
        finally:
            complete_lifecycle(asg_name, hook_name, token, instance_id, "ABANDON")
        return {"result": "ABANDON", "instance": instance_id, "reason": f"exception: {e}"}
