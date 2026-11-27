# Single host workload scheduler specification

Status: proposed design. These interfaces and behaviors are not implemented unless listed under current functions.

The scheduler controls when jobs run, which jobs can run together, and what happens after failure.
It uses agentd to execute local programs.
It stores scheduling decisions and history on persistent local storage.

The first release supports one Linux host and one trusted service account.
It does not provide distributed execution or automatic failover.

## 1. Terms and requirement words

In this specification, **must** identifies a required behavior.
**Should** identifies a preferred behavior with a documented exception.

| Term | Meaning |
|---|---|
| Job | A versioned definition of a program and its execution policy. |
| Flow | A versioned graph of job nodes and dependencies. |
| Run | One requested execution of a flow or a standalone job. |
| Node run | One job occurrence within a run. |
| Attempt | One execution attempt for a node run. |
| Execution ID | A unique identifier supplied to agentd for an attempt. |
| Occurrence | One time at which a schedule requests a run. |
| Business date | The date of the work, which can differ from the execution date. |
| Calendar | Versioned rules that select permitted business dates. |
| Unknown outcome | Work might have executed, but its result cannot be established. |
| Resource pool | A configured number of slots for a shared resource. |
| Exclusion lock | A named lock that prevents conflicting work from running together. |

Definitions, occurrences, runs and attempts are separate records.
A retry creates another attempt. It does not create another scheduled occurrence.

## 2. Scope

### Required functions

- Manual, scheduled and local event-triggered runs.
- Job dependencies, including failure and cleanup branches.
- Business calendars and time-zone rules.
- Priorities, concurrency limits and named resources.
- Configured resource limits for job processes.
- Time limits, cancellation and retry policies.
- Durable dispatch, completion records and recovery.
- Operator hold, release, retry and repair operations.
- Searchable history, logs and notifications.
- A CLI first, followed by a local operator interface.

### Excluded from the first release

- Workers on other hosts.
- Multiple scheduler leaders or automatic host failover.
- Host placement, cluster resource allocation or network discovery.
- Isolation of hostile programs under the same user ID.
- Running jobs as arbitrary UNIX users through a privileged daemon.
- Automatic rollback of application side effects.
- A claim of exactly-once application execution.
- Broker leases, capability delegation or a replacement for the existing transport.
- A graphical workflow editor before execution and recovery are reliable.

One host can still access databases, APIs and files on other systems.
Those systems do not become scheduler workers.

## 3. Architecture and ownership

The proposed program names are `schedulerd` and `schedctl`.
They are separate from `agentd` and `agentctl`.

```text
schedctl / local operator interface
                  |
             schedulerd ---- scheduler.db
                  |
          versioned Unix socket API
                  |
               agentd ----- executions.db
                  |
          local job processes and cgroups
```

| Component | Owns |
|---|---|
| schedulerd | Definitions, calendars, occurrences, runs, dependencies, retries and scheduling reservations. |
| agentd | Execution acceptance, process identity, applied restrictions, cancellation and durable process results. |
| Job program | Application work, application validation and external side effects. |
| schedctl | Operator requests and output formatting. It does not edit either database directly. |

Each service has one database writer.
Neither service writes the other service's database.
They exchange versioned requests and durable event identifiers.

Use SQLite for both ledgers, in separate files.
This adds a SQLite dependency to the new agentd batch functions.
It does not move scheduling rules into agentd.

Production batch mode requires Linux pidfds, a writable delegated cgroup v2 hierarchy and Landlock ABI 3 or later.
Each execution needs an owned cgroup even when no numeric resource limits are configured.
Refuse batch startup if these controls are unavailable.
Existing named-agent fallback behavior remains unchanged.

Use WAL mode, foreign keys and `synchronous=FULL`.
Keep the databases on a local filesystem with working file locks and synchronization operations.
Do not place them on NFS or another network filesystem.

The scheduler implementation language is not part of the protocol contract.
Keep the process launcher and restriction code in the existing C implementation.
Phase 0 must select the scheduler language and SQLite bindings before implementation starts.

## 4. Persistent state and access

Add a persistent state root distinct from `AGENTCTL_ROOT`.
The existing runtime root can be temporary and must not contain the only copy of job history.

Proposed lookup order for `AGENTCTL_STATE_ROOT`:

1. The explicit environment value.
2. `$XDG_STATE_HOME/agentctl`.
3. `$HOME/.local/state/agentctl`.

```text
<state-root>/
  scheduler/
    scheduler.db
    definitions/
    exports/
  supervisor/
    executions.db
  runs/
    <run-id>/
      <node-id>/
        <attempt-id>/
          stdout.log
          stderr.log
          artifacts/
```

The services must validate the state root's owner and permissions.
Create private directories with mode `0700` and private files with mode `0600`.
Refuse unexpected symlinks at database and control paths.

Each service must hold an exclusive lock under its persistent state directory.
Changing the runtime socket directory must not permit a second writer for the same ledger.

Job processes must not receive writable access to either ledger.
Expose only their permitted working and artifact directories.
Keep supervisor records outside child-writable `runtime/` paths.

The supported trust model remains one trusted service account.
File permissions and tokens do not isolate hostile code under that same user ID.

## 5. Definition model

### Job definition

A job version must contain:

| Field | Requirement |
|---|---|
| Name and version | Stable job name and immutable version identifier. |
| Program | Absolute executable path. |
| Arguments | An ordered array. Do not construct a shell command string. |
| Working directory | An absolute, validated path or an attempt-local directory. |
| Parameters | Typed inputs, required values, defaults and bounds. |
| Environment | An explicit allowlist of literal values and approved secret references. |
| Resource profile | Filesystem rules, seccomp choice and configured CPU, memory and PID limits. |
| Success codes | Explicit exit codes. Default: only zero. |
| Time limit | Positive duration. Initial default: 3600 seconds. |
| Startup limit | Maximum time to complete process setup and exec. Initial default: 30 seconds. |
| Stop grace | Positive duration before forced termination. Initial default: 10 seconds. |
| Retry policy | Maximum attempts, eligible outcomes, delay and maximum elapsed retry time. |
| Repeat safety | `manual`, `safe_to_repeat` or `idempotency_key`. Default: `manual`. |
| Concurrency | Maximum active node runs for this job. Default: one. |
| Resource requests | Pool slots and exclusion locks required before dispatch. |
| Output contract | Expected artifacts and optional bounded result metadata. |

Jobs must not inherit the scheduler's complete environment.
In particular, credentials used by the scheduler must not reach jobs by default.

Shell execution requires an explicit executable such as `/bin/sh` and explicit arguments.
The scheduler must not interpolate parameters into shell text.
Do not execute expressions supplied in definitions.

An exit code can establish the job's reported result.
It does not independently prove that a payment, upload or database change occurred exactly once.

### Flow definition

A flow version contains named nodes, job-version references and directed dependency edges.
Reject cycles and missing references before activation.

Each node defines its input mapping and required predecessor outcomes.
Mappings can refer to parameters and recorded predecessor outputs.
Do not provide arbitrary code evaluation in the mapping language.

Default dependencies require success from every predecessor.
Additional conditions are `failed`, `finished` and explicitly allowed `skipped`.

`finished` accepts success, failure, cancellation or time-limit expiry.
It does not accept an unknown outcome or an active attempt.

Declare failure handlers and cleanup nodes explicitly.
A successful cleanup node must not change a failed primary flow into a successful flow.

A flow can also declare exclusion keys for the complete run.
For example, use the account ID and business date to exclude another close for the same account and date.
Keys must use declared run parameters, not program output or arbitrary expressions.

If a dependency cannot be satisfied, mark the dependent node `BLOCKED` with a reason.
Do not leave it waiting without an explanation.

### Definition versions

Publishing creates an immutable version with a content digest.
Existing runs retain their original job, flow, calendar and schedule versions.
Editing a definition affects future runs only.

Pin the resolved resource profile and its digest with the job version.
Retain approved profile versions needed by existing runs.
agentd must reject a launch if the approved profile does not match the requested digest.
Batch grants must not give the job write access to scheduler or supervisor control state.

Deleting an active definition disables new use.
Retain versions referenced by history.

### Definition format and example

Use strict UTF-8 JSON with `api_version` and `kind` fields.
Reject duplicate keys, unknown fields, invalid types and out-of-range values.
Publication assigns the immutable version identifier.
Job and flow names share one namespace; reject a name collision.

Arguments can contain literal strings or typed parameter references.
The publisher validates every reference against the declared parameter schema.
A date parameter uses `YYYY-MM-DD` and must identify a real calendar date.
Do not perform shell substitution on any value.

The following is a proposed job definition, not an existing executable example:

```json
{
  "api_version": "scheduler/v1",
  "kind": "job",
  "name": "daily-import",
  "program": "/usr/local/bin/import-transactions",
  "arguments": ["--business-date", {"parameter": "business_date"}],
  "parameters": {
    "business_date": {"type": "date", "required": true}
  },
  "working_directory": {"attempt_local": true},
  "environment": {"TZ": "UTC"},
  "resource_profile": "batch-standard@1",
  "success_codes": [0],
  "timeout_seconds": 3600,
  "stop_grace_seconds": 10,
  "retry": {"maximum_attempts": 1},
  "repeat_safety": "manual",
  "concurrency": 1
}
```

Publish and run a standalone job through an implicit one-node flow.
That flow uses the same execution, history and recovery rules as an explicit flow.

## 6. Run and attempt records

Use opaque UUIDs for run, node-run, attempt and execution identifiers.
Do not derive identity from a PID, program name or timestamp alone.
Never reuse an execution ID for different arguments or policies.

A run must record its trigger, request ID, business date, parameters and definition versions.
An attempt must record its execution ID, launch digest, state, timing and complete supervisor result.

### Node-run states

| State | Meaning |
|---|---|
| `WAITING` | Dependencies or a permitted start time are not yet satisfied. |
| `READY` | Dependencies are satisfied, but dispatch has not been reserved. |
| `DISPATCHING` | The database contains a durable attempt and resource reservation. |
| `RUNNING` | The supervisor reports that the program was executed. |
| `RETRY_WAIT` | A permitted retry is waiting for its next time. |
| `STOPPING` | Cancellation or a time limit requires process termination. |
| `SUCCEEDED` | A completed attempt met the success contract. |
| `FAILED` | A known failure has no permitted automatic retry. |
| `CANCELLED` | Cancellation completed and the execution subtree is empty. |
| `TIMED_OUT` | Time-limit termination completed and the subtree is empty. |
| `SKIPPED` | A definition rule or recorded operator action skipped the node. |
| `BLOCKED` | The node cannot proceed under its dependency rules. |
| `UNKNOWN` | Execution or its outcome cannot be established. |

A hold is a separate flag, not another execution state.
Holding a running node does not stop it.

An attempt has separate supervisor states:

```text
PREPARED -> START_AUTHORIZED -> RUNNING -> EXIT_RECORDED -> FINAL
     |               |             |
START_FAILED       UNKNOWN        STOPPING
```

The supervisor result includes:

- Execution ID, launch digest and supervisor event sequence.
- Host boot ID and supervisor instance ID.
- Process start time and observed exit time.
- Exit code or terminating signal.
- Start error and failing setup stage, when applicable.
- Cancellation or timeout cause, when applicable.
- Applied restriction results and cgroup identity.
- Confirmation that the execution subtree is empty.

Record intent separately from observed results.
For example, preserve an observed exit code even if accepted cancellation determines the final scheduling outcome.

## 7. Durable dispatch

The scheduler must not send an execution request before committing its dispatch record.

The dispatch sequence is:

1. Select a ready node within a database transaction.
2. Confirm its revision, hold flags and dependency results.
3. Reserve concurrency, pool slots and exclusion locks.
4. Create the attempt and execution ID.
5. Store a launch request in the dispatch outbox.
6. Commit the transaction.
7. Send the request to agentd.
8. Record the supervisor's durable response or reconcile an uncertain response.

The outbox is a database record awaiting delivery.
It is not an in-memory message queue.

On retry of the same launch request, agentd must return the same execution record.
The same execution ID with a different launch digest must return a conflict.
A lost reply must never cause creation of a new execution ID automatically.

### Supervisor launch sequence

For batch execution, agentd must:

1. Validate the request, paths, environment, policy and configured limits.
2. Commit a `PREPARED` record before acknowledging acceptance.
3. Create an execution-specific cgroup under its delegated parent.
4. Fork a child that waits behind a supervisor-controlled startup gate.
5. Acquire the process handle and attach the child to the cgroup.
6. Verify attachment and all required restrictions.
7. Commit `START_AUTHORIZED` before releasing the child.
8. Release the gate and execute the program through an argument-array interface.
9. Use the existing exec error pipe to distinguish setup or exec failure from successful exec.
10. Persist execution events and the final result.

If attachment or a required restriction fails, the child must not execute the job program.
If the parent dies before gate release, the child must exit without executing that program.

A crash after `START_AUTHORIZED` can leave an unknown outcome.
That record must not be replayed as a new launch.

Acceptance means the request is durable.
It does not mean that the program has started or completed.

## 8. Completion and result delivery

agentd must record a completed execution before publishing its terminal event.
The scheduler must consume supervisor events by durable sequence number.

In one scheduler transaction:

1. Deduplicate the event.
2. Store the attempt result.
3. Update the node and run state.
4. Release permitted reservations.
5. Evaluate dependent nodes.
6. Queue notifications.
7. Advance the consumed event sequence.

Repeating an event must not repeat dependency release or create another attempt.
The scheduler must also support a complete execution-state query when event history is insufficient.

Leader exit alone is not complete subtree termination.
The batch default must terminate remaining descendants and wait for an empty cgroup before finalization.
Batch jobs that intentionally leave background daemons are not supported.

Missing artifacts can fail a declared output contract.
Artifacts must not override a failed process result unless the job explicitly defines a separate verified completion protocol.
The first release uses exit codes and declared artifact checks only.

If a short job exits before a start event is consumed, the scheduler can move directly to its completed state.
It must still retain the attempt's authorization and result records.

### Run states

Run states are `QUEUED`, `RUNNING`, `STOPPING`, `SUCCEEDED`, `FAILED`, `CANCELLED` and `UNKNOWN`.
`QUEUED` means no node has yet been authorized.
`RUNNING` includes waits between nodes after work has started.
`STOPPING` means cancellation is waiting for execution termination.

A required blocked node produces run failure when no permitted handler or retry can make progress.
An unknown required node produces `UNKNOWN` instead.
An unknown run remains unresolved and is not eligible for ordinary history purge.

## 9. Scheduling and business calendars

### Schedule types

Support these schedule types:

- One absolute time.
- A fixed interval measured from a defined anchor time.
- A five-field cron expression.
- A calendar rule at a local time.
- Manual submission.
- A local event with an explicit deduplication key.

The first cron parser must reject expressions that restrict both day-of-month and day-of-week.
Do not introduce an implicit AND or OR interpretation.
Use an explicit calendar rule for that requirement.

Intervals must not depend on how long the previous execution took.
Completion-relative repetition is a separate schedule type for a later release.

### Calendars

Calendar versions can define weekdays, explicit included dates and excluded dates.
An included date extends the normal weekday rule.
An excluded date always wins.

Support the first or last permitted business day of a month and a specified weekday occurrence.
For example, support the third Thursday or last permitted business day.
Reject a rule that produces no valid date within its configured search bound.

Store business dates separately from UTC execution timestamps.
An accounting run for Friday can execute on Saturday after a delay.

### Time zones and clock changes

Each schedule must name UTC or an IANA time zone.
Do not use the host's current time zone implicitly.

For a local time that does not exist during a clock change, the default is to skip that occurrence.
For a repeated local time, the default is to use the first occurrence once.
Alternative behavior must be explicit and versioned.

The supported options are `gap=skip|next_valid` and `fold=first|second|both`.
`next_valid` uses the first valid instant after the local-time gap.
If several requested times resolve to the same instant, create one occurrence for that schedule.

Store the resolved UTC time, local date, offset and calendar version with each occurrence.
Record the time-zone database version used for resolution.
Do not recalculate an occurrence that already exists after a time-zone update.

Persist the schedule cursor and occurrence in the same transaction.
Enforce uniqueness on schedule ID and resolved occurrence time.
A schedule revision must not duplicate an existing occurrence at the same instant.

Use monotonic time for live execution deadlines.
Use UTC wall time for schedules and stored history.
Moving the wall clock backwards must not produce duplicate occurrences.
Moving it forwards must apply the missed-occurrence policy.

### Missed occurrences and overlap

Each schedule must select one policy:

| Policy | Behavior |
|---|---|
| `skip` | Record missed occurrences without execution. Default. |
| `latest` | Request only the most recent missed occurrence. |
| `all` | Request each missed occurrence within configured age and count limits. |

An initial catch-up limit is 100 occurrences per schedule per reconciliation pass.
Larger requests must be processed in bounded transactions.

For `all`, the initial default maximum age is 24 hours.
Older missed work requires a manual backfill request.

Run overlap is separate from missed-occurrence handling.
Default: one active run per flow, with later occurrences queued in time order.
Optional overlap policies are reject-new and permit-up-to-limit.
An unknown run remains active for overlap checks until resolved.

Manual backfill requires a date range, a maximum run count and a preview.
Initial maximum: 1000 occurrences per request.
Execution requires explicit confirmation of the preview identifier.

## 10. Dependencies and run outcomes

Dependency evaluation must use persisted node outcomes, not log text or PID presence.
For default success edges, every predecessor must succeed before the node becomes ready.

Failure handlers must name the outcomes they accept.
Cleanup nodes may depend on `finished` edges.
An unknown predecessor must block automatic continuation unless an operator resolves it.

A flow succeeds when all required primary nodes succeed and required cleanup finishes successfully.
Failure or cancellation of a required primary node prevents flow success.
A cleanup result must remain visible separately.

If any required node has an unknown outcome, the run outcome is unknown.
Do not replace it with ordinary failure merely to finish the flow.

Operator skip does not satisfy a success dependency by default.
Only a definition edge that explicitly accepts skipped work can use that outcome.

## 11. Priorities, resources and fairness

Dispatch requires all of these conditions:

- Dependencies and start-time conditions are satisfied.
- The node, run, definition and scheduler are not held.
- Global execution capacity is available.
- Job and flow concurrency limits permit execution.
- Required resource-pool slots and exclusion locks are available.
- The supervisor is available and supports the requested protocol and restrictions.

Use integer priorities from zero to 100.
Default priority: 50.
Increase effective priority by one for every 300 seconds spent ready, up to 100.
For equal effective priority, select the earliest ready time, then the node-run ID.

Reserve all requested scheduling resources in one transaction.
Do not reserve some locks while waiting for others.
This rule prevents scheduler-created resource deadlocks.

For the first release, all named exclusion locks are run-scoped.
Resolve the complete set from the flow, its jobs and the validated run parameters before first dispatch.
Acquire that set atomically with the first attempt's resource reservations.
Retain the exclusion locks until the run reaches a known final outcome.
Do not acquire additional exclusion keys halfway through a run.

Pool slots and compute reservations remain attempt-scoped.
Acquire all slots needed by one attempt together and release them after confirmed process completion.
This distinction avoids retaining scarce compute capacity during waits between nodes.

Pool slots are scheduling limits, not kernel resource limits.
For example, a database pool with four slots permits four participating attempts.
CPU and memory protection still require applied kernel controls.

Keep an exclusion lock across an unknown outcome until an operator resolves the conflicting work.
Release compute reservations only after process termination is established.
If processes are gone but application outcome is unknown, release compute slots but retain business exclusion locks.

Every waiting node must report its current reasons.
Examples include a predecessor, a held run, a resource holder or the next permitted start time.

## 12. Retries and application side effects

The scheduler owns batch retries.
agentd must not automatically restart a batch attempt.
Existing persistent-agent restart policies remain separate.

The default job policy permits one attempt and no automatic retry.
Retries require an explicit policy and a repeat-safety declaration.

Known setup failures that occurred before authorization can be retried after their cause is corrected.
Failures after execution require the job's declared repeat-safety policy.
That rule also applies to cancellation and time-limit expiry.
Neither operation proves that external side effects did not occur.

For `idempotency_key`, provide the same key for every attempt of the same node run.
The receiving application must enforce that key.
Recording a key in the scheduler alone does not make a job idempotent.

Use bounded exponential retry delay with an explicit maximum.
Store the next retry time and attempt count durably.
A scheduler restart must not reset either value.

Automatic retry of unknown outcomes is disabled by default.
An exception requires an explicit policy and an application-enforced idempotency key.
Operators must see that exception in the job definition and run history.

## 13. Cancellation and time limits

Cancellation is a durable request, not a claim that work has stopped.
Record the requester and reason before sending it to agentd.

agentd must serialize cancellation against completion recording.
If a terminal result was already committed, return that result without changing it.
Otherwise, accept cancellation, request graceful termination, then force termination after the stop grace period.

An explicit force option skips the graceful interval.
It still requires durable intent and confirmed subtree termination.

For accepted cancellation, preserve the observed process result and classify the scheduling outcome as cancelled.
Use the same ordering rule for a time-limit request.

agentd must enforce the execution time limit even when the scheduler is unavailable.
Measure it from startup gate release using monotonic time.
Persist the configured duration and wall-clock timestamps for inspection.
Do not reconstruct a precise live deadline from wall time after daemon restart.

Wait for confirmed subtree termination before recording `CANCELLED` or `TIMED_OUT`.
If termination cannot be confirmed, retain `STOPPING` and alert the operator.
Do not release reservations as if termination succeeded.

Cancellation of a flow prevents further automatic dispatch in that flow.
Its declared cleanup nodes can run only after affected attempts reach known terminal outcomes.

## 14. Recovery rules

### Scheduler restart while agentd remains active

On startup, the scheduler must:

1. Acquire its exclusive service lock.
2. Check database integrity and schema compatibility.
3. Reconcile every dispatching, running, stopping and unknown attempt by execution ID.
4. Consume missed supervisor events without repeating state changes.
5. Restore reservations from persisted records.
6. Evaluate missed occurrences under their policies.
7. Resume dispatch only after reconciliation completes.

A lost launch response is resolved by querying the same execution ID.
It must not create another attempt simply because the response was lost.

### agentd restart

agentd must reload its own durable execution ledger before accepting batch launches.
It must not reconstruct execution identity from child-writable PID files.

A prepared record without start authorization proves that the job program was not permitted through the startup gate.
Confirm that no related processes remain before finalizing a setup failure.

A start-authorized record without a durable terminal result is uncertain.
The new daemon cannot recover a lost child exit status from a PID alone.
Mark that execution unknown. Do not claim transparent adoption.

The daemon may inspect or stop a remaining execution subtree only through a verified supervisor-owned cgroup identity.
Use the delegated parent, unique execution name, boot ID and trusted stored metadata.
Reject unexpected path, ownership or filesystem changes.
Never signal a process solely because an old PID file names it.

### Host restart

A changed boot ID proves that the old local processes are no longer running.
It does not establish their application outcomes before the host stopped.

Use recorded terminal results when available.
Otherwise, mark previously authorized executions unknown and apply the job's explicit recovery policy.
Keep non-repeatable work held for operator review.

### Database or storage failure

If durable writes fail, stop new dispatch immediately.
Do not acknowledge a launch or completion that was not committed.

If agentd cannot record a terminal result, retain the observation in memory and retry the write.
Report degraded storage state to the scheduler.
A later daemon crash can turn that unrecorded result into an unknown outcome.

Existing job processes do not become successful because a database is unavailable.
Do not create a replacement database automatically after corruption.

## 15. Operator commands

The CLI must support human-readable and JSON output.
The following names are proposed commands, not existing agentctl commands.

```text
schedctl validate <definition-file>
schedctl publish <definition-file>
schedctl run <job-or-flow> --business-date <date> --request-id <id>
schedctl status <run-id>
schedctl explain <node-run-id>
schedctl hold <target> --reason <text>
schedctl release <target> --reason <text>
schedctl cancel <run-id> [--force] --reason <text>
schedctl retry <node-run-id> --reason <text>
schedctl skip <node-run-id> --reason <text>
schedctl resolve <node-run-id> --outcome <result> --reason <text>
schedctl repair <run-id> --from <node> --preview
schedctl backfill <schedule> --from <date> --to <date> --preview
schedctl logs <attempt-id> --stream stdout
schedctl history <job-or-flow>
schedctl drain --reason <text>
```

Hold targets can be a definition, run, node run or the whole scheduler.
Drain stops new dispatch but does not cancel running work.

State-changing requests require a request ID and expected record revision.
The CLI can generate request IDs, but must retain them when retrying an uncertain response.
Record the peer user ID, action, time, reason and affected records.
The first release does not claim separate human identities for people sharing one account.

After an uncertain command response, query the request ID before generating another request.
The CLI must not hide transport failure by submitting the same action with a new ID.

An operator cannot resolve an unknown node as successful while its execution might still be active.
Require process reconciliation or confirmed termination first.
Resolution must preserve the original unknown record and add the operator's decision.

### Retry and repair

Retry of a failed node is permitted only when no active or completed descendant depends on that result.
It creates another attempt under the same node run and repeat-safety rules.

If the run already reached a failed outcome, retry reopens its current state.
Retain the earlier failure and operator action in history.
Reacquire the run's complete exclusion-lock set before dispatching the retry.

If descendants already completed, create a repair run instead.
A repair run has new run, node and attempt identifiers.
It links to the original run and includes the selected node and affected descendants.
Unaffected predecessor outputs can be referenced through immutable manifests.

A preview must identify work that will repeat and external side effects that need operator review.
Do not overwrite old outcomes or silently reuse a result invalidated by the repair.

## 16. Local APIs

Use separate Unix sockets for scheduler and supervisor control.
Require owner checks, peer credentials and an authenticated session or token.
The initial API is for the trusted service account only.

The batch protocol must have an explicit major version.
Use bounded length-prefixed JSON messages, not additions to the current line-oriented command syntax.
Initial maximum request size: 256 KiB.
Reject unknown required fields and incompatible major versions.

Use a four-byte unsigned big-endian length followed by that many UTF-8 JSON bytes.
Each connection carries one complete request and one response, then closes.
Initial maximum response size: 1 MiB.
Lists and event pages must stop before that bound and return a continuation cursor.
Do not include job log contents or secret values in execution events.

Reject malformed JSON, duplicate keys, incomplete frames and unexpected descriptor transfers.
Close all received descriptors on every rejection path.
The batch API does not support descriptor delegation.

A launch contains the execution ID, request ID, job and profile digests, argument array and working directory.
It also contains environment entries, secret references, output policy, time limit, stop grace and resource settings.
The supervisor must validate the complete resolved launch specification before accepting it.

Standard input defaults to `/dev/null`.
An optional input file must be an approved immutable artifact.
Reserve descriptors 3 through 5 for the existing agent protocol when that protocol is enabled.
Pass other approved inputs or secrets through explicitly assigned descriptors from 6 upwards.
Close every descriptor outside the launch allowlist before exec.
No other child may retain a startup gate descriptor.

Required supervisor operations are:

| Operation | Result |
|---|---|
| `hello` | Protocol version, supported functions, capacity, boot ID, ledger identity and supervisor instance ID. |
| `launch` | Durable acceptance or rejection for an execution ID and launch digest. |
| `get_execution` | Current durable execution record. |
| `get_request` | Recorded result for a request ID, including its ledger identity and recovery epoch. |
| `list_executions` | Bounded, paginated execution records for reconciliation. |
| `cancel_execution` | Durable cancellation acceptance or an existing terminal result. |
| `events_after` | Ordered, paginated events after a supplied sequence. |
| `ack_events` | Highest sequence committed by this scheduler consumer. |

Every mutating request must be idempotent by request ID.
Errors need stable codes, a setup stage, a retry classification and a bounded human-readable message.

The socket handler must not block process reaping or other control requests.
Use bounded client buffers, total request deadlines and nonblocking writes.
An event consumer that stops reading must not block execution management.

Do not use broker audit tokens as scheduler authentication tokens or execution IDs.
The existing mailbox broker is optional for jobs that communicate with other managed agents.
It is not the scheduler's durable dispatch queue.

The supervisor must expose configured capacity, available capacity and any admission failure through this API.
Capacity exhaustion is a known rejection, not an unknown execution outcome.
It must occur before durable execution acceptance.
Return the node to ready state and release its scheduling reservations.
Retain its pending execution ID and digest; do not count admission rejection as an executed attempt.

A repeated request ID returns its original recorded response.
After a confirmed admission rejection, a later admission request can use a new request ID with the same execution ID.
Do not make that change after an uncertain response.
Query the original request and execution first, under the expected ledger identity and recovery epoch.

## 17. Database records and constraints

The scheduler ledger must include these logical tables:

| Record | Required contents or constraint |
|---|---|
| Definition versions | Immutable body, digest and publication metadata. |
| Calendars | Immutable calendar versions and date rules. |
| Schedules | Definition references, cursor, time zone, missed-occurrence and overlap policy. |
| Occurrences | Unique schedule ID and resolved UTC occurrence time. |
| Runs | Trigger, business date, pinned versions, parameters and aggregate outcome. |
| Node runs | Job version, dependency results, state, hold and revision. |
| Attempts | Unique execution ID, launch digest, retry number and supervisor result. |
| Dispatch outbox | Durable requests and delivery state. |
| Consumed events | Unique ledger ID, recovery epoch and event sequence. |
| Pools and reservations | Capacity, holders and resource units. |
| Exclusion locks | Unique active owner for each configured lock key. |
| Operator actions | Append-only action records with request IDs and reasons. |
| Notifications | Outbox state, event ID, recipient and delivery attempts. |

The supervisor ledger must contain executions, request deduplication records and ordered execution events.
Persist the immutable launch digest with each execution ID.
Persist start authorization separately from observed program start and terminal results.

An execution ledger has a stable ledger ID.
Its event sequence must increase across daemon restarts.
A supervisor instance ID identifies one daemon process; it must not reset the event sequence.

An explicit database restore must create a new recovery epoch before serving requests.
Clients must detect an unexpected ledger or epoch change and enter reconciliation mode.
Never treat a new event with a reused sequence as an already consumed old event.

Enforce unique run-creation request IDs and local-event deduplication keys.
State transitions must use expected revisions or an equivalent conditional update.
Reject a transition if another action already changed the record.

Use database constraints for identity and ownership rules where possible.
Do not rely only on CLI validation.

## 18. Logs, artifacts and notifications

Keep stdout and stderr separate for each attempt.
Do not mix job output with the supervisor's audit file.
Use bounded log storage and a documented retention policy.

The initial default output limit is 64 MiB for stdout and stderr combined per attempt.
The default response to that limit is to stop the execution and record failure with reason `OUTPUT_LIMIT`.
An explicit truncate policy can retain a bounded prefix instead, but it must record that output was discarded.

On a configured output limit, record truncation or stop the job under its output policy.
Do not allow unlimited output to fill the state filesystem.
Do not silently discard a required result artifact.

Artifact manifests must record path, size and digest.
Validate path components and do not follow child-controlled symlinks into supervisor state.
Only explicitly permitted predecessor artifacts become inputs to another node.

Finalize artifact manifests after the execution subtree is empty.
Verify file types and digests without following paths outside the approved artifact directory.
Recheck a referenced digest before a repair run uses an earlier artifact.

Notifications must use a durable outbox.
Delivery can repeat. Include a stable event ID for recipient deduplication.
Notification failure must be visible but must not repeat the job itself.

Secrets must not appear in definitions, launch logs, CLI output or notifications.
Store secret references, not secret values, in scheduler history.
Job output can still disclose secrets; operators must control access and retention.

The first secret provider uses versioned files under an operator-configured secret directory.
agentd resolves those references at launch and opens them without following symlinks.
Validate the file owner, mode and requested version before release of the startup gate.
Pass secret files read-only through approved descriptors by default.
Do not include their contents in launch digests, database records or event messages.

The launch digest includes the secret reference and version, not its value.
An unavailable or changed required secret version causes a known setup failure.
An external secret service is outside the first release.

## 19. Local operator interface

The first graphical interface must show:

- Upcoming and missed occurrences.
- Active runs and their node states.
- The reason each node is waiting or blocked.
- Attempt history, exit results and output.
- Holds, unknown outcomes and required operator actions.
- Pool capacity and current resource holders.

Add read-only views before state-changing controls.
All controls must use the same API and revision checks as the CLI.
The interface must not edit the database directly.

If a browser interface is used, bind it to loopback by default.
Require authentication, CSRF protection and restricted origin handling.
Do not expose it to the network as part of the initial release.

## 20. Required agentctl and agentd changes

| Area | Current behavior | Required addition |
|---|---|---|
| Launch | Executes a named runtime with its agent name. | Batch execution with an argument array, working directory and explicit environment. |
| Identity | Managed name, PID and live pidfd. | Durable execution ID, launch digest, boot ID and process identity record. |
| Startup | Cgroup attachment follows fork without a gate. | Block the child until verified attachment and restriction setup. |
| Acceptance | Current control response is not a durable batch receipt. | Persistent acceptance and deduplication across daemon restarts. |
| Completion | Process exit updates agent state and logs. | Durable exit record, ordered events and query by execution ID. |
| Recovery | Reads stored PIDs and opens new pidfds. | Conservative batch recovery without treating stored PIDs as authority. |
| Stop and kill | CLI operations remove the agent directory. | Batch cancellation that retains attempt output and history. |
| Restart | Supervisor can restart named agents. | Batch mode with automatic restarts disabled. |
| Capacity | Fixed `MAX_MANAGED` value of 32. | Configurable bounded execution capacity and explicit capacity errors. |
| Environment | Runtime inherits daemon environment. | Allowlisted batch environment and controlled secret delivery. |
| Output | Agent output shares its audit destination. | Separate bounded stdout and stderr for each attempt. |
| Cgroup path | Shared hardcoded agents path. | Configured delegated parent and unique execution-specific subgroups. |
| Storage | Runtime files under the agentctl root. | Supervisor-owned persistent execution ledger and result retention. |
| Control API | Line-oriented named-agent commands. | Separate versioned batch socket with bounded messages and durable request IDs. |
| Build | Existing userspace C build. | SQLite integration, migrations and static Linux VM build support. |

Keep existing named-agent commands available.
Do not silently change `agentctl stop` or `kill` retention behavior for current users.
Add explicit batch commands and a separate result-purge operation.

Do not reuse `task_recover_interrupted` as scheduler recovery.
It marks interrupted application tasks failed, which is insufficient for unknown execution outcomes.
Existing task and checkpoint helpers can remain application APIs.
They must not authorize scheduler transitions or new execution attempts.

The broker does not need DAG, calendar or retry logic.
Do not add those responsibilities to agentd.

## 21. Backup, retention and upgrades

Back up the scheduler and supervisor ledgers through a consistent SQLite backup procedure.
Do not copy a live database file without its required WAL state.
Back up referenced immutable definitions and required artifacts with the database snapshot.

Default retention must not delete active, unknown or unresolved execution records.
Prune only terminal records that are no longer needed for reconciliation or referenced history.
Keep execution deduplication records for every period in which a request can be replayed.
Require explicit acknowledgement before destructive history purge.

Run schema migrations only after taking a backup and stopping new dispatch.
Refuse an unsupported newer schema instead of attempting a downgrade.
Protocol negotiation must reject an incompatible scheduler and supervisor pair.

Restoring an old backup must not automatically launch previously authorized work.
Enter reconciliation mode and hold records whose execution history cannot be established.

## 22. Acceptance tests

### Durable execution

- Repeat one launch request 100 times. Only one job execution can be authorized.
- Reuse an execution ID with a changed digest. The request must fail.
- Lose the launch reply. Reconciliation must find the original execution.
- Repeat completion events. Dependency release and retry creation must occur once.
- Fail database writes. No uncommitted acceptance can be reported.
- Reject malformed, oversized and unauthorized API requests without leaking descriptors or blocking process management.

### Crash points

Inject termination at each of these points:

1. Before scheduler dispatch commit.
2. After dispatch commit but before send.
3. After supervisor preparation but before fork.
4. After fork but before attachment.
5. After authorization commit but before gate release.
6. After exec but before the start event.
7. After program exit but before result commit.
8. After result commit but before event delivery.
9. During scheduler result consumption.

For every case, assert the run state, execution count, reservations and operator action required.
Unknown outcomes are valid conservative results.
Duplicate automatic side effects are not an acceptable recovery strategy.

### Real kernel controls

- Verify the child cannot execute before cgroup attachment.
- Deny controller writes and attachment. Confirm no job program executes.
- Exercise memory, PID and CPU limits and inspect kernel counters.
- Terminate nested cgroups containing children in other sessions.
- Confirm an unrelated execution remains alive.
- Test timeout and cancellation while other jobs start and exit.
- Confirm the subtree is empty before releasing compute reservations.

Use an isolated VM with a writable delegated hierarchy.
Retain the test verdict separately from QEMU's exit code.

### Scheduling rules

- Test business-day, month-end and holiday exclusions.
- Test nonexistent and repeated local times.
- Move the wall clock forwards and backwards.
- Restart while generating occurrences and confirm deduplication.
- Test every missed-occurrence and overlap policy.
- Change definitions and confirm existing runs keep their pinned versions.
- Test concurrent holds, cancellations, resolutions and dispatch decisions.

### Application and storage failures

- Simulate a payment accepted before loss of its completion result.
- Confirm default recovery holds that work as unknown.
- Confirm an application idempotency key is stable across an explicitly permitted retry.
- Fill log and database storage using bounded test files.
- Corrupt a test database and confirm dispatch stops.
- Restore an old backup and confirm reconciliation prevents blind replay.

### Initial sizing targets

Validate 10,000 job definitions, 100 active executions and 100,000 retained run records on a declared test host.
These are release test targets, not measured current capacity.

A supported load must keep ordinary status queries below one second for at least 95% of requests.
Record host configuration and the workload used for that measurement.
Do not accept unbounded memory growth in the scheduler or supervisor.

## 23. Phased implementation plan

Phases are dependency ordered.
Do not assign calendar estimates before the contract tests expose the recovery work.

| Phase | Deliverables | Exit gate |
|---|---|---|
| 0. Contracts and fixtures | Select scheduler language. Define schemas, IDs, state transitions, protocol and crash injection points. | Reviewed schemas and an automated isolated-VM fixture. |
| 1. Batch supervisor | Add the startup gate, strict attachment checks, execution IDs, durable ledger, argument arrays and retained output. | Manual batch execution passes deduplication, real cgroup and daemon-crash tests. |
| 2. Durable single-job scheduler | Add scheduler storage, dispatch outbox, completion consumption, reconciliation, hold, cancel and explicit retry. | Scheduler restart cannot lose an accepted run or create a duplicate launch. Unknown outcomes remain held. |
| 3. Dependencies and resources | Add immutable flows, dependency evaluation, pools, exclusion locks, priorities and explanations. | Failure branches, concurrency races and resource reservation tests pass. |
| 4. Time and calendars | Add recurrence, business dates, holidays, DST rules, missed occurrences, overlap and backfill preview. | Clock-change and occurrence-deduplication tests pass. |
| 5. Operation and recovery | Add repair runs, notifications, retention, backup, restore, migration and administrative audit. | Host reboot, restored-backup and application-side-effect scenarios pass. |
| 6. Operator interface | Add read-only views, then authenticated controls using the same API as the CLI. | Operators can diagnose blocked and unknown runs without editing files or databases. |
| 7. Release qualification | Run sizing tests, extended mixed workloads, security review and documented upgrade procedures. | All release acceptance tests pass with recorded results and known limits. |

Phases 1 and 2 produce a useful manual single-job system.
They are not a complete workload scheduler.
Phases 3 through 5 establish the first functional scheduler release candidate.
The graphical interface must not delay execution and recovery tests.

The recovery fixture must use a persistent virtual disk for ledgers and run data.
An initramfs-only test cannot establish recovery across guest reboot.
The fixture must support abrupt VM termination without an orderly guest shutdown.

### Phase 1 source areas

- `common.c` and `common.h`: new batch launch path, argument arrays, environment and startup gate.
- `enforcement.c` and `enforcement.h`: configured delegated parent, verified attachment and trusted cgroup handles.
- `agentd.c`: durable batch records, bounded execution capacity, completion events and batch cancellation.
- `agentctl.c`: batch inspection commands without implicit directory removal.
- New supervisor ledger and batch protocol modules.
- `Makefile`, CI and VM tooling: SQLite builds and recovery fault tests.

Keep the old spawn API as a compatibility wrapper where practical.
Do not make old callers supply scheduler fields.

### Phase 2 source areas

- New scheduler service and CLI directories.
- Scheduler schema migrations and transaction helpers.
- Dispatch and notification outbox processing.
- Supervisor event reconciliation.
- Fake-clock, fake-supervisor and real-supervisor test implementations.

### Later phase discipline

Keep calendar evaluation, dependency decisions and retry policy in the scheduler.
Keep process observations and execution records in agentd.
Add a regression test for each new recovery rule before exposing it in the operator interface.

## 24. First complete workload

Use a business-day accounting close as the end-to-end acceptance workload:

```text
import transactions -> reconcile accounts -> generate reports -> archive
                              |
                       failure notification
```

The flow must prevent two closes for the same account and business date from running together.
A reconciliation failure must block reports.
An operator must be able to correct the problem and retry reconciliation without repeating a successful import.

If reports already completed, a reconciliation rerun requires a previewed repair run.
The original history must remain unchanged.

During the test, stop and restart the scheduler, agentd and the guest host at the defined crash points.
The resulting state must explain completed, pending, blocked and unknown work without guessing.

## 25. Related documents

- [Current process and transport requirements](design-invariants.md)
- [Security model and current limits](../SECURITY.md)
- [Capability broker](capabilities.md)
- [Existing tests](../tests/README.md)
- [Kernel and VM test tools](../kernel/dev/README.md)
