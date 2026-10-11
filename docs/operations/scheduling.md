# Scheduling

Give a job a cron expression and the server creates a **Temporal Schedule** for it. You can see them under `/temporal/` → Schedules.

- Standard 5-field cron, plus `@daily`, `@every 6h` and friends.
- Evaluated in the **server's timezone**: `timezone:` in `server.yaml` or `FALLBCK_TIMEZONE`. If neither is set it's auto-detected from `TZ` / the host zone, and falls back to UTC. On Docker, set `TZ` on the container.
- DST is Temporal's problem, not yours. `0 2 * * *` stays at 02:00 local all year.

## How runs behave

- A scheduled firing starts the same workflow as **Run now**.
- If the previous run of that job is still going, the firing is **skipped**. Runs don't pile up.
- After server downtime, one missed firing from the last hour gets caught up. Older ones don't.

## Changing things

- Disable the job and its schedule gets paused.
- Clear the cron or delete the job and the schedule is removed.
- The server reconciles schedules against the jobs table on every start, so they can't drift.

The Jobs page shows when each job fires next.
