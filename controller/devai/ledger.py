from __future__ import annotations

from uuid import UUID, uuid4

from .db import connect
from .types import ExecutionAttempt


def create_job(
    objective: str,
    status: str = "running",
) -> UUID:
    job_id = uuid4()

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO jobs (
                    id,
                    objective,
                    status
                )
                VALUES (%s, %s, %s)
                """,
                (job_id, objective, status),
            )

    return job_id


def create_task(
    job_id: UUID,
    external_id: str,
    title: str,
    description: str,
    capability: str,
    risk: str,
    needs_review: bool,
    status: str = "running",
) -> UUID:
    task_id = uuid4()

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tasks (
                    id,
                    job_id,
                    external_id,
                    title,
                    description,
                    capability,
                    risk,
                    needs_review,
                    status
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    task_id,
                    job_id,
                    external_id,
                    title,
                    description,
                    capability,
                    risk,
                    needs_review,
                    status,
                ),
            )

    return task_id


def record_attempt(
    job_id: UUID,
    task_id: UUID,
    attempt_number: int,
    attempt: ExecutionAttempt,
) -> UUID:
    attempt_id = uuid4()

    status = "succeeded" if attempt.success else "failed"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO execution_attempts (
                    id,
                    job_id,
                    task_id,
                    attempt_number,
                    route_key,
                    provider,
                    gateway_model,
                    status,
                    error_message,
                    started_at,
                    finished_at
                )
                VALUES (
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    now(), now()
                )
                """,
                (
                    attempt_id,
                    job_id,
                    task_id,
                    attempt_number,
                    attempt.route_key,
                    attempt.provider,
                    attempt.gateway_model,
                    status,
                    attempt.error,
                ),
            )

    return attempt_id


def complete_task(task_id: UUID) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks
                SET status = 'completed',
                    updated_at = now()
                WHERE id = %s
                """,
                (task_id,),
            )


def complete_job(job_id: UUID) -> None:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE jobs
                SET status = 'completed',
                    updated_at = now()
                WHERE id = %s
                """,
                (job_id,),
            )


def start_attempt(
    job_id: UUID,
    task_id: UUID,
    attempt_number: int,
    route_key: str,
    provider: str,
    gateway_model: str,
) -> UUID:
    attempt_id = uuid4()

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO execution_attempts (
                    id,
                    job_id,
                    task_id,
                    attempt_number,
                    route_key,
                    provider,
                    gateway_model,
                    status,
                    started_at
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    'running',
                    now()
                )
                """,
                (
                    attempt_id,
                    job_id,
                    task_id,
                    attempt_number,
                    route_key,
                    provider,
                    gateway_model,
                ),
            )

    return attempt_id


def finish_attempt(
    attempt_id: UUID,
    success: bool,
    error: str | None = None,
) -> None:
    status = "succeeded" if success else "failed"

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE execution_attempts
                SET status = %s,
                    error_message = %s,
                    finished_at = now()
                WHERE id = %s
                  AND status = 'running'
                """,
                (
                    status,
                    error,
                    attempt_id,
                ),
            )

            if cur.rowcount != 1:
                raise RuntimeError(
                    f"Attempt {attempt_id} is not in running state"
                )
