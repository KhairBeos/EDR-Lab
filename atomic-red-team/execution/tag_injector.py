"""Inject art.* metadata into Atomic Red Team execution logs."""


def inject_metadata(event: dict, metadata: dict) -> dict:
    return {**event, **metadata}
