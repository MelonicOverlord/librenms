#!/usr/bin/env python3

"""
JSON interface between LibreNMS PHP and PyWinRM.

Input is read from stdin.
Output is emitted as one JSON object on stdout.
"""

import json
import sys
import traceback

from WinRMScan import test_connection


def emit(result):
    print(
        json.dumps(
            result,
            separators=(",", ":"),
            default=str,
        )
    )


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception as error:
        emit(
            {
                "success": False,
                "status_code": -1,
                "error": f"Invalid WinRM helper input: {error}",
            }
        )
        return 2

    action = payload.get("action")
    configuration = payload.get("configuration")

    if not isinstance(configuration, dict):
        emit(
            {
                "success": False,
                "status_code": -1,
                "error": "Missing WinRM configuration",
            }
        )
        return 2

    if action == "test":
        result = test_connection(configuration)
        emit(result)
        return 0 if result.get("success") else 1

    emit(
        {
            "success": False,
            "status_code": -1,
            "error": f"Unsupported WinRM helper action: {action}",
        }
    )
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        traceback.print_exc(file=sys.stderr)

        emit(
            {
                "success": False,
                "status_code": -1,
                "error": str(error),
            }
        )

        sys.exit(1)
