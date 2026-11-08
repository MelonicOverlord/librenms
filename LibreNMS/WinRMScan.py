#!/usr/bin/env python3
"""
Scan windows computers with WinRM using PyWinRM
Install PyWinRM - pip install pywinrm

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

File reworked from PR13483 for new Polling Methods and Secrets support
"""

import json
import logging

logger = logging.getLogger(__name__)

try:
    import winrm
except ModuleNotFoundError:
    winrm = None


class WinRMConfigurationError(Exception):
    """Raised when WinRM is unavailable or incorrectly configured"""


def create_session(config):
    """
    Create a PyWinRM session from a resolved WinRM configuration.

    Example Kerberos config:

    """

    if winrm is None:
        raise WinRMConfigurationError(
            "Unable to load PyWinRM. "
            "Install it with: pip install 'pywinrm[kerberos]'"
        )

    hostname = config.get("hostname")
    if not hostname:
        raise WinRMConfigurationError(
            "No hostname supplied for WinRM connection"
        )

    scheme = config.get("scheme", "http").lower()

    if scheme not in ("http", "https"):
        raise WinRMConfigurationError(
            f"Unsupported WinRM scheme: {scheme}"
        )

    default_port = 5986 if scheme == "https" else 5985
    port = int(config.get("port", default_port))

    path = config.get("path", "/wsman")
    if not path.startswith("/"):
        path = "/" + path

    authentication = config.get(
        "authentication",
        "kerberos",
    ).lower()

    endpoint = f"{scheme}://{hostname}:{port}{path}"

    session_options = {
        "read_timeout_sec": int(
            config.get("read_timeout", 60)
        ),
        "operation_timeout_sec": int(
            config.get("operation_timeout", 50)
        ),
    }

    # Certificate validation only matters for HTTPS.
    if scheme == "https":
        session_options["server_cert_validation"] = (
            config.get(
                "server_cert_validation",
                "validate",
            )
        )

    if authentication == "kerberos":
        #
        # No username or password is supplied.
        #
        # PyWinRM/GSSAPI will use the Kerberos credential
        # cache available to the LibreNMS process.
        #
        return winrm.Session(
            endpoint,
            transport="kerberos",
            **session_options,
        )

    if authentication == "ntlm":
        username = config.get("username")
        password = config.get("password")

        if not username or password is None:
            raise WinRMConfigurationError(
                "NTLM authentication requires a username "
                "and password"
            )

        return winrm.Session(
            endpoint,
            auth=(username, password),
            transport="ntlm",
            **session_options,
        )

    if authentication == "basic":
        if scheme != "https":
            raise WinRMConfigurationError(
                "Basic authentication is only permitted "
                "over HTTPS"
            )

        username = config.get("username")
        password = config.get("password")

        if not username or password is None:
            raise WinRMConfigurationError(
                "Basic authentication requires a username "
                "and password"
            )

        return winrm.Session(
            endpoint,
            auth=(username, password),
            transport="basic",
            **session_options,
        )

    raise WinRMConfigurationError(
        "Unsupported WinRM authentication method: "
        f"{authentication}"
    )


def get_device_details(self, device_id):
    """
    Retrieve the hostname for a LibreNMS device.
    """

    devices = self._db.query(
        "SELECT `hostname` FROM `devices` "
        "WHERE (`device_id` = %s)",
        (device_id,),
    )

    for device in devices:
        return device[0]

    raise WinRMConfigurationError(
        f"Unable to find LibreNMS device {device_id}"
    )


def get_device_config(self, device_id, winrm_config):
    """
    Build the runtime WinRM configuration.

    The calling LibreNMS code is responsible for resolving
    credentials/secrets before supplying winrm_config.
    """

    config = dict(winrm_config)

    if not config.get("hostname"):
        config["hostname"] = get_device_details(
            self,
            device_id,
        )

    return config


def _decode_stdout(result):
    return result.std_out.decode(
        "utf-8",
        "ignore",
    ).strip()


def _decode_stderr(result):
    return result.std_err.decode(
        "utf-8",
        "ignore",
    ).strip()


def test_connection(config):
    """
    Test WinRM and return basic information about Windows.

    """

    try:
        session = create_session(config)

        command = """
$ErrorActionPreference = 'Stop'

Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption,
                  Version,
                  BuildNumber,
                  LastBootUpTime,
                  CSName |
    ConvertTo-Json -Compress
"""

        result = session.run_ps(command)

        if result.status_code != 0:
            return {
                "success": False,
                "status_code": result.status_code,
                "error": _decode_stderr(result),
            }

        output = _decode_stdout(result)

        if not output:
            return {
                "success": False,
                "status_code": -1,
                "error": (
                    "WinRM command completed successfully "
                    "but returned no data"
                ),
            }

        return {
            "success": True,
            "status_code": 0,
            "data": json.loads(output),
        }

    except Exception as error:
        logger.exception(
            "WinRM connection test failed"
        )

        return {
            "success": False,
            "status_code": -1,
            "error": str(error),
        }


def process_polling(
    self,
    device_id,
    winrm_config,
):
    """
    Run normal WinRM polling for a device.
    """

    try:
        config = get_device_config(
            self,
            device_id,
            winrm_config,
        )

        session = create_session(config)

        exit_code, output = process_services(
            self,
            session,
            device_id,
        )

        if exit_code != 0:
            return exit_code, output

        return process_processes(
            self,
            session,
            device_id,
        )

    except Exception as error:
        logger.exception(
            "WinRM polling failed for device %s",
            device_id,
        )

        return 1, str(error)


def process_discovery(
    self,
    device_id,
    winrm_config,
):
    """
    Run WinRM discovery.

    """

    try:
        config = get_device_config(
            self,
            device_id,
            winrm_config,
        )

        session = create_session(config)

        result = session.run_ps(
            "$PSVersionTable.PSVersion.ToString()"
        )

        if result.status_code != 0:
            return (
                result.status_code,
                _decode_stderr(result),
            )

        return (
            0,
            "WinRM discovery connection successful. "
            f"PowerShell version: {_decode_stdout(result)}",
        )

    except Exception as error:
        logger.exception(
            "WinRM discovery failed for device %s",
            device_id,
        )

        return 1, str(error)


def process_services(
    self,
    session,
    device_id,
):
    """
    Poll Windows services.
    """

    try:
        command = """
$ErrorActionPreference = 'Stop'

Get-Service |
    Select-Object ServiceName,
                  DisplayName,
                  Status,
                  ServiceType,
                  StartType,
                  CanPauseAndContinue,
                  CanShutdown,
                  CanStop |
    ConvertTo-Json -Compress
"""

        result = session.run_ps(command)

        if result.status_code != 0:
            return (
                result.status_code,
                _decode_stderr(result),
            )

        output = _decode_stdout(result)

        if not output:
            return 0, None

        services = json.loads(output)

        # PowerShell returns an object rather than an array
        # when there is only one result.
        if isinstance(services, dict):
            services = [services]

        self._db.query(
            "UPDATE `winrm_services` "
            "SET `disabled` = 1 "
            "WHERE (`device_id` = %s)",
            (device_id,),
        )

        for service in services:
            try:
                self._db.query(
                    "INSERT INTO `winrm_services` "
                    "(`device_id`, "
                    "`service_name`, "
                    "`display_name`, "
                    "`status`, "
                    "`service_type`, "
                    "`start_type`, "
                    "`can_pause_and_continue`, "
                    "`can_shutdown`, "
                    "`can_stop`, "
                    "`disabled`) "
                    "VALUES "
                    "(%s, %s, %s, %s, %s, "
                    "%s, %s, %s, %s, 0) "
                    "ON DUPLICATE KEY UPDATE "
                    "`display_name`=%s, "
                    "`status`=%s, "
                    "`service_type`=%s, "
                    "`start_type`=%s, "
                    "`can_pause_and_continue`=%s, "
                    "`can_shutdown`=%s, "
                    "`can_stop`=%s, "
                    "`disabled`=0",
                    (
                        device_id,
                        service.get("ServiceName"),
                        service.get("DisplayName"),
                        service.get("Status"),
                        service.get("ServiceType"),
                        service.get("StartType"),
                        service.get(
                            "CanPauseAndContinue"
                        ),
                        service.get("CanShutdown"),
                        service.get("CanStop"),
                        service.get("DisplayName"),
                        service.get("Status"),
                        service.get("ServiceType"),
                        service.get("StartType"),
                        service.get(
                            "CanPauseAndContinue"
                        ),
                        service.get("CanShutdown"),
                        service.get("CanStop"),
                    ),
                )

            except Exception:
                logger.exception(
                    "Unable to update WinRM service "
                    "for device %s: %s",
                    device_id,
                    service.get("ServiceName"),
                )

        return 0, None

    except Exception as error:
        logger.exception(
            "WinRM service polling failed for device %s",
            device_id,
        )

        return 1, str(error)


def process_processes(
    self,
    session,
    device_id,
):
    """
    Poll Windows processes
    """

    try:
        command = """
$ErrorActionPreference = 'Stop'

Get-Process -IncludeUserName |
    Select-Object Id,
                  Name,
                  ProcessName,
                  UserName,
                  NPM,
                  PM,
                  WS,
                  VM,
                  CPU |
    ConvertTo-Json -Compress
"""

        result = session.run_ps(command)

        if result.status_code != 0:
            return (
                result.status_code,
                _decode_stderr(result),
            )

        output = _decode_stdout(result)

        if not output:
            return 0, None

        processes = json.loads(output)

        if isinstance(processes, dict):
            processes = [processes]

        self._db.query(
            "DELETE FROM `winrm_processes` "
            "WHERE (`device_id` = %s)",
            (device_id,),
        )

        for process in processes:
            try:
                username = process.get("UserName")

                self._db.query(
                    "INSERT INTO `winrm_processes` "
                    "(`device_id`, "
                    "`pid`, "
                    "`name`, "
                    "`process_name`, "
                    "`username`, "
                    "`npm`, "
                    "`pm`, "
                    "`ws`, "
                    "`vm`, "
                    "`cpu`) "
                    "VALUES "
                    "(%s, %s, %s, %s, %s, "
                    "%s, %s, %s, %s, %s)",
                    (
                        device_id,
                        process.get("Id"),
                        process.get("Name"),
                        process.get("ProcessName"),
                        username,
                        process.get("NPM"),
                        process.get("PM"),
                        process.get("WS"),
                        process.get("VM"),
                        process.get("CPU"),
                    ),
                )

            except Exception:
                logger.exception(
                    "Unable to update WinRM process "
                    "for device %s PID %s",
                    device_id,
                    process.get("Id"),
                )

        return 0, None

    except Exception as error:
        logger.exception(
            "WinRM process polling failed for device %s",
            device_id,
        )

        return 1, str(error)
