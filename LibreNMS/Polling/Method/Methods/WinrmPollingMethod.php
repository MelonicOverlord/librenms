<?php

namespace LibreNMS\Polling\Method\Methods;

use App\Models\Device;
use App\Models\DevicePollingMethod;
use Illuminate\Validation\ValidationException;
use LibreNMS\Enum\SecretType;
use LibreNMS\Enum\PollingMethodType;
use LibreNMS\Polling\Method\Config\PollingMethodConfig;
use LibreNMS\Polling\Method\Config\WinrmConfig;
use LibreNMS\Polling\Method\Definitions\WinrmDefinition;
use LibreNMS\Polling\Method\ProbeResult;
use LibreNMS\Polling\Secrets\Data\WinrmSecretData;
use RuntimeException;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

/**
 * @extends PollingMethod<WinrmConfig>
 */
final class WinrmPollingMethod extends PollingMethod
{
    public function definition(): WinrmDefinition
    {
        return new WinrmDefinition;
    }

    public function defaultAffectsAvailability(): bool
    {
        return false;
    }

    /**
     * @return array{
     *     hostname: string,
     *     scheme: string,
     *     port: int,
     *     path: string,
     *     authentication: string,
     *     server_cert_validation: string,
     *     operation_timeout: int,
     *     read_timeout: int
     * }
     */
    public function defaults(?Device $device = null): array
    {
        return [
            'hostname' => $device->hostname ?? '',
            'scheme' => 'http',
            'port' => 5985,
            'path' => '/wsman',
            'authentication' => 'kerberos',
            'server_cert_validation' => 'validate',
            'operation_timeout' => 50,
            'read_timeout' => 60,
        ];
    }

    public function config(
        Device $device,
        ?DevicePollingMethod $deviceMethod = null
    ): WinrmConfig {
        $settings = ($deviceMethod?->settings ?? [])
            + $this->defaults($device);

        $scheme = strtolower((string) $settings['scheme']);
        $authentication = strtolower(
            (string) $settings['authentication']
        );

        $storedSettings = $deviceMethod?->settings ?? [];

        $port = isset($storedSettings['port'])
            ? (int) $storedSettings['port']
            : ($scheme === 'https' ? 5986 : 5985);

        $secret = $this->secretData($deviceMethod?->secret);

        if ($secret !== null && ! $secret instanceof WinrmSecretData) {
            throw new RuntimeException(
                'The selected secret is not a WinRM credential'
            );
        }

        return new WinrmConfig(
            hostname: (string) $settings['hostname'],
            scheme: $scheme,
            port: $port,
            path: (string) $settings['path'],
            authentication: $authentication,
            username: $secret?->username,
            password: $secret?->password,
            serverCertValidation: (string) $settings['server_cert_validation'],
            operationTimeout: (int) $settings['operation_timeout'],
            readTimeout: (int) $settings['read_timeout'],
        );
    }

    public function validate(DevicePollingMethod $deviceMethod): void
    {
        parent::validate($deviceMethod);

        $settings = ($deviceMethod->settings ?? [])
            + $this->defaults();

        $authentication = strtolower(
            (string) $settings['authentication']
        );

        $scheme = strtolower(
            (string) $settings['scheme']
        );

        if (! in_array(
            $authentication,
            ['kerberos', 'ntlm', 'basic'],
            true
        )) {
            throw ValidationException::withMessages([
                'settings.authentication' =>
                    'Unsupported WinRM authentication method.',
            ]);
        }

        if (! in_array(
            $scheme,
            ['http', 'https'],
            true
        )) {
            throw ValidationException::withMessages([
                'settings.scheme' =>
                    'WinRM transport must be HTTP or HTTPS.',
            ]);
        }

        if (
            $authentication === 'basic'
            && $scheme !== 'https'
        ) {
            throw ValidationException::withMessages([
                'settings.authentication' =>
                    'Basic WinRM authentication requires HTTPS.',
            ]);
        }

        if (
            in_array(
                $authentication,
                ['ntlm', 'basic'],
                true
            )
            && $deviceMethod->secret === null
        ) {
            throw ValidationException::withMessages([
                'secret_id' =>
                    'A Windows credential is required for '
                    . strtoupper($authentication)
                    . ' authentication.',
            ]);
        }
    }

    public function probe(
        Device $device,
        PollingMethodConfig $config
    ): ProbeResult {
        assert($config instanceof WinrmConfig);

        $helper = base_path(
            'LibreNMS/winrm_helper.py'
        );

        if (! is_file($helper)) {
            return ProbeResult::failure(
                errorMessage:
                    "WinRM helper not found: $helper"
            );
        }

        $python = $this->pythonExecutable();

        try {
            $payload = json_encode(
                [
                    'action' => 'test',
                    'configuration' => $config->toArray(),
                ],
                JSON_THROW_ON_ERROR
            );
        } catch (\JsonException $exception) {
            return ProbeResult::failure(
                errorMessage:
                    'Unable to encode WinRM configuration: '
                    . $exception->getMessage()
            );
        }

        /*
         * Credentials are supplied on stdin rather than the command
         * line so they are not exposed in the process list.
         */
        $process = new Process([
            $python,
            $helper,
        ]);

        $process->setInput($payload);

        $process->setTimeout(
            $config->readTimeout + 15
        );

        try {
            $process->run();
        } catch (ProcessTimedOutException $exception) {
            return ProbeResult::failure(
                errorMessage:
                    'WinRM connection test timed out.'
            );
        } catch (\Throwable $exception) {
            return ProbeResult::failure(
                errorMessage:
                    $exception->getMessage()
            );
        }

        $responseText = trim(
            $process->getOutput()
        );

        if ($responseText === '') {
            $error = trim(
                $process->getErrorOutput()
            );

            return ProbeResult::failure(
                errorMessage:
                    $error !== ''
                        ? $error
                        : 'WinRM helper returned no output.'
            );
        }

        try {
            $response = json_decode(
                $responseText,
                true,
                flags: JSON_THROW_ON_ERROR
            );
        } catch (\JsonException $exception) {
            return ProbeResult::failure(
                stats: [
                    'helper_output' => $responseText,
                ],
                errorMessage:
                    'WinRM helper returned invalid JSON: '
                    . $exception->getMessage()
            );
        }

        if (! is_array($response)) {
            return ProbeResult::failure(
                errorMessage:
                    'WinRM helper returned an invalid response.'
            );
        }

        if (! ($response['success'] ?? false)) {
            return ProbeResult::failure(
                stats: [
                    'status_code' =>
                        $response['status_code'] ?? null,
                ],
                errorMessage:
                    (string) (
                        $response['error']
                        ?? 'WinRM connection failed.'
                    )
            );
        }

        return ProbeResult::success([
            'status_code' =>
                $response['status_code'] ?? 0,
            'windows' =>
                $response['data'] ?? [],
        ]);
    }

    public function enrichDeviceMetadata(Device $device): void
    {
        $deviceMethod = $device->pollingMethod(
            PollingMethodType::Winrm
        );

        if ($deviceMethod === null || ! $deviceMethod->enabled) {
            return;
        }

        $config = $this->config(
            $device,
            $deviceMethod
        );

        $result = $this->probe(
            $device,
            $config
        );

        if (! $result->isSuccess()) {
            return;
        }

        $windows = $result->stat(
            'windows',
            []
        );

        if (! is_array($windows)) {
            return;
        }

        $computerName = trim(
            (string) ($windows['CSName'] ?? '')
        );

        $version = trim(
            (string) ($windows['Version'] ?? '')
        );

        $buildNumber = trim(
            (string) ($windows['BuildNumber'] ?? '')
        );

        $caption = trim(
            (string) ($windows['Caption'] ?? '')
        );

        if ($computerName !== '') {
            $device->sysName = $computerName;
        }

        $device->os = 'windows';

        if ($version !== '' && $buildNumber !== '') {
            $device->version = sprintf(
                '%s (Build %s)',
                $version,
                $buildNumber
            );
        } elseif ($version !== '') {
            $device->version = $version;
        }

        if ($caption !== '') {
            $device->hardware = $caption;
        }
    }

    public function secretTypes(): array
    {
        return [
            SecretType::Winrm,
        ];
    }

    private function pythonExecutable(): string
    {
        $configured = getenv(
            'LIBRENMS_WINRM_PYTHON'
        );

        if (
            is_string($configured)
            && $configured !== ''
            && is_executable($configured)
        ) {
            return $configured;
        }

        $virtualEnvironmentPython = base_path(
            '.venv-winrm/bin/python'
        );

        if (
            is_executable(
                $virtualEnvironmentPython
            )
        ) {
            return $virtualEnvironmentPython;
        }

        return 'python3';
    }
}
