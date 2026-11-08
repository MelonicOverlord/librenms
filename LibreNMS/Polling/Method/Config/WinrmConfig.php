<?php

namespace LibreNMS\Polling\Method\Config;

final readonly class WinrmConfig extends PollingMethodConfig
{
    public function __construct(
        public string $hostname,
        public string $scheme,
        public int $port,
        public string $path,
        public string $authentication,
        public ?string $username,
        public ?string $password,
        public string $serverCertValidation,
        public int $operationTimeout,
        public int $readTimeout,
    ) {
    }

    /**
     * Runtime configuration passed to the Python WinRM helper.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $config = [
            'hostname' => $this->hostname,
            'scheme' => $this->scheme,
            'port' => $this->port,
            'path' => $this->path,
            'authentication' => $this->authentication,
            'server_cert_validation' => $this->serverCertValidation,
            'operation_timeout' => $this->operationTimeout,
            'read_timeout' => $this->readTimeout,
        ];

        if ($this->username !== null) {
            $config['username'] = $this->username;
        }

        if ($this->password !== null) {
            $config['password'] = $this->password;
        }

        return $config;
    }
}
