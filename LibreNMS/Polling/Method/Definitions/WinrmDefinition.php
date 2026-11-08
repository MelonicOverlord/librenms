<?php

namespace LibreNMS\Polling\Method\Definitions;

use App\View\FieldSchema\FieldDefinition;

final class WinrmDefinition extends PollingMethodDefinition
{
    public function icon(): string
    {
        return 'fa-windows';
    }

    public function fields(): array
    {
        return [
            'hostname' => FieldDefinition::make('hostname', 'text')
                ->placeholder('Default: device hostname or FQDN')
                ->rules(['nullable', 'string', 'max:255']),

            'scheme' => FieldDefinition::make('scheme', 'select')
                ->label('Transport')
                ->options([
                    'http' => 'HTTP',
                    'https' => 'HTTPS',
                ]),

            'port' => FieldDefinition::make('port', 'number')
                ->min(1)
                ->max(65535)
                ->placeholder('Default: 5985 for HTTP, 5986 for HTTPS'),

            'path' => FieldDefinition::make('path', 'text')
                ->placeholder('Default: /wsman')
                ->rules(['nullable', 'string', 'max:255']),

            'authentication' => FieldDefinition::make(
                'authentication',
                'select'
            )
                ->label('Authentication')
                ->options([
                    'kerberos' => 'Kerberos (system credential cache)',
                    'ntlm' => 'NTLM (stored credential)',
                    'basic' => 'Basic (HTTPS only)',
                ]),

            'server_cert_validation' => FieldDefinition::make(
                'server_cert_validation',
                'select'
            )
                ->label('TLS certificate validation')
                ->options([
                    'validate' => 'Validate',
                    'ignore' => 'Ignore',
                ]),

            'operation_timeout' => FieldDefinition::make(
                'operation_timeout',
                'number'
            )
                ->min(1)
                ->max(3600)
                ->placeholder('Default: 50 seconds'),

            'read_timeout' => FieldDefinition::make(
                'read_timeout',
                'number'
            )
                ->min(2)
                ->max(3600)
                ->placeholder('Default: 60 seconds'),
        ];
    }
}
