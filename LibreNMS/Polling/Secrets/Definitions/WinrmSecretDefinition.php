<?php

namespace LibreNMS\Polling\Secrets\Definitions;

use App\View\FieldSchema\FieldDefinition;

final class WinrmSecretDefinition extends SecretDefinition
{
    public function fields(): array
    {
        return [
            'username' => FieldDefinition::make('username', 'text')
                ->label('Windows username')
                ->placeholder('DOMAIN\\username or username@domain')
                ->rules([
                    'required',
                    'string',
                    'max:255',
                ]),

            'password' => FieldDefinition::make('password', 'password')
                ->label('Password')
                ->rules([
                    'required',
                    'string',
                ]),
        ];
    }
}
