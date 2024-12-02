<?php

return [
    'settings' => [
        'settings' => [
            'poller_groups' => [
                'description' => 'Назначенные группы',
                'help' => 'Этот узел будет действовать только на устройства в этих группах опроса.',
            ],
            'poller_enabled' => [
                'description' => 'Опрос включен',
                'help' => 'Включить рабочие процессы опроса на этом узле.',
            ],
            'poller_workers' => [
                'description' => 'Рабочие процессы опроса',
                'help' => 'Количество рабочих процессов опроса, которые будут запущены на этом узле.',
            ],
            'poller_frequency' => [
                'description' => 'Частота опроса (Внимание!)',
                'help' => 'Как часто опрашивать устройства на этом узле. Внимание! Изменение этого значения без исправления файлов rrd сломает графики. См. документацию для получения дополнительной информации.',
            ],
            'poller_down_retry' => [
                'description' => 'Повторная попытка при отключенном устройстве',
                'help' => 'Если устройство отключено во время попытки опроса на этом узле, это время ожидания перед повторной попыткой.',
            ],
            'discovery_enabled' => [
                'description' => 'Обнаружение включено',
                'help' => 'Включить рабочие процессы обнаружения на этом узле.',
            ],
            'discovery_workers' => [
                'description' => 'Рабочие процессы обнаружения',
                'help' => 'Количество рабочих процессов обнаружения, которые будут запущены на этом узле. Слишком высокая настройка может вызвать перегрузку.',
            ],
            'discovery_frequency' => [
                'description' => 'Частота обнаружения',
                'help' => 'Как часто выполнять обнаружение устройств на этом узле. По умолчанию 4 раза в день.',
            ],
            'services_enabled' => [
                'description' => 'Сервисы включены',
                'help' => 'Включить рабочие процессы сервисов на этом узле.',
            ],
            'services_workers' => [
                'description' => 'Рабочие процессы сервисов',
                'help' => 'Количество рабочих процессов сервисов на этом узле.',
            ],
            'services_frequency' => [
                'description' => 'Частота сервисов',
                'help' => 'Как часто запускать сервисы на этом узле. Это должно соответствовать частоте опроса.',
            ],
            'billing_enabled' => [
                'description' => 'Биллинг включен',
                'help' => 'Включить рабочие процессы биллинга на этом узле.',
            ],
            'billing_frequency' => [
                'description' => 'Частота биллинга',
                'help' => 'Как часто собирать данные биллинга на этом узле.',
            ],
            'billing_calculate_frequency' => [
                'description' => 'Частота расчета биллинга',
                'help' => 'Как часто рассчитывать использование биллинга на этом узле.',
            ],
            'alerting_enabled' => [
                'description' => 'Оповещение включено',
                'help' => 'Включить рабочий процесс оповещения на этом узле.',
            ],
            'alerting_frequency' => [
                'description' => 'Частота оповещения',
                'help' => 'Как часто проверяются правила оповещения на этом узле. Обратите внимание, что данные обновляются только на основе частоты опроса.',
            ],
            'ping_enabled' => [
                'description' => 'Быстрый пинг включен',
                'help' => 'Быстрый пинг просто пингует устройства, чтобы проверить, работают ли они или отключены.',
            ],
            'ping_frequency' => [
                'description' => 'Частота пинга',
                'help' => 'Как часто проверять пинг на этом узле. Внимание! Если вы измените это, вам необходимо внести дополнительные изменения. Проверьте документацию по быстрому пингу.',
            ],
            'update_enabled' => [
                'description' => 'Ежедневное обслуживание включено',
                'help' => 'Запустить скрипт обслуживания daily.sh и перезапустить службу диспетчера после этого.',
            ],
            'update_frequency' => [
                'description' => 'Частота обслуживания',
                'help' => 'Как часто выполнять ежедневное обслуживание на этом узле. По умолчанию 1 день. Настоятельно рекомендуется не изменять это значение.',
            ],
            'loglevel' => [
                'description' => 'Уровень логирования',
                'help' => 'Уровень логирования службы диспетчера.',
            ],
            'watchdog_enabled' => [
                'description' => 'Сторожевой таймер включен',
                'help' => 'Сторожевой таймер следит за лог-файлом и перезапускает службу, если она не обновлялась.',
            ],
            'watchdog_log' => [
                'description' => 'Лог-файл для наблюдения',
                'help' => 'По умолчанию это лог-файл LibreNMS.',
            ],
        ],
        'units' => [
            'seconds' => 'Секунды',
            'workers' => 'Рабочие процессы',
        ],
    ],
];