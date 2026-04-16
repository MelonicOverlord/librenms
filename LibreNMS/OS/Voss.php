* Voss.php
 *
 * Extreme VOSS ISIS Neighbors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 *
 * Code repurposed from Cisco IOS-XE ISIS Neighbors
 * LibreNMS/OS/Iosxe.php

namespace LibreNMS\OS;

use App\Models\IsisAdjacency;
use LibreNMS\Interfaces\Discovery\IsIsDiscovery;
use LibreNMS\Interfaces\Polling\IsIsPolling;
use LibreNMS\Util\IP;
use SnmpQuery;

    /**
     * Array of shortened ISIS codes
     *
     * @var array
     */
    protected $isis_codes = [
        'l1IntermediateSystem' => 'L1',
        'l2IntermediateSystem' => 'L2',
        'l1L2IntermediateSystem' => 'L1L2',
    ];

    public function discoverIsIs(): Collection
    {
        // Check if the device has any ISIS enabled interfaces
        $circuits = SnmpQuery::enumStrings()->walk('ISIS-MIB::isisCircIfIndex');
        $adjacencies = new Collection;

        if ($circuits->isValid()) {
            $circuits = $circuits->table(1);
            $adjacencies_data = SnmpQuery::enumStrings()->walk('ISIS-MIB::isisISAdjState')->table(2);

            foreach ($adjacencies_data as $circuit_index => $adjacency_list) {
                foreach ($adjacency_list as $adjacency_index => $adjacency_data) {
                    if (empty($circuits[$circuit_index]['ISIS-MIB::isisCircIfIndex'])) {
                        continue;
                    }

                    if (($circuits[$circuit_index]['ISIS-MIB::isisCircPassiveCircuit'] ?? 'true') == 'true') {
                        continue; // Do not poll passive interfaces and bad data
                    }

                    $adjacencies->push(new IsisAdjacency([
                        'device_id' => $this->getDeviceId(),
                        'index' => "[$circuit_index][$adjacency_index]",
                        'ifIndex' => $circuits[$circuit_index]['ISIS-MIB::isisCircIfIndex'],
                        'port_id' => $this->ifIndexToId($circuits[$circuit_index]['ISIS-MIB::isisCircIfIndex']),
                        'isisCircAdminState' => $circuits[$circuit_index]['ISIS-MIB::isisCircAdminState'] ?? 'down',
                        'isisISAdjState' => $adjacency_data['ISIS-MIB::isisAdjState'] ?? 'down',
                        'isisISAdjNeighSysType' => Arr::get($this->isis_codes, $adjacency_data['ISIS-MIB::isisISAdjNeighSysType'] ?? '', 'unknown'),
                        'isisISAdjNeighSysID' => $this->formatIsIsId($adjacency_data['ISIS-MIB::isisISAdjNeighSysID'] ?? ''),
                        'isisISAdjNeighPriority' => $adjacency_data['ISIS-MIB::isisISAdjNeighPriority'] ?? '',
                        'isisISAdjLastUpTime' => $this->parseAdjacencyTime($adjacency_data['ISIS-MIB::isisISAdjLastUpTime'] ?? 0),
                        'isisISAdjAreaAddress' => implode(',', array_map([$this, 'formatIsIsId'], $adjacency_data['ISIS-MIB::isisISAdjAreaAddress'] ?? [])),
                        'isisISAdjIPAddrType' => implode(',', $adjacency_data['ISIS-MIB::isisISAdjIPAddrType'] ?? []),
                        'isisISAdjIPAddrAddress' => implode(',', array_map(function ($ip) {
                            return (string) IP::fromHexstring($ip, true);
                        }, $adjacency_data['ISIS-MIB::isisISAdjIPAddrAddress'] ?? [])),
                    ]));
                }
            }
        }

        return $adjacencies;
    }

    public function pollIsIs($adjacencies): Collection
    {
        $states = SnmpQuery::enumStrings()->walk('ISIS-MIB::isisAdjState')->values();
        $up_count = array_count_values($states)['up'] ?? 0;

        if ($up_count !== $adjacencies->count()) {
            echo 'New Adjacencies, running discovery';

            return $this->fillNew($adjacencies, $this->discoverIsIs());
        }

        $uptime = SnmpQuery::walk('ISIS-MIB::isisISAdjLastUpTime')->values();

        return $adjacencies->each(function (IsisAdjacency $adjacency) use ($states, $uptime) {
            $adjacency->isisISAdjState = $states['ISIS-MIB::isisAdjState' . $adjacency->index] ?? $adjacency->isisISAdjState;
            $adjacency->isisISAdjLastUpTime = $this->parseAdjacencyTime($uptime['ISIS-MIB::isisCircLastUpTime' . $adjacency->index] ?? 0);
        });
    }
