<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Device;
use App\Models\Position;
use App\Models\Rute;
use App\Models\Assignment;

class DatabaseSeeder extends Seeder
{
    public function run()
    {
        $this->call([
            DeviceSeeder::class,
            PositionSeeder::class,
            RuteSeeder::class,
            AssignmentSeeder::class,
        ]);
    }
}