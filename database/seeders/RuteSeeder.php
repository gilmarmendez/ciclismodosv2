<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\Rute;

class RuteSeeder extends Seeder
{
    public function run()
    {
        Rute::factory()->count(10)->create();
    }
}
