<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use App\Models\Rute;

class RuteFactory extends Factory
{
    protected $model = Rute::class;

    public function definition()
    {
        return [
            'nombre' => $this->faker->text(50),
            'disponibilidad' => $this->faker->date(),
        ];
    }
}

