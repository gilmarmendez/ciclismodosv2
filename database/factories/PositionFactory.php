<?php

namespace Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use App\Models\Position;
use App\Models\Device;


class PositionFactory extends Factory
{
    protected $model = Position::class;

    public function definition()
    {
        return [
            'latitud' => $this->faker->latitude,
            'longitud' => $this->faker->longitude,
            'elevation' => $this->faker->numberBetween(0, 5000),
            'distancia' => $this->faker->numberBetween(0, 5000),
            'id_dispositivo' => Device::factory(),
        ];
    }
}