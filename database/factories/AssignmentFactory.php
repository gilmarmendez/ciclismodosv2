<?php



use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Assignment>
 * 
 */

 class AssignmentFactory extends Factory
{
    protected $model = Assignment::class;

    public function definition()
    {
        return [
            'device_id' => Device::factory(),
            'alias' => $this->faker->word,
            'id_rutas' => Rute::factory(),
        ];
    }
}
