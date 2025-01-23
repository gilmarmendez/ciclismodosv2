<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Rute extends Model
{
    use HasFactory;

   

    // Asegúrate de reflejar los cambios al campo 'nombre'
    protected $fillable = ['nombre', 'disponibilidad'];

    public function positions()
    {
        return $this->hasMany(Position::class, 'id_ruta');
    }
}

