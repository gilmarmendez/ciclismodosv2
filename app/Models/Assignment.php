<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Assignment extends Model
{
    use HasFactory;

    protected $fillable = [
        'device_id',
        'alias',
        'id_rutas'
    ];

    public function device()
    {
        return $this->belongsTo(Device::class);
    }

    public function rute()
    {
        return $this->belongsTo(Rute::class, 'id_rutas');
    }
}
