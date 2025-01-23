<?php

namespace App\Http\Controllers;

use App\Models\rute;
use Illuminate\Http\Request;

class RuteController extends Controller
{
    public function index()
    {
        return Rute::all();
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'nombre' => 'required|string',
            'disponibilidad' => 'required|date',
        ]);

        $rute = Rute::create($validated);

        return response()->json($rute, 201);
    }

    public function show(Rute $rute)
    {
        return $rute;
    }

    public function update(Request $request, Rute $rute)
    {
        $validated = $request->validate([
            'nombre' => 'sometimes|string',
            'disponibilidad' => 'sometimes|date',
        ]);

        $rute->update($validated);

        return response()->json($rute);
    }

    public function destroy(Rute $rute)
    {
        $rute->delete();

        return response()->json(null, 204);
    }
}
