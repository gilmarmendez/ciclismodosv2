<?php

namespace App\Http\Controllers;

use App\Models\position;
use App\Models\rute;
use Illuminate\Http\Request;

class PositionController extends Controller
{
    public function index()
    {
        return Position::all();
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'latitud' => 'required|numeric',
            'longitud' => 'required|numeric',
            'elevation' => 'required|integer',
            'distancia' => 'required|numeric',
            'id_dispositivo' => 'required|exists:devices,id',
        ]);

        $position = Position::create($validated);

        return response()->json($position, 201);
    }

    public function show(Position $position)
    {
        return $position;
    }

    public function update(Request $request, Position $position)
    {
        $validated = $request->validate([
            'latitud' => 'sometimes|numeric',
            'longitud' => 'sometimes|numeric',
            'elevation' => 'sometimes|integer',
            'distancia' => 'sometimes|numeric',
            'id_dispositivo' => 'sometimes|exists:devices,id',
        ]);

        $position->update($validated);

        return response()->json($position);
    }

    public function destroy(Position $position)
    {
        $position->delete();

        return response()->json(null, 204);
    }


    public function getFilteredPositions($deviceId, $ruteId)
    {
        // Buscar la ruta por su ID
        $rute = Rute::find($ruteId);
        if (!$rute) {
            return response()->json([
                'message' => 'No se encontró la ruta con el ID proporcionado.',
            ], 404);
        }

        // Filtrar posiciones por id_dispositivo y condición de fecha
        $positions = Position::where('id_dispositivo', $deviceId)
            ->where('updated_at', '>', $rute->created_at)
            ->get(['latitud', 'longitud', 'elevation']);

        // Si no se encuentran posiciones
        if ($positions->isEmpty()) {
            return response()->json([
                'message' => 'No se encontraron posiciones con los criterios proporcionados.',
            ], 404);
        }

        // Construir la estructura GeoJSON
        $geojson = [
            "type" => "Feature",
            "properties" => [
                "name" => $rute->nombre, // Cambia 'nombre' si usas otro campo
                "elevations" => $positions->pluck('elevation'),
            ],
            "geometry" => [
                "type" => "LineString",
                "coordinates" => $positions->map(fn($position) => [
                    $position->longitud,
                    $position->latitud,
                ]),
            ],
        ];

        // Retornar la respuesta
        return response()->json($geojson, 200, [], JSON_PRETTY_PRINT);
    }
   
}
