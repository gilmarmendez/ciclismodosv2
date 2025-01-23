<?php

namespace App\Http\Controllers;

use App\Models\Assignment;
use Illuminate\Http\Request;

class AssignmentController extends Controller
{
    public function index()
    {
        return Assignment::all();
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'device_id' => 'required|exists:devices,id',
            'alias' => 'required|string',
            'id_rutas' => 'required|exists:rutes,id',
        ]);

        $assignment = Assignment::create($validated);

        return response()->json($assignment, 201);
    }

    public function show(Assignment $assignment)
    {
        return $assignment;
    }

    public function update(Request $request, Assignment $assignment)
    {
        $validated = $request->validate([
            'device_id' => 'sometimes|exists:devices,id',
            'alias' => 'sometimes|string',
            'id_rutas' => 'sometimes|exists:rutes,id',
        ]);

        $assignment->update($validated);

        return response()->json($assignment);
    }

    public function destroy(Assignment $assignment)
    {
        $assignment->delete();

        return response()->json(null, 204);
    }
}