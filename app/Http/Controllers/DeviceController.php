<?php

namespace App\Http\Controllers;

use App\Models\Device;
use App\Models\Position;
use App\Models\Rute;
use App\Models\Assignment;
use Illuminate\Http\Request;

class DeviceController extends Controller
{
    public function index()
    {
        return Device::all();
    }

    public function store(Request $request)
    {
        $validated = $request->validate([
            'nombre' => 'required|string',
        ]);

        $device = Device::create($validated);

        return response()->json($device, 201);
    }

    public function show(Device $device)
    {
        return $device;
    }

    public function update(Request $request, Device $device)
    {
        $validated = $request->validate([
            'nombre' => 'sometimes|string',
        ]);

        $device->update($validated);

        return response()->json($device);
    }

    public function destroy(Device $device)
    {
        $device->delete();

        return response()->json(null, 204);
    }
}
