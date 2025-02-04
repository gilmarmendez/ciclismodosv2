<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\DeviceController;
use App\Http\Controllers\PositionController;
use App\Http\Controllers\RuteController;
use App\Http\Controllers\AssignmentController;

// Rutas de autenticación (No protegidas)



Route::post('/register', function (Request $request) {
    $request->validate([
        'name' => 'required|string',
        'email' => 'required|email|unique:users',
        'password' => 'required|min:6',
    ]);

    $user = \App\Models\User::create([
        'name' => $request->name,
        'email' => $request->email,
        'password' => \Illuminate\Support\Facades\Hash::make($request->password),
    ]);

    return response()->json(['message' => 'Usuario registrado con éxito'], 201);
});

Route::post('/login', function (Request $request) {
    $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);

    $user = \App\Models\User::where('email', $request->email)->first();

    if (! $user || ! \Illuminate\Support\Facades\Hash::check($request->password, $user->password)) {
        return response()->json(['message' => 'Credenciales incorrectas'], 401);
    }

    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json(['token' => $token]);
});

// Agrupar todas las rutas que requieren autenticación
Route::middleware('auth:sanctum')->group(function () {

    // Endpoints protegidos para el proyecto CiclismoDos
    Route::get('devices', [DeviceController::class, 'index']);
    
    Route::post('devices', [DeviceController::class, 'store']);
    Route::get('devices/{device}', [DeviceController::class, 'show']);
    Route::put('devices/{device}', [DeviceController::class, 'update']);
    Route::delete('devices/{device}', [DeviceController::class, 'destroy']);

    Route::get('positions', [PositionController::class, 'index']);
    Route::post('positions', [PositionController::class, 'store']);
    Route::get('positions/{position}', [PositionController::class, 'show']);
    Route::put('positions/{position}', [PositionController::class, 'update']);
    Route::delete('positions/{position}', [PositionController::class, 'destroy']);

    Route::get('rutes', [RuteController::class, 'index']);
    Route::post('rutes', [RuteController::class, 'store']);
    Route::get('rutes/{rute}', [RuteController::class, 'show']);
    Route::put('rutes/{rute}', [RuteController::class, 'update']);
    Route::delete('rutes/{rute}', [RuteController::class, 'destroy']);

    Route::get('assignments', [AssignmentController::class, 'index']);
    Route::post('assignments', [AssignmentController::class, 'store']);
    Route::get('assignments/{assignment}', [AssignmentController::class, 'show']);
    Route::put('assignments/{assignment}', [AssignmentController::class, 'update']);
    Route::delete('assignments/{assignment}', [AssignmentController::class, 'destroy']);

    // Rutas especiales protegidas
    Route::get('/filtered-positions/{deviceId}/{ruteId}', [PositionController::class, 'getFilteredPositions']);

    // Ruta para obtener usuario autenticado
    Route::get('/user', function (Request $request) {
        return response()->json($request->user());
    });

    // Ruta para cerrar sesión (revocar tokens)
    Route::post('/logout', function (Request $request) {
        $request->user()->tokens()->delete();
        return response()->json(['message' => 'Sesión cerrada correctamente']);
    });

});
