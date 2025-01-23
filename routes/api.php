<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth:sanctum'])->get('/user', function (Request $request) {
    return $request->user();
});


use App\Http\Controllers\DeviceController;
use App\Http\Controllers\PositionController;
use App\Http\Controllers\RuteController;
use App\Http\Controllers\AssignmentController;

// Endpoints for the CiclismoDos project
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


//Especiales

Route::get('/filtered-positions/{deviceId}/{ruteId}', [PositionController::class, 'getFilteredPositions']);
