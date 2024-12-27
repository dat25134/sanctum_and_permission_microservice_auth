<?php

use App\Http\Controllers\Api\PostController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

// Route::get('/posts', [PostController::class, 'index'])->middleware('auth.api');

Route::get('/posts', [PostController::class, 'index'])->middleware(['auth.api', 'role:admin']);
