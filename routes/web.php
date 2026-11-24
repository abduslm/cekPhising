<?php

use App\Http\Controllers\PhishingController;
use Illuminate\Support\Facades\Route;

// Pemeriksaan otomatis membuka situs dan memanggil layanan luar, jadi dibatasi per IP.
Route::match(['get', 'post'], '/', PhishingController::class)->middleware('throttle:15,1');
