<?php

use App\Models\Product;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ProductController;

Route::get('/products', [ProductController::class,"index"]);

Route::middleware("auth:sanctum")->post("/products", function (Request $request) {
    $product = Product::create([
        'name' => $request->name,
        'description' => $request->description,
        'price' => $request->price
    ]);

    return response()->json([
        "message" => "Product Added Successfully"
    ], 201);
});

Route::middleware("auth:sanctum")->put("/products/{id}", function (Request $request, $id) {
    $product = Product::findOrFail($id);

    // Validasi input
    $request->validate([
        'name' => 'required|string',
        'description' => 'required|string',
        'price' => 'required|numeric',
    ]);

    $product->update([
        'name' => $request->name,
        'description' => $request->description,
        'price' => $request->price
    ]);

    return response()->json([
        "message" => "Product updated successfully"
    ], 200);
});

Route::middleware("auth:sanctum")->delete("/products/{id}", function (Request $request, $id) {
    $product = Product::findOrFail($id);

    $product->delete();

    return response()->json([
        "message" => "Product deleted successfully"
    ], 200);
});

Route::post('/register', function (Request $request) {
    $user = User::create([
        'name' => $request->name,
        'email' => $request->email,
        'password' => Hash::make($request->password)
    ]);

    return response()->json([
        "message" => "User Registered Successfully",
    ], 201);
});

Route::post("/login", function (Request $request) {
    $user = User::where("email", $request->email)->first();

    if (! $user || ! Hash::check($request->password, $user->password)) {
        return response()->json([
            "message" => "Invalid Credentials"
        ], 401);
    }

    $token = $user->createToken('auth_token')->plainTextToken;
    Auth::login($user);

    return response()->json([
        "token" => $token,
    ]);
});

Route::middleware("auth:sanctum")->post("/logout", function (Request $request) {
    $user = Auth::user();
    $user->tokens()->delete();
});

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');
