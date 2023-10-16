<?php

namespace App\Http\Controllers;

use App\Models\User;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use App\Http\Requests\LoginRequest;
use App\Http\Resources\AuthResource;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Http\Requests\RegisterRequest;

class AuthController extends Controller
{
    public function register(RegisterRequest $request)
    {
        $user = User::create(
            [
                'name' => $request->input('name'),
                'email' => $request->input('email'),
                'password' => Hash::make($request->input('password'))
            ]
        );
        return new AuthResource($user, Response::HTTP_CREATED, 'Register success');
    }

    public function login(LoginRequest $request)
    {
        $user = User::where('email', $request->input('email'))->firstOrFail();
        if (!Hash::check($request->input('password'), $user->password)) {
            abort(Response::HTTP_UNAUTHORIZED, 'Invalid credentials');
        }

        $token = JWT::encode(
            [
                'iat' => now()->timestamp,
                'exp' => now()->addSeconds(config('auth.jwt_ttl'))->timestamp,
                'sub' => $user->id,
                'user' => $user
            ],
            config('auth.jwt_key'),
            'HS256'
        );
        return new AuthResource([
            'access_token' => $token,
            'token_type' => 'Bearer'
        ], Response::HTTP_OK, 'Login success');
    }

    /*
    public function logout(Request $request)
    {
    }*/

    public function info()
    {
        $user = (array) Auth::user();
        return new AuthResource($user, Response::HTTP_OK, 'User info');
    }
}
