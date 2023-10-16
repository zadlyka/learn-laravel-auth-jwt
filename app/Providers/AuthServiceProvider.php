<?php

namespace App\Providers;

// use Illuminate\Support\Facades\Gate;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;

class AuthServiceProvider extends ServiceProvider
{
    /**
     * The model to policy mappings for the application.
     *
     * @var array<class-string, class-string>
     */
    protected $policies = [
        //
    ];

    /**
     * Register any authentication / authorization services.
     */
    public function boot(): void
    {
        Auth::viaRequest('custom-token', function (Request $request) {
            if (!$request->bearerToken()) return null;
            $data = JWT::decode($request->bearerToken(), new Key(config('auth.jwt_key'), 'HS256'));
            return $data->user;
        });
    }
}
