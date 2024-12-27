<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Auth\Middleware\Authenticate as Middleware;

class ExternalApiAuth extends Middleware
{
    protected function authenticate($request, array $guards)
    {
        if (!$this->auth->guard('api')->check()) {
            $this->unauthenticated($request, $guards);
        }
    }

    protected function redirectTo($request)
    {
        return response()->json(['error' => 'Unauthenticated.'], 401);
    }
}