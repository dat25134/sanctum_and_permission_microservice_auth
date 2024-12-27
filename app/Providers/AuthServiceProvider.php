<?php

namespace App\Providers;

use App\Auth\Guards\ExternalApiGuard;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;

class AuthServiceProvider extends ServiceProvider
{
    public function boot()
    {
        $this->registerPolicies();

        Auth::extend('external-api', function ($app, $name, array $config) {
            return new ExternalApiGuard($app['request']);
        });
    }
}