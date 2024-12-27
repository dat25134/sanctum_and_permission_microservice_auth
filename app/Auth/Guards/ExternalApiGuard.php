<?php

namespace App\Auth\Guards;

use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ExternalApiGuard implements Guard
{
    protected $request;
    protected $user;
    protected $authServiceUrl;

    public function __construct(Request $request)
    {
        $this->request = $request;
        $this->authServiceUrl = config('auth.services.auth_url', 'http://192.168.110.216');
    }

    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $token = $this->request->bearerToken();

        if (!$token) {
            return null;
        }

        $cacheKey = 'auth_user_' . md5($token);
        
        try {
            $userData = Cache::remember($cacheKey, 300, function () use ($token) {
                $response = Http::withToken($token)
                    ->timeout(5)
                    ->post("{$this->authServiceUrl}/api/verify-token");

                if ($response->successful()) {
                    $data = $response->json();
                    return array_merge($data, [
                        'roles' => $data['roles'] ?? [],
                        'permissions' => $data['permissions'] ?? []
                    ]);
                }
                
                return null;
            });

            if ($userData) {
                $this->user = new \App\Models\User((array) $userData);
                return $this->user;
            }
        } catch (\Exception $e) {
            Log::error('Auth service error: ' . $e->getMessage());
            Cache::forget($cacheKey);
        }

        return null;
    }

    public function check()
    {
        return $this->user() !== null;
    }

    public function guest()
    {
        return !$this->check();
    }

    public function id()
    {
        return $this->user() ? $this->user()->getAuthIdentifier() : null;
    }

    public function validate(array $credentials = [])
    {
        try {
            $response = Http::post("{$this->authServiceUrl}/api/login", $credentials);
            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Auth validation error: ' . $e->getMessage());
            return false;
        }
    }

    public function setUser(Authenticatable $user)
    {
        $this->user = $user;
        return $this;
    }

    public function hasUser()
    {
        return $this->user() !== null;
    }
}
