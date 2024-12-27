<?php

namespace App\Models;

use Spatie\Permission\Traits\HasRoles;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    use HasRoles;

    protected $attributes = [];
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function __construct(array $attributes = [])
    {
        $this->attributes = $attributes;
        parent::__construct($attributes);
    }

    // Override method từ HasRoles trait
    public function getAllPermissions($keys = null)
    {
        return collect($this->attributes['permissions'] ?? [])
            ->map(function ($permission) {
                return is_string($permission) ? $permission : $permission['name'];
            });
    }

    // Override method từ HasRoles trait
    public function roles()
    {
        return collect($this->attributes['roles'] ?? [])
            ->map(function ($role) {
                return is_string($role) ? $role : $role['name'];
            });
    }

    // Override method từ HasRoles trait
    public function hasRole($roles, string $guard = null): bool
    {
        if (is_string($roles) && false !== strpos($roles, '|')) {
            $roles = explode('|', $roles);
        }

        if (is_string($roles)) {
            return in_array($roles, $this->getRoleNames()->toArray());
        }

        if (is_array($roles)) {
            foreach ($roles as $role) {
                if (in_array($role, $this->getRoleNames()->toArray())) {
                    return true;
                }
            }
        }

        return false;
    }

    // Override method từ HasRoles trait
    public function hasPermissionTo($permission, $guardName = null): bool
    {
        $permissionNames = $this->getAllPermissions()
            ->map(function ($permission) {
                return is_string($permission) ? $permission : $permission['name'];
            })
            ->toArray();

        return in_array($permission, $permissionNames);
    }

    public function getRoleNames()
    {
        return collect($this->attributes['roles'] ?? [])
            ->map(function ($role) {
                return is_string($role) ? $role : $role['name'];
            });
    }

    public function hasAnyRole($roles)
    {
        return $this->roles()->intersect($roles)->isNotEmpty();
    }
}
