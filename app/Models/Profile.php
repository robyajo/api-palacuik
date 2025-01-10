<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Profile extends Model
{
    use  SoftDeletes;
    protected $table = 'profiles';
    protected $fillable = [
        'uuid',
        'user_id',
        'phone',
        'profile_photo',
        'profile_photo_path',
    ];
    protected static function boot()
    {
        parent::boot();

        static::creating(function ($model) {
            if (empty($model->uuid)) {
                $model->uuid = (string) str()->uuid();
            }
        });
    }
}
