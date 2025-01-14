<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class MarketPlace extends Model
{
    use  SoftDeletes;
    protected $table = 'market_places';
    protected $fillable = [
        'uuid',
        'name',
        'logo',
        'logo_path',
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
