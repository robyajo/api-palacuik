<?php

namespace Database\Seeders;

use App\Models\Profile;
use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class ProfileSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Ambil pengguna terakhir
        $user = User::latest()->first();

        // Pastikan pengguna terakhir ditemukan
        if ($user) {
            Profile::create([
                'user_id' => $user->id, // Gunakan 'id', bukan 'uuid' untuk relasi
            ]);
        } else {
            $this->command->info('Tidak ada pengguna yang ditemukan.');
        }
    }
}
