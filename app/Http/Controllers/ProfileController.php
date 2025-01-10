<?php

namespace App\Http\Controllers;

use App\Models\Profile;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class ProfileController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        // Ambil pengguna yang sedang login
        $user = Auth::user();

        // Cek apakah pengguna sudah login
        if (!$user) {
            return response()->json([
                'success' => false,
                'status' => 401,
                'message' => 'Unauthorized',
            ], 401);
        }

        // Ambil profil berdasarkan user_id
        $profile = Profile::where('user_id', $user->id)->first();

        // Cek apakah profil ditemukan
        if (!$profile) {
            return response()->json([
                'success' => false,
                'status' => 404,
                'message' => 'Profil tidak ditemukan',
            ], 404);
        }

        // Berikan respons dengan data profil
        return response()->json([
            'success' => true,
            'status' => 200,
            'data' => [
                'uuid' => $profile->uuid,
                'phone' => $profile->phone,
                'profile' => $profile->profile,
                'profile_photo_path' => $profile->profile_photo_path,
            ],
        ], 200);
    }

    public function show(string $uuid)
    {
        $profile = Profile::where('uuid', $uuid)->first();
        if (!$profile) {
            return response()->json([
                'success' => false,
                'status' => 404,
                'message' => 'Profil tidak ditemukan',
            ], 404);
        }

        return response()->json([
            'success' => true,
            'status' => 200,
            'data' => [
                'uuid' => $profile->uuid,
                'phone' => $profile->phone,
                'profile' => $profile->profile,
                'profile_photo_path' => $profile->profile_photo_path,
            ],
        ], 200);
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $uuid)
    {
        // Validasi data input
        $validatedData = Validator::make($request->all(), [
            'phone' => 'nullable|string|max:15',
            'profile' => 'nullable|string|max:255',
            'profile_photo_path' => 'nullable|string|max:255',
        ], [
            'phone.max' => 'Nomor telepon tidak boleh lebih dari 15 karakter.',
            'profile.max' => 'Profil tidak boleh lebih dari 255 karakter.',
            'profile_photo_path.max' => 'Path foto profil tidak boleh lebih dari 255 karakter.',
        ]);
        if ($validatedData->fails()) {
            return response()->json([
                'success' => false,
                'status' => 422,
                'message' => $validatedData->errors()->first(),
            ], 422);
        }
        // Cari profil berdasarkan UUID
        $profile = Profile::where('uuid', $uuid)->first();

        // Jika profil tidak ditemukan
        if (!$profile) {
            return response()->json([
                'success' => false,
                'status' => 404,
                'message' => 'Profil tidak ditemukan.',
            ], 404);
        }

        // Perbarui data profil
        $profile->update($validatedData);

        return response()->json([
            'success' => true,
            'status' => 200,
            'message' => 'Profil berhasil diperbarui.',
            'data' => [
                'uuid' => $profile->uuid,
                'phone' => $profile->phone,
                'profile' => $profile->profile,
                'profile_photo_path' => $profile->profile_photo_path,
            ], // Tambahkan data profil untuk respon
        ], 200);
    }
}
