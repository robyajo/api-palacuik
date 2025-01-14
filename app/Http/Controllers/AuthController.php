<?php

namespace App\Http\Controllers;

use App\Models\Profile;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|max:200',
            'email' => 'required|email|unique:users,email',
            'password' => [
                'required',
                'min:3',
                'regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&_])[A-Za-z\d@$!%*#?&_]+$/',
            ],
            'c_password' => 'required|same:password',
        ], [
            'name.required' => 'Kolom nama tidak boleh kosong.',
            'name.max' => 'Nama tidak boleh lebih dari 200 karakter.',
            'email.required' => 'Kolom email tidak boleh kosong.',
            'email.email' => 'Format email tidak valid.',
            'email.unique' => 'Email yang Anda masukkan sudah terdaftar.',
            'password.required' => 'Kolom password tidak boleh kosong.',
            'password.min' => 'Password yang Anda masukkan minimal 3 karakter huruf dan angka.',
            'password.regex' => 'Password harus mengandung setidaknya satu huruf besar, satu huruf kecil, satu angka, dan satu simbol.',
            'c_password.required' => 'Kolom konfirmasi password tidak boleh kosong.',
            'c_password.same' => 'Konfirmasi password yang Anda masukkan tidak sama. Silakan ulangi kembali.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'status' => 422,
                'message' => $validator->errors()->first(),
            ], 422);
        }

        try {
            DB::beginTransaction();

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'role' => 'user',
                'password' => Hash::make($request->password),
            ]);
            Profile::create([
                'user_id' => $user->id,
            ]);

            $token = Auth::login($user);
            DB::commit();
            return response()->json([
                'success' => true,
                'status' => 201,
                'message' => 'Pendaftaran Akun Berhasil.',
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'uuid' => $user->uuid,
                        'name' => $user->name,
                        'email' => $user->email,
                        'role' => $user->role,
                    ],
                    'access_token' => [
                        'token' =>  $token,
                        'token_type' => 'Bearer',
                        'expires_in' => auth()->factory()->getTTL() * 60
                    ]
                ],
            ], 201);
        } catch (\Exception $e) {
            DB::rollBack();
            return response()->json([
                'success' => false,
                'status' => 500,
                'message' => $e->getMessage() . 'Terjadi kesalahan saat mendaftarkan akun. Silakan coba lagi.',
            ], 500);
        }
    }


    public function login(Request $request)
    {
        // Validasi input
        $validator = Validator::make(
            $request->all(),
            [
                'email' => 'required|email|exists:users,email',
                'password' => 'required|min:6',
            ],
            [
                'email.required' => 'Form Alamat Email Tidak Boleh Kosong',
                'email.email' => 'Format Alamat Email Salah',
                'email.exists' => 'Alamat Email Tidak Terdaftar',
                'password.required' => 'Form Password Tidak Boleh Kosong',
                'password.min' => 'Password Minimal 6 Karakter',
            ]
        );

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'status' => 400,
                'message' => $validator->errors()->first(),
            ], 400);
        }

        try {
            // Ambil user berdasarkan email

            if (!$token = Auth::attempt($request->only('email', 'password'))) {
                return response()->json([
                    'status' => 401,
                    'success' => false,
                    'message' => 'Email atau password yang Anda masukkan salah.',
                ], 401);
            }

            // Get the authenticated user.
            $user = Auth::user();

            // (optional) Attach the role to the token.
            $token = JWTAuth::claims(['role' => $user->email])->fromUser($user);

            return response()->json([
                'success' => true,
                'status' => 200,
                'message' => 'Berhasil masuk',
                'data' => [
                    'user' => [
                        'id' => $user->id,
                        'uuid' => $user->uuid,
                        'name' => $user->name,
                        'email' => $user->email,
                        'role' => $user->role,
                    ],
                    'access_token' => [
                        'token' => $token,
                        'token_type' => 'Bearer',
                        'expires_in' => auth()->factory()->getTTL() * 60
                    ],
                ],
            ], 200);
        } catch (\Throwable $e) {
            // Log error untuk keperluan debugging
            Log::error('Login Error: ' . $e->getMessage());

            return response()->json([
                'success' => false,
                'status' => 500,
                'message' => 'Terjadi kesalahan pada server. Silakan coba lagi nanti.',
            ], 500);
        }
    }

    public function refresh()
    {
        try {
            $token = Auth::refresh();
            return response()->json([
                'status' => 200,
                'success' => true,
                'message' => 'Token berhasil diperbarui',
                'data' => [
                    'access_token' => $token,
                    'token_type' => 'Bearer',
                ]
            ]);
        } catch (\Throwable $th) {
            return response()->json([
                'status' => 500,
                'success' => false,
                'message' => 'Gagal memperbarui token: ' . $th->getMessage(),
                'data' => []
            ], 500);
        }
    }
    public function logout()
    {
        try {
            Auth::logout();
            return response()->json([
                'success' => true,
                'status' => 200,
                'message' => 'Berhasil keluar',
            ], 200);
        } catch (\Throwable $th) {
            return response()->json([
                'success' => false,
                'status' => 500,
                'message' => $th->getMessage() . 'Terjadi kesalahan pada server. Silakan coba lagi nanti.',
            ], 500);
        }
    }
}
