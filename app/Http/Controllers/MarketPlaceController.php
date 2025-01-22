<?php

namespace App\Http\Controllers;

use App\Models\MarketPlace;
use Exception;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class MarketPlaceController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index(Request $request)
    {
        $search = $request->query('search', ''); // Nilai default jika search tidak diisi
        $perPage = $request->query('per_page', 10); // Nilai default jika per_page tidak diisi

        try {
            // Query data dengan pencarian
            $data = MarketPlace::select('uuid', 'name', 'logo', 'logo_path')
                ->when($search, function ($query, $search) {
                    return $query->where('name', 'LIKE', "%{$search}%");
                })
                ->orderBy('created_at', 'desc')
                ->paginate($perPage);

            // Struktur respons API
            return response()->json([
                'success' => true,
                'status' => 200,
                'message' => 'Data berhasil diambil.',
                'data' => $data,
            ]);
        } catch (\Throwable $th) {
            // Respons error jika terjadi kesalahan
            return response()->json([
                'success' => false,
                'status' => 500,
                'message' => 'Terjadi kesalahan pada server. Silakan coba lagi nanti.',
                'error' => $th->getMessage(),
            ], 500);
        }
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|max:200',
            'logo' => 'required|file|mimes:jpeg,png,jpg|max:2000',
        ], [
            'logo.required' => 'Logo wajib diisi.',
            'logo.file' => 'Logo harus berupa file.',
            'logo.mimes' => 'Logo harus berupa file dengan format jpeg, png, jpg.',
            'logo.max' => 'Ukuran file logo maksimal 2MB.',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'status' => 422,
                'message' => $validator->errors()->first(),
            ], 422);
        }

        try {
            $fileName = null;
            $savePath = null;

            if ($request->hasFile('logo')) {
                $file = $request->file('logo');

                $uploadPath = public_path('assets/marketplace/logo');
                if (!file_exists($uploadPath)) {
                    mkdir($uploadPath, 0777, true);
                }

                $fileName = 'logo_' . $request->name . '_' . str()->random(10) . '.' . $file->getClientOriginalExtension();

                $file->move($uploadPath, $fileName);

                $baseUrl = config('app.url');
                $savePath = $baseUrl . '/assets/marketplace/logo/' . $fileName;
            }
            $data = MarketPlace::create([
                'name' => $request->name,
                'logo' => $fileName,
                'logo_path' => $savePath
            ]);
            return response()->json([
                'success' => true,
                'status' => 201,
                'message' => 'Data berhasil disimpan.',
                'data' => $data
            ], 201);
        } catch (\Exception $e) {
            return response()->json([
                'success' => false,
                'status' => 500,
                'message' => $e->getMessage() . 'Terjadi kesalahan pada server. Silakan coba lagi.',
            ], 500);
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(string $uuid)
    {
        try {
            $data = MarketPlace::select('uuid', 'name', 'logo', 'logo_path')->where('uuid', $uuid)->firstOrFail();
            return response()->json([
                'success' => true,
                'status' => 200,
                'message' => 'Data berhasil diambil.',
                'data' => $data,
            ]);
        } catch (\Illuminate\Database\Eloquent\ModelNotFoundException $e) {
            return response()->json([
                'success' => false,
                'status' => 404,
                'message' => 'Data tidak ditemukan.',
            ], 404);
        } catch (\Exception $e) {
            Log::error('Error updating marketplace: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'status' => 500,
                'message' => 'Terjadi kesalahan pada server. Silakan coba lagi.',
            ], 500);
        }
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $uuid)
    {
        try {
            // Validasi input
            $validator = Validator::make($request->all(), [
                'name' => 'required|max:200',
                'logo' => 'nullable|file|mimes:jpeg,png,jpg|max:2000',
            ], [
                'logo.file' => 'Logo harus berupa file.',
                'logo.mimes' => 'Logo harus berupa file dengan format jpeg, png, jpg.',
                'logo.max' => 'Ukuran file logo maksimal 2MB.',
            ]);

            if ($validator->fails()) {
                return response()->json([
                    'success' => false,
                    'status' => 422,
                    'message' => $validator->errors()->first(),
                ], 422);
            }

            // Cari data
            $data = MarketPlace::where('uuid', $uuid)->firstOrFail();
            $fileName = $data->logo;
            $savePath = $data->logo_path;

            if ($request->hasFile('logo')) {
                // Hapus file lama jika ada
                $oldFilePath = public_path('assets/marketplace/logo/' . $fileName);
                if ($fileName && file_exists($oldFilePath)) {
                    unlink($oldFilePath);
                }

                $file = $request->file('logo'); // Fixed: Changed from 'file_voice' to 'logo'
                $uploadPath = public_path('assets/marketplace/logo');

                // Buat direktori jika belum ada
                if (!file_exists($uploadPath)) {
                    mkdir($uploadPath, 0777, true);
                }

                // Generate nama file yang aman
                $fileName = 'logo_' . str_replace(' ', '_', $request->name) . '_' . str()->random(10) . '.' . $file->getClientOriginalExtension();

                // Pindahkan file
                $file->move($uploadPath, $fileName);

                // Generate URL path
                $baseUrl = config('app.url');
                $savePath = $baseUrl . '/assets/marketplace/logo/' . $fileName;
            }

            // Update data
            $data->update([
                'name' => $request->name,
                'logo' => $fileName,
                'logo_path' => $savePath
            ]);

            // Refresh data untuk mendapatkan data terbaru
            $data = $data->fresh();

            return response()->json([
                'success' => true,
                'status' => 200,
                'message' => 'Data berhasil diperbarui.',
                'data' => $data
            ], 200);
        } catch (ModelNotFoundException $e) {
            return response()->json([
                'success' => false,
                'status' => 404,
                'message' => 'Data tidak ditemukan.',
            ], 404);
        } catch (Exception $e) {
            Log::error('Error updating marketplace: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'status' => 500,
                'message' => 'Terjadi kesalahan pada server. Silakan coba lagi.',
            ], 500);
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $uuid)
    {
        try {
            $data = MarketPlace::where('uuid', $uuid)->firstOrFail();
            if ($data->file_voice && file_exists(public_path('assets/marketplace/logo/' . $data->logo))) {
                unlink(public_path('assets/marketplace/logo/' . $data->logo));
            }
            $data->delete();
            return response()->json([
                'success' => true,
                'status' => 200,
                'message' => 'Data berhasil dihapus.',
                'data' => $data
            ], 200);
        } catch (\Illuminate\Database\Eloquent\ModelNotFoundException $e) {
            return response()->json([
                'success' => false,
                'status' => 404,
                'message' => 'Data tidak ditemukan.',
            ], 404);
        } catch (\Exception $e) {
            Log::error('Error updating marketplace: ' . $e->getMessage());
            return response()->json([
                'success' => false,
                'status' => 500,
                'message' => 'Terjadi kesalahan pada server. Silakan coba lagi.',
            ], 500);
        }
    }
}
