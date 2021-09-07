<?php

namespace App\Http\Controllers;

use Exception;
use Illuminate\Http\Request;
use App\Models\User;
use App\Models\Session;
use JWTAuth;
use JWTAuthException;
use Carbon\Carbon;

class AuthController extends Controller
{
    public function login(Request $request){
        $accessToken = $request['accessToken'];

        $client = new \GuzzleHttp\Client();
        $headers = [
            'Authorization' => 'Bearer ' . $accessToken,
        ];

        try {
            $identityResponse = $client->request('GET', 'https://graph.microsoft.com/v1.0/me', ['headers' => $headers]);
            $result = json_decode($identityResponse->getBody(), TRUE);

            if(array_key_exists('error', $result)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid account',
                ]);
            } else {
                try {
                    $email = $result['userPrincipalName'];
                    $user = User::where('email', $email)->first();

                    if (is_null($user)) {
                        return response()->json([
                            'status' => false,
                            'message' => 'Invalid account',
                        ]);
                    }


                    else {
                        JWTAuth::factory()->setTTL(10);
                        $token = JWTAuth::fromUser($user);

                        return response()->json([
                            'status' => true,
                            'message' => 'User logged in successfully',
                            'jwtToken' => $token,
                            'userInfo' => ['name' => $user['name'], 'email' => $user['email']],
                        ]);
                    }
                } catch (Exception $e) {
                    error_log($e->getMessage());
                    return response()->json([
                        'status' => false,
                        'message' => $e->getMessage(),
                    ]);
                }
            }
        } catch(\GuzzleHttp\Exception\ClientException $e) {
            return response()->json([
                'status' => false,
                'message' => 'User logged in failed',
            ]);
        }
    }

    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());

            return response()->json([
                'status' => false,
                'message' => 'User logged out successfully'
            ]);
        } catch (Exception $e) {
            error_log($e->getMessage());

            return response()->json([
                'status' => false,
                'message' => 'User logged out successfully'
            ], 500);
        }
    }
}
