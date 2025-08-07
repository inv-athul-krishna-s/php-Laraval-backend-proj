<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\User;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        // Validate the user
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'role' => 'required|string|in:admin,student,teacher',
        ]);
        
           //Checking admin exist in the db. if exist error occured
        if($request->role == 'admin'){
            $adminExists = User::where('role', 'admin')->exists();
            if($adminExists){
                return response()->json(['error' => 'Admin already exists'], 400);
            }
        }
        elseif (!in_array($request->role,['student','teacher'])) {
            return  response()->json(['error'=> 'invalid role'],400);
        }
 
        //create a user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'role' => $request->role,
        ]);
     


        $token=JWTAuth::fromUser($user);
        
        return response()->json(['accesstoken'=>$token,'user'=>$user], 201);
    }
    //user login
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (!$token = JWTauth::attempt($credentials)) {
            return response()->json(['error' => 'invalid credentials'], 401);
        }

        return response()->json(['accesstoken' => $token,'user'=>auth()->user(),'role'=>auth()->user()->role]);
    }

    //user logout
    public function logout(){
        try {
            auth()->logout();
            return response()->json(['message' => 'Successfully Logged Out']);
        } catch (Exception $e) {
            return response()->json(['error' => 'Failed to logout, try again'], 500);
        }
    }

    //current user
    public function me()
    {
        return response()->json(auth()->user());
    }
}
