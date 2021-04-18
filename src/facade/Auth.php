<?php
namespace Love\JWTAuth\Facade;

use Love\JWTAuth\Component\Auth as AuthCpt;
use Love\JWTAuth\Component\Singleton\Singleton;
use Love\JWTAuth\Component\Singleton\SingletonInterface;

class Auth implements SingletonInterface
{

    use Singleton;

    public static function getObj()
    {
        return new AuthCpt();
    }
}
