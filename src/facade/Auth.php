<?php
namespace Love\JWTAuth\Facade;

use Machengjun\JWTAuth\Component\Auth as AuthCpt;
use Machengjun\JWTAuth\Component\Singleton\Singleton;
use Machengjun\JWTAuth\Component\Singleton\SingletonInterface;

class Auth implements SingletonInterface
{

    use Singleton;

    public static function getObj()
    {
        return new AuthCpt();
    }
}
