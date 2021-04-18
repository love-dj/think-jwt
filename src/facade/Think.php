<?php
namespace Love\JWTAuth\Facade;

use Love\JWTAuth\Component\Singleton\Singleton;
use Love\JWTAuth\Component\Singleton\SingletonInterface;
use Love\JWTAuth\Component\Think as ThinkCpt;

class Think implements SingletonInterface
{

    use Singleton;

    public static function getObj()
    {
        return new ThinkCpt();
    }
}
