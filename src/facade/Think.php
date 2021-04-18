<?php
namespace Love\JWTAuth\Facade;

use Machengjun\JWTAuth\Component\Singleton\Singleton;
use Machengjun\JWTAuth\Component\Singleton\SingletonInterface;
use Machengjun\JWTAuth\Component\Think as ThinkCpt;

class Think implements SingletonInterface
{

    use Singleton;

    public static function getObj()
    {
        return new ThinkCpt();
    }
}
