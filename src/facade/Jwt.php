<?php
namespace think\facade;

use think\Facade;

class Jwt extends Facade
{
    protected static function getFacadeClass()
    {
        return \think\Jwt::class;
    }
}
