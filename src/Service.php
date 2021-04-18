<?php

namespace Love\JWTAuth;

use Love\JWTAuth\command\SecretCommand;

class Service extends \think\Service
{
    public function boot()
    {
        $this->commands(SecretCommand::class);
    }
}
