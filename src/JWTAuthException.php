<?php
namespace Love\JWTAuth;

use \Exception;

class JWTAuthException extends Exception
{
    protected $message = 'An error occurred';
}
