<?php

return [
    'secret'        => env('JWT_SECRET'),
    //JWT time to live
    'use_limit'     => env('JWT_TTL', 60),
    //刷新时间
    'refresh_limit' => env('JWT_REFRESH_TTL', 20160),
];
