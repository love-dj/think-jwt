<?php
namespace Love\JWTAuth\Component;

class Think
{

    /**
     * 缓存方法
     * @param $name
     * @param string $value
     * @param null $options
     * @return mixed
     */
    public function cache($name, $value = '', $options = null)
    {
        $param = func_get_args();
        return call_user_func_array('cache', $param);
    }

    /**
     * 配置方法
     * @param null $name
     * @param null $value
     * @param null $default
     * @return mixed
     */
    public function config($name = null, $value = null, $default = null)
    {
        $param = func_get_args();
        return call_user_func_array('config', $param);
    }

}
