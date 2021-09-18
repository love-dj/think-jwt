<?php
namespace think;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use \InvalidArgumentException;
use \UnexpectedValueException;

class Jwt
{

    protected $jwtSecret    = '';
    protected $userlimit    = 3600; //一小时
    protected $refreshLimit = 604800; //七天
    const ENCRYPT_EORROR    = 50001; //jwt加密算法运算时异常
    const JWT_SECRET_MISS   = 50002; //jwt加密秘钥值未设置
    const INVALID_TOKEN     = 40001; //token格式不正确不合法，异常的token
    const TOKEN_EXPIRE      = 20001; //token过期，需要刷新
    const TOKEN_EXPIRE_LONG = 20002; //token过期，过期时间超过上限
    const TOKEN_LOGOUT      = 20003; //token已经被注销

    /**
     * 根据配置文件设置相关参数
     * Auth constructor.
     */
    public function __construct()
    {
        $this->jwtSecret = config('jwt.secret') ? config('jwt.secret') : '';
        if ($this->jwtSecret == '') {
            throw new \Exception('未设置jwt秘钥', Auth::JWT_SECRET_MISS);
        }
        $this->userlimit    = config('jwt.use_limit') ? config('jwt.use_limit') : 3600;
        $this->refreshLimit = config('jwt.refresh_limit') ? config('jwt.refresh_limit') : 604800;
    }

    /**
     * 获取token
     * @param $data
     * @return string
     */
    public function getToken($data)
    {
        $invali_time = time();
        $expire_time = time() + $this->refreshLimit;
        $keyId       = $this->random();
        $payload     = [
            'nbf'     => $invali_time,
            'exp'     => $expire_time,
            'jwt_ide' => $keyId,
            'data'    => $data,
        ];
        try {
            return JWT::encode($payload, $this->jwtSecret, 'HS256', $keyId);
        } catch (\Exception $e) {
            throw new \Exception('数据加密出错', Auth::ENCRYPT_EORROR);
        }
    }

    /**
     * 验证tonken有效性，不正确抛出异常，正确返回用户数据
     * @param string $token
     * @return array
     */
    public function check($token = '')
    {
        $token_obj = $this->analysisToken($token);
        if ($token_obj->nbf - time() >= $this->userlimit) {
            throw new \Exception('token过期需要刷新', Auth::TOKEN_EXPIRE);
        }
        return $this->object_to_array($token_obj);
    }

    /**
     * 刷新token
     * @param string $token
     * @return string
     */
    public function refreshToken($token = '')
    {
        $token_obj = $this->analysisToken($token);
        $this->_addBlacklist($token_obj->jwt_ide);
        return $this->getToken($token_obj->data);
    }

    /**
     * 注销token
     * @param string $token
     * @return bool
     */
    public function killToken($token)
    {
        $token_obj = $this->analysisToken($token);
        $this->_addBlacklist($token_obj->jwt_ide);
        return true;
    }

    /**
     * 解析token
     * @param string $token
     * @return object
     */
    public function analysisToken($token)
    {
        try {
            $token_obj = JWT::decode($token, $this->jwtSecret, array('HS256'));
        } catch (InvalidArgumentException $e) {
            throw new \Exception('未设置jwt秘钥', Auth::JWT_SECRET_MISS);
        } catch (UnexpectedValueException $e) {
            throw new \Exception('token格式异常：' . $e->getMessage(), Auth::INVALID_TOKEN);
        } catch (SignatureInvalidException $e) {
            throw new \Exception('token格式异常：' . $e->getMessage(), Auth::INVALID_TOKEN);
        } catch (BeforeValidException $e) {
            throw new \Exception('token失效：' . $e->getMessage(), Auth::INVALID_TOKEN);
        } catch (ExpiredException $e) {
            throw new \Exception('token完全失效：' . $e->getMessage(), Auth::TOKEN_EXPIRE_LONG);
        }
        if ($this->_inBlacklist($token_obj->jwt_ide) === true) {
            throw new \Exception('token已被注销', Auth::TOKEN_LOGOUT);
        }
        return $token_obj;
    }
    /**
     * 验证token是否在黑名单（验证是否注销token）
     * @param $jwt_ide
     * @return bool
     */
    protected function _inBlacklist($jwt_ide)
    {
        $key = 'jwt_ide_' . $jwt_ide;
        if (!cache($key)) {
            return false;
        }
        return true;
    }

    /**
     * 将token加入黑名单（注销token）
     * @param $jwt_ide
     * @return bool
     */
    protected function _addBlacklist($jwt_ide)
    {
        $key = 'jwt_ide_' . $jwt_ide;
        cache($key, 1, $this->refreshLimit);
        return true;
    }

    /**
     * Generate a more truly "random" alpha-numeric string.
     *
     * @param  int $length
     * @return string
     */
    public function random($length = 16)
    {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $str   = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    /**
     * 将对象转换成数组
     * @param $array
     * @return array
     */
    public function object_to_array($obj)
    {
        $_arr = is_object($obj) ? get_object_vars($obj) : $obj;
        foreach ($_arr as $key => $val) {
            $val       = (is_array($val) || is_object($val)) ? self::object_to_array($val) : $val;
            $arr[$key] = $val;
        }
        return $arr;
    }
}
