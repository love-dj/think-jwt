<?php
namespace Love\JWTAuth\Component;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use Love\JWTAuth\JWTAuthCode;
use Love\JWTAuth\JWTAuthException;
use \DomainException;
use \InvalidArgumentException;
use \UnexpectedValueException;

class Auth
{

    protected $jwtSecret    = '';
    protected $jwtKey       = '';
    protected $userlimit    = 3600; //一小时
    protected $refreshLimit = 604800; //七天

    /**
     * 根据配置文件设置相关参数
     * Auth constructor.
     * @throws JWTAuthException
     */
    public function __construct()
    {
        $this->jwtSecret = config('jwt.secret') ? config('secret') : '';
        if ($this->jwtSecret == '') {
            throw new JWTAuthException('未设置jwt秘钥', JWTAuthCode::JWT_SECRET_MISS);
        }
        $this->jwtKey       = config('jwt.key') ? config('jwt.key') : '123456';
        $this->userlimit    = config('jwt.use_limit') ? config('jwt.use_limit') : 3600;
        $this->refreshLimit = config('jwt.refresh_limit') ? config('jwt.refresh_limit') : 604800;
    }

    /**
     * 获取token
     * @param $data
     * @return string
     * @throws JWTAuthException
     */
    public function getToken($data)
    {
        $invali_time = time();
        $expire_time = time() + $this->refreshLimit;
        $keyId       = Tool::random();
        $payload     = [
            'nbf'     => $invali_time,
            'exp'     => $expire_time,
            'jwt_ide' => $keyId,
            'data'    => $data,
        ];
        try {
            return JWT::encode($payload, $this->jwtKey, 'HS256', $keyId);
        } catch (DomainException $e) {
            throw new JWTAuthException('数据加密出错', JWTAuthCode::ENCRYPT_EORROR);
        }
    }

    /**
     * 验证tonken有效性，不正确抛出异常，正确返回用户数据
     * @param string $token
     * @return array
     * @throws JWTAuthException
     */
    public function check($token = '')
    {
        $token_obj = $this->analysisToken($token);
        if ($token_obj->nbf - time() >= $this->userlimit) {
            throw new JWTAuthException('token过期需要刷新', JWTAuthCode::TOKEN_EXPIRE);
        }
        return Tool::object_to_array($token_obj);
    }

    /**
     * 刷新token
     * @param string $token
     * @return string
     * @throws JWTAuthException
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
     * @throws JWTAuthException
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
     * @throws JWTAuthException
     */
    public function analysisToken($token)
    {
        try {
            $token_obj = JWT::decode($token, $this->jwtKey, array('HS256'));
        } catch (InvalidArgumentException $e) {
            throw new JWTAuthException('未设置jwt秘钥', JWTAuthCode::JWT_SECRET_MISS);
        } catch (UnexpectedValueException $e) {
            throw new JWTAuthException('token格式异常：' . $e->getMessage(), JWTAuthCode::INVALID_TOKEN);
        } catch (SignatureInvalidException $e) {
            throw new JWTAuthException('token格式异常：' . $e->getMessage(), JWTAuthCode::INVALID_TOKEN);
        } catch (BeforeValidException $e) {
            throw new JWTAuthException('token失效：' . $e->getMessage(), JWTAuthCode::INVALID_TOKEN);
        } catch (ExpiredException $e) {
            throw new JWTAuthException('token完全失效：' . $e->getMessage(), JWTAuthCode::TOKEN_EXPIRE_LONG);
        }
        if ($this->_inBlacklist($token_obj->jwt_ide) === true) {
            throw new JWTAuthException('token已被注销', JWTAuthCode::TOKEN_LOGOUT);
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

}
