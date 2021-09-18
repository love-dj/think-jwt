# thinkphp-jwt-author
为thinkPHP写的jwt认证组件
## 安装 
使用composer管理依赖方式安装
```
composer require love-dj/jwt-auth dev-main
```
## 环境要求
php:>=7.1
thinkphp:>=6.0
## 配置
```
    'secret' => 'rolling in the deep'//加密秘钥
    'use_limit' => 'rolling in the deep'//token过期时间
    'refresh_limit' => 'rolling in the deep'//token可以用时间，（可刷新）
  ```  
## 使用案例
```
<?php
namespace app\index\controller;


use think\Controller;
use think\facade\Jwt;

class McjController extends Controller {

    //获取token,data为用户自定义数据
    public function getToken(){
        $data = [
            'user_id'=>12
        ];
        try{
            $res = Jwt::getToken($data);
        }catch (\Exception $e){
            echo json_encode(['error_msg'=>'加密出错']);
        }
        dump($res);exit;
    }
    //权限认证
    public function checkToken(){
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IlFzMkdJaVRnVldSVUZSV3MifQ.eyJuYmYiOjE1MzQyMzQyNDksImV4cCI6MTUzNDgzOTA0OSwiand0X2lkZSI6IlFzMkdJaVRnVldSVUZSV3MiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.pond6EJ59yH9k3MJusVugg7W6hHx1Y_lLGawJBctflY';
        try{
            $res =  Jwt::check($token);
        }catch (\Exception $e){
            //token暂时失效，请刷新令牌
            if($e->getCode() === 20001){
                echo json_encode(['error_msg'=>'请刷新token']);
            }else{
                echo json_encode(['error_msg'=>'登录过期，请重新登录']);
            }
        }
        dump($res);
    }

    //刷新令牌
    public function refreshToken(){
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IlFzMkdJaVRnVldSVUZSV3MifQ.eyJuYmYiOjE1MzQyMzQyNDksImV4cCI6MTUzNDgzOTA0OSwiand0X2lkZSI6IlFzMkdJaVRnVldSVUZSV3MiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.pond6EJ59yH9k3MJusVugg7W6hHx1Y_lLGawJBctflY';
        try{
            $res =  Jwt::refreshToken($token);
        }catch (\Exception $e){
            echo json_encode(['error_msg'=>'token不合法']);
        }
        dump($res);
    }
    //注销令牌，账号登出
    public function killToken(){
        $token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IlFzMkdJaVRnVldSVUZSV3MifQ.eyJuYmYiOjE1MzQyMzQyNDksImV4cCI6MTUzNDgzOTA0OSwiand0X2lkZSI6IlFzMkdJaVRnVldSVUZSV3MiLCJkYXRhIjp7InVzZXJfaWQiOjEyfX0.pond6EJ59yH9k3MJusVugg7W6hHx1Y_lLGawJBctflY';
        try{
            Jwt::killToken($token);
        }catch (Exception $e){
            echo json_encode(['error_msg'=>'token不合法']);
        }
        echo('logout success');
    }

}
```

###### 欢迎交流：myhsj@qq.com
