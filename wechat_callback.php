<?php 
// 企业微信应用配置 [6]()
$token = "pcShoMAAB";
$encodingAESKey = "stEmR7QKoPI4T9JG28ceOzkdrXItNnO6PcCTNIxDT2d";
$corpId = "ww7a344ebade47beb3";
 
// 1. 处理URL验证请求（GET）
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    $signature = $_GET["msg_signature"];
    $timestamp = $_GET["timestamp"];
    $nonce = $_GET["nonce"];
    $echostr = $_GET["echostr"];
 
    // 生成验证签名 [2]()
    $array = array($echostr, $token, $timestamp, $nonce);
    sort($array, SORT_STRING);
    $str = implode($array);
    $shaStr = sha1($str);
    
    if ($shaStr == $signature) {
        // 解密echostr [3]()
        $crypt = new WXBizMsgCrypt($token, $encodingAESKey, $corpId);
        $errCode = $crypt->VerifyURL($signature, $timestamp, $nonce, $echostr, $msg);
        if ($errCode == 0) {
            echo $msg; // 返回明文给企业微信验证 
        } else {
            file_put_contents('record.txt',  "验证失败: $errCode\n", FILE_APPEND);
        }
    }
    exit;
}
 
// 2. 处理消息接收（POST）
$rawData = file_get_contents("php://input");
if (!empty($rawData)) {
    $crypt = new WXBizMsgCrypt($token, $encodingAESKey, $corpId);
    
    // 解密消息 [3]()
    $errCode = $crypt->DecryptMsg(
        $_GET['msg_signature'],
        $_GET['timestamp'],
        $_GET['nonce'],
        $rawData,
        $decryptedMsg 
    );
 
    if ($errCode == 0) {
        // 解析XML内容 
        $xml = simplexml_load_string($decryptedMsg);
        $msgType = $xml->MsgType; // 消息类型 
        $content = $xml->Content; // 消息内容 
        
        // 记录到文件 [1]()
        $log = date('Y-m-d H:i:s') . " [{$msgType}] {$content}\n";
        file_put_contents('record.txt',  $log, FILE_APPEND | LOCK_EX);
        
        // 返回成功响应（必须）
        echo "success";
    } else {
        file_put_contents('record.txt',  "解密失败: $errCode\n", FILE_APPEND);
    }
}