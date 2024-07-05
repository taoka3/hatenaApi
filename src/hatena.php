<?php
ini_set('display_errors', 1);
require '../config/config.php';

class hatena
{
    public $oauthCallback = OAUTH_CALLBACK;
    public $oauthConsumerKey = OAUTH_CONSUMER_KEY;
    public $oauthConsumeSecret = OAUTH_CONSUMER_SECRET;
    public $oauthSignature = '';
    public $oauthParameters = [];
    public $dbh = null;
    public $id = 1;

    public function __construct()
    {
        $dsn = 'mysql:dbname=' . DBNAME . ';host=' . HOST;
        try {
            $this->dbh = new PDO($dsn, DBUSER, DBPASSWORD);

            if ($this->dbh == null) {
                //print('接続に失敗しました');
            } else {
                //print('接続に成功しました');
            }
        } catch (PDOException $e) {
            print('Error:' . $e->getMessage());
            die();
        }

        return $this;
    }


    /**
     * データを初回DBに保存する
     */
    public function getData($sql = '', $value = [])
    {
        try {
            //$sql = 'select user_id, long_access_token from threads';
            $stmt = $this->dbh->prepare($sql);
            $stmt->execute($value);

            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            return $result;
        } catch (PDOException $e) {
            print('Error:' . $e->getMessage());
            die();
        }

        return $this;
    }

    /**
     * データを初回DBに保存する
     */
    public function save($sql = '', $value = [])
    {
        try {
            //'insert into threads (user_id, long_access_token) values (?, ?)';
            $stmt = $this->dbh->prepare($sql);
            $flag = $stmt->execute($value);

            if ($flag) {
                //print('データの追加に成功しました');
            } else {
                die();
            }
        } catch (PDOException $e) {
            print('Error:' . $e->getMessage());
            die();
        }
    }

    /**
     * データを更新する
     */
    public function setUpdate($sql = '', $value = [])
    {
        try {
            //$sql = 'UPDATE threads SET long_access_token = ? WHERE user_id = ?';
            $stmt = $this->dbh->prepare($sql);
            $flag = $stmt->execute($value);

            if ($flag) {
                //print('データの追加に成功しました');
            } else {
                die();
            }
        } catch (PDOException $e) {
            print('Error:' . $e->getMessage());
            die();
        }
    }

    /**
     * Request token を取得する
     */
    public function getOauthInitiate($method = "POST", $url = 'https://www.hatena.com/oauth/initiate', $contentType = 'application/x-www-form-urlencoded')
    {
        $this->oauthParameters = [
            'oauth_callback' =>$this->oauthCallback,
            'oauth_consumer_key' => $this->oauthConsumerKey,
            'oauth_nonce' => uniqid(),
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => time(),
            'oauth_version' => '1.0',
        ];

        $params = [
            'scope' => 'read_public,write_public,read_private,write_private'
        ];

        $this->getSignature($url, $method, $params);

        $authorization = $this->getPostParam($this->oauthParameters, true, ',');

        $headers = [
            'Authorization: OAuth ' . $authorization,
            'Host' => 'www.hatena.com',
            'User-Agent: ' => $_SERVER['HTTP_USER_AGENT'],
            'Content-Type: ' . $contentType,
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params, '', '&', PHP_QUERY_RFC3986));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

        $response = curl_exec($ch);
        if (curl_error($ch)) {
            echo 'Curl error: ' . curl_error($ch);
        }
        //oauth_token=?????oauth_token_secret=?????&oauth_callback_confirmed=true
        parse_str($response, $responseParams);

        $values = [
            $responseParams['oauth_token'],
            $responseParams['oauth_token_secret'],
        ];

        if ($this->getData('select * from hatena where id = ?', [$this->id])) {
            $sql = 'UPDATE hatena SET token = ? , token_secret = ? WHERE id = ' . $this->id;
            $this->setUpdate($sql, $values);
        } else {
            $sql = 'insert into hatena (token, token_secret) values (?, ?)';
            $this->save($sql, $values);
        }

        header('Location:https://www.hatena.ne.jp/oauth/authorize?oauth_token=' . rawurlencode($responseParams['oauth_token']));
        return $this;
    }

    /**
     * Access token を取得する
     */
    public function getVerifier()
    {
        if ($_GET['oauth_verifier']) {
            $sql = 'UPDATE hatena SET verifier = ? WHERE id = ' . $this->id;
            $values = [
                $_GET['oauth_verifier'],
            ];
            $this->setUpdate($sql, $values);
        }
    }

    public function getAccessToken($method = 'POST', $url = 'https://www.hatena.com/oauth/token', $contentType = 'application/x-www-form-urlencoded')
    {
        $result = $this->getData('select * from hatena where id = ?', [$this->id]);
        $this->oauthParameters = [
            'oauth_consumer_key' => $this->oauthConsumerKey,
            'oauth_nonce' => uniqid(),
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => time(),
            'oauth_token' => $result['token'],
            'oauth_verifier' => $result['verifier'],
            'oauth_version' => '1.0',
        ];

        $params = [];
        $this->getSignature($url, $method, $params, $result['token_secret']);
        $authorization = $this->getPostParam($this->oauthParameters, true, ',');

        $headers = [
            'Authorization: OAuth ' . $authorization,
            'Host' => 'www.hatena.com',
            'User-Agent: ' => $_SERVER['HTTP_USER_AGENT'],
            'Content-Type: ' . $contentType,
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params, '', '&', PHP_QUERY_RFC3986));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

        $response = curl_exec($ch);
        if (curl_error($ch)) {
            echo 'Curl error: ' . curl_error($ch);
        }
        //oauth_token=?????oauth_token_secret=?????&url_name=????display_name=????
        parse_str($response, $responseParams);

        $values = [
            $responseParams['oauth_token'],
            $responseParams['oauth_token_secret'],
        ];
        if ($responseParams['oauth_token'] && $responseParams['oauth_token_secret']) {
            $sql = 'UPDATE hatena SET oauth_token = ? , oauth_token_secret = ? WHERE id = ' . $this->id;
            $this->setUpdate($sql, $values);
        }

        return $this;
    }

    public function saveBookmark($saveUrl = 'https://google.com', $tag = null, $method = 'POST', $url = 'https://bookmark.hatenaapis.com/rest/1/my/bookmark', $contentType = 'application/x-www-form-urlencoded')
    {
        $result = $this->getData('select * from hatena where id = ?', [$this->id]);
        $this->oauthParameters = [
            'oauth_consumer_key' => $this->oauthConsumerKey,
            'oauth_nonce' => uniqid(),
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => time(),
            'oauth_token' => $result['oauth_token'],
            'oauth_verifier' => $result['verifier'],
            'oauth_version' => '1.0',
        ];

        $params = [
            'url'=>$saveUrl
        ];

        if($tag){
            $params['tags'] = $tag;
        }

        $this->getSignature($url, $method, $params, $result['oauth_token_secret']);
        $authorization = $this->getPostParam($this->oauthParameters, true, ',');

        $headers = [
            'Authorization: OAuth ' . $authorization,
            'Host' => 'bookmark.hatenaapis.com',
            'User-Agent: ' => $_SERVER['HTTP_USER_AGENT'],
            'Content-Type: ' . $contentType,
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params, '', '&', PHP_QUERY_RFC3986));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

        $response = curl_exec($ch);
        if (curl_error($ch)) {
            echo 'Curl error: ' . curl_error($ch);
        }
        //{"comment":"","private":false,"eid":"255393713","created_datetime":"2024-07-06T05:52:29+09:00","created_epoch":1720212749,"user":"taoka_toshiaki","permalink":"https://b.hatena.ne.jp/taoka_toshiaki/20240706#bookmark-255393713","tags":[],"comment_raw":""}
        parse_str($response, $responseParams);
        

        return $this;
    }

    /**
     * シグネチャを生成および取得する
     */
    public function getSignature($url, $method = 'POST', $params = [], $oauthTokenSecret = '')
    {
        $base_string = implode('&', array(
            rawurlencode($method),
            rawurlencode($url),
            rawurlencode(http_build_query($this->oauthsort(array_merge($this->oauthParameters, $params)), '', '&', PHP_QUERY_RFC3986))
        ));
        $key = implode('&', array(rawurlencode($this->oauthConsumeSecret), rawurlencode($oauthTokenSecret)));
        $this->oauthParameters['oauth_signature'] = base64_encode(hash_hmac('sha1', $base_string, $key, true));
        ksort($this->oauthParameters);
        return $this;
    }

    //OAuth式 パラメータのソート関数
    public function oauthsort($a)
    {
        $b = array_map(null, array_keys($a), $a);
        usort($b, ['hatena', 'oauthcmp']);
        $c = array();
        foreach ($b as $v) {
            $c[$v[0]] = $v[1];
        }
        return $c;
    }
    /**
     * oauthcmp
     */
    public function oauthcmp($a, $b)
    {
        return strcmp($a[0], $b[0])
            ? strcmp(rawurlencode($a[0]), rawurlencode($b[0]))
            : strcmp(rawurlencode($a[1]), rawurlencode($b[1]));
    }
    /**
     * getPostParam
     */
    public function getPostParam($value, $rawurlencodeSwitch = false, $separator = '&')
    {
        $str = [];
        foreach ($value as $key => $val) {
            $val = $rawurlencodeSwitch ? rawurlencode($val) : $val;
            $str[] = $key . '=' . $val . '';
        }
        return implode($separator, $str);
    }
}
