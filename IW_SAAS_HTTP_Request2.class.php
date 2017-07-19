<?php

/**
 * Socket-based adapter for HTTP_Request2
 *
 * PHP version 5
 *
 * LICENSE:
 *
 * Copyright (c) 2008-2011, Alexey Borzov <avb@php.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * The names of the authors may not be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    SVN: $Id: Socket.php 309921 2011-04-03 16:43:02Z avb $
 * @link       http://pear.php.net/package/HTTP_Request2
 */

/**
 * Socket-based adapter for HTTP_Request2
 *
 * This adapter uses only PHP sockets and will work on almost any PHP
 * environment. Code is based on original HTTP_Request PEAR package.
 *
 * @category    HTTP
 * @package     HTTP_Request2
 * @author      Alexey Borzov <avb@php.net>
 * @version     Release: 2.0.0beta3
 */
class HTTP_Request2_Adapter_Socket extends HTTP_Request2_Adapter
{
   /**
    * Regular expression for 'token' rule from RFC 2616
    */
    const REGEXP_TOKEN = '[^\x00-\x1f\x7f-\xff()<>@,;:\\\\"/\[\]?={}\s]+';

   /**
    * Regular expression for 'quoted-string' rule from RFC 2616
    */
    const REGEXP_QUOTED_STRING = '"(?:\\\\.|[^\\\\"])*"';

   /**
    * Connected sockets, needed for Keep-Alive support
    * @var  array
    * @see  connect()
    */
    protected static $sockets = array();

   /**
    * Data for digest authentication scheme
    *
    * The keys for the array are URL prefixes.
    *
    * The values are associative arrays with data (realm, nonce, nonce-count,
    * opaque...) needed for digest authentication. Stored here to prevent making
    * duplicate requests to digest-protected resources after we have already
    * received the challenge.
    *
    * @var  array
    */
    protected static $challenges = array();

   /**
    * Connected socket
    * @var  resource
    * @see  connect()
    */
    protected $socket;

   /**
    * Challenge used for server digest authentication
    * @var  array
    */
    protected $serverChallenge;

   /**
    * Challenge used for proxy digest authentication
    * @var  array
    */
    protected $proxyChallenge;

   /**
    * Sum of start time and global timeout, exception will be thrown if request continues past this time
    * @var  integer
    */
    protected $deadline = null;

   /**
    * Remaining length of the current chunk, when reading chunked response
    * @var  integer
    * @see  readChunked()
    */
    protected $chunkLength = 0;

   /**
    * Remaining amount of redirections to follow
    *
    * Starts at 'max_redirects' configuration parameter and is reduced on each
    * subsequent redirect. An Exception will be thrown once it reaches zero.
    *
    * @var  integer
    */
    protected $redirectCountdown = null;

   /**
    * Sends request to the remote server and returns its response
    *
    * @param    HTTP_Request2
    * @return   HTTP_Request2_Response
    * @throws   HTTP_Request2_Exception
    */
    public function sendRequest(HTTP_Request2 $request)
    {
        $this->request = $request;

        // Use global request timeout if given, see feature requests #5735, #8964
        if ($timeout = $request->getConfig('timeout')) {
            $this->deadline = time() + $timeout;
        } else {
            $this->deadline = null;
        }

        try {
            $keepAlive = $this->connect();
            $headers   = $this->prepareHeaders();
            if (false === @fwrite($this->socket, $headers, strlen($headers))) {
                throw new HTTP_Request2_MessageException('Error writing request');
            }
            // provide request headers to the observer, see request #7633
            $this->request->setLastEvent('sentHeaders', $headers);
            $this->writeBody();

            if ($this->deadline && time() > $this->deadline) {
                throw new HTTP_Request2_MessageException(
                    'Request timed out after ' .
                    $request->getConfig('timeout') . ' second(s)',
                    HTTP_Request2_Exception::TIMEOUT
                );
            }

            $response = $this->readResponse();

            if ($jar = $request->getCookieJar()) {
                $jar->addCookiesFromResponse($response, $request->getUrl());
            }

            if (!$this->canKeepAlive($keepAlive, $response)) {
                $this->disconnect();
            }

            if ($this->shouldUseProxyDigestAuth($response)) {
                return $this->sendRequest($request);
            }
            if ($this->shouldUseServerDigestAuth($response)) {
                return $this->sendRequest($request);
            }
            if ($authInfo = $response->getHeader('authentication-info')) {
                $this->updateChallenge($this->serverChallenge, $authInfo);
            }
            if ($proxyInfo = $response->getHeader('proxy-authentication-info')) {
                $this->updateChallenge($this->proxyChallenge, $proxyInfo);
            }

        } catch (Exception $e) {
            $this->disconnect();
        }

        unset($this->request, $this->requestBody);

        if (!empty($e)) {
            $this->redirectCountdown = null;
            throw $e;
        }

        if (!$request->getConfig('follow_redirects') || !$response->isRedirect()) {
            $this->redirectCountdown = null;
            return $response;
        } else {
            return $this->handleRedirect($request, $response);
        }
    }

   /**
    * Connects to the remote server
    *
    * @return   bool    whether the connection can be persistent
    * @throws   HTTP_Request2_Exception
    */
    protected function connect()
    {
        $secure  = 0 == strcasecmp($this->request->getUrl()->getScheme(), 'https');
        $tunnel  = HTTP_Request2::METHOD_CONNECT == $this->request->getMethod();
        $headers = $this->request->getHeaders();
        $reqHost = $this->request->getUrl()->getHost();
        if (!($reqPort = $this->request->getUrl()->getPort())) {
            $reqPort = $secure? 443: 80;
        }

        if ($host = $this->request->getConfig('proxy_host')) {
            if (!($port = $this->request->getConfig('proxy_port'))) {
                throw new HTTP_Request2_LogicException(
                    'Proxy port not provided',
                    HTTP_Request2_Exception::MISSING_VALUE
                );
            }
            $proxy = true;
        } else {
            $host  = $reqHost;
            $port  = $reqPort;
            $proxy = false;
        }

        if ($tunnel && !$proxy) {
            throw new HTTP_Request2_LogicException(
                "Trying to perform CONNECT request without proxy",
                HTTP_Request2_Exception::MISSING_VALUE
            );
        }
        if ($secure && !in_array('ssl', stream_get_transports())) {
            throw new HTTP_Request2_LogicException(
                'Need OpenSSL support for https:// requests',
                HTTP_Request2_Exception::MISCONFIGURATION
            );
        }

        // RFC 2068, section 19.7.1: A client MUST NOT send the Keep-Alive
        // connection token to a proxy server...
        if ($proxy && !$secure &&
            !empty($headers['connection']) && 'Keep-Alive' == $headers['connection']
        ) {
            $this->request->setHeader('connection');
        }

        $keepAlive = ('1.1' == $this->request->getConfig('protocol_version') &&
                      empty($headers['connection'])) ||
                     (!empty($headers['connection']) &&
                      'Keep-Alive' == $headers['connection']);
        $host = ((!$secure || $proxy)? 'tcp://': 'ssl://') . $host;

        $options = array();
        if ($secure || $tunnel) {
            foreach ($this->request->getConfig() as $name => $value) {
                if ('ssl_' == substr($name, 0, 4) && null !== $value) {
                    if ('ssl_verify_host' == $name) {
                        if ($value) {
                            $options['CN_match'] = $reqHost;
                        }
                    } else {
                        $options[substr($name, 4)] = $value;
                    }
                }
            }
            ksort($options);
        }

        // Changing SSL context options after connection is established does *not*
        // work, we need a new connection if options change
        $remote    = $host . ':' . $port;
        $socketKey = $remote . (($secure && $proxy)? "->{$reqHost}:{$reqPort}": '') .
                     (empty($options)? '': ':' . serialize($options));
        unset($this->socket);

        // We use persistent connections and have a connected socket?
        // Ensure that the socket is still connected, see bug #16149
        if ($keepAlive && !empty(self::$sockets[$socketKey]) &&
            !feof(self::$sockets[$socketKey])
        ) {
            $this->socket =& self::$sockets[$socketKey];

        } elseif ($secure && $proxy && !$tunnel) {
            $this->establishTunnel();
            $this->request->setLastEvent(
                'connect', "ssl://{$reqHost}:{$reqPort} via {$host}:{$port}"
            );
            self::$sockets[$socketKey] =& $this->socket;

        } else {
            // Set SSL context options if doing HTTPS request or creating a tunnel
            $context = stream_context_create();
            foreach ($options as $name => $value) {
                if (!stream_context_set_option($context, 'ssl', $name, $value)) {
                    throw new HTTP_Request2_LogicException(
                        "Error setting SSL context option '{$name}'"
                    );
                }
            }
            $track = @ini_set('track_errors', 1);
            $this->socket = @stream_socket_client(
                $remote, $errno, $errstr,
                $this->request->getConfig('connect_timeout'),
                STREAM_CLIENT_CONNECT, $context
            );
            if (!$this->socket) {
                $e = new HTTP_Request2_ConnectionException(
                    "Unable to connect to {$remote}. Error: "
                     . (empty($errstr)? $php_errormsg: $errstr), 0, $errno
                );
            }
            @ini_set('track_errors', $track);
            if (isset($e)) {
                throw $e;
            }
            $this->request->setLastEvent('connect', $remote);
            self::$sockets[$socketKey] =& $this->socket;
        }
        return $keepAlive;
    }

   /**
    * Establishes a tunnel to a secure remote server via HTTP CONNECT request
    *
    * This method will fail if 'ssl_verify_peer' is enabled. Probably because PHP
    * sees that we are connected to a proxy server (duh!) rather than the server
    * that presents its certificate.
    *
    * @link     http://tools.ietf.org/html/rfc2817#section-5.2
    * @throws   HTTP_Request2_Exception
    */
    protected function establishTunnel()
    {
        $donor   = new self;
        $connect = new HTTP_Request2(
            $this->request->getUrl(), HTTP_Request2::METHOD_CONNECT,
            array_merge($this->request->getConfig(),
                        array('adapter' => $donor))
        );
        $response = $connect->send();
        // Need any successful (2XX) response
        if (200 > $response->getStatus() || 300 <= $response->getStatus()) {
            throw new HTTP_Request2_ConnectionException(
                'Failed to connect via HTTPS proxy. Proxy response: ' .
                $response->getStatus() . ' ' . $response->getReasonPhrase()
            );
        }
        $this->socket = $donor->socket;

        $modes = array(
            STREAM_CRYPTO_METHOD_TLS_CLIENT,
            STREAM_CRYPTO_METHOD_SSLv3_CLIENT,
            STREAM_CRYPTO_METHOD_SSLv23_CLIENT,
            STREAM_CRYPTO_METHOD_SSLv2_CLIENT
        );

        foreach ($modes as $mode) {
            if (stream_socket_enable_crypto($this->socket, true, $mode)) {
                return;
            }
        }
        throw new HTTP_Request2_ConnectionException(
            'Failed to enable secure connection when connecting through proxy'
        );
    }

   /**
    * Checks whether current connection may be reused or should be closed
    *
    * @param    boolean                 whether connection could be persistent
    *                                   in the first place
    * @param    HTTP_Request2_Response  response object to check
    * @return   boolean
    */
    protected function canKeepAlive($requestKeepAlive, HTTP_Request2_Response $response)
    {
        // Do not close socket on successful CONNECT request
        if (HTTP_Request2::METHOD_CONNECT == $this->request->getMethod() &&
            200 <= $response->getStatus() && 300 > $response->getStatus()
        ) {
            return true;
        }

        $lengthKnown = 'chunked' == strtolower($response->getHeader('transfer-encoding'))
                       || null !== $response->getHeader('content-length')
                       // no body possible for such responses, see also request #17031
                       || HTTP_Request2::METHOD_HEAD == $this->request->getMethod()
                       || in_array($response->getStatus(), array(204, 304));
        $persistent  = 'keep-alive' == strtolower($response->getHeader('connection')) ||
                       (null === $response->getHeader('connection') &&
                        '1.1' == $response->getVersion());
        return $requestKeepAlive && $lengthKnown && $persistent;
    }

   /**
    * Disconnects from the remote server
    */
    protected function disconnect()
    {
        if (is_resource($this->socket)) {
            fclose($this->socket);
            $this->socket = null;
            $this->request->setLastEvent('disconnect');
        }
    }

   /**
    * Handles HTTP redirection
    *
    * This method will throw an Exception if redirect to a non-HTTP(S) location
    * is attempted, also if number of redirects performed already is equal to
    * 'max_redirects' configuration parameter.
    *
    * @param    HTTP_Request2               Original request
    * @param    HTTP_Request2_Response      Response containing redirect
    * @return   HTTP_Request2_Response      Response from a new location
    * @throws   HTTP_Request2_Exception
    */
    protected function handleRedirect(HTTP_Request2 $request,
                                      HTTP_Request2_Response $response)
    {
        if (is_null($this->redirectCountdown)) {
            $this->redirectCountdown = $request->getConfig('max_redirects');
        }
        if (0 == $this->redirectCountdown) {
            $this->redirectCountdown = null;
            // Copying cURL behaviour
            throw new HTTP_Request2_MessageException (
                'Maximum (' . $request->getConfig('max_redirects') . ') redirects followed',
                HTTP_Request2_Exception::TOO_MANY_REDIRECTS
            );
        }
        $redirectUrl = new Net_URL2(
            $response->getHeader('location'),
            array(Net_URL2::OPTION_USE_BRACKETS => $request->getConfig('use_brackets'))
        );
        // refuse non-HTTP redirect
        if ($redirectUrl->isAbsolute()
            && !in_array($redirectUrl->getScheme(), array('http', 'https'))
        ) {
            $this->redirectCountdown = null;
            throw new HTTP_Request2_MessageException(
                'Refusing to redirect to a non-HTTP URL ' . $redirectUrl->__toString(),
                HTTP_Request2_Exception::NON_HTTP_REDIRECT
            );
        }
        // Theoretically URL should be absolute (see http://tools.ietf.org/html/rfc2616#section-14.30),
        // but in practice it is often not
        if (!$redirectUrl->isAbsolute()) {
            $redirectUrl = $request->getUrl()->resolve($redirectUrl);
        }
        $redirect = clone $request;
        $redirect->setUrl($redirectUrl);
        if (303 == $response->getStatus() || (!$request->getConfig('strict_redirects')
             && in_array($response->getStatus(), array(301, 302)))
        ) {
            $redirect->setMethod(HTTP_Request2::METHOD_GET);
            $redirect->setBody('');
        }

        if (0 < $this->redirectCountdown) {
            $this->redirectCountdown--;
        }
        return $this->sendRequest($redirect);
    }

   /**
    * Checks whether another request should be performed with server digest auth
    *
    * Several conditions should be satisfied for it to return true:
    *   - response status should be 401
    *   - auth credentials should be set in the request object
    *   - response should contain WWW-Authenticate header with digest challenge
    *   - there is either no challenge stored for this URL or new challenge
    *     contains stale=true parameter (in other case we probably just failed
    *     due to invalid username / password)
    *
    * The method stores challenge values in $challenges static property
    *
    * @param    HTTP_Request2_Response  response to check
    * @return   boolean whether another request should be performed
    * @throws   HTTP_Request2_Exception in case of unsupported challenge parameters
    */
    protected function shouldUseServerDigestAuth(HTTP_Request2_Response $response)
    {
        // no sense repeating a request if we don't have credentials
        if (401 != $response->getStatus() || !$this->request->getAuth()) {
            return false;
        }
        if (!$challenge = $this->parseDigestChallenge($response->getHeader('www-authenticate'))) {
            return false;
        }

        $url    = $this->request->getUrl();
        $scheme = $url->getScheme();
        $host   = $scheme . '://' . $url->getHost();
        if ($port = $url->getPort()) {
            if ((0 == strcasecmp($scheme, 'http') && 80 != $port) ||
                (0 == strcasecmp($scheme, 'https') && 443 != $port)
            ) {
                $host .= ':' . $port;
            }
        }

        if (!empty($challenge['domain'])) {
            $prefixes = array();
            foreach (preg_split('/\\s+/', $challenge['domain']) as $prefix) {
                // don't bother with different servers
                if ('/' == substr($prefix, 0, 1)) {
                    $prefixes[] = $host . $prefix;
                }
            }
        }
        if (empty($prefixes)) {
            $prefixes = array($host . '/');
        }

        $ret = true;
        foreach ($prefixes as $prefix) {
            if (!empty(self::$challenges[$prefix]) &&
                (empty($challenge['stale']) || strcasecmp('true', $challenge['stale']))
            ) {
                // probably credentials are invalid
                $ret = false;
            }
            self::$challenges[$prefix] =& $challenge;
        }
        return $ret;
    }

   /**
    * Checks whether another request should be performed with proxy digest auth
    *
    * Several conditions should be satisfied for it to return true:
    *   - response status should be 407
    *   - proxy auth credentials should be set in the request object
    *   - response should contain Proxy-Authenticate header with digest challenge
    *   - there is either no challenge stored for this proxy or new challenge
    *     contains stale=true parameter (in other case we probably just failed
    *     due to invalid username / password)
    *
    * The method stores challenge values in $challenges static property
    *
    * @param    HTTP_Request2_Response  response to check
    * @return   boolean whether another request should be performed
    * @throws   HTTP_Request2_Exception in case of unsupported challenge parameters
    */
    protected function shouldUseProxyDigestAuth(HTTP_Request2_Response $response)
    {
        if (407 != $response->getStatus() || !$this->request->getConfig('proxy_user')) {
            return false;
        }
        if (!($challenge = $this->parseDigestChallenge($response->getHeader('proxy-authenticate')))) {
            return false;
        }

        $key = 'proxy://' . $this->request->getConfig('proxy_host') .
               ':' . $this->request->getConfig('proxy_port');

        if (!empty(self::$challenges[$key]) &&
            (empty($challenge['stale']) || strcasecmp('true', $challenge['stale']))
        ) {
            $ret = false;
        } else {
            $ret = true;
        }
        self::$challenges[$key] = $challenge;
        return $ret;
    }

   /**
    * Extracts digest method challenge from (WWW|Proxy)-Authenticate header value
    *
    * There is a problem with implementation of RFC 2617: several of the parameters
    * are defined as quoted-string there and thus may contain backslash escaped
    * double quotes (RFC 2616, section 2.2). However, RFC 2617 defines unq(X) as
    * just value of quoted-string X without surrounding quotes, it doesn't speak
    * about removing backslash escaping.
    *
    * Now realm parameter is user-defined and human-readable, strange things
    * happen when it contains quotes:
    *   - Apache allows quotes in realm, but apparently uses realm value without
    *     backslashes for digest computation
    *   - Squid allows (manually escaped) quotes there, but it is impossible to
    *     authorize with either escaped or unescaped quotes used in digest,
    *     probably it can't parse the response (?)
    *   - Both IE and Firefox display realm value with backslashes in
    *     the password popup and apparently use the same value for digest
    *
    * HTTP_Request2 follows IE and Firefox (and hopefully RFC 2617) in
    * quoted-string handling, unfortunately that means failure to authorize
    * sometimes
    *
    * @param    string  value of WWW-Authenticate or Proxy-Authenticate header
    * @return   mixed   associative array with challenge parameters, false if
    *                   no challenge is present in header value
    * @throws   HTTP_Request2_NotImplementedException in case of unsupported challenge parameters
    */
    protected function parseDigestChallenge($headerValue)
    {
        $authParam   = '(' . self::REGEXP_TOKEN . ')\\s*=\\s*(' .
                       self::REGEXP_TOKEN . '|' . self::REGEXP_QUOTED_STRING . ')';
        $challenge   = "!(?<=^|\\s|,)Digest ({$authParam}\\s*(,\\s*|$))+!";
        if (!preg_match($challenge, $headerValue, $matches)) {
            return false;
        }

        preg_match_all('!' . $authParam . '!', $matches[0], $params);
        $paramsAry   = array();
        $knownParams = array('realm', 'domain', 'nonce', 'opaque', 'stale',
                             'algorithm', 'qop');
        for ($i = 0; $i < count($params[0]); $i++) {
            // section 3.2.1: Any unrecognized directive MUST be ignored.
            if (in_array($params[1][$i], $knownParams)) {
                if ('"' == substr($params[2][$i], 0, 1)) {
                    $paramsAry[$params[1][$i]] = substr($params[2][$i], 1, -1);
                } else {
                    $paramsAry[$params[1][$i]] = $params[2][$i];
                }
            }
        }
        // we only support qop=auth
        if (!empty($paramsAry['qop']) &&
            !in_array('auth', array_map('trim', explode(',', $paramsAry['qop'])))
        ) {
            throw new HTTP_Request2_NotImplementedException(
                "Only 'auth' qop is currently supported in digest authentication, " .
                "server requested '{$paramsAry['qop']}'"
            );
        }
        // we only support algorithm=MD5
        if (!empty($paramsAry['algorithm']) && 'MD5' != $paramsAry['algorithm']) {
            throw new HTTP_Request2_NotImplementedException(
                "Only 'MD5' algorithm is currently supported in digest authentication, " .
                "server requested '{$paramsAry['algorithm']}'"
            );
        }

        return $paramsAry;
    }

   /**
    * Parses [Proxy-]Authentication-Info header value and updates challenge
    *
    * @param    array   challenge to update
    * @param    string  value of [Proxy-]Authentication-Info header
    * @todo     validate server rspauth response
    */
    protected function updateChallenge(&$challenge, $headerValue)
    {
        $authParam   = '!(' . self::REGEXP_TOKEN . ')\\s*=\\s*(' .
                       self::REGEXP_TOKEN . '|' . self::REGEXP_QUOTED_STRING . ')!';
        $paramsAry   = array();

        preg_match_all($authParam, $headerValue, $params);
        for ($i = 0; $i < count($params[0]); $i++) {
            if ('"' == substr($params[2][$i], 0, 1)) {
                $paramsAry[$params[1][$i]] = substr($params[2][$i], 1, -1);
            } else {
                $paramsAry[$params[1][$i]] = $params[2][$i];
            }
        }
        // for now, just update the nonce value
        if (!empty($paramsAry['nextnonce'])) {
            $challenge['nonce'] = $paramsAry['nextnonce'];
            $challenge['nc']    = 1;
        }
    }

   /**
    * Creates a value for [Proxy-]Authorization header when using digest authentication
    *
    * @param    string  user name
    * @param    string  password
    * @param    string  request URL
    * @param    array   digest challenge parameters
    * @return   string  value of [Proxy-]Authorization request header
    * @link     http://tools.ietf.org/html/rfc2617#section-3.2.2
    */
    protected function createDigestResponse($user, $password, $url, &$challenge)
    {
        if (false !== ($q = strpos($url, '?')) &&
            $this->request->getConfig('digest_compat_ie')
        ) {
            $url = substr($url, 0, $q);
        }

        $a1 = md5($user . ':' . $challenge['realm'] . ':' . $password);
        $a2 = md5($this->request->getMethod() . ':' . $url);

        if (empty($challenge['qop'])) {
            $digest = md5($a1 . ':' . $challenge['nonce'] . ':' . $a2);
        } else {
            $challenge['cnonce'] = 'Req2.' . rand();
            if (empty($challenge['nc'])) {
                $challenge['nc'] = 1;
            }
            $nc     = sprintf('%08x', $challenge['nc']++);
            $digest = md5($a1 . ':' . $challenge['nonce'] . ':' . $nc . ':' .
                          $challenge['cnonce'] . ':auth:' . $a2);
        }
        return 'Digest username="' . str_replace(array('\\', '"'), array('\\\\', '\\"'), $user) . '", ' .
               'realm="' . $challenge['realm'] . '", ' .
               'nonce="' . $challenge['nonce'] . '", ' .
               'uri="' . $url . '", ' .
               'response="' . $digest . '"' .
               (!empty($challenge['opaque'])?
                ', opaque="' . $challenge['opaque'] . '"':
                '') .
               (!empty($challenge['qop'])?
                ', qop="auth", nc=' . $nc . ', cnonce="' . $challenge['cnonce'] . '"':
                '');
    }

   /**
    * Adds 'Authorization' header (if needed) to request headers array
    *
    * @param    array   request headers
    * @param    string  request host (needed for digest authentication)
    * @param    string  request URL (needed for digest authentication)
    * @throws   HTTP_Request2_NotImplementedException
    */
    protected function addAuthorizationHeader(&$headers, $requestHost, $requestUrl)
    {
        if (!($auth = $this->request->getAuth())) {
            return;
        }
        switch ($auth['scheme']) {
            case HTTP_Request2::AUTH_BASIC:
                $headers['authorization'] =
                    'Basic ' . base64_encode($auth['user'] . ':' . $auth['password']);
                break;

            case HTTP_Request2::AUTH_DIGEST:
                unset($this->serverChallenge);
                $fullUrl = ('/' == $requestUrl[0])?
                           $this->request->getUrl()->getScheme() . '://' .
                            $requestHost . $requestUrl:
                           $requestUrl;
                foreach (array_keys(self::$challenges) as $key) {
                    if ($key == substr($fullUrl, 0, strlen($key))) {
                        $headers['authorization'] = $this->createDigestResponse(
                            $auth['user'], $auth['password'],
                            $requestUrl, self::$challenges[$key]
                        );
                        $this->serverChallenge =& self::$challenges[$key];
                        break;
                    }
                }
                break;

            default:
                throw new HTTP_Request2_NotImplementedException(
                    "Unknown HTTP authentication scheme '{$auth['scheme']}'"
                );
        }
    }

   /**
    * Adds 'Proxy-Authorization' header (if needed) to request headers array
    *
    * @param    array   request headers
    * @param    string  request URL (needed for digest authentication)
    * @throws   HTTP_Request2_NotImplementedException
    */
    protected function addProxyAuthorizationHeader(&$headers, $requestUrl)
    {
        if (!$this->request->getConfig('proxy_host') ||
            !($user = $this->request->getConfig('proxy_user')) ||
            (0 == strcasecmp('https', $this->request->getUrl()->getScheme()) &&
             HTTP_Request2::METHOD_CONNECT != $this->request->getMethod())
        ) {
            return;
        }

        $password = $this->request->getConfig('proxy_password');
        switch ($this->request->getConfig('proxy_auth_scheme')) {
            case HTTP_Request2::AUTH_BASIC:
                $headers['proxy-authorization'] =
                    'Basic ' . base64_encode($user . ':' . $password);
                break;

            case HTTP_Request2::AUTH_DIGEST:
                unset($this->proxyChallenge);
                $proxyUrl = 'proxy://' . $this->request->getConfig('proxy_host') .
                            ':' . $this->request->getConfig('proxy_port');
                if (!empty(self::$challenges[$proxyUrl])) {
                    $headers['proxy-authorization'] = $this->createDigestResponse(
                        $user, $password,
                        $requestUrl, self::$challenges[$proxyUrl]
                    );
                    $this->proxyChallenge =& self::$challenges[$proxyUrl];
                }
                break;

            default:
                throw new HTTP_Request2_NotImplementedException(
                    "Unknown HTTP authentication scheme '" .
                    $this->request->getConfig('proxy_auth_scheme') . "'"
                );
        }
    }


   /**
    * Creates the string with the Request-Line and request headers
    *
    * @return   string
    * @throws   HTTP_Request2_Exception
    */
    protected function prepareHeaders()
    {
        $headers = $this->request->getHeaders();
        $url     = $this->request->getUrl();
        $connect = HTTP_Request2::METHOD_CONNECT == $this->request->getMethod();
        $host    = $url->getHost();

        $defaultPort = 0 == strcasecmp($url->getScheme(), 'https')? 443: 80;
        if (($port = $url->getPort()) && $port != $defaultPort || $connect) {
            $host .= ':' . (empty($port)? $defaultPort: $port);
        }
        // Do not overwrite explicitly set 'Host' header, see bug #16146
        if (!isset($headers['host'])) {
            $headers['host'] = $host;
        }

        if ($connect) {
            $requestUrl = $host;

        } else {
            if (!$this->request->getConfig('proxy_host') ||
                0 == strcasecmp($url->getScheme(), 'https')
            ) {
                $requestUrl = '';
            } else {
                $requestUrl = $url->getScheme() . '://' . $host;
            }
            $path        = $url->getPath();
            $query       = $url->getQuery();
            $requestUrl .= (empty($path)? '/': $path) . (empty($query)? '': '?' . $query);
        }

        if ('1.1' == $this->request->getConfig('protocol_version') &&
            extension_loaded('zlib') && !isset($headers['accept-encoding'])
        ) {
            $headers['accept-encoding'] = 'gzip, deflate';
        }
        if (($jar = $this->request->getCookieJar())
            && ($cookies = $jar->getMatching($this->request->getUrl(), true))
        ) {
            $headers['cookie'] = (empty($headers['cookie'])? '': $headers['cookie'] . '; ') . $cookies;
        }

        $this->addAuthorizationHeader($headers, $host, $requestUrl);
        $this->addProxyAuthorizationHeader($headers, $requestUrl);
        $this->calculateRequestLength($headers);

        $headersStr = $this->request->getMethod() . ' ' . $requestUrl . ' HTTP/' .
                      $this->request->getConfig('protocol_version') . "\r\n";
        foreach ($headers as $name => $value) {
            $canonicalName = implode('-', array_map('ucfirst', explode('-', $name)));
            $headersStr   .= $canonicalName . ': ' . $value . "\r\n";
        }
        return $headersStr . "\r\n";
    }

   /**
    * Sends the request body
    *
    * @throws   HTTP_Request2_MessageException
    */
    protected function writeBody()
    {
        if (in_array($this->request->getMethod(), self::$bodyDisallowed) ||
            0 == $this->contentLength
        ) {
            return;
        }

        $position   = 0;
        $bufferSize = $this->request->getConfig('buffer_size');
        while ($position < $this->contentLength) {
            if (is_string($this->requestBody)) {
                $str = substr($this->requestBody, $position, $bufferSize);
            } elseif (is_resource($this->requestBody)) {
                $str = fread($this->requestBody, $bufferSize);
            } else {
                $str = $this->requestBody->read($bufferSize);
            }
            if (false === @fwrite($this->socket, $str, strlen($str))) {
                throw new HTTP_Request2_MessageException('Error writing request');
            }
            // Provide the length of written string to the observer, request #7630
            $this->request->setLastEvent('sentBodyPart', strlen($str));
            $position += strlen($str);
        }
        $this->request->setLastEvent('sentBody', $this->contentLength);
    }

   /**
    * Reads the remote server's response
    *
    * @return   HTTP_Request2_Response
    * @throws   HTTP_Request2_Exception
    */
    protected function readResponse()
    {
        $bufferSize = $this->request->getConfig('buffer_size');

        do {
            $response = new HTTP_Request2_Response(
                $this->readLine($bufferSize), true, $this->request->getUrl()
            );
            do {
                $headerLine = $this->readLine($bufferSize);
                $response->parseHeaderLine($headerLine);
            } while ('' != $headerLine);
        } while (in_array($response->getStatus(), array(100, 101)));

        $this->request->setLastEvent('receivedHeaders', $response);

        // No body possible in such responses
        if (HTTP_Request2::METHOD_HEAD == $this->request->getMethod() ||
            (HTTP_Request2::METHOD_CONNECT == $this->request->getMethod() &&
             200 <= $response->getStatus() && 300 > $response->getStatus()) ||
            in_array($response->getStatus(), array(204, 304))
        ) {
            return $response;
        }

        $chunked = 'chunked' == $response->getHeader('transfer-encoding');
        $length  = $response->getHeader('content-length');
        $hasBody = false;
        if ($chunked || null === $length || 0 < intval($length)) {
            // RFC 2616, section 4.4:
            // 3. ... If a message is received with both a
            // Transfer-Encoding header field and a Content-Length header field,
            // the latter MUST be ignored.
            $toRead = ($chunked || null === $length)? null: $length;
            $this->chunkLength = 0;

            while (!feof($this->socket) && (is_null($toRead) || 0 < $toRead)) {
                if ($chunked) {
                    $data = $this->readChunked($bufferSize);
                } elseif (is_null($toRead)) {
                    $data = $this->fread($bufferSize);
                } else {
                    $data    = $this->fread(min($toRead, $bufferSize));
                    $toRead -= strlen($data);
                }
                if ('' == $data && (!$this->chunkLength || feof($this->socket))) {
                    break;
                }

                $hasBody = true;
                if ($this->request->getConfig('store_body')) {
                    $response->appendBody($data);
                }
                if (!in_array($response->getHeader('content-encoding'), array('identity', null))) {
                    $this->request->setLastEvent('receivedEncodedBodyPart', $data);
                } else {
                    $this->request->setLastEvent('receivedBodyPart', $data);
                }
            }
        }

        if ($hasBody) {
            $this->request->setLastEvent('receivedBody', $response);
        }
        return $response;
    }

   /**
    * Reads until either the end of the socket or a newline, whichever comes first
    *
    * Strips the trailing newline from the returned data, handles global
    * request timeout. Method idea borrowed from Net_Socket PEAR package.
    *
    * @param    int     buffer size to use for reading
    * @return   Available data up to the newline (not including newline)
    * @throws   HTTP_Request2_MessageException     In case of timeout
    */
    protected function readLine($bufferSize)
    {
        $line = '';
        while (!feof($this->socket)) {
            if ($this->deadline) {
                stream_set_timeout($this->socket, max($this->deadline - time(), 1));
            }
            $line .= @fgets($this->socket, $bufferSize);
            $info  = stream_get_meta_data($this->socket);
            if ($info['timed_out'] || $this->deadline && time() > $this->deadline) {
                $reason = $this->deadline
                          ? 'after ' . $this->request->getConfig('timeout') . ' second(s)'
                          : 'due to default_socket_timeout php.ini setting';
                throw new HTTP_Request2_MessageException(
                    "Request timed out {$reason}", HTTP_Request2_Exception::TIMEOUT
                );
            }
            if (substr($line, -1) == "\n") {
                return rtrim($line, "\r\n");
            }
        }
        return $line;
    }

   /**
    * Wrapper around fread(), handles global request timeout
    *
    * @param    int     Reads up to this number of bytes
    * @return   Data read from socket
    * @throws   HTTP_Request2_MessageException     In case of timeout
    */
    protected function fread($length)
    {
        if ($this->deadline) {
            stream_set_timeout($this->socket, max($this->deadline - time(), 1));
        }
        $data = fread($this->socket, $length);
        $info = stream_get_meta_data($this->socket);
        if ($info['timed_out'] || $this->deadline && time() > $this->deadline) {
            $reason = $this->deadline
                      ? 'after ' . $this->request->getConfig('timeout') . ' second(s)'
                      : 'due to default_socket_timeout php.ini setting';
            throw new HTTP_Request2_MessageException(
                "Request timed out {$reason}", HTTP_Request2_Exception::TIMEOUT
            );
        }
        return $data;
    }

   /**
    * Reads a part of response body encoded with chunked Transfer-Encoding
    *
    * @param    int     buffer size to use for reading
    * @return   string
    * @throws   HTTP_Request2_MessageException
    */
    protected function readChunked($bufferSize)
    {
        // at start of the next chunk?
        if (0 == $this->chunkLength) {
            $line = $this->readLine($bufferSize);
            if (!preg_match('/^([0-9a-f]+)/i', $line, $matches)) {
                throw new HTTP_Request2_MessageException(
                    "Cannot decode chunked response, invalid chunk length '{$line}'",
                    HTTP_Request2_Exception::DECODE_ERROR
                );
            } else {
                $this->chunkLength = hexdec($matches[1]);
                // Chunk with zero length indicates the end
                if (0 == $this->chunkLength) {
                    $this->readLine($bufferSize);
                    return '';
                }
            }
        }
        $data = $this->fread(min($this->chunkLength, $bufferSize));
        $this->chunkLength -= strlen($data);
        if (0 == $this->chunkLength) {
            $this->readLine($bufferSize); // Trailing CRLF
        }
        return $data;
    }
}

// ----------------------------------------------------------------------------------------- //
//F PEAR://HTTP/Request2/Adapter/Curl.php                                                    //
// ----------------------------------------------------------------------------------------- //

/**
 * Adapter for HTTP_Request2 wrapping around cURL extension
 *
 * PHP version 5
 *
 * LICENSE:
 *
 * Copyright (c) 2008-2011, Alexey Borzov <avb@php.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * The names of the authors may not be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    SVN: $Id: Curl.php 309921 2011-04-03 16:43:02Z avb $
 * @link       http://pear.php.net/package/HTTP_Request2
 */

/**
 * Adapter for HTTP_Request2 wrapping around cURL extension
 *
 * @category    HTTP
 * @package     HTTP_Request2
 * @author      Alexey Borzov <avb@php.net>
 * @version     Release: 2.0.0beta3
 */
class HTTP_Request2_Adapter_Curl extends HTTP_Request2_Adapter
{
   /**
    * Mapping of header names to cURL options
    * @var  array
    */
    protected static $headerMap = array(
        'accept-encoding' => CURLOPT_ENCODING,
        'cookie'          => CURLOPT_COOKIE,
        'referer'         => CURLOPT_REFERER,
        'user-agent'      => CURLOPT_USERAGENT
    );

   /**
    * Mapping of SSL context options to cURL options
    * @var  array
    */
    protected static $sslContextMap = array(
        'ssl_verify_peer' => CURLOPT_SSL_VERIFYPEER,
        'ssl_cafile'      => CURLOPT_CAINFO,
        'ssl_capath'      => CURLOPT_CAPATH,
        'ssl_local_cert'  => CURLOPT_SSLCERT,
        'ssl_passphrase'  => CURLOPT_SSLCERTPASSWD
   );

   /**
    * Mapping of CURLE_* constants to Exception subclasses and error codes
    * @var  array
    */
    protected static $errorMap = array(
        CURLE_UNSUPPORTED_PROTOCOL  => array('HTTP_Request2_MessageException',
                                             HTTP_Request2_Exception::NON_HTTP_REDIRECT),
        CURLE_COULDNT_RESOLVE_PROXY => array('HTTP_Request2_ConnectionException'),
        CURLE_COULDNT_RESOLVE_HOST  => array('HTTP_Request2_ConnectionException'),
        CURLE_COULDNT_CONNECT       => array('HTTP_Request2_ConnectionException'),
        // error returned from write callback
        CURLE_WRITE_ERROR           => array('HTTP_Request2_MessageException',
                                             HTTP_Request2_Exception::NON_HTTP_REDIRECT),
        CURLE_OPERATION_TIMEOUTED   => array('HTTP_Request2_MessageException',
                                             HTTP_Request2_Exception::TIMEOUT),
        CURLE_HTTP_RANGE_ERROR      => array('HTTP_Request2_MessageException'),
        CURLE_SSL_CONNECT_ERROR     => array('HTTP_Request2_ConnectionException'),
        CURLE_LIBRARY_NOT_FOUND     => array('HTTP_Request2_LogicException',
                                             HTTP_Request2_Exception::MISCONFIGURATION),
        CURLE_FUNCTION_NOT_FOUND    => array('HTTP_Request2_LogicException',
                                             HTTP_Request2_Exception::MISCONFIGURATION),
        CURLE_ABORTED_BY_CALLBACK   => array('HTTP_Request2_MessageException',
                                             HTTP_Request2_Exception::NON_HTTP_REDIRECT),
        CURLE_TOO_MANY_REDIRECTS    => array('HTTP_Request2_MessageException',
                                             HTTP_Request2_Exception::TOO_MANY_REDIRECTS),
        CURLE_SSL_PEER_CERTIFICATE  => array('HTTP_Request2_ConnectionException'),
        CURLE_GOT_NOTHING           => array('HTTP_Request2_MessageException'),
        CURLE_SSL_ENGINE_NOTFOUND   => array('HTTP_Request2_LogicException',
                                             HTTP_Request2_Exception::MISCONFIGURATION),
        CURLE_SSL_ENGINE_SETFAILED  => array('HTTP_Request2_LogicException',
                                             HTTP_Request2_Exception::MISCONFIGURATION),
        CURLE_SEND_ERROR            => array('HTTP_Request2_MessageException'),
        CURLE_RECV_ERROR            => array('HTTP_Request2_MessageException'),
        CURLE_SSL_CERTPROBLEM       => array('HTTP_Request2_LogicException',
                                             HTTP_Request2_Exception::INVALID_ARGUMENT),
        CURLE_SSL_CIPHER            => array('HTTP_Request2_ConnectionException'),
        CURLE_SSL_CACERT            => array('HTTP_Request2_ConnectionException'),
        CURLE_BAD_CONTENT_ENCODING  => array('HTTP_Request2_MessageException'),
    );

   /**
    * Response being received
    * @var  HTTP_Request2_Response
    */
    protected $response;

   /**
    * Whether 'sentHeaders' event was sent to observers
    * @var  boolean
    */
    protected $eventSentHeaders = false;

   /**
    * Whether 'receivedHeaders' event was sent to observers
    * @var boolean
    */
    protected $eventReceivedHeaders = false;

   /**
    * Position within request body
    * @var  integer
    * @see  callbackReadBody()
    */
    protected $position = 0;

   /**
    * Information about last transfer, as returned by curl_getinfo()
    * @var  array
    */
    protected $lastInfo;

   /**
    * Creates a subclass of HTTP_Request2_Exception from curl error data
    *
    * @param resource curl handle
    * @return HTTP_Request2_Exception
    */
    protected static function wrapCurlError($ch)
    {
        $nativeCode = curl_errno($ch);
        $message    = 'Curl error: ' . curl_error($ch);
        if (!isset(self::$errorMap[$nativeCode])) {
            return new HTTP_Request2_Exception($message, 0, $nativeCode);
        } else {
            $class = self::$errorMap[$nativeCode][0];
            $code  = empty(self::$errorMap[$nativeCode][1])
                     ? 0 : self::$errorMap[$nativeCode][1];
            return new $class($message, $code, $nativeCode);
        }
    }

   /**
    * Sends request to the remote server and returns its response
    *
    * @param    HTTP_Request2
    * @return   HTTP_Request2_Response
    * @throws   HTTP_Request2_Exception
    */
    public function sendRequest(HTTP_Request2 $request)
    {
        if (!extension_loaded('curl')) {
            throw new HTTP_Request2_LogicException(
                'cURL extension not available', HTTP_Request2_Exception::MISCONFIGURATION
            );
        }

        $this->request              = $request;
        $this->response             = null;
        $this->position             = 0;
        $this->eventSentHeaders     = false;
        $this->eventReceivedHeaders = false;

        try {
            if (false === curl_exec($ch = $this->createCurlHandle())) {
                $e = self::wrapCurlError($ch);
            }
        } catch (Exception $e) {
        }
        if (isset($ch)) {
            $this->lastInfo = curl_getinfo($ch);
            curl_close($ch);
        }

        $response = $this->response;
        unset($this->request, $this->requestBody, $this->response);

        if (!empty($e)) {
            throw $e;
        }

        if ($jar = $request->getCookieJar()) {
            $jar->addCookiesFromResponse($response, $request->getUrl());
        }

        if (0 < $this->lastInfo['size_download']) {
            $request->setLastEvent('receivedBody', $response);
        }
        return $response;
    }

   /**
    * Returns information about last transfer
    *
    * @return   array   associative array as returned by curl_getinfo()
    */
    public function getInfo()
    {
        return $this->lastInfo;
    }

   /**
    * Creates a new cURL handle and populates it with data from the request
    *
    * @return   resource    a cURL handle, as created by curl_init()
    * @throws   HTTP_Request2_LogicException
    */
    protected function createCurlHandle()
    {
        $ch = curl_init();

        curl_setopt_array($ch, array(
            // setup write callbacks
            CURLOPT_HEADERFUNCTION => array($this, 'callbackWriteHeader'),
            CURLOPT_WRITEFUNCTION  => array($this, 'callbackWriteBody'),
            // buffer size
            CURLOPT_BUFFERSIZE     => $this->request->getConfig('buffer_size'),
            // connection timeout
            CURLOPT_CONNECTTIMEOUT => $this->request->getConfig('connect_timeout'),
            // save full outgoing headers, in case someone is interested
            CURLINFO_HEADER_OUT    => true,
            // request url
            CURLOPT_URL            => $this->request->getUrl()->getUrl()
        ));

        // set up redirects
        if (!$this->request->getConfig('follow_redirects')) {
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        } else {
            if (!@curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true)) {
                throw new HTTP_Request2_LogicException(
                    'Redirect support in curl is unavailable due to open_basedir or safe_mode setting',
                    HTTP_Request2_Exception::MISCONFIGURATION
                );
            }
            curl_setopt($ch, CURLOPT_MAXREDIRS, $this->request->getConfig('max_redirects'));
            // limit redirects to http(s), works in 5.2.10+
            if (defined('CURLOPT_REDIR_PROTOCOLS')) {
                curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            }
            // works in 5.3.2+, http://bugs.php.net/bug.php?id=49571
            if ($this->request->getConfig('strict_redirects') && defined('CURLOPT_POSTREDIR')) {
                curl_setopt($ch, CURLOPT_POSTREDIR, 3);
            }
        }

        // request timeout
        if ($timeout = $this->request->getConfig('timeout')) {
            curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        }

        // set HTTP version
        switch ($this->request->getConfig('protocol_version')) {
            case '1.0':
                curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
                break;
            case '1.1':
                curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        }

        // set request method
        switch ($this->request->getMethod()) {
            case HTTP_Request2::METHOD_GET:
                curl_setopt($ch, CURLOPT_HTTPGET, true);
                break;
            case HTTP_Request2::METHOD_POST:
                curl_setopt($ch, CURLOPT_POST, true);
                break;
            case HTTP_Request2::METHOD_HEAD:
                curl_setopt($ch, CURLOPT_NOBODY, true);
                break;
            case HTTP_Request2::METHOD_PUT:
                curl_setopt($ch, CURLOPT_UPLOAD, true);
                break;
            default:
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $this->request->getMethod());
        }

        // set proxy, if needed
        if ($host = $this->request->getConfig('proxy_host')) {
            if (!($port = $this->request->getConfig('proxy_port'))) {
                throw new HTTP_Request2_LogicException(
                    'Proxy port not provided', HTTP_Request2_Exception::MISSING_VALUE
                );
            }
            curl_setopt($ch, CURLOPT_PROXY, $host . ':' . $port);
            if ($user = $this->request->getConfig('proxy_user')) {
                curl_setopt($ch, CURLOPT_PROXYUSERPWD, $user . ':' .
                            $this->request->getConfig('proxy_password'));
                switch ($this->request->getConfig('proxy_auth_scheme')) {
                    case HTTP_Request2::AUTH_BASIC:
                        curl_setopt($ch, CURLOPT_PROXYAUTH, CURLAUTH_BASIC);
                        break;
                    case HTTP_Request2::AUTH_DIGEST:
                        curl_setopt($ch, CURLOPT_PROXYAUTH, CURLAUTH_DIGEST);
                }
            }
        }

        // set authentication data
        if ($auth = $this->request->getAuth()) {
            curl_setopt($ch, CURLOPT_USERPWD, $auth['user'] . ':' . $auth['password']);
            switch ($auth['scheme']) {
                case HTTP_Request2::AUTH_BASIC:
                    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
                    break;
                case HTTP_Request2::AUTH_DIGEST:
                    curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST);
            }
        }

        // set SSL options
        if (0 == strcasecmp($this->request->getUrl()->getScheme(), 'https')) {
            foreach ($this->request->getConfig() as $name => $value) {
                if ('ssl_verify_host' == $name && null !== $value) {
                    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $value? 2: 0);
                } elseif (isset(self::$sslContextMap[$name]) && null !== $value) {
                    curl_setopt($ch, self::$sslContextMap[$name], $value);
                }
            }
        }

        $headers = $this->request->getHeaders();
        // make cURL automagically send proper header
        if (!isset($headers['accept-encoding'])) {
            $headers['accept-encoding'] = '';
        }

        if (($jar = $this->request->getCookieJar())
            && ($cookies = $jar->getMatching($this->request->getUrl(), true))
        ) {
            $headers['cookie'] = (empty($headers['cookie'])? '': $headers['cookie'] . '; ') . $cookies;
        }

        // set headers having special cURL keys
        foreach (self::$headerMap as $name => $option) {
            if (isset($headers[$name])) {
                curl_setopt($ch, $option, $headers[$name]);
                unset($headers[$name]);
            }
        }

        $this->calculateRequestLength($headers);
        if (isset($headers['content-length'])) {
            $this->workaroundPhpBug47204($ch, $headers);
        }

        // set headers not having special keys
        $headersFmt = array();
        foreach ($headers as $name => $value) {
            $canonicalName = implode('-', array_map('ucfirst', explode('-', $name)));
            $headersFmt[]  = $canonicalName . ': ' . $value;
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headersFmt);

        return $ch;
    }

   /**
    * Workaround for PHP bug #47204 that prevents rewinding request body
    *
    * The workaround consists of reading the entire request body into memory
    * and setting it as CURLOPT_POSTFIELDS, so it isn't recommended for large
    * file uploads, use Socket adapter instead.
    *
    * @param    resource    cURL handle
    * @param    array       Request headers
    */
    protected function workaroundPhpBug47204($ch, &$headers)
    {
        // no redirects, no digest auth -> probably no rewind needed
        if (!$this->request->getConfig('follow_redirects')
            && (!($auth = $this->request->getAuth())
                || HTTP_Request2::AUTH_DIGEST != $auth['scheme'])
        ) {
            curl_setopt($ch, CURLOPT_READFUNCTION, array($this, 'callbackReadBody'));

        // rewind may be needed, read the whole body into memory
        } else {
            if ($this->requestBody instanceof HTTP_Request2_MultipartBody) {
                $this->requestBody = $this->requestBody->__toString();

            } elseif (is_resource($this->requestBody)) {
                $fp = $this->requestBody;
                $this->requestBody = '';
                while (!feof($fp)) {
                    $this->requestBody .= fread($fp, 16384);
                }
            }
            // curl hangs up if content-length is present
            unset($headers['content-length']);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $this->requestBody);
        }
    }

   /**
    * Callback function called by cURL for reading the request body
    *
    * @param    resource    cURL handle
    * @param    resource    file descriptor (not used)
    * @param    integer     maximum length of data to return
    * @return   string      part of the request body, up to $length bytes
    */
    protected function callbackReadBody($ch, $fd, $length)
    {
        if (!$this->eventSentHeaders) {
            $this->request->setLastEvent(
                'sentHeaders', curl_getinfo($ch, CURLINFO_HEADER_OUT)
            );
            $this->eventSentHeaders = true;
        }
        if (in_array($this->request->getMethod(), self::$bodyDisallowed) ||
            0 == $this->contentLength || $this->position >= $this->contentLength
        ) {
            return '';
        }
        if (is_string($this->requestBody)) {
            $string = substr($this->requestBody, $this->position, $length);
        } elseif (is_resource($this->requestBody)) {
            $string = fread($this->requestBody, $length);
        } else {
            $string = $this->requestBody->read($length);
        }
        $this->request->setLastEvent('sentBodyPart', strlen($string));
        $this->position += strlen($string);
        return $string;
    }

   /**
    * Callback function called by cURL for saving the response headers
    *
    * @param    resource    cURL handle
    * @param    string      response header (with trailing CRLF)
    * @return   integer     number of bytes saved
    * @see      HTTP_Request2_Response::parseHeaderLine()
    */
    protected function callbackWriteHeader($ch, $string)
    {
        // we may receive a second set of headers if doing e.g. digest auth
        if ($this->eventReceivedHeaders || !$this->eventSentHeaders) {
            // don't bother with 100-Continue responses (bug #15785)
            if (!$this->eventSentHeaders ||
                $this->response->getStatus() >= 200
            ) {
                $this->request->setLastEvent(
                    'sentHeaders', curl_getinfo($ch, CURLINFO_HEADER_OUT)
                );
            }
            $upload = curl_getinfo($ch, CURLINFO_SIZE_UPLOAD);
            // if body wasn't read by a callback, send event with total body size
            if ($upload > $this->position) {
                $this->request->setLastEvent(
                    'sentBodyPart', $upload - $this->position
                );
                $this->position = $upload;
            }
            if ($upload && (!$this->eventSentHeaders
                            || $this->response->getStatus() >= 200)
            ) {
                $this->request->setLastEvent('sentBody', $upload);
            }
            $this->eventSentHeaders = true;
            // we'll need a new response object
            if ($this->eventReceivedHeaders) {
                $this->eventReceivedHeaders = false;
                $this->response             = null;
            }
        }
        if (empty($this->response)) {
            $this->response = new HTTP_Request2_Response(
                $string, false, curl_getinfo($ch, CURLINFO_EFFECTIVE_URL)
            );
        } else {
            $this->response->parseHeaderLine($string);
            if ('' == trim($string)) {
                // don't bother with 100-Continue responses (bug #15785)
                if (200 <= $this->response->getStatus()) {
                    $this->request->setLastEvent('receivedHeaders', $this->response);
                }

                if ($this->request->getConfig('follow_redirects') && $this->response->isRedirect()) {
                    $redirectUrl = new Net_URL2($this->response->getHeader('location'));

                    // for versions lower than 5.2.10, check the redirection URL protocol
                    if (!defined('CURLOPT_REDIR_PROTOCOLS') && $redirectUrl->isAbsolute()
                        && !in_array($redirectUrl->getScheme(), array('http', 'https'))
                    ) {
                        return -1;
                    }

                    if ($jar = $this->request->getCookieJar()) {
                        $jar->addCookiesFromResponse($this->response, $this->request->getUrl());
                        if (!$redirectUrl->isAbsolute()) {
                            $redirectUrl = $this->request->getUrl()->resolve($redirectUrl);
                        }
                        if ($cookies = $jar->getMatching($redirectUrl, true)) {
                            curl_setopt($ch, CURLOPT_COOKIE, $cookies);
                        }
                    }
                }
                $this->eventReceivedHeaders = true;
            }
        }
        return strlen($string);
    }

   /**
    * Callback function called by cURL for saving the response body
    *
    * @param    resource    cURL handle (not used)
    * @param    string      part of the response body
    * @return   integer     number of bytes saved
    * @see      HTTP_Request2_Response::appendBody()
    */
    protected function callbackWriteBody($ch, $string)
    {
        // cURL calls WRITEFUNCTION callback without calling HEADERFUNCTION if
        // response doesn't start with proper HTTP status line (see bug #15716)
        if (empty($this->response)) {
            throw new HTTP_Request2_MessageException(
                "Malformed response: {$string}",
                HTTP_Request2_Exception::MALFORMED_RESPONSE
            );
        }
        if ($this->request->getConfig('store_body')) {
            $this->response->appendBody($string);
        }
        $this->request->setLastEvent('receivedBodyPart', $string);
        return strlen($string);
    }
}

// ----------------------------------------------------------------------------------------- //
//F PEAR://HTTP/Request2/Response.php                                                        //
// ----------------------------------------------------------------------------------------- //

/**
 * Class representing a HTTP response
 *
 * PHP version 5
 *
 * LICENSE:
 *
 * Copyright (c) 2008-2011, Alexey Borzov <avb@php.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * The names of the authors may not be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    SVN: $Id: Response.php 309921 2011-04-03 16:43:02Z avb $
 * @link       http://pear.php.net/package/HTTP_Request2
 */

/**
 * Class representing a HTTP response
 *
 * The class is designed to be used in "streaming" scenario, building the
 * response as it is being received:
 * <code>
 * $statusLine = read_status_line();
 * $response = new HTTP_Request2_Response($statusLine);
 * do {
 *     $headerLine = read_header_line();
 *     $response->parseHeaderLine($headerLine);
 * } while ($headerLine != '');
 *
 * while ($chunk = read_body()) {
 *     $response->appendBody($chunk);
 * }
 *
 * var_dump($response->getHeader(), $response->getCookies(), $response->getBody());
 * </code>
 *
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @version    Release: 2.0.0beta3
 * @link       http://tools.ietf.org/html/rfc2616#section-6
 */
class HTTP_Request2_Response
{
   /**
    * HTTP protocol version (e.g. 1.0, 1.1)
    * @var  string
    */
    protected $version;

   /**
    * Status code
    * @var  integer
    * @link http://tools.ietf.org/html/rfc2616#section-6.1.1
    */
    protected $code;

   /**
    * Reason phrase
    * @var  string
    * @link http://tools.ietf.org/html/rfc2616#section-6.1.1
    */
    protected $reasonPhrase;

   /**
    * Effective URL (may be different from original request URL in case of redirects)
    * @var  string
    */
    protected $effectiveUrl;

   /**
    * Associative array of response headers
    * @var  array
    */
    protected $headers = array();

   /**
    * Cookies set in the response
    * @var  array
    */
    protected $cookies = array();

   /**
    * Name of last header processed by parseHederLine()
    *
    * Used to handle the headers that span multiple lines
    *
    * @var  string
    */
    protected $lastHeader = null;

   /**
    * Response body
    * @var  string
    */
    protected $body = '';

   /**
    * Whether the body is still encoded by Content-Encoding
    *
    * cURL provides the decoded body to the callback; if we are reading from
    * socket the body is still gzipped / deflated
    *
    * @var  bool
    */
    protected $bodyEncoded;

   /**
    * Associative array of HTTP status code / reason phrase.
    *
    * @var  array
    * @link http://tools.ietf.org/html/rfc2616#section-10
    */
    protected static $phrases = array(

        // 1xx: Informational - Request received, continuing process
        100 => 'Continue',
        101 => 'Switching Protocols',

        // 2xx: Success - The action was successfully received, understood and
        // accepted
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',

        // 3xx: Redirection - Further action must be taken in order to complete
        // the request
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',  // 1.1
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        307 => 'Temporary Redirect',

        // 4xx: Client Error - The request contains bad syntax or cannot be
        // fulfilled
        400 => 'Bad Request',
        401 => 'Unauthorized',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Timeout',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Long',
        415 => 'Unsupported Media Type',
        416 => 'Requested Range Not Satisfiable',
        417 => 'Expectation Failed',

        // 5xx: Server Error - The server failed to fulfill an apparently
        // valid request
        500 => 'Internal Server Error',
        501 => 'Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Unavailable',
        504 => 'Gateway Timeout',
        505 => 'HTTP Version Not Supported',
        509 => 'Bandwidth Limit Exceeded',

    );

   /**
    * Constructor, parses the response status line
    *
    * @param    string Response status line (e.g. "HTTP/1.1 200 OK")
    * @param    bool   Whether body is still encoded by Content-Encoding
    * @param    string Effective URL of the response
    * @throws   HTTP_Request2_MessageException if status line is invalid according to spec
    */
    public function __construct($statusLine, $bodyEncoded = true, $effectiveUrl = null)
    {
        if (!preg_match('!^HTTP/(\d\.\d) (\d{3})(?: (.+))?!', $statusLine, $m)) {
            throw new HTTP_Request2_MessageException(
                "Malformed response: {$statusLine}",
                HTTP_Request2_Exception::MALFORMED_RESPONSE
            );
        }
        $this->version = $m[1];
        $this->code    = intval($m[2]);
        if (!empty($m[3])) {
            $this->reasonPhrase = trim($m[3]);
        } elseif (!empty(self::$phrases[$this->code])) {
            $this->reasonPhrase = self::$phrases[$this->code];
        }
        $this->bodyEncoded  = (bool)$bodyEncoded;
        $this->effectiveUrl = (string)$effectiveUrl;
    }

   /**
    * Parses the line from HTTP response filling $headers array
    *
    * The method should be called after reading the line from socket or receiving
    * it into cURL callback. Passing an empty string here indicates the end of
    * response headers and triggers additional processing, so be sure to pass an
    * empty string in the end.
    *
    * @param    string  Line from HTTP response
    */
    public function parseHeaderLine($headerLine)
    {
        $headerLine = trim($headerLine, "\r\n");

        // empty string signals the end of headers, process the received ones
        if ('' == $headerLine) {
            if (!empty($this->headers['set-cookie'])) {
                $cookies = is_array($this->headers['set-cookie'])?
                           $this->headers['set-cookie']:
                           array($this->headers['set-cookie']);
                foreach ($cookies as $cookieString) {
                    $this->parseCookie($cookieString);
                }
                unset($this->headers['set-cookie']);
            }
            foreach (array_keys($this->headers) as $k) {
                if (is_array($this->headers[$k])) {
                    $this->headers[$k] = implode(', ', $this->headers[$k]);
                }
            }

        // string of the form header-name: header value
        } elseif (preg_match('!^([^\x00-\x1f\x7f-\xff()<>@,;:\\\\"/\[\]?={}\s]+):(.+)$!', $headerLine, $m)) {
            $name  = strtolower($m[1]);
            $value = trim($m[2]);
            if (empty($this->headers[$name])) {
                $this->headers[$name] = $value;
            } else {
                if (!is_array($this->headers[$name])) {
                    $this->headers[$name] = array($this->headers[$name]);
                }
                $this->headers[$name][] = $value;
            }
            $this->lastHeader = $name;

        // continuation of a previous header
        } elseif (preg_match('!^\s+(.+)$!', $headerLine, $m) && $this->lastHeader) {
            if (!is_array($this->headers[$this->lastHeader])) {
                $this->headers[$this->lastHeader] .= ' ' . trim($m[1]);
            } else {
                $key = count($this->headers[$this->lastHeader]) - 1;
                $this->headers[$this->lastHeader][$key] .= ' ' . trim($m[1]);
            }
        }
    }

   /**
    * Parses a Set-Cookie header to fill $cookies array
    *
    * @param    string    value of Set-Cookie header
    * @link     http://web.archive.org/web/20080331104521/http://cgi.netscape.com/newsref/std/cookie_spec.html
    */
    protected function parseCookie($cookieString)
    {
        $cookie = array(
            'expires' => null,
            'domain'  => null,
            'path'    => null,
            'secure'  => false
        );

        // Only a name=value pair
        if (!strpos($cookieString, ';')) {
            $pos = strpos($cookieString, '=');
            $cookie['name']  = trim(substr($cookieString, 0, $pos));
            $cookie['value'] = trim(substr($cookieString, $pos + 1));

        // Some optional parameters are supplied
        } else {
            $elements = explode(';', $cookieString);
            $pos = strpos($elements[0], '=');
            $cookie['name']  = trim(substr($elements[0], 0, $pos));
            $cookie['value'] = trim(substr($elements[0], $pos + 1));

            for ($i = 1; $i < count($elements); $i++) {
                if (false === strpos($elements[$i], '=')) {
                    $elName  = trim($elements[$i]);
                    $elValue = null;
                } else {
                    list ($elName, $elValue) = array_map('trim', explode('=', $elements[$i]));
                }
                $elName = strtolower($elName);
                if ('secure' == $elName) {
                    $cookie['secure'] = true;
                } elseif ('expires' == $elName) {
                    $cookie['expires'] = str_replace('"', '', $elValue);
                } elseif ('path' == $elName || 'domain' == $elName) {
                    $cookie[$elName] = urldecode($elValue);
                } else {
                    $cookie[$elName] = $elValue;
                }
            }
        }
        $this->cookies[] = $cookie;
    }

   /**
    * Appends a string to the response body
    * @param    string
    */
    public function appendBody($bodyChunk)
    {
        $this->body .= $bodyChunk;
    }

   /**
    * Returns the effective URL of the response
    *
    * This may be different from the request URL if redirects were followed.
    *
    * @return string
    * @link   http://pear.php.net/bugs/bug.php?id=18412
    */
    public function getEffectiveUrl()
    {
        return $this->effectiveUrl;
    }

   /**
    * Returns the status code
    * @return   integer
    */
    public function getStatus()
    {
        return $this->code;
    }

   /**
    * Returns the reason phrase
    * @return   string
    */
    public function getReasonPhrase()
    {
        return $this->reasonPhrase;
    }

   /**
    * Whether response is a redirect that can be automatically handled by HTTP_Request2
    * @return   bool
    */
    public function isRedirect()
    {
        return in_array($this->code, array(300, 301, 302, 303, 307))
               && isset($this->headers['location']);
    }

   /**
    * Returns either the named header or all response headers
    *
    * @param    string          Name of header to return
    * @return   string|array    Value of $headerName header (null if header is
    *                           not present), array of all response headers if
    *                           $headerName is null
    */
    public function getHeader($headerName = null)
    {
        if (null === $headerName) {
            return $this->headers;
        } else {
            $headerName = strtolower($headerName);
            return isset($this->headers[$headerName])? $this->headers[$headerName]: null;
        }
    }

   /**
    * Returns cookies set in response
    *
    * @return   array
    */
    public function getCookies()
    {
        return $this->cookies;
    }

   /**
    * Returns the body of the response
    *
    * @return   string
    * @throws   HTTP_Request2_Exception if body cannot be decoded
    */
    public function getBody()
    {
        if (0 == strlen($this->body) || !$this->bodyEncoded ||
            !in_array(strtolower($this->getHeader('content-encoding')), array('gzip', 'deflate'))
        ) {
            return $this->body;

        } else {
            if (extension_loaded('mbstring') && (2 & ini_get('mbstring.func_overload'))) {
                $oldEncoding = mb_internal_encoding();
                mb_internal_encoding('iso-8859-1');
            }

            try {
                switch (strtolower($this->getHeader('content-encoding'))) {
                    case 'gzip':
                        $decoded = self::decodeGzip($this->body);
                        break;
                    case 'deflate':
                        $decoded = self::decodeDeflate($this->body);
                }
            } catch (Exception $e) {
            }

            if (!empty($oldEncoding)) {
                mb_internal_encoding($oldEncoding);
            }
            if (!empty($e)) {
                throw $e;
            }
            return $decoded;
        }
    }

   /**
    * Get the HTTP version of the response
    *
    * @return   string
    */
    public function getVersion()
    {
        return $this->version;
    }

   /**
    * Decodes the message-body encoded by gzip
    *
    * The real decoding work is done by gzinflate() built-in function, this
    * method only parses the header and checks data for compliance with
    * RFC 1952
    *
    * @param    string  gzip-encoded data
    * @return   string  decoded data
    * @throws   HTTP_Request2_LogicException
    * @throws   HTTP_Request2_MessageException
    * @link     http://tools.ietf.org/html/rfc1952
    */
    public static function decodeGzip($data)
    {
        $length = strlen($data);
        // If it doesn't look like gzip-encoded data, don't bother
        if (18 > $length || strcmp(substr($data, 0, 2), "\x1f\x8b")) {
            return $data;
        }
        if (!function_exists('gzinflate')) {
            throw new HTTP_Request2_LogicException(
                'Unable to decode body: gzip extension not available',
                HTTP_Request2_Exception::MISCONFIGURATION
            );
        }
        $method = ord(substr($data, 2, 1));
        if (8 != $method) {
            throw new HTTP_Request2_MessageException(
                'Error parsing gzip header: unknown compression method',
                HTTP_Request2_Exception::DECODE_ERROR
            );
        }
        $flags = ord(substr($data, 3, 1));
        if ($flags & 224) {
            throw new HTTP_Request2_MessageException(
                'Error parsing gzip header: reserved bits are set',
                HTTP_Request2_Exception::DECODE_ERROR
            );
        }

        // header is 10 bytes minimum. may be longer, though.
        $headerLength = 10;
        // extra fields, need to skip 'em
        if ($flags & 4) {
            if ($length - $headerLength - 2 < 8) {
                throw new HTTP_Request2_MessageException(
                    'Error parsing gzip header: data too short',
                    HTTP_Request2_Exception::DECODE_ERROR
                );
            }
            $extraLength = unpack('v', substr($data, 10, 2));
            if ($length - $headerLength - 2 - $extraLength[1] < 8) {
                throw new HTTP_Request2_MessageException(
                    'Error parsing gzip header: data too short',
                    HTTP_Request2_Exception::DECODE_ERROR
                );
            }
            $headerLength += $extraLength[1] + 2;
        }
        // file name, need to skip that
        if ($flags & 8) {
            if ($length - $headerLength - 1 < 8) {
                throw new HTTP_Request2_MessageException(
                    'Error parsing gzip header: data too short',
                    HTTP_Request2_Exception::DECODE_ERROR
                );
            }
            $filenameLength = strpos(substr($data, $headerLength), chr(0));
            if (false === $filenameLength || $length - $headerLength - $filenameLength - 1 < 8) {
                throw new HTTP_Request2_MessageException(
                    'Error parsing gzip header: data too short',
                    HTTP_Request2_Exception::DECODE_ERROR
                );
            }
            $headerLength += $filenameLength + 1;
        }
        // comment, need to skip that also
        if ($flags & 16) {
            if ($length - $headerLength - 1 < 8) {
                throw new HTTP_Request2_MessageException(
                    'Error parsing gzip header: data too short',
                    HTTP_Request2_Exception::DECODE_ERROR
                );
            }
            $commentLength = strpos(substr($data, $headerLength), chr(0));
            if (false === $commentLength || $length - $headerLength - $commentLength - 1 < 8) {
                throw new HTTP_Request2_MessageException(
                    'Error parsing gzip header: data too short',
                    HTTP_Request2_Exception::DECODE_ERROR
                );
            }
            $headerLength += $commentLength + 1;
        }
        // have a CRC for header. let's check
        if ($flags & 2) {
            if ($length - $headerLength - 2 < 8) {
                throw new HTTP_Request2_MessageException(
                    'Error parsing gzip header: data too short',
                    HTTP_Request2_Exception::DECODE_ERROR
                );
            }
            $crcReal   = 0xffff & crc32(substr($data, 0, $headerLength));
            $crcStored = unpack('v', substr($data, $headerLength, 2));
            if ($crcReal != $crcStored[1]) {
                throw new HTTP_Request2_MessageException(
                    'Header CRC check failed',
                    HTTP_Request2_Exception::DECODE_ERROR
                );
            }
            $headerLength += 2;
        }
        // unpacked data CRC and size at the end of encoded data
        $tmp = unpack('V2', substr($data, -8));
        $dataCrc  = $tmp[1];
        $dataSize = $tmp[2];

        // finally, call the gzinflate() function
        // don't pass $dataSize to gzinflate, see bugs #13135, #14370
        $unpacked = gzinflate(substr($data, $headerLength, -8));
        if (false === $unpacked) {
            throw new HTTP_Request2_MessageException(
                'gzinflate() call failed',
                HTTP_Request2_Exception::DECODE_ERROR
            );
        } elseif ($dataSize != strlen($unpacked)) {
            throw new HTTP_Request2_MessageException(
                'Data size check failed',
                HTTP_Request2_Exception::DECODE_ERROR
            );
        } elseif ((0xffffffff & $dataCrc) != (0xffffffff & crc32($unpacked))) {
            throw new HTTP_Request2_Exception(
                'Data CRC check failed',
                HTTP_Request2_Exception::DECODE_ERROR
            );
        }
        return $unpacked;
    }

   /**
    * Decodes the message-body encoded by deflate
    *
    * @param    string  deflate-encoded data
    * @return   string  decoded data
    * @throws   HTTP_Request2_LogicException
    */
    public static function decodeDeflate($data)
    {
        if (!function_exists('gzuncompress')) {
            throw new HTTP_Request2_LogicException(
                'Unable to decode body: gzip extension not available',
                HTTP_Request2_Exception::MISCONFIGURATION
            );
        }
        // RFC 2616 defines 'deflate' encoding as zlib format from RFC 1950,
        // while many applications send raw deflate stream from RFC 1951.
        // We should check for presence of zlib header and use gzuncompress() or
        // gzinflate() as needed. See bug #15305
        $header = unpack('n', substr($data, 0, 2));
        return (0 == $header[1] % 31)? gzuncompress($data): gzinflate($data);
    }
}

// ----------------------------------------------------------------------------------------- //
//F PEAR://HTTP/Request2/Adapter.php                                                         //
// ----------------------------------------------------------------------------------------- //

/**
 * Base class for HTTP_Request2 adapters
 *
 * PHP version 5
 *
 * LICENSE:
 *
 * Copyright (c) 2008-2011, Alexey Borzov <avb@php.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * The names of the authors may not be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    SVN: $Id: Adapter.php 308322 2011-02-14 13:58:03Z avb $
 * @link       http://pear.php.net/package/HTTP_Request2
 */

/**
 * Base class for HTTP_Request2 adapters
 *
 * HTTP_Request2 class itself only defines methods for aggregating the request
 * data, all actual work of sending the request to the remote server and
 * receiving its response is performed by adapters.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @version    Release: 2.0.0beta3
 */
abstract class HTTP_Request2_Adapter
{
   /**
    * A list of methods that MUST NOT have a request body, per RFC 2616
    * @var  array
    */
    protected static $bodyDisallowed = array('TRACE');

   /**
    * Methods having defined semantics for request body
    *
    * Content-Length header (indicating that the body follows, section 4.3 of
    * RFC 2616) will be sent for these methods even if no body was added
    *
    * @var  array
    * @link http://pear.php.net/bugs/bug.php?id=12900
    * @link http://pear.php.net/bugs/bug.php?id=14740
    */
    protected static $bodyRequired = array('POST', 'PUT');

   /**
    * Request being sent
    * @var  HTTP_Request2
    */
    protected $request;

   /**
    * Request body
    * @var  string|resource|HTTP_Request2_MultipartBody
    * @see  HTTP_Request2::getBody()
    */
    protected $requestBody;

   /**
    * Length of the request body
    * @var  integer
    */
    protected $contentLength;

   /**
    * Sends request to the remote server and returns its response
    *
    * @param    HTTP_Request2
    * @return   HTTP_Request2_Response
    * @throws   HTTP_Request2_Exception
    */
    abstract public function sendRequest(HTTP_Request2 $request);

   /**
    * Calculates length of the request body, adds proper headers
    *
    * @param    array   associative array of request headers, this method will
    *                   add proper 'Content-Length' and 'Content-Type' headers
    *                   to this array (or remove them if not needed)
    */
    protected function calculateRequestLength(&$headers)
    {
        $this->requestBody = $this->request->getBody();

        if (is_string($this->requestBody)) {
            $this->contentLength = strlen($this->requestBody);
        } elseif (is_resource($this->requestBody)) {
            $stat = fstat($this->requestBody);
            $this->contentLength = $stat['size'];
            rewind($this->requestBody);
        } else {
            $this->contentLength = $this->requestBody->getLength();
            $headers['content-type'] = 'multipart/form-data; boundary=' .
                                       $this->requestBody->getBoundary();
            $this->requestBody->rewind();
        }

        if (in_array($this->request->getMethod(), self::$bodyDisallowed) ||
            0 == $this->contentLength
        ) {
            // No body: send a Content-Length header nonetheless (request #12900),
            // but do that only for methods that require a body (bug #14740)
            if (in_array($this->request->getMethod(), self::$bodyRequired)) {
                $headers['content-length'] = 0;
            } else {
                unset($headers['content-length']);
                // if the method doesn't require a body and doesn't have a
                // body, don't send a Content-Type header. (request #16799)
                unset($headers['content-type']);
            }
        } else {
            if (empty($headers['content-type'])) {
                $headers['content-type'] = 'application/x-www-form-urlencoded';
            }
            $headers['content-length'] = $this->contentLength;
        }
    }
}

// ----------------------------------------------------------------------------------------- //
//F PEAR://Net/URL2.php                                                                      //
// ----------------------------------------------------------------------------------------- //

/**
 * Net_URL2, a class representing a URL as per RFC 3986.
 *
 * PHP version 5
 *
 * LICENSE:
 *
 * Copyright (c) 2007-2009, Peytz & Co. A/S
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Net_URL2 nor the names of its contributors may
 *     be used to endorse or promote products derived from this software
 *     without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @category  Networking
 * @package   Net_URL2
 * @author    Christian Schmidt <schmidt@php.net>
 * @copyright 2007-2009 Peytz & Co. A/S
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD License
 * @version   CVS: $Id: URL2.php 290036 2009-10-28 19:52:49Z schmidt $
 * @link      http://www.rfc-editor.org/rfc/rfc3986.txt
 */

/**
 * Represents a URL as per RFC 3986.
 *
 * @category  Networking
 * @package   Net_URL2
 * @author    Christian Schmidt <schmidt@php.net>
 * @copyright 2007-2009 Peytz & Co. A/S
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD License
 * @version   Release: @package_version@
 * @link      http://pear.php.net/package/Net_URL2
 */
class Net_URL2
{
    /**
     * Do strict parsing in resolve() (see RFC 3986, section 5.2.2). Default
     * is true.
     */
    const OPTION_STRICT = 'strict';

    /**
     * Represent arrays in query using PHP's [] notation. Default is true.
     */
    const OPTION_USE_BRACKETS = 'use_brackets';

    /**
     * URL-encode query variable keys. Default is true.
     */
    const OPTION_ENCODE_KEYS = 'encode_keys';

    /**
     * Query variable separators when parsing the query string. Every character
     * is considered a separator. Default is "&".
     */
    const OPTION_SEPARATOR_INPUT = 'input_separator';

    /**
     * Query variable separator used when generating the query string. Default
     * is "&".
     */
    const OPTION_SEPARATOR_OUTPUT = 'output_separator';

    /**
     * Default options corresponds to how PHP handles $_GET.
     */
    private $_options = array(
        self::OPTION_STRICT           => true,
        self::OPTION_USE_BRACKETS     => true,
        self::OPTION_ENCODE_KEYS      => true,
        self::OPTION_SEPARATOR_INPUT  => '&',
        self::OPTION_SEPARATOR_OUTPUT => '&',
        );

    /**
     * @var  string|bool
     */
    private $_scheme = false;

    /**
     * @var  string|bool
     */
    private $_userinfo = false;

    /**
     * @var  string|bool
     */
    private $_host = false;

    /**
     * @var  string|bool
     */
    private $_port = false;

    /**
     * @var  string
     */
    private $_path = '';

    /**
     * @var  string|bool
     */
    private $_query = false;

    /**
     * @var  string|bool
     */
    private $_fragment = false;

    /**
     * Constructor.
     *
     * @param string $url     an absolute or relative URL
     * @param array  $options an array of OPTION_xxx constants
     */
    public function __construct($url, array $options = array())
    {
        foreach ($options as $optionName => $value) {
            if (array_key_exists($optionName, $this->_options)) {
                $this->_options[$optionName] = $value;
            }
        }

        // The regular expression is copied verbatim from RFC 3986, appendix B.
        // The expression does not validate the URL but matches any string.
        preg_match('!^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?!',
                   $url,
                   $matches);

        // "path" is always present (possibly as an empty string); the rest
        // are optional.
        $this->_scheme = !empty($matches[1]) ? $matches[2] : false;
        $this->setAuthority(!empty($matches[3]) ? $matches[4] : false);
        $this->_path = $matches[5];
        $this->_query = !empty($matches[6]) ? $matches[7] : false;
        $this->_fragment = !empty($matches[8]) ? $matches[9] : false;
    }

    /**
     * Magic Setter.
     *
     * This method will magically set the value of a private variable ($var)
     * with the value passed as the args
     *
     * @param  string $var      The private variable to set.
     * @param  mixed  $arg      An argument of any type.
     * @return void
     */
    public function __set($var, $arg)
    {
        $method = 'set' . $var;
        if (method_exists($this, $method)) {
            $this->$method($arg);
        }
    }
    
    /**
     * Magic Getter.
     *
     * This is the magic get method to retrieve the private variable 
     * that was set by either __set() or it's setter...
     * 
     * @param  string $var         The property name to retrieve.
     * @return mixed  $this->$var  Either a boolean false if the
     *                             property is not set or the value
     *                             of the private property.
     */
    public function __get($var)
    {
        $method = 'get' . $var;
        if (method_exists($this, $method)) {
            return $this->$method();
        }
        
        return false;
    }
    
    /**
     * Returns the scheme, e.g. "http" or "urn", or false if there is no
     * scheme specified, i.e. if this is a relative URL.
     *
     * @return  string|bool
     */
    public function getScheme()
    {
        return $this->_scheme;
    }

    /**
     * Sets the scheme, e.g. "http" or "urn". Specify false if there is no
     * scheme specified, i.e. if this is a relative URL.
     *
     * @param string|bool $scheme e.g. "http" or "urn", or false if there is no
     *                            scheme specified, i.e. if this is a relative
     *                            URL
     *
     * @return void
     * @see    getScheme()
     */
    public function setScheme($scheme)
    {
        $this->_scheme = $scheme;
    }

    /**
     * Returns the user part of the userinfo part (the part preceding the first
     *  ":"), or false if there is no userinfo part.
     *
     * @return  string|bool
     */
    public function getUser()
    {
        return $this->_userinfo !== false
            ? preg_replace('@:.*$@', '', $this->_userinfo)
            : false;
    }

    /**
     * Returns the password part of the userinfo part (the part after the first
     *  ":"), or false if there is no userinfo part (i.e. the URL does not
     * contain "@" in front of the hostname) or the userinfo part does not
     * contain ":".
     *
     * @return  string|bool
     */
    public function getPassword()
    {
        return $this->_userinfo !== false
            ? substr(strstr($this->_userinfo, ':'), 1)
            : false;
    }

    /**
     * Returns the userinfo part, or false if there is none, i.e. if the
     * authority part does not contain "@".
     *
     * @return  string|bool
     */
    public function getUserinfo()
    {
        return $this->_userinfo;
    }

    /**
     * Sets the userinfo part. If two arguments are passed, they are combined
     * in the userinfo part as username ":" password.
     *
     * @param string|bool $userinfo userinfo or username
     * @param string|bool $password optional password, or false
     *
     * @return void
     */
    public function setUserinfo($userinfo, $password = false)
    {
        $this->_userinfo = $userinfo;
        if ($password !== false) {
            $this->_userinfo .= ':' . $password;
        }
    }

    /**
     * Returns the host part, or false if there is no authority part, e.g.
     * relative URLs.
     *
     * @return  string|bool a hostname, an IP address, or false
     */
    public function getHost()
    {
        return $this->_host;
    }

    /**
     * Sets the host part. Specify false if there is no authority part, e.g.
     * relative URLs.
     *
     * @param string|bool $host a hostname, an IP address, or false
     *
     * @return void
     */
    public function setHost($host)
    {
        $this->_host = $host;
    }

    /**
     * Returns the port number, or false if there is no port number specified,
     * i.e. if the default port is to be used.
     *
     * @return  string|bool
     */
    public function getPort()
    {
        return $this->_port;
    }

    /**
     * Sets the port number. Specify false if there is no port number specified,
     * i.e. if the default port is to be used.
     *
     * @param string|bool $port a port number, or false
     *
     * @return void
     */
    public function setPort($port)
    {
        $this->_port = $port;
    }

    /**
     * Returns the authority part, i.e. [ userinfo "@" ] host [ ":" port ], or
     * false if there is no authority.
     *
     * @return string|bool
     */
    public function getAuthority()
    {
        if (!$this->_host) {
            return false;
        }

        $authority = '';

        if ($this->_userinfo !== false) {
            $authority .= $this->_userinfo . '@';
        }

        $authority .= $this->_host;

        if ($this->_port !== false) {
            $authority .= ':' . $this->_port;
        }

        return $authority;
    }

    /**
     * Sets the authority part, i.e. [ userinfo "@" ] host [ ":" port ]. Specify
     * false if there is no authority.
     *
     * @param string|false $authority a hostname or an IP addresse, possibly
     *                                with userinfo prefixed and port number
     *                                appended, e.g. "foo:bar@example.org:81".
     *
     * @return void
     */
    public function setAuthority($authority)
    {
        $this->_userinfo = false;
        $this->_host     = false;
        $this->_port     = false;
        if (preg_match('@^(([^\@]*)\@)?([^:]+)(:(\d*))?$@', $authority, $reg)) {
            if ($reg[1]) {
                $this->_userinfo = $reg[2];
            }

            $this->_host = $reg[3];
            if (isset($reg[5])) {
                $this->_port = $reg[5];
            }
        }
    }

    /**
     * Returns the path part (possibly an empty string).
     *
     * @return string
     */
    public function getPath()
    {
        return $this->_path;
    }

    /**
     * Sets the path part (possibly an empty string).
     *
     * @param string $path a path
     *
     * @return void
     */
    public function setPath($path)
    {
        $this->_path = $path;
    }

    /**
     * Returns the query string (excluding the leading "?"), or false if "?"
     * is not present in the URL.
     *
     * @return  string|bool
     * @see     self::getQueryVariables()
     */
    public function getQuery()
    {
        return $this->_query;
    }

    /**
     * Sets the query string (excluding the leading "?"). Specify false if "?"
     * is not present in the URL.
     *
     * @param string|bool $query a query string, e.g. "foo=1&bar=2"
     *
     * @return void
     * @see   self::setQueryVariables()
     */
    public function setQuery($query)
    {
        $this->_query = $query;
    }

    /**
     * Returns the fragment name, or false if "#" is not present in the URL.
     *
     * @return  string|bool
     */
    public function getFragment()
    {
        return $this->_fragment;
    }

    /**
     * Sets the fragment name. Specify false if "#" is not present in the URL.
     *
     * @param string|bool $fragment a fragment excluding the leading "#", or
     *                              false
     *
     * @return void
     */
    public function setFragment($fragment)
    {
        $this->_fragment = $fragment;
    }

    /**
     * Returns the query string like an array as the variables would appear in
     * $_GET in a PHP script. If the URL does not contain a "?", an empty array
     * is returned.
     *
     * @return  array
     */
    public function getQueryVariables()
    {
        $pattern = '/[' .
                   preg_quote($this->getOption(self::OPTION_SEPARATOR_INPUT), '/') .
                   ']/';
        $parts   = preg_split($pattern, $this->_query, -1, PREG_SPLIT_NO_EMPTY);
        $return  = array();

        foreach ($parts as $part) {
            if (strpos($part, '=') !== false) {
                list($key, $value) = explode('=', $part, 2);
            } else {
                $key   = $part;
                $value = null;
            }

            if ($this->getOption(self::OPTION_ENCODE_KEYS)) {
                $key = rawurldecode($key);
            }
            $value = rawurldecode($value);

            if ($this->getOption(self::OPTION_USE_BRACKETS) &&
                preg_match('#^(.*)\[([0-9a-z_-]*)\]#i', $key, $matches)) {

                $key = $matches[1];
                $idx = $matches[2];

                // Ensure is an array
                if (empty($return[$key]) || !is_array($return[$key])) {
                    $return[$key] = array();
                }

                // Add data
                if ($idx === '') {
                    $return[$key][] = $value;
                } else {
                    $return[$key][$idx] = $value;
                }
            } elseif (!$this->getOption(self::OPTION_USE_BRACKETS)
                      && !empty($return[$key])
            ) {
                $return[$key]   = (array) $return[$key];
                $return[$key][] = $value;
            } else {
                $return[$key] = $value;
            }
        }

        return $return;
    }

    /**
     * Sets the query string to the specified variable in the query string.
     *
     * @param array $array (name => value) array
     *
     * @return void
     */
    public function setQueryVariables(array $array)
    {
        if (!$array) {
            $this->_query = false;
        } else {
            foreach ($array as $name => $value) {
                if ($this->getOption(self::OPTION_ENCODE_KEYS)) {
                    $name = self::urlencode($name);
                }

                if (is_array($value)) {
                    foreach ($value as $k => $v) {
                        $parts[] = $this->getOption(self::OPTION_USE_BRACKETS)
                            ? sprintf('%s[%s]=%s', $name, $k, $v)
                            : ($name . '=' . $v);
                    }
                } elseif (!is_null($value)) {
                    $parts[] = $name . '=' . self::urlencode($value);
                } else {
                    $parts[] = $name;
                }
            }
            $this->_query = implode($this->getOption(self::OPTION_SEPARATOR_OUTPUT),
                                    $parts);
        }
    }

    /**
     * Sets the specified variable in the query string.
     *
     * @param string $name  variable name
     * @param mixed  $value variable value
     *
     * @return  array
     */
    public function setQueryVariable($name, $value)
    {
        $array = $this->getQueryVariables();
        $array[$name] = $value;
        $this->setQueryVariables($array);
    }

    /**
     * Removes the specifed variable from the query string.
     *
     * @param string $name a query string variable, e.g. "foo" in "?foo=1"
     *
     * @return void
     */
    public function unsetQueryVariable($name)
    {
        $array = $this->getQueryVariables();
        unset($array[$name]);
        $this->setQueryVariables($array);
    }

    /**
     * Returns a string representation of this URL.
     *
     * @return  string
     */
    public function getURL()
    {
        // See RFC 3986, section 5.3
        $url = "";

        if ($this->_scheme !== false) {
            $url .= $this->_scheme . ':';
        }

        $authority = $this->getAuthority();
        if ($authority !== false) {
            $url .= '//' . $authority;
        }
        $url .= $this->_path;

        if ($this->_query !== false) {
            $url .= '?' . $this->_query;
        }

        if ($this->_fragment !== false) {
            $url .= '#' . $this->_fragment;
        }
    
        return $url;
    }

    /**
     * Returns a string representation of this URL.
     *
     * @return  string
     * @see toString()
     */
    public function __toString()
    {
        return $this->getURL();
    }

    /** 
     * Returns a normalized string representation of this URL. This is useful
     * for comparison of URLs.
     *
     * @return  string
     */
    public function getNormalizedURL()
    {
        $url = clone $this;
        $url->normalize();
        return $url->getUrl();
    }

    /** 
     * Returns a normalized Net_URL2 instance.
     *
     * @return  Net_URL2
     */
    public function normalize()
    {
        // See RFC 3886, section 6

        // Schemes are case-insensitive
        if ($this->_scheme) {
            $this->_scheme = strtolower($this->_scheme);
        }

        // Hostnames are case-insensitive
        if ($this->_host) {
            $this->_host = strtolower($this->_host);
        }

        // Remove default port number for known schemes (RFC 3986, section 6.2.3)
        if ($this->_port &&
            $this->_scheme &&
            $this->_port == getservbyname($this->_scheme, 'tcp')) {

            $this->_port = false;
        }

        // Normalize case of %XX percentage-encodings (RFC 3986, section 6.2.2.1)
        foreach (array('_userinfo', '_host', '_path') as $part) {
            if ($this->$part) {
                $this->$part = preg_replace('/%[0-9a-f]{2}/ie',
                                            'strtoupper("\0")',
                                            $this->$part);
            }
        }

        // Path segment normalization (RFC 3986, section 6.2.2.3)
        $this->_path = self::removeDotSegments($this->_path);

        // Scheme based normalization (RFC 3986, section 6.2.3)
        if ($this->_host && !$this->_path) {
            $this->_path = '/';
        }
    }

    /**
     * Returns whether this instance represents an absolute URL.
     *
     * @return  bool
     */
    public function isAbsolute()
    {
        return (bool) $this->_scheme;
    }

    /**
     * Returns an Net_URL2 instance representing an absolute URL relative to
     * this URL.
     *
     * @param Net_URL2|string $reference relative URL
     *
     * @return Net_URL2
     */
    public function resolve($reference)
    {
        if (!$reference instanceof Net_URL2) {
            $reference = new self($reference);
        }
        if (!$this->isAbsolute()) {
            throw new Exception('Base-URL must be absolute');
        }

        // A non-strict parser may ignore a scheme in the reference if it is
        // identical to the base URI's scheme.
        if (!$this->getOption(self::OPTION_STRICT) && $reference->_scheme == $this->_scheme) {
            $reference->_scheme = false;
        }

        $target = new self('');
        if ($reference->_scheme !== false) {
            $target->_scheme = $reference->_scheme;
            $target->setAuthority($reference->getAuthority());
            $target->_path  = self::removeDotSegments($reference->_path);
            $target->_query = $reference->_query;
        } else {
            $authority = $reference->getAuthority();
            if ($authority !== false) {
                $target->setAuthority($authority);
                $target->_path  = self::removeDotSegments($reference->_path);
                $target->_query = $reference->_query;
            } else {
                if ($reference->_path == '') {
                    $target->_path = $this->_path;
                    if ($reference->_query !== false) {
                        $target->_query = $reference->_query;
                    } else {
                        $target->_query = $this->_query;
                    }
                } else {
                    if (substr($reference->_path, 0, 1) == '/') {
                        $target->_path = self::removeDotSegments($reference->_path);
                    } else {
                        // Merge paths (RFC 3986, section 5.2.3)
                        if ($this->_host !== false && $this->_path == '') {
                            $target->_path = '/' . $this->_path;
                        } else {
                            $i = strrpos($this->_path, '/');
                            if ($i !== false) {
                                $target->_path = substr($this->_path, 0, $i + 1);
                            }
                            $target->_path .= $reference->_path;
                        }
                        $target->_path = self::removeDotSegments($target->_path);
                    }
                    $target->_query = $reference->_query;
                }
                $target->setAuthority($this->getAuthority());
            }
            $target->_scheme = $this->_scheme;
        }

        $target->_fragment = $reference->_fragment;

        return $target;
    }

    /**
     * Removes dots as described in RFC 3986, section 5.2.4, e.g.
     * "/foo/../bar/baz" => "/bar/baz"
     *
     * @param string $path a path
     *
     * @return string a path
     */
    public static function removeDotSegments($path)
    {
        $output = '';

        // Make sure not to be trapped in an infinite loop due to a bug in this
        // method
        $j = 0; 
        while ($path && $j++ < 100) {
            if (substr($path, 0, 2) == './') {
                // Step 2.A
                $path = substr($path, 2);
            } elseif (substr($path, 0, 3) == '../') {
                // Step 2.A
                $path = substr($path, 3);
            } elseif (substr($path, 0, 3) == '/./' || $path == '/.') {
                // Step 2.B
                $path = '/' . substr($path, 3);
            } elseif (substr($path, 0, 4) == '/../' || $path == '/..') {
                // Step 2.C
                $path   = '/' . substr($path, 4);
                $i      = strrpos($output, '/');
                $output = $i === false ? '' : substr($output, 0, $i);
            } elseif ($path == '.' || $path == '..') {
                // Step 2.D
                $path = '';
            } else {
                // Step 2.E
                $i = strpos($path, '/');
                if ($i === 0) {
                    $i = strpos($path, '/', 1);
                }
                if ($i === false) {
                    $i = strlen($path);
                }
                $output .= substr($path, 0, $i);
                $path = substr($path, $i);
            }
        }

        return $output;
    }

    /**
     * Percent-encodes all non-alphanumeric characters except these: _ . - ~
     * Similar to PHP's rawurlencode(), except that it also encodes ~ in PHP
     * 5.2.x and earlier.
     *
     * @param  $raw the string to encode
     * @return string
     */
    public static function urlencode($string)
    {
    	$encoded = rawurlencode($string);
	// This is only necessary in PHP < 5.3.
	$encoded = str_replace('%7E', '~', $encoded);
	return $encoded;
    }

    /**
     * Returns a Net_URL2 instance representing the canonical URL of the
     * currently executing PHP script.
     * 
     * @return  string
     */
    public static function getCanonical()
    {
        if (!isset($_SERVER['REQUEST_METHOD'])) {
            // ALERT - no current URL
            throw new Exception('Script was not called through a webserver');
        }

        // Begin with a relative URL
        $url = new self($_SERVER['PHP_SELF']);
        $url->_scheme = isset($_SERVER['HTTPS']) ? 'https' : 'http';
        $url->_host   = $_SERVER['SERVER_NAME'];
        $port = $_SERVER['SERVER_PORT'];
        if ($url->_scheme == 'http' && $port != 80 ||
            $url->_scheme == 'https' && $port != 443) {

            $url->_port = $port;
        }
        return $url;
    }

    /**
     * Returns the URL used to retrieve the current request.
     *
     * @return  string
     */
    public static function getRequestedURL()
    {
        return self::getRequested()->getUrl();
    }

    /**
     * Returns a Net_URL2 instance representing the URL used to retrieve the
     * current request.
     *
     * @return  Net_URL2
     */
    public static function getRequested()
    {
        if (!isset($_SERVER['REQUEST_METHOD'])) {
            // ALERT - no current URL
            throw new Exception('Script was not called through a webserver');
        }

        // Begin with a relative URL
        $url = new self($_SERVER['REQUEST_URI']);
        $url->_scheme = isset($_SERVER['HTTPS']) ? 'https' : 'http';
        // Set host and possibly port
        $url->setAuthority($_SERVER['HTTP_HOST']);
        return $url;
    }

    /**
     * Returns the value of the specified option.
     *
     * @param string $optionName The name of the option to retrieve
     *
     * @return  mixed
     */
    function getOption($optionName)
    {
        return isset($this->_options[$optionName])
            ? $this->_options[$optionName] : false;
    }
}

// ----------------------------------------------------------------------------------------- //
//F PEAR://PEAR/Exception.php                                                                //
// ----------------------------------------------------------------------------------------- //

/* vim: set expandtab tabstop=4 shiftwidth=4 foldmethod=marker: */
/**
 * PEAR_Exception
 *
 * PHP versions 4 and 5
 *
 * @category   pear
 * @package    PEAR
 * @author     Tomas V. V. Cox <cox@idecnet.com>
 * @author     Hans Lellelid <hans@velum.net>
 * @author     Bertrand Mansion <bmansion@mamasam.com>
 * @author     Greg Beaver <cellog@php.net>
 * @copyright  1997-2009 The Authors
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    CVS: $Id: Exception.php 307683 2011-01-23 21:56:12Z dufuz $
 * @link       http://pear.php.net/package/PEAR
 * @since      File available since Release 1.3.3
 */

/**
 * Base PEAR_Exception Class
 *
 * 1) Features:
 *
 * - Nestable exceptions (throw new PEAR_Exception($msg, $prev_exception))
 * - Definable triggers, shot when exceptions occur
 * - Pretty and informative error messages
 * - Added more context info available (like class, method or cause)
 * - cause can be a PEAR_Exception or an array of mixed
 *   PEAR_Exceptions/PEAR_ErrorStack warnings
 * - callbacks for specific exception classes and their children
 *
 * 2) Ideas:
 *
 * - Maybe a way to define a 'template' for the output
 *
 * 3) Inherited properties from PHP Exception Class:
 *
 * protected $message
 * protected $code
 * protected $line
 * protected $file
 * private   $trace
 *
 * 4) Inherited methods from PHP Exception Class:
 *
 * __clone
 * __construct
 * getMessage
 * getCode
 * getFile
 * getLine
 * getTraceSafe
 * getTraceSafeAsString
 * __toString
 *
 * 5) Usage example
 *
 * <code>
 *  require_once 'PEAR_HTTP_Request2.php';
 *
 *  class Test {
 *     function foo() {
 *         throw new PEAR_Exception('Error Message', ERROR_CODE);
 *     }
 *  }
 *
 *  function myLogger($pear_exception) {
 *     echo $pear_exception->getMessage();
 *  }
 *  // each time a exception is thrown the 'myLogger' will be called
 *  // (its use is completely optional)
 *  PEAR_Exception::addObserver('myLogger');
 *  $test = new Test;
 *  try {
 *     $test->foo();
 *  } catch (PEAR_Exception $e) {
 *     print $e;
 *  }
 * </code>
 *
 * @category   pear
 * @package    PEAR
 * @author     Tomas V.V.Cox <cox@idecnet.com>
 * @author     Hans Lellelid <hans@velum.net>
 * @author     Bertrand Mansion <bmansion@mamasam.com>
 * @author     Greg Beaver <cellog@php.net>
 * @copyright  1997-2009 The Authors
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    Release: 1.9.2
 * @link       http://pear.php.net/package/PEAR
 * @since      Class available since Release 1.3.3
 *
 */
class PEAR_Exception extends Exception
{
    const OBSERVER_PRINT = -2;
    const OBSERVER_TRIGGER = -4;
    const OBSERVER_DIE = -8;
    protected $cause;
    private static $_observers = array();
    private static $_uniqueid = 0;
    private $_trace;

    /**
     * Supported signatures:
     *  - PEAR_Exception(string $message);
     *  - PEAR_Exception(string $message, int $code);
     *  - PEAR_Exception(string $message, Exception $cause);
     *  - PEAR_Exception(string $message, Exception $cause, int $code);
     *  - PEAR_Exception(string $message, PEAR_Error $cause);
     *  - PEAR_Exception(string $message, PEAR_Error $cause, int $code);
     *  - PEAR_Exception(string $message, array $causes);
     *  - PEAR_Exception(string $message, array $causes, int $code);
     * @param string exception message
     * @param int|Exception|PEAR_Error|array|null exception cause
     * @param int|null exception code or null
     */
    public function __construct($message, $p2 = null, $p3 = null)
    {
        if (is_int($p2)) {
            $code = $p2;
            $this->cause = null;
        } elseif (is_object($p2) || is_array($p2)) {
            // using is_object allows both Exception and PEAR_Error
            if (is_object($p2) && !($p2 instanceof Exception)) {
                if (!class_exists('PEAR_Error') || !($p2 instanceof PEAR_Error)) {
                    throw new PEAR_Exception('exception cause must be Exception, ' .
                        'array, or PEAR_Error');
                }
            }
            $code = $p3;
            if (is_array($p2) && isset($p2['message'])) {
                // fix potential problem of passing in a single warning
                $p2 = array($p2);
            }
            $this->cause = $p2;
        } else {
            $code = null;
            $this->cause = null;
        }
        parent::__construct($message, $code);
        $this->signal();
    }

    /**
     * @param mixed $callback  - A valid php callback, see php func is_callable()
     *                         - A PEAR_Exception::OBSERVER_* constant
     *                         - An array(const PEAR_Exception::OBSERVER_*,
     *                           mixed $options)
     * @param string $label    The name of the observer. Use this if you want
     *                         to remove it later with removeObserver()
     */
    public static function addObserver($callback, $label = 'default')
    {
        self::$_observers[$label] = $callback;
    }

    public static function removeObserver($label = 'default')
    {
        unset(self::$_observers[$label]);
    }

    /**
     * @return int unique identifier for an observer
     */
    public static function getUniqueId()
    {
        return self::$_uniqueid++;
    }

    private function signal()
    {
        foreach (self::$_observers as $func) {
            if (is_callable($func)) {
                call_user_func($func, $this);
                continue;
            }
            settype($func, 'array');
            switch ($func[0]) {
                case self::OBSERVER_PRINT :
                    $f = (isset($func[1])) ? $func[1] : '%s';
                    printf($f, $this->getMessage());
                    break;
                case self::OBSERVER_TRIGGER :
                    $f = (isset($func[1])) ? $func[1] : E_USER_NOTICE;
                    trigger_error($this->getMessage(), $f);
                    break;
                case self::OBSERVER_DIE :
                    $f = (isset($func[1])) ? $func[1] : '%s';
                    die(printf($f, $this->getMessage()));
                    break;
                default:
                    trigger_error('invalid observer type', E_USER_WARNING);
            }
        }
    }

    /**
     * Return specific error information that can be used for more detailed
     * error messages or translation.
     *
     * This method may be overridden in child exception classes in order
     * to add functionality not present in PEAR_Exception and is a placeholder
     * to define API
     *
     * The returned array must be an associative array of parameter => value like so:
     * <pre>
     * array('name' => $name, 'context' => array(...))
     * </pre>
     * @return array
     */
    public function getErrorData()
    {
        return array();
    }

    /**
     * Returns the exception that caused this exception to be thrown
     * @access public
     * @return Exception|array The context of the exception
     */
    public function getCause()
    {
        return $this->cause;
    }

    /**
     * Function must be public to call on caused exceptions
     * @param array
     */
    public function getCauseMessage(&$causes)
    {
        $trace = $this->getTraceSafe();
        $cause = array('class'   => get_class($this),
                       'message' => $this->message,
                       'file' => 'unknown',
                       'line' => 'unknown');
        if (isset($trace[0])) {
            if (isset($trace[0]['file'])) {
                $cause['file'] = $trace[0]['file'];
                $cause['line'] = $trace[0]['line'];
            }
        }
        $causes[] = $cause;
        if ($this->cause instanceof PEAR_Exception) {
            $this->cause->getCauseMessage($causes);
        } elseif ($this->cause instanceof Exception) {
            $causes[] = array('class'   => get_class($this->cause),
                              'message' => $this->cause->getMessage(),
                              'file' => $this->cause->getFile(),
                              'line' => $this->cause->getLine());
        } elseif (class_exists('PEAR_Error') && $this->cause instanceof PEAR_Error) {
            $causes[] = array('class' => get_class($this->cause),
                              'message' => $this->cause->getMessage(),
                              'file' => 'unknown',
                              'line' => 'unknown');
        } elseif (is_array($this->cause)) {
            foreach ($this->cause as $cause) {
                if ($cause instanceof PEAR_Exception) {
                    $cause->getCauseMessage($causes);
                } elseif ($cause instanceof Exception) {
                    $causes[] = array('class'   => get_class($cause),
                                   'message' => $cause->getMessage(),
                                   'file' => $cause->getFile(),
                                   'line' => $cause->getLine());
                } elseif (class_exists('PEAR_Error') && $cause instanceof PEAR_Error) {
                    $causes[] = array('class' => get_class($cause),
                                      'message' => $cause->getMessage(),
                                      'file' => 'unknown',
                                      'line' => 'unknown');
                } elseif (is_array($cause) && isset($cause['message'])) {
                    // PEAR_ErrorStack warning
                    $causes[] = array(
                        'class' => $cause['package'],
                        'message' => $cause['message'],
                        'file' => isset($cause['context']['file']) ?
                                            $cause['context']['file'] :
                                            'unknown',
                        'line' => isset($cause['context']['line']) ?
                                            $cause['context']['line'] :
                                            'unknown',
                    );
                }
            }
        }
    }

    public function getTraceSafe()
    {
        if (!isset($this->_trace)) {
            $this->_trace = $this->getTrace();
            if (empty($this->_trace)) {
                $backtrace = debug_backtrace();
                $this->_trace = array($backtrace[count($backtrace)-1]);
            }
        }
        return $this->_trace;
    }

    public function getErrorClass()
    {
        $trace = $this->getTraceSafe();
        return $trace[0]['class'];
    }

    public function getErrorMethod()
    {
        $trace = $this->getTraceSafe();
        return $trace[0]['function'];
    }

    public function __toString()
    {
        if (isset($_SERVER['REQUEST_URI'])) {
            return $this->toHtml();
        }
        return $this->toText();
    }

    public function toHtml()
    {
        $trace = $this->getTraceSafe();
        $causes = array();
        $this->getCauseMessage($causes);
        $html =  '<table style="border: 1px" cellspacing="0">' . "\n";
        foreach ($causes as $i => $cause) {
            $html .= '<tr><td colspan="3" style="background: #ff9999">'
               . str_repeat('-', $i) . ' <b>' . $cause['class'] . '</b>: '
               . htmlspecialchars($cause['message']) . ' in <b>' . $cause['file'] . '</b> '
               . 'on line <b>' . $cause['line'] . '</b>'
               . "</td></tr>\n";
        }
        $html .= '<tr><td colspan="3" style="background-color: #aaaaaa; text-align: center; font-weight: bold;">Exception trace</td></tr>' . "\n"
               . '<tr><td style="text-align: center; background: #cccccc; width:20px; font-weight: bold;">#</td>'
               . '<td style="text-align: center; background: #cccccc; font-weight: bold;">Function</td>'
               . '<td style="text-align: center; background: #cccccc; font-weight: bold;">Location</td></tr>' . "\n";

        foreach ($trace as $k => $v) {
            $html .= '<tr><td style="text-align: center;">' . $k . '</td>'
                   . '<td>';
            if (!empty($v['class'])) {
                $html .= $v['class'] . $v['type'];
            }
            $html .= $v['function'];
            $args = array();
            if (!empty($v['args'])) {
                foreach ($v['args'] as $arg) {
                    if (is_null($arg)) $args[] = 'null';
                    elseif (is_array($arg)) $args[] = 'Array';
                    elseif (is_object($arg)) $args[] = 'Object('.get_class($arg).')';
                    elseif (is_bool($arg)) $args[] = $arg ? 'true' : 'false';
                    elseif (is_int($arg) || is_double($arg)) $args[] = $arg;
                    else {
                        $arg = (string)$arg;
                        $str = htmlspecialchars(substr($arg, 0, 16));
                        if (strlen($arg) > 16) $str .= '&hellip;';
                        $args[] = "'" . $str . "'";
                    }
                }
            }
            $html .= '(' . implode(', ',$args) . ')'
                   . '</td>'
                   . '<td>' . (isset($v['file']) ? $v['file'] : 'unknown')
                   . ':' . (isset($v['line']) ? $v['line'] : 'unknown')
                   . '</td></tr>' . "\n";
        }
        $html .= '<tr><td style="text-align: center;">' . ($k+1) . '</td>'
               . '<td>{main}</td>'
               . '<td>&nbsp;</td></tr>' . "\n"
               . '</table>';
        return $html;
    }

    public function toText()
    {
        $causes = array();
        $this->getCauseMessage($causes);
        $causeMsg = '';
        foreach ($causes as $i => $cause) {
            $causeMsg .= str_repeat(' ', $i) . $cause['class'] . ': '
                   . $cause['message'] . ' in ' . $cause['file']
                   . ' on line ' . $cause['line'] . "\n";
        }
        return $causeMsg . $this->getTraceAsString();
    }
}

// ----------------------------------------------------------------------------------------- //
//F PEAR://HTTP/Request2/Exception.php                                                       //
// ----------------------------------------------------------------------------------------- //

/**
 * Exception classes for HTTP_Request2 package
 *
 * PHP version 5
 *
 * LICENSE:
 *
 * Copyright (c) 2008-2011, Alexey Borzov <avb@php.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * The names of the authors may not be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    SVN: $Id: Exception.php 308629 2011-02-24 17:34:24Z avb $
 * @link       http://pear.php.net/package/HTTP_Request2
 */


/**
 * Base exception class for HTTP_Request2 package
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @version    Release: 2.0.0beta3
 * @link       http://pear.php.net/pepr/pepr-proposal-show.php?id=132
 */
class HTTP_Request2_Exception extends PEAR_Exception
{
    /** An invalid argument was passed to a method */
    const INVALID_ARGUMENT   = 1;
    /** Some required value was not available */
    const MISSING_VALUE      = 2;
    /** Request cannot be processed due to errors in PHP configuration */
    const MISCONFIGURATION   = 3;
    /** Error reading the local file */
    const READ_ERROR         = 4;

    /** Server returned a response that does not conform to HTTP protocol */
    const MALFORMED_RESPONSE = 10;
    /** Failure decoding Content-Encoding or Transfer-Encoding of response */
    const DECODE_ERROR       = 20;
    /** Operation timed out */
    const TIMEOUT            = 30;
    /** Number of redirects exceeded 'max_redirects' configuration parameter */
    const TOO_MANY_REDIRECTS = 40;
    /** Redirect to a protocol other than http(s):// */
    const NON_HTTP_REDIRECT  = 50;

   /**
    * Native error code
    * @var int
    */
    private $_nativeCode;

   /**
    * Constructor, can set package error code and native error code
    *
    * @param string exception message
    * @param int    package error code, one of class constants
    * @param int    error code from underlying PHP extension
    */
    public function __construct($message = null, $code = null, $nativeCode = null)
    {
        parent::__construct($message, $code);
        $this->_nativeCode = $nativeCode;
    }

   /**
    * Returns error code produced by underlying PHP extension
    *
    * For Socket Adapter this may contain error number returned by
    * stream_socket_client(), for Curl Adapter this will contain error number
    * returned by curl_errno()
    *
    * @return integer
    */
    public function getNativeCode()
    {
        return $this->_nativeCode;
    }
}

/**
 * Exception thrown in case of missing features
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @version    Release: 2.0.0beta3
 */
class HTTP_Request2_NotImplementedException extends HTTP_Request2_Exception {}

/**
 * Exception that represents error in the program logic
 *
 * This exception usually implies a programmer's error, like passing invalid
 * data to methods or trying to use PHP extensions that weren't installed or
 * enabled. Usually exceptions of this kind will be thrown before request even
 * starts.
 *
 * The exception will usually contain a package error code.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @version    Release: 2.0.0beta3
 */
class HTTP_Request2_LogicException extends HTTP_Request2_Exception {}

/**
 * Exception thrown when connection to a web or proxy server fails
 *
 * The exception will not contain a package error code, but will contain
 * native error code, as returned by stream_socket_client() or curl_errno().
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @version    Release: 2.0.0beta3
 */
class HTTP_Request2_ConnectionException extends HTTP_Request2_Exception {}

/**
 * Exception thrown when sending or receiving HTTP message fails
 *
 * The exception may contain both package error code and native error code.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @version    Release: 2.0.0beta3
 */
class HTTP_Request2_MessageException extends HTTP_Request2_Exception {}

// ----------------------------------------------------------------------------------------- //
//F PEAR://HTTP/Request2/MultipartBody.php                                                   //
// ----------------------------------------------------------------------------------------- //

/**
 * Helper class for building multipart/form-data request body
 *
 * PHP version 5
 *
 * LICENSE:
 *
 * Copyright (c) 2008-2011, Alexey Borzov <avb@php.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * The names of the authors may not be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    SVN: $Id: MultipartBody.php 308322 2011-02-14 13:58:03Z avb $
 * @link       http://pear.php.net/package/HTTP_Request2
 */

/**
 * Class for building multipart/form-data request body
 *
 * The class helps to reduce memory consumption by streaming large file uploads
 * from disk, it also allows monitoring of upload progress (see request #7630)
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @version    Release: 2.0.0beta3
 * @link       http://tools.ietf.org/html/rfc1867
 */
class HTTP_Request2_MultipartBody
{
   /**
    * MIME boundary
    * @var  string
    */
    private $_boundary;

   /**
    * Form parameters added via {@link HTTP_Request2::addPostParameter()}
    * @var  array
    */
    private $_params = array();

   /**
    * File uploads added via {@link HTTP_Request2::addUpload()}
    * @var  array
    */
    private $_uploads = array();

   /**
    * Header for parts with parameters
    * @var  string
    */
    private $_headerParam = "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n";

   /**
    * Header for parts with uploads
    * @var  string
    */
    private $_headerUpload = "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n";

   /**
    * Current position in parameter and upload arrays
    *
    * First number is index of "current" part, second number is position within
    * "current" part
    *
    * @var  array
    */
    private $_pos = array(0, 0);


   /**
    * Constructor. Sets the arrays with POST data.
    *
    * @param    array   values of form fields set via {@link HTTP_Request2::addPostParameter()}
    * @param    array   file uploads set via {@link HTTP_Request2::addUpload()}
    * @param    bool    whether to append brackets to array variable names
    */
    public function __construct(array $params, array $uploads, $useBrackets = true)
    {
        $this->_params = self::_flattenArray('', $params, $useBrackets);
        foreach ($uploads as $fieldName => $f) {
            if (!is_array($f['fp'])) {
                $this->_uploads[] = $f + array('name' => $fieldName);
            } else {
                for ($i = 0; $i < count($f['fp']); $i++) {
                    $upload = array(
                        'name' => ($useBrackets? $fieldName . '[' . $i . ']': $fieldName)
                    );
                    foreach (array('fp', 'filename', 'size', 'type') as $key) {
                        $upload[$key] = $f[$key][$i];
                    }
                    $this->_uploads[] = $upload;
                }
            }
        }
    }

   /**
    * Returns the length of the body to use in Content-Length header
    *
    * @return   integer
    */
    public function getLength()
    {
        $boundaryLength     = strlen($this->getBoundary());
        $headerParamLength  = strlen($this->_headerParam) - 4 + $boundaryLength;
        $headerUploadLength = strlen($this->_headerUpload) - 8 + $boundaryLength;
        $length             = $boundaryLength + 6;
        foreach ($this->_params as $p) {
            $length += $headerParamLength + strlen($p[0]) + strlen($p[1]) + 2;
        }
        foreach ($this->_uploads as $u) {
            $length += $headerUploadLength + strlen($u['name']) + strlen($u['type']) +
                       strlen($u['filename']) + $u['size'] + 2;
        }
        return $length;
    }

   /**
    * Returns the boundary to use in Content-Type header
    *
    * @return   string
    */
    public function getBoundary()
    {
        if (empty($this->_boundary)) {
            $this->_boundary = '--' . md5('PEAR-HTTP_Request2-' . microtime());
        }
        return $this->_boundary;
    }

   /**
    * Returns next chunk of request body
    *
    * @param    integer Amount of bytes to read
    * @return   string  Up to $length bytes of data, empty string if at end
    */
    public function read($length)
    {
        $ret         = '';
        $boundary    = $this->getBoundary();
        $paramCount  = count($this->_params);
        $uploadCount = count($this->_uploads);
        while ($length > 0 && $this->_pos[0] <= $paramCount + $uploadCount) {
            $oldLength = $length;
            if ($this->_pos[0] < $paramCount) {
                $param = sprintf($this->_headerParam, $boundary,
                                 $this->_params[$this->_pos[0]][0]) .
                         $this->_params[$this->_pos[0]][1] . "\r\n";
                $ret    .= substr($param, $this->_pos[1], $length);
                $length -= min(strlen($param) - $this->_pos[1], $length);

            } elseif ($this->_pos[0] < $paramCount + $uploadCount) {
                $pos    = $this->_pos[0] - $paramCount;
                $header = sprintf($this->_headerUpload, $boundary,
                                  $this->_uploads[$pos]['name'],
                                  $this->_uploads[$pos]['filename'],
                                  $this->_uploads[$pos]['type']);
                if ($this->_pos[1] < strlen($header)) {
                    $ret    .= substr($header, $this->_pos[1], $length);
                    $length -= min(strlen($header) - $this->_pos[1], $length);
                }
                $filePos  = max(0, $this->_pos[1] - strlen($header));
                if ($length > 0 && $filePos < $this->_uploads[$pos]['size']) {
                    $ret     .= fread($this->_uploads[$pos]['fp'], $length);
                    $length  -= min($length, $this->_uploads[$pos]['size'] - $filePos);
                }
                if ($length > 0) {
                    $start   = $this->_pos[1] + ($oldLength - $length) -
                               strlen($header) - $this->_uploads[$pos]['size'];
                    $ret    .= substr("\r\n", $start, $length);
                    $length -= min(2 - $start, $length);
                }

            } else {
                $closing  = '--' . $boundary . "--\r\n";
                $ret     .= substr($closing, $this->_pos[1], $length);
                $length  -= min(strlen($closing) - $this->_pos[1], $length);
            }
            if ($length > 0) {
                $this->_pos     = array($this->_pos[0] + 1, 0);
            } else {
                $this->_pos[1] += $oldLength;
            }
        }
        return $ret;
    }

   /**
    * Sets the current position to the start of the body
    *
    * This allows reusing the same body in another request
    */
    public function rewind()
    {
        $this->_pos = array(0, 0);
        foreach ($this->_uploads as $u) {
            rewind($u['fp']);
        }
    }

   /**
    * Returns the body as string
    *
    * Note that it reads all file uploads into memory so it is a good idea not
    * to use this method with large file uploads and rely on read() instead.
    *
    * @return   string
    */
    public function __toString()
    {
        $this->rewind();
        return $this->read($this->getLength());
    }


   /**
    * Helper function to change the (probably multidimensional) associative array
    * into the simple one.
    *
    * @param    string  name for item
    * @param    mixed   item's values
    * @param    bool    whether to append [] to array variables' names
    * @return   array   array with the following items: array('item name', 'item value');
    */
    private static function _flattenArray($name, $values, $useBrackets)
    {
        if (!is_array($values)) {
            return array(array($name, $values));
        } else {
            $ret = array();
            foreach ($values as $k => $v) {
                if (empty($name)) {
                    $newName = $k;
                } elseif ($useBrackets) {
                    $newName = $name . '[' . $k . ']';
                } else {
                    $newName = $name;
                }
                $ret = array_merge($ret, self::_flattenArray($newName, $v, $useBrackets));
            }
            return $ret;
        }
    }
}

// ----------------------------------------------------------------------------------------- //
//F PEAR://HTTP/Request2/CookieJar.php                                                       //
// ----------------------------------------------------------------------------------------- //

/**
 * Stores cookies and passes them between HTTP requests
 *
 * PHP version 5
 *
 * LICENSE:
 *
 * Copyright (c) 2008-2011, Alexey Borzov <avb@php.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * The names of the authors may not be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    SVN: $Id: CookieJar.php 308629 2011-02-24 17:34:24Z avb $
 * @link       http://pear.php.net/package/HTTP_Request2
 */

/**
 * Stores cookies and passes them between HTTP requests
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @version    Release: 2.0.0beta3
 */
class HTTP_Request2_CookieJar implements Serializable
{
   /**
    * Array of stored cookies
    *
    * The array is indexed by domain, path and cookie name
    *   .example.com
    *     /
    *       some_cookie => cookie data
    *     /subdir
    *       other_cookie => cookie data
    *   .example.org
    *     ...
    *
    * @var array
    */
    protected $cookies = array();

   /**
    * Whether session cookies should be serialized when serializing the jar
    * @var bool
    */
    protected $serializeSession = false;

   /**
    * Whether Public Suffix List should be used for domain matching
    * @var bool
    */
    protected $useList = true;

   /**
    * Array with Public Suffix List data
    * @var  array
    * @link http://publicsuffix.org/
    */
    protected static $psl = array();

   /**
    * Class constructor, sets various options
    *
    * @param bool Controls serializing session cookies, see {@link serializeSessionCookies()}
    * @param bool Controls using Public Suffix List, see {@link usePublicSuffixList()}
    */
    public function __construct($serializeSessionCookies = false, $usePublicSuffixList = true)
    {
        $this->serializeSessionCookies($serializeSessionCookies);
        $this->usePublicSuffixList($usePublicSuffixList);
    }

   /**
    * Returns current time formatted in ISO-8601 at UTC timezone
    *
    * @return string
    */
    protected function now()
    {
        $dt = new DateTime();
        $dt->setTimezone(new DateTimeZone('UTC'));
        return $dt->format(DateTime::ISO8601);
    }

   /**
    * Checks cookie array for correctness, possibly updating its 'domain', 'path' and 'expires' fields
    *
    * The checks are as follows:
    *   - cookie array should contain 'name' and 'value' fields;
    *   - name and value should not contain disallowed symbols;
    *   - 'expires' should be either empty parseable by DateTime;
    *   - 'domain' and 'path' should be either not empty or an URL where
    *     cookie was set should be provided.
    *   - if $setter is provided, then document at that URL should be allowed
    *     to set a cookie for that 'domain'. If $setter is not provided,
    *     then no domain checks will be made.
    *
    * 'expires' field will be converted to ISO8601 format from COOKIE format,
    * 'domain' and 'path' will be set from setter URL if empty.
    *
    * @param    array    cookie data, as returned by {@link HTTP_Request2_Response::getCookies()}
    * @param    Net_URL2 URL of the document that sent Set-Cookie header
    * @return   array    Updated cookie array
    * @throws   HTTP_Request2_LogicException
    * @throws   HTTP_Request2_MessageException
    */
    protected function checkAndUpdateFields(array $cookie, Net_URL2 $setter = null)
    {
        if ($missing = array_diff(array('name', 'value'), array_keys($cookie))) {
            throw new HTTP_Request2_LogicException(
                "Cookie array should contain 'name' and 'value' fields",
                HTTP_Request2_Exception::MISSING_VALUE
            );
        }
        if (preg_match(HTTP_Request2::REGEXP_INVALID_COOKIE, $cookie['name'])) {
            throw new HTTP_Request2_LogicException(
                "Invalid cookie name: '{$cookie['name']}'",
                HTTP_Request2_Exception::INVALID_ARGUMENT
            );
        }
        if (preg_match(HTTP_Request2::REGEXP_INVALID_COOKIE, $cookie['value'])) {
            throw new HTTP_Request2_LogicException(
                "Invalid cookie value: '{$cookie['value']}'",
                HTTP_Request2_Exception::INVALID_ARGUMENT
            );
        }
        $cookie += array('domain' => '', 'path' => '', 'expires' => null, 'secure' => false);

        // Need ISO-8601 date @ UTC timezone
        if (!empty($cookie['expires'])
            && !preg_match('/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\+0000$/', $cookie['expires'])
        ) {
            try {
                $dt = new DateTime($cookie['expires']);
                $dt->setTimezone(new DateTimeZone('UTC'));
                $cookie['expires'] = $dt->format(DateTime::ISO8601);
            } catch (Exception $e) {
                throw new HTTP_Request2_LogicException($e->getMessage());
            }
        }

        if (empty($cookie['domain']) || empty($cookie['path'])) {
            if (!$setter) {
                throw new HTTP_Request2_LogicException(
                    'Cookie misses domain and/or path component, cookie setter URL needed',
                    HTTP_Request2_Exception::MISSING_VALUE
                );
            }
            if (empty($cookie['domain'])) {
                if ($host = $setter->getHost()) {
                    $cookie['domain'] = $host;
                } else {
                    throw new HTTP_Request2_LogicException(
                        'Setter URL does not contain host part, can\'t set cookie domain',
                        HTTP_Request2_Exception::MISSING_VALUE
                    );
                }
            }
            if (empty($cookie['path'])) {
                $path = $setter->getPath();
                $cookie['path'] = empty($path)? '/': substr($path, 0, strrpos($path, '/') + 1);
            }
        }

        if ($setter && !$this->domainMatch($setter->getHost(), $cookie['domain'])) {
            throw new HTTP_Request2_MessageException(
                "Domain " . $setter->getHost() . " cannot set cookies for "
                . $cookie['domain']
            );
        }

        return $cookie;
    }

   /**
    * Stores a cookie in the jar
    *
    * @param    array    cookie data, as returned by {@link HTTP_Request2_Response::getCookies()}
    * @param    Net_URL2 URL of the document that sent Set-Cookie header
    * @throws   HTTP_Request2_Exception
    */
    public function store(array $cookie, Net_URL2 $setter = null)
    {
        $cookie = $this->checkAndUpdateFields($cookie, $setter);

        if (strlen($cookie['value'])
            && (is_null($cookie['expires']) || $cookie['expires'] > $this->now())
        ) {
            if (!isset($this->cookies[$cookie['domain']])) {
                $this->cookies[$cookie['domain']] = array();
            }
            if (!isset($this->cookies[$cookie['domain']][$cookie['path']])) {
                $this->cookies[$cookie['domain']][$cookie['path']] = array();
            }
            $this->cookies[$cookie['domain']][$cookie['path']][$cookie['name']] = $cookie;

        } elseif (isset($this->cookies[$cookie['domain']][$cookie['path']][$cookie['name']])) {
            unset($this->cookies[$cookie['domain']][$cookie['path']][$cookie['name']]);
        }
    }

   /**
    * Adds cookies set in HTTP response to the jar
    *
    * @param HTTP_Request2_Response response
    * @param Net_URL2               original request URL, needed for setting
    *                               default domain/path
    */
    public function addCookiesFromResponse(HTTP_Request2_Response $response, Net_URL2 $setter)
    {
        foreach ($response->getCookies() as $cookie) {
            $this->store($cookie, $setter);
        }
    }

   /**
    * Returns all cookies matching a given request URL
    *
    * The following checks are made:
    *   - cookie domain should match request host
    *   - cookie path should be a prefix for request path
    *   - 'secure' cookies will only be sent for HTTPS requests
    *
    * @param  Net_URL2
    * @param  bool      Whether to return cookies as string for "Cookie: " header
    * @return array
    */
    public function getMatching(Net_URL2 $url, $asString = false)
    {
        $host   = $url->getHost();
        $path   = $url->getPath();
        $secure = 0 == strcasecmp($url->getScheme(), 'https');

        $matched = $ret = array();
        foreach (array_keys($this->cookies) as $domain) {
            if ($this->domainMatch($host, $domain)) {
                foreach (array_keys($this->cookies[$domain]) as $cPath) {
                    if (0 === strpos($path, $cPath)) {
                        foreach ($this->cookies[$domain][$cPath] as $name => $cookie) {
                            if (!$cookie['secure'] || $secure) {
                                $matched[$name][strlen($cookie['path'])] = $cookie;
                            }
                        }
                    }
                }
            }
        }
        foreach ($matched as $cookies) {
            krsort($cookies);
            $ret = array_merge($ret, $cookies);
        }
        if (!$asString) {
            return $ret;
        } else {
            $str = '';
            foreach ($ret as $c) {
                $str .= (empty($str)? '': '; ') . $c['name'] . '=' . $c['value'];
            }
            return $str;
        }
    }

   /**
    * Returns all cookies stored in a jar
    *
    * @return array
    */
    public function getAll()
    {
        $cookies = array();
        foreach (array_keys($this->cookies) as $domain) {
            foreach (array_keys($this->cookies[$domain]) as $path) {
                foreach ($this->cookies[$domain][$path] as $name => $cookie) {
                    $cookies[] = $cookie;
                }
            }
        }
        return $cookies;
    }

   /**
    * Sets whether session cookies should be serialized when serializing the jar
    *
    * @param    boolean
    */
    public function serializeSessionCookies($serialize)
    {
        $this->serializeSession = (bool)$serialize;
    }

   /**
    * Sets whether Public Suffix List should be used for restricting cookie-setting
    *
    * Without PSL {@link domainMatch()} will only prevent setting cookies for
    * top-level domains like '.com' or '.org'. However, it will not prevent
    * setting a cookie for '.co.uk' even though only third-level registrations
    * are possible in .uk domain.
    *
    * With the List it is possible to find the highest level at which a domain
    * may be registered for a particular top-level domain and consequently
    * prevent cookies set for '.co.uk' or '.msk.ru'. The same list is used by
    * Firefox, Chrome and Opera browsers to restrict cookie setting.
    *
    * Note that PSL is licensed differently to HTTP_Request2 package (refer to
    * the license information in public-suffix-list.php), so you can disable
    * its use if this is an issue for you.
    *
    * @param    boolean
    * @link     http://publicsuffix.org/learn/
    */
    public function usePublicSuffixList($useList)
    {
        $this->useList = (bool)$useList;
    }

   /**
    * Returns string representation of object
    *
    * @return string
    * @see    Serializable::serialize()
    */
    public function serialize()
    {
        $cookies = $this->getAll();
        if (!$this->serializeSession) {
            for ($i = count($cookies) - 1; $i >= 0; $i--) {
                if (empty($cookies[$i]['expires'])) {
                    unset($cookies[$i]);
                }
            }
        }
        return serialize(array(
            'cookies'          => $cookies,
            'serializeSession' => $this->serializeSession,
            'useList'          => $this->useList
        ));
    }

   /**
    * Constructs the object from serialized string
    *
    * @param string  string representation
    * @see   Serializable::unserialize()
    */
    public function unserialize($serialized)
    {
        $data = unserialize($serialized);
        $now  = $this->now();
        $this->serializeSessionCookies($data['serializeSession']);
        $this->usePublicSuffixList($data['useList']);
        foreach ($data['cookies'] as $cookie) {
            if (!empty($cookie['expires']) && $cookie['expires'] <= $now) {
                continue;
            }
            if (!isset($this->cookies[$cookie['domain']])) {
                $this->cookies[$cookie['domain']] = array();
            }
            if (!isset($this->cookies[$cookie['domain']][$cookie['path']])) {
                $this->cookies[$cookie['domain']][$cookie['path']] = array();
            }
            $this->cookies[$cookie['domain']][$cookie['path']][$cookie['name']] = $cookie;
        }
    }

   /**
    * Checks whether a cookie domain matches a request host.
    *
    * The method is used by {@link store()} to check for whether a document
    * at given URL can set a cookie with a given domain attribute and by
    * {@link getMatching()} to find cookies matching the request URL.
    *
    * @param    string  request host
    * @param    string  cookie domain
    * @return   bool    match success
    */
    public function domainMatch($requestHost, $cookieDomain)
    {
        if ($requestHost == $cookieDomain) {
            return true;
        }
        // IP address, we require exact match
        if (preg_match('/^(?:\d{1,3}\.){3}\d{1,3}$/', $requestHost)) {
            return false;
        }
        if ('.' != $cookieDomain[0]) {
            $cookieDomain = '.' . $cookieDomain;
        }
        // prevents setting cookies for '.com' and similar domains
        if (!$this->useList && substr_count($cookieDomain, '.') < 2
            || $this->useList && !self::getRegisteredDomain($cookieDomain)
        ) {
            return false;
        }
        return substr('.' . $requestHost, -strlen($cookieDomain)) == $cookieDomain;
    }

   /**
    * Removes subdomains to get the registered domain (the first after top-level)
    *
    * The method will check Public Suffix List to find out where top-level
    * domain ends and registered domain starts. It will remove domain parts
    * to the left of registered one.
    *
    * @param  string        domain name
    * @return string|bool   registered domain, will return false if $domain is
    *                       either invalid or a TLD itself
    */
    public static function getRegisteredDomain($domain)
    {
        $domainParts = explode('.', ltrim($domain, '.'));

        // load the list if needed
        if (empty(self::$psl)) {
            self::$psl = array(
							 'ac' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'net' => true,
							  'mil' => true,
							  'org' => true
							 ),
							 'ad' => array(
							  'nom' => true
							 ),
							 'ae' => array(
							  'co' => true,
							  'net' => true,
							  'org' => true,
							  'sch' => true,
							  'ac' => true,
							  'gov' => true,
							  'mil' => true
							 ),
							 'aero' => array(
							  'accident-investigation' => true,
							  'accident-prevention' => true,
							  'aerobatic' => true,
							  'aeroclub' => true,
							  'aerodrome' => true,
							  'agents' => true,
							  'aircraft' => true,
							  'airline' => true,
							  'airport' => true,
							  'air-surveillance' => true,
							  'airtraffic' => true,
							  'air-traffic-control' => true,
							  'ambulance' => true,
							  'amusement' => true,
							  'association' => true,
							  'author' => true,
							  'ballooning' => true,
							  'broker' => true,
							  'caa' => true,
							  'cargo' => true,
							  'catering' => true,
							  'certification' => true,
							  'championship' => true,
							  'charter' => true,
							  'civilaviation' => true,
							  'club' => true,
							  'conference' => true,
							  'consultant' => true,
							  'consulting' => true,
							  'control' => true,
							  'council' => true,
							  'crew' => true,
							  'design' => true,
							  'dgca' => true,
							  'educator' => true,
							  'emergency' => true,
							  'engine' => true,
							  'engineer' => true,
							  'entertainment' => true,
							  'equipment' => true,
							  'exchange' => true,
							  'express' => true,
							  'federation' => true,
							  'flight' => true,
							  'freight' => true,
							  'fuel' => true,
							  'gliding' => true,
							  'government' => true,
							  'groundhandling' => true,
							  'group' => true,
							  'hanggliding' => true,
							  'homebuilt' => true,
							  'insurance' => true,
							  'journal' => true,
							  'journalist' => true,
							  'leasing' => true,
							  'logistics' => true,
							  'magazine' => true,
							  'maintenance' => true,
							  'marketplace' => true,
							  'media' => true,
							  'microlight' => true,
							  'modelling' => true,
							  'navigation' => true,
							  'parachuting' => true,
							  'paragliding' => true,
							  'passenger-association' => true,
							  'pilot' => true,
							  'press' => true,
							  'production' => true,
							  'recreation' => true,
							  'repbody' => true,
							  'res' => true,
							  'research' => true,
							  'rotorcraft' => true,
							  'safety' => true,
							  'scientist' => true,
							  'services' => true,
							  'show' => true,
							  'skydiving' => true,
							  'software' => true,
							  'student' => true,
							  'taxi' => true,
							  'trader' => true,
							  'trading' => true,
							  'trainer' => true,
							  'union' => true,
							  'workinggroup' => true,
							  'works' => true
							 ),
							 'af' => array(
							  'gov' => true,
							  'com' => true,
							  'org' => true,
							  'net' => true,
							  'edu' => true
							 ),
							 'ag' => array(
							  'com' => true,
							  'org' => true,
							  'net' => true,
							  'co' => true,
							  'nom' => true
							 ),
							 'ai' => array(
							  'off' => true,
							  'com' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'al' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'mil' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'am' => true,
							 'an' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true
							 ),
							 'ao' => array(
							  'ed' => true,
							  'gv' => true,
							  'og' => true,
							  'co' => true,
							  'pb' => true,
							  'it' => true
							 ),
							 'aq' => true,
							 'ar' => array(
							  '*' => true,
							  '!congresodelalengua3' => true,
							  '!educ' => true,
							  '!gobiernoelectronico' => true,
							  '!mecon' => true,
							  '!nacion' => true,
							  '!nic' => true,
							  '!promocion' => true,
							  '!retina' => true,
							  '!uba' => true
							 ),
							 'arpa' => array(
							  'e164' => true,
							  'in-addr' => true,
							  'ip6' => true,
							  'iris' => true,
							  'uri' => true,
							  'urn' => true
							 ),
							 'as' => array(
							  'gov' => true
							 ),
							 'asia' => true,
							 'at' => array(
							  'ac' => true,
							  'co' => true,
							  'gv' => true,
							  'or' => true,
							  'biz' => true,
							  'info' => true,
							  'priv' => true
							 ),
							 'au' => array(
							  '*' => true,
							  'edu' => array(
							   'act' => true,
							   'nsw' => true,
							   'nt' => true,
							   'qld' => true,
							   'sa' => true,
							   'tas' => true,
							   'vic' => true,
							   'wa' => true
							  ),
							  'gov' => array(
							   'act' => true,
							   'nt' => true,
							   'qld' => true,
							   'sa' => true,
							   'tas' => true,
							   'vic' => true,
							   'wa' => true
							  ),
							  'act' => true,
							  'nsw' => true,
							  'nt' => true,
							  'qld' => true,
							  'sa' => true,
							  'tas' => true,
							  'vic' => true,
							  'wa' => true
							 ),
							 'aw' => array(
							  'com' => true
							 ),
							 'ax' => true,
							 'az' => array(
							  'com' => true,
							  'net' => true,
							  'int' => true,
							  'gov' => true,
							  'org' => true,
							  'edu' => true,
							  'info' => true,
							  'pp' => true,
							  'mil' => true,
							  'name' => true,
							  'pro' => true,
							  'biz' => true
							 ),
							 'ba' => array(
							  'org' => true,
							  'net' => true,
							  'edu' => true,
							  'gov' => true,
							  'mil' => true,
							  'unsa' => true,
							  'unbi' => true,
							  'co' => true,
							  'com' => true,
							  'rs' => true
							 ),
							 'bb' => array(
							  'biz' => true,
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'info' => true,
							  'net' => true,
							  'org' => true,
							  'store' => true
							 ),
							 'bd' => array(
							  '*' => true
							 ),
							 'be' => array(
							  'ac' => true
							 ),
							 'bf' => array(
							  'gov' => true
							 ),
							 'bg' => array(
							  'a' => true,
							  'b' => true,
							  'c' => true,
							  'd' => true,
							  'e' => true,
							  'f' => true,
							  'g' => true,
							  'h' => true,
							  'i' => true,
							  'j' => true,
							  'k' => true,
							  'l' => true,
							  'm' => true,
							  'n' => true,
							  'o' => true,
							  'p' => true,
							  'q' => true,
							  'r' => true,
							  's' => true,
							  't' => true,
							  'u' => true,
							  'v' => true,
							  'w' => true,
							  'x' => true,
							  'y' => true,
							  'z' => true,
							  '0' => true,
							  '1' => true,
							  '2' => true,
							  '3' => true,
							  '4' => true,
							  '5' => true,
							  '6' => true,
							  '7' => true,
							  '8' => true,
							  '9' => true
							 ),
							 'bh' => array(
							  'com' => true,
							  'edu' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true
							 ),
							 'bi' => array(
							  'co' => true,
							  'com' => true,
							  'edu' => true,
							  'or' => true,
							  'org' => true
							 ),
							 'biz' => true,
							 'bj' => array(
							  'asso' => true,
							  'barreau' => true,
							  'gouv' => true
							 ),
							 'bm' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'bn' => array(
							  '*' => true
							 ),
							 'bo' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'gob' => true,
							  'int' => true,
							  'org' => true,
							  'net' => true,
							  'mil' => true,
							  'tv' => true
							 ),
							 'br' => array(
							  'adm' => true,
							  'adv' => true,
							  'agr' => true,
							  'am' => true,
							  'arq' => true,
							  'art' => true,
							  'ato' => true,
							  'bio' => true,
							  'blog' => true,
							  'bmd' => true,
							  'can' => true,
							  'cim' => true,
							  'cng' => true,
							  'cnt' => true,
							  'com' => true,
							  'coop' => true,
							  'ecn' => true,
							  'edu' => true,
							  'eng' => true,
							  'esp' => true,
							  'etc' => true,
							  'eti' => true,
							  'far' => true,
							  'flog' => true,
							  'fm' => true,
							  'fnd' => true,
							  'fot' => true,
							  'fst' => true,
							  'g12' => true,
							  'ggf' => true,
							  'gov' => true,
							  'imb' => true,
							  'ind' => true,
							  'inf' => true,
							  'jor' => true,
							  'jus' => true,
							  'lel' => true,
							  'mat' => true,
							  'med' => true,
							  'mil' => true,
							  'mus' => true,
							  'net' => true,
							  'nom' => true,
							  'not' => true,
							  'ntr' => true,
							  'odo' => true,
							  'org' => true,
							  'ppg' => true,
							  'pro' => true,
							  'psc' => true,
							  'psi' => true,
							  'qsl' => true,
							  'rec' => true,
							  'slg' => true,
							  'srv' => true,
							  'tmp' => true,
							  'trd' => true,
							  'tur' => true,
							  'tv' => true,
							  'vet' => true,
							  'vlog' => true,
							  'wiki' => true,
							  'zlg' => true
							 ),
							 'bs' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true,
							  'gov' => true
							 ),
							 'bt' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'bw' => array(
							  'co' => true,
							  'org' => true
							 ),
							 'by' => array(
							  'gov' => true,
							  'mil' => true,
							  'com' => true,
							  'of' => true
							 ),
							 'bz' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true,
							  'gov' => true
							 ),
							 'ca' => array(
							  'ab' => true,
							  'bc' => true,
							  'mb' => true,
							  'nb' => true,
							  'nf' => true,
							  'nl' => true,
							  'ns' => true,
							  'nt' => true,
							  'nu' => true,
							  'on' => true,
							  'pe' => true,
							  'qc' => true,
							  'sk' => true,
							  'yk' => true,
							  'gc' => true
							 ),
							 'cat' => true,
							 'cc' => true,
							 'cd' => array(
							  'gov' => true
							 ),
							 'cf' => true,
							 'cg' => true,
							 'ch' => true,
							 'ci' => array(
							  'org' => true,
							  'or' => true,
							  'com' => true,
							  'co' => true,
							  'edu' => true,
							  'ed' => true,
							  'ac' => true,
							  'net' => true,
							  'go' => true,
							  'asso' => true,
							  'aéroport' => true,
							  'int' => true,
							  'presse' => true,
							  'md' => true,
							  'gouv' => true
							 ),
							 'ck' => array(
							  '*' => true
							 ),
							 'cl' => array(
							  'gov' => true,
							  'gob' => true
							 ),
							 'cm' => array(
							  'gov' => true
							 ),
							 'cn' => array(
							  'ac' => true,
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'net' => true,
							  'org' => true,
							  'mil' => true,
							  '公司' => true,
							  '网络' => true,
							  '網絡' => true,
							  'ah' => true,
							  'bj' => true,
							  'cq' => true,
							  'fj' => true,
							  'gd' => true,
							  'gs' => true,
							  'gz' => true,
							  'gx' => true,
							  'ha' => true,
							  'hb' => true,
							  'he' => true,
							  'hi' => true,
							  'hl' => true,
							  'hn' => true,
							  'jl' => true,
							  'js' => true,
							  'jx' => true,
							  'ln' => true,
							  'nm' => true,
							  'nx' => true,
							  'qh' => true,
							  'sc' => true,
							  'sd' => true,
							  'sh' => true,
							  'sn' => true,
							  'sx' => true,
							  'tj' => true,
							  'xj' => true,
							  'xz' => true,
							  'yn' => true,
							  'zj' => true,
							  'hk' => true,
							  'mo' => true,
							  'tw' => true
							 ),
							 'co' => array(
							  'arts' => true,
							  'com' => true,
							  'edu' => true,
							  'firm' => true,
							  'gov' => true,
							  'info' => true,
							  'int' => true,
							  'mil' => true,
							  'net' => true,
							  'nom' => true,
							  'org' => true,
							  'rec' => true,
							  'web' => true
							 ),
							 'com' => array(
							  'ar' => true,
							  'br' => true,
							  'cn' => true,
							  'de' => true,
							  'eu' => true,
							  'gb' => true,
							  'hu' => true,
							  'jpn' => true,
							  'kr' => true,
							  'no' => true,
							  'qc' => true,
							  'ru' => true,
							  'sa' => true,
							  'se' => true,
							  'uk' => true,
							  'us' => true,
							  'uy' => true,
							  'za' => true,
							  'operaunite' => true,
							  'appspot' => true
							 ),
							 'coop' => true,
							 'cr' => array(
							  'ac' => true,
							  'co' => true,
							  'ed' => true,
							  'fi' => true,
							  'go' => true,
							  'or' => true,
							  'sa' => true
							 ),
							 'cu' => array(
							  'com' => true,
							  'edu' => true,
							  'org' => true,
							  'net' => true,
							  'gov' => true,
							  'inf' => true
							 ),
							 'cv' => true,
							 'cx' => array(
							  'gov' => true
							 ),
							 'cy' => array(
							  '*' => true
							 ),
							 'cz' => true,
							 'de' => true,
							 'dj' => true,
							 'dk' => true,
							 'dm' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true,
							  'gov' => true
							 ),
							 'do' => array(
							  '*' => true
							 ),
							 'dz' => array(
							  'com' => true,
							  'org' => true,
							  'net' => true,
							  'gov' => true,
							  'edu' => true,
							  'asso' => true,
							  'pol' => true,
							  'art' => true
							 ),
							 'ec' => array(
							  'com' => true,
							  'info' => true,
							  'net' => true,
							  'fin' => true,
							  'k12' => true,
							  'med' => true,
							  'pro' => true,
							  'org' => true,
							  'edu' => true,
							  'gov' => true,
							  'gob' => true,
							  'mil' => true
							 ),
							 'edu' => true,
							 'ee' => array(
							  'edu' => true,
							  'gov' => true,
							  'riik' => true,
							  'lib' => true,
							  'med' => true,
							  'com' => true,
							  'pri' => true,
							  'aip' => true,
							  'org' => true,
							  'fie' => true
							 ),
							 'eg' => array(
							  '*' => true
							 ),
							 'er' => array(
							  '*' => true
							 ),
							 'es' => array(
							  'com' => true,
							  'nom' => true,
							  'org' => true,
							  'gob' => true,
							  'edu' => true
							 ),
							 'et' => array(
							  '*' => true
							 ),
							 'eu' => true,
							 'fi' => array(
							  'aland' => true,
							  'iki' => true
							 ),
							 'fj' => array(
							  '*' => true
							 ),
							 'fk' => array(
							  '*' => true
							 ),
							 'fm' => true,
							 'fo' => true,
							 'fr' => array(
							  'com' => true,
							  'asso' => true,
							  'nom' => true,
							  'prd' => true,
							  'presse' => true,
							  'tm' => true,
							  'aeroport' => true,
							  'assedic' => true,
							  'avocat' => true,
							  'avoues' => true,
							  'cci' => true,
							  'chambagri' => true,
							  'chirurgiens-dentistes' => true,
							  'experts-comptables' => true,
							  'geometre-expert' => true,
							  'gouv' => true,
							  'greta' => true,
							  'huissier-justice' => true,
							  'medecin' => true,
							  'notaires' => true,
							  'pharmacien' => true,
							  'port' => true,
							  'veterinaire' => true
							 ),
							 'ga' => true,
							 'gd' => true,
							 'ge' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'org' => true,
							  'mil' => true,
							  'net' => true,
							  'pvt' => true
							 ),
							 'gf' => true,
							 'gg' => array(
							  'co' => true,
							  'org' => true,
							  'net' => true,
							  'sch' => true,
							  'gov' => true
							 ),
							 'gh' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'org' => true,
							  'mil' => true
							 ),
							 'gi' => array(
							  'com' => true,
							  'ltd' => true,
							  'gov' => true,
							  'mod' => true,
							  'edu' => true,
							  'org' => true
							 ),
							 'gl' => true,
							 'gm' => true,
							 'gn' => array(
							  'ac' => true,
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'org' => true,
							  'net' => true
							 ),
							 'gov' => true,
							 'gp' => array(
							  'com' => true,
							  'net' => true,
							  'mobi' => true,
							  'edu' => true,
							  'org' => true,
							  'asso' => true
							 ),
							 'gq' => true,
							 'gr' => array(
							  'com' => true,
							  'edu' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true
							 ),
							 'gs' => true,
							 'gt' => array(
							  '*' => true
							 ),
							 'gu' => array(
							  '*' => true
							 ),
							 'gw' => true,
							 'gy' => array(
							  'co' => true,
							  'com' => true,
							  'net' => true
							 ),
							 'hk' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'idv' => true,
							  'net' => true,
							  'org' => true,
							  '公司' => true,
							  '教育' => true,
							  '敎育' => true,
							  '政府' => true,
							  '個人' => true,
							  '个人' => true,
							  '箇人' => true,
							  '網络' => true,
							  '网络' => true,
							  '组織' => true,
							  '網絡' => true,
							  '网絡' => true,
							  '组织' => true,
							  '組織' => true,
							  '組织' => true
							 ),
							 'hm' => true,
							 'hn' => array(
							  'com' => true,
							  'edu' => true,
							  'org' => true,
							  'net' => true,
							  'mil' => true,
							  'gob' => true
							 ),
							 'hr' => array(
							  'iz' => true,
							  'from' => true,
							  'name' => true,
							  'com' => true
							 ),
							 'ht' => array(
							  'com' => true,
							  'shop' => true,
							  'firm' => true,
							  'info' => true,
							  'adult' => true,
							  'net' => true,
							  'pro' => true,
							  'org' => true,
							  'med' => true,
							  'art' => true,
							  'coop' => true,
							  'pol' => true,
							  'asso' => true,
							  'edu' => true,
							  'rel' => true,
							  'gouv' => true,
							  'perso' => true
							 ),
							 'hu' => array(
							  'co' => true,
							  'info' => true,
							  'org' => true,
							  'priv' => true,
							  'sport' => true,
							  'tm' => true,
							  '2000' => true,
							  'agrar' => true,
							  'bolt' => true,
							  'casino' => true,
							  'city' => true,
							  'erotica' => true,
							  'erotika' => true,
							  'film' => true,
							  'forum' => true,
							  'games' => true,
							  'hotel' => true,
							  'ingatlan' => true,
							  'jogasz' => true,
							  'konyvelo' => true,
							  'lakas' => true,
							  'media' => true,
							  'news' => true,
							  'reklam' => true,
							  'sex' => true,
							  'shop' => true,
							  'suli' => true,
							  'szex' => true,
							  'tozsde' => true,
							  'utazas' => true,
							  'video' => true
							 ),
							 'id' => array(
							  'ac' => true,
							  'co' => true,
							  'go' => true,
							  'mil' => true,
							  'net' => true,
							  'or' => true,
							  'sch' => true,
							  'web' => true
							 ),
							 'ie' => array(
							  'gov' => true
							 ),
							 'il' => array(
							  '*' => true
							 ),
							 'im' => array(
							  'co' => array(
							   'ltd' => true,
							   'plc' => true
							  ),
							  'net' => true,
							  'gov' => true,
							  'org' => true,
							  'nic' => true,
							  'ac' => true
							 ),
							 'in' => array(
							  'co' => true,
							  'firm' => true,
							  'net' => true,
							  'org' => true,
							  'gen' => true,
							  'ind' => true,
							  'nic' => true,
							  'ac' => true,
							  'edu' => true,
							  'res' => true,
							  'gov' => true,
							  'mil' => true
							 ),
							 'info' => true,
							 'int' => array(
							  'eu' => true
							 ),
							 'io' => array(
							  'com' => true
							 ),
							 'iq' => array(
							  'gov' => true,
							  'edu' => true,
							  'mil' => true,
							  'com' => true,
							  'org' => true,
							  'net' => true
							 ),
							 'ir' => array(
							  'ac' => true,
							  'co' => true,
							  'gov' => true,
							  'id' => true,
							  'net' => true,
							  'org' => true,
							  'sch' => true,
							  'ایران' => true,
							  'ايران' => true
							 ),
							 'is' => array(
							  'net' => true,
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'org' => true,
							  'int' => true
							 ),
							 'it' => array(
							  'gov' => true,
							  'edu' => true,
							  'agrigento' => true,
							  'ag' => true,
							  'alessandria' => true,
							  'al' => true,
							  'ancona' => true,
							  'an' => true,
							  'aosta' => true,
							  'aoste' => true,
							  'ao' => true,
							  'arezzo' => true,
							  'ar' => true,
							  'ascoli-piceno' => true,
							  'ascolipiceno' => true,
							  'ap' => true,
							  'asti' => true,
							  'at' => true,
							  'avellino' => true,
							  'av' => true,
							  'bari' => true,
							  'ba' => true,
							  'andria-barletta-trani' => true,
							  'andriabarlettatrani' => true,
							  'trani-barletta-andria' => true,
							  'tranibarlettaandria' => true,
							  'barletta-trani-andria' => true,
							  'barlettatraniandria' => true,
							  'andria-trani-barletta' => true,
							  'andriatranibarletta' => true,
							  'trani-andria-barletta' => true,
							  'traniandriabarletta' => true,
							  'bt' => true,
							  'belluno' => true,
							  'bl' => true,
							  'benevento' => true,
							  'bn' => true,
							  'bergamo' => true,
							  'bg' => true,
							  'biella' => true,
							  'bi' => true,
							  'bologna' => true,
							  'bo' => true,
							  'bolzano' => true,
							  'bozen' => true,
							  'balsan' => true,
							  'alto-adige' => true,
							  'altoadige' => true,
							  'suedtirol' => true,
							  'bz' => true,
							  'brescia' => true,
							  'bs' => true,
							  'brindisi' => true,
							  'br' => true,
							  'cagliari' => true,
							  'ca' => true,
							  'caltanissetta' => true,
							  'cl' => true,
							  'campobasso' => true,
							  'cb' => true,
							  'carboniaiglesias' => true,
							  'carbonia-iglesias' => true,
							  'iglesias-carbonia' => true,
							  'iglesiascarbonia' => true,
							  'ci' => true,
							  'caserta' => true,
							  'ce' => true,
							  'catania' => true,
							  'ct' => true,
							  'catanzaro' => true,
							  'cz' => true,
							  'chieti' => true,
							  'ch' => true,
							  'como' => true,
							  'co' => true,
							  'cosenza' => true,
							  'cs' => true,
							  'cremona' => true,
							  'cr' => true,
							  'crotone' => true,
							  'kr' => true,
							  'cuneo' => true,
							  'cn' => true,
							  'dell-ogliastra' => true,
							  'dellogliastra' => true,
							  'ogliastra' => true,
							  'og' => true,
							  'enna' => true,
							  'en' => true,
							  'ferrara' => true,
							  'fe' => true,
							  'fermo' => true,
							  'fm' => true,
							  'firenze' => true,
							  'florence' => true,
							  'fi' => true,
							  'foggia' => true,
							  'fg' => true,
							  'forli-cesena' => true,
							  'forlicesena' => true,
							  'cesena-forli' => true,
							  'cesenaforli' => true,
							  'fc' => true,
							  'frosinone' => true,
							  'fr' => true,
							  'genova' => true,
							  'genoa' => true,
							  'ge' => true,
							  'gorizia' => true,
							  'go' => true,
							  'grosseto' => true,
							  'gr' => true,
							  'imperia' => true,
							  'im' => true,
							  'isernia' => true,
							  'is' => true,
							  'laquila' => true,
							  'aquila' => true,
							  'aq' => true,
							  'la-spezia' => true,
							  'laspezia' => true,
							  'sp' => true,
							  'latina' => true,
							  'lt' => true,
							  'lecce' => true,
							  'le' => true,
							  'lecco' => true,
							  'lc' => true,
							  'livorno' => true,
							  'li' => true,
							  'lodi' => true,
							  'lo' => true,
							  'lucca' => true,
							  'lu' => true,
							  'macerata' => true,
							  'mc' => true,
							  'mantova' => true,
							  'mn' => true,
							  'massa-carrara' => true,
							  'massacarrara' => true,
							  'carrara-massa' => true,
							  'carraramassa' => true,
							  'ms' => true,
							  'matera' => true,
							  'mt' => true,
							  'medio-campidano' => true,
							  'mediocampidano' => true,
							  'campidano-medio' => true,
							  'campidanomedio' => true,
							  'vs' => true,
							  'messina' => true,
							  'me' => true,
							  'milano' => true,
							  'milan' => true,
							  'mi' => true,
							  'modena' => true,
							  'mo' => true,
							  'monza' => true,
							  'monza-brianza' => true,
							  'monzabrianza' => true,
							  'monzaebrianza' => true,
							  'monzaedellabrianza' => true,
							  'monza-e-della-brianza' => true,
							  'mb' => true,
							  'napoli' => true,
							  'naples' => true,
							  'na' => true,
							  'novara' => true,
							  'no' => true,
							  'nuoro' => true,
							  'nu' => true,
							  'oristano' => true,
							  'or' => true,
							  'padova' => true,
							  'padua' => true,
							  'pd' => true,
							  'palermo' => true,
							  'pa' => true,
							  'parma' => true,
							  'pr' => true,
							  'pavia' => true,
							  'pv' => true,
							  'perugia' => true,
							  'pg' => true,
							  'pescara' => true,
							  'pe' => true,
							  'pesaro-urbino' => true,
							  'pesarourbino' => true,
							  'urbino-pesaro' => true,
							  'urbinopesaro' => true,
							  'pu' => true,
							  'piacenza' => true,
							  'pc' => true,
							  'pisa' => true,
							  'pi' => true,
							  'pistoia' => true,
							  'pt' => true,
							  'pordenone' => true,
							  'pn' => true,
							  'potenza' => true,
							  'pz' => true,
							  'prato' => true,
							  'po' => true,
							  'ragusa' => true,
							  'rg' => true,
							  'ravenna' => true,
							  'ra' => true,
							  'reggio-calabria' => true,
							  'reggiocalabria' => true,
							  'rc' => true,
							  'reggio-emilia' => true,
							  'reggioemilia' => true,
							  're' => true,
							  'rieti' => true,
							  'ri' => true,
							  'rimini' => true,
							  'rn' => true,
							  'roma' => true,
							  'rome' => true,
							  'rm' => true,
							  'rovigo' => true,
							  'ro' => true,
							  'salerno' => true,
							  'sa' => true,
							  'sassari' => true,
							  'ss' => true,
							  'savona' => true,
							  'sv' => true,
							  'siena' => true,
							  'si' => true,
							  'siracusa' => true,
							  'sr' => true,
							  'sondrio' => true,
							  'so' => true,
							  'taranto' => true,
							  'ta' => true,
							  'tempio-olbia' => true,
							  'tempioolbia' => true,
							  'olbia-tempio' => true,
							  'olbiatempio' => true,
							  'ot' => true,
							  'teramo' => true,
							  'te' => true,
							  'terni' => true,
							  'tr' => true,
							  'torino' => true,
							  'turin' => true,
							  'to' => true,
							  'trapani' => true,
							  'tp' => true,
							  'trento' => true,
							  'trentino' => true,
							  'tn' => true,
							  'treviso' => true,
							  'tv' => true,
							  'trieste' => true,
							  'ts' => true,
							  'udine' => true,
							  'ud' => true,
							  'varese' => true,
							  'va' => true,
							  'venezia' => true,
							  'venice' => true,
							  've' => true,
							  'verbania' => true,
							  'vb' => true,
							  'vercelli' => true,
							  'vc' => true,
							  'verona' => true,
							  'vr' => true,
							  'vibo-valentia' => true,
							  'vibovalentia' => true,
							  'vv' => true,
							  'vicenza' => true,
							  'vi' => true,
							  'viterbo' => true,
							  'vt' => true
							 ),
							 'je' => array(
							  'co' => true,
							  'org' => true,
							  'net' => true,
							  'sch' => true,
							  'gov' => true
							 ),
							 'jm' => array(
							  '*' => true
							 ),
							 'jo' => array(
							  'com' => true,
							  'org' => true,
							  'net' => true,
							  'edu' => true,
							  'sch' => true,
							  'gov' => true,
							  'mil' => true,
							  'name' => true
							 ),
							 'jobs' => true,
							 'jp' => array(
							  'ac' => true,
							  'ad' => true,
							  'co' => true,
							  'ed' => true,
							  'go' => true,
							  'gr' => true,
							  'lg' => true,
							  'ne' => true,
							  'or' => true,
							  'aichi' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'akita' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'aomori' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'chiba' => array(
							   '*' => true,
							   '!pref' => true,
							   '!city' => true
							  ),
							  'ehime' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'fukui' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'fukuoka' => array(
							   '*' => true,
							   '!pref' => true,
							   '!city' => true
							  ),
							  'fukushima' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'gifu' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'gunma' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'hiroshima' => array(
							   '*' => true,
							   '!pref' => true,
							   '!city' => true
							  ),
							  'hokkaido' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'hyogo' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'ibaraki' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'ishikawa' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'iwate' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'kagawa' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'kagoshima' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'kanagawa' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'kawasaki' => array(
							   '*' => true,
							   '!city' => true
							  ),
							  'kitakyushu' => array(
							   '*' => true,
							   '!city' => true
							  ),
							  'kobe' => array(
							   '*' => true,
							   '!city' => true
							  ),
							  'kochi' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'kumamoto' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'kyoto' => array(
							   '*' => true,
							   '!pref' => true,
							   '!city' => true
							  ),
							  'mie' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'miyagi' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'miyazaki' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'nagano' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'nagasaki' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'nagoya' => array(
							   '*' => true,
							   '!city' => true
							  ),
							  'nara' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'niigata' => array(
							   '*' => true,
							   '!pref' => true,
							   '!city' => true
							  ),
							  'oita' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'okayama' => array(
							   '*' => true,
							   '!pref' => true,
							   '!city' => true
							  ),
							  'okinawa' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'osaka' => array(
							   '*' => true,
							   '!pref' => true,
							   '!city' => true
							  ),
							  'saga' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'saitama' => array(
							   '*' => true,
							   '!pref' => true,
							   '!city' => true
							  ),
							  'sapporo' => array(
							   '*' => true,
							   '!city' => true
							  ),
							  'sendai' => array(
							   '*' => true,
							   '!city' => true
							  ),
							  'shiga' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'shimane' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'shizuoka' => array(
							   '*' => true,
							   '!pref' => true,
							   '!city' => true
							  ),
							  'tochigi' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'tokushima' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'tokyo' => array(
							   '*' => true,
							   '!metro' => true
							  ),
							  'tottori' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'toyama' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'wakayama' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'yamagata' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'yamaguchi' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'yamanashi' => array(
							   '*' => true,
							   '!pref' => true
							  ),
							  'yokohama' => array(
							   '*' => true,
							   '!city' => true
							  )
							 ),
							 'ke' => array(
							  '*' => true
							 ),
							 'kg' => array(
							  'org' => true,
							  'net' => true,
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'mil' => true
							 ),
							 'kh' => array(
							  '*' => true
							 ),
							 'ki' => array(
							  'edu' => true,
							  'biz' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true,
							  'info' => true,
							  'com' => true
							 ),
							 'km' => array(
							  'org' => true,
							  'nom' => true,
							  'gov' => true,
							  'prd' => true,
							  'tm' => true,
							  'edu' => true,
							  'mil' => true,
							  'ass' => true,
							  'com' => true,
							  'coop' => true,
							  'asso' => true,
							  'presse' => true,
							  'medecin' => true,
							  'notaires' => true,
							  'pharmaciens' => true,
							  'veterinaire' => true,
							  'gouv' => true
							 ),
							 'kn' => array(
							  'net' => true,
							  'org' => true,
							  'edu' => true,
							  'gov' => true
							 ),
							 'kp' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'org' => true,
							  'rep' => true,
							  'tra' => true
							 ),
							 'kr' => array(
							  'ac' => true,
							  'co' => true,
							  'es' => true,
							  'go' => true,
							  'hs' => true,
							  'kg' => true,
							  'mil' => true,
							  'ms' => true,
							  'ne' => true,
							  'or' => true,
							  'pe' => true,
							  're' => true,
							  'sc' => true,
							  'busan' => true,
							  'chungbuk' => true,
							  'chungnam' => true,
							  'daegu' => true,
							  'daejeon' => true,
							  'gangwon' => true,
							  'gwangju' => true,
							  'gyeongbuk' => true,
							  'gyeonggi' => true,
							  'gyeongnam' => true,
							  'incheon' => true,
							  'jeju' => true,
							  'jeonbuk' => true,
							  'jeonnam' => true,
							  'seoul' => true,
							  'ulsan' => true
							 ),
							 'kw' => array(
							  '*' => true
							 ),
							 'ky' => array(
							  'edu' => true,
							  'gov' => true,
							  'com' => true,
							  'org' => true,
							  'net' => true
							 ),
							 'kz' => array(
							  'org' => true,
							  'edu' => true,
							  'net' => true,
							  'gov' => true,
							  'mil' => true,
							  'com' => true
							 ),
							 'la' => array(
							  'int' => true,
							  'net' => true,
							  'info' => true,
							  'edu' => true,
							  'gov' => true,
							  'per' => true,
							  'com' => true,
							  'org' => true,
							  'c' => true
							 ),
							 'lb' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'lc' => array(
							  'com' => true,
							  'net' => true,
							  'co' => true,
							  'org' => true,
							  'edu' => true,
							  'gov' => true
							 ),
							 'li' => true,
							 'lk' => array(
							  'gov' => true,
							  'sch' => true,
							  'net' => true,
							  'int' => true,
							  'com' => true,
							  'org' => true,
							  'edu' => true,
							  'ngo' => true,
							  'soc' => true,
							  'web' => true,
							  'ltd' => true,
							  'assn' => true,
							  'grp' => true,
							  'hotel' => true
							 ),
							 'local' => true,
							 'lr' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'org' => true,
							  'net' => true
							 ),
							 'ls' => array(
							  'co' => true,
							  'org' => true
							 ),
							 'lt' => array(
							  'gov' => true
							 ),
							 'lu' => true,
							 'lv' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'org' => true,
							  'mil' => true,
							  'id' => true,
							  'net' => true,
							  'asn' => true,
							  'conf' => true
							 ),
							 'ly' => array(
							  'com' => true,
							  'net' => true,
							  'gov' => true,
							  'plc' => true,
							  'edu' => true,
							  'sch' => true,
							  'med' => true,
							  'org' => true,
							  'id' => true
							 ),
							 'ma' => array(
							  'co' => true,
							  'net' => true,
							  'gov' => true,
							  'org' => true,
							  'ac' => true,
							  'press' => true
							 ),
							 'mc' => array(
							  'tm' => true,
							  'asso' => true
							 ),
							 'md' => true,
							 'me' => array(
							  'co' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true,
							  'ac' => true,
							  'gov' => true,
							  'its' => true,
							  'priv' => true
							 ),
							 'mg' => array(
							  'org' => true,
							  'nom' => true,
							  'gov' => true,
							  'prd' => true,
							  'tm' => true,
							  'edu' => true,
							  'mil' => true,
							  'com' => true
							 ),
							 'mh' => true,
							 'mil' => true,
							 'mk' => array(
							  'com' => true,
							  'org' => true,
							  'net' => true,
							  'edu' => true,
							  'gov' => true,
							  'inf' => true,
							  'name' => true
							 ),
							 'ml' => array(
							  'com' => true,
							  'edu' => true,
							  'gouv' => true,
							  'gov' => true,
							  'net' => true,
							  'org' => true,
							  'presse' => true
							 ),
							 'mm' => array(
							  '*' => true
							 ),
							 'mn' => array(
							  'gov' => true,
							  'edu' => true,
							  'org' => true
							 ),
							 'mo' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true,
							  'gov' => true
							 ),
							 'mobi' => true,
							 'mp' => true,
							 'mq' => true,
							 'mr' => array(
							  'gov' => true
							 ),
							 'ms' => true,
							 'mt' => array(
							  '*' => true
							 ),
							 'mu' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true,
							  'ac' => true,
							  'co' => true,
							  'or' => true
							 ),
							 'museum' => array(
							  'academy' => true,
							  'agriculture' => true,
							  'air' => true,
							  'airguard' => true,
							  'alabama' => true,
							  'alaska' => true,
							  'amber' => true,
							  'ambulance' => true,
							  'american' => true,
							  'americana' => true,
							  'americanantiques' => true,
							  'americanart' => true,
							  'amsterdam' => true,
							  'and' => true,
							  'annefrank' => true,
							  'anthro' => true,
							  'anthropology' => true,
							  'antiques' => true,
							  'aquarium' => true,
							  'arboretum' => true,
							  'archaeological' => true,
							  'archaeology' => true,
							  'architecture' => true,
							  'art' => true,
							  'artanddesign' => true,
							  'artcenter' => true,
							  'artdeco' => true,
							  'arteducation' => true,
							  'artgallery' => true,
							  'arts' => true,
							  'artsandcrafts' => true,
							  'asmatart' => true,
							  'assassination' => true,
							  'assisi' => true,
							  'association' => true,
							  'astronomy' => true,
							  'atlanta' => true,
							  'austin' => true,
							  'australia' => true,
							  'automotive' => true,
							  'aviation' => true,
							  'axis' => true,
							  'badajoz' => true,
							  'baghdad' => true,
							  'bahn' => true,
							  'bale' => true,
							  'baltimore' => true,
							  'barcelona' => true,
							  'baseball' => true,
							  'basel' => true,
							  'baths' => true,
							  'bauern' => true,
							  'beauxarts' => true,
							  'beeldengeluid' => true,
							  'bellevue' => true,
							  'bergbau' => true,
							  'berkeley' => true,
							  'berlin' => true,
							  'bern' => true,
							  'bible' => true,
							  'bilbao' => true,
							  'bill' => true,
							  'birdart' => true,
							  'birthplace' => true,
							  'bonn' => true,
							  'boston' => true,
							  'botanical' => true,
							  'botanicalgarden' => true,
							  'botanicgarden' => true,
							  'botany' => true,
							  'brandywinevalley' => true,
							  'brasil' => true,
							  'bristol' => true,
							  'british' => true,
							  'britishcolumbia' => true,
							  'broadcast' => true,
							  'brunel' => true,
							  'brussel' => true,
							  'brussels' => true,
							  'bruxelles' => true,
							  'building' => true,
							  'burghof' => true,
							  'bus' => true,
							  'bushey' => true,
							  'cadaques' => true,
							  'california' => true,
							  'cambridge' => true,
							  'can' => true,
							  'canada' => true,
							  'capebreton' => true,
							  'carrier' => true,
							  'cartoonart' => true,
							  'casadelamoneda' => true,
							  'castle' => true,
							  'castres' => true,
							  'celtic' => true,
							  'center' => true,
							  'chattanooga' => true,
							  'cheltenham' => true,
							  'chesapeakebay' => true,
							  'chicago' => true,
							  'children' => true,
							  'childrens' => true,
							  'childrensgarden' => true,
							  'chiropractic' => true,
							  'chocolate' => true,
							  'christiansburg' => true,
							  'cincinnati' => true,
							  'cinema' => true,
							  'circus' => true,
							  'civilisation' => true,
							  'civilization' => true,
							  'civilwar' => true,
							  'clinton' => true,
							  'clock' => true,
							  'coal' => true,
							  'coastaldefence' => true,
							  'cody' => true,
							  'coldwar' => true,
							  'collection' => true,
							  'colonialwilliamsburg' => true,
							  'coloradoplateau' => true,
							  'columbia' => true,
							  'columbus' => true,
							  'communication' => true,
							  'communications' => true,
							  'community' => true,
							  'computer' => true,
							  'computerhistory' => true,
							  'comunicações' => true,
							  'contemporary' => true,
							  'contemporaryart' => true,
							  'convent' => true,
							  'copenhagen' => true,
							  'corporation' => true,
							  'correios-e-telecomunicações' => true,
							  'corvette' => true,
							  'costume' => true,
							  'countryestate' => true,
							  'county' => true,
							  'crafts' => true,
							  'cranbrook' => true,
							  'creation' => true,
							  'cultural' => true,
							  'culturalcenter' => true,
							  'culture' => true,
							  'cyber' => true,
							  'cymru' => true,
							  'dali' => true,
							  'dallas' => true,
							  'database' => true,
							  'ddr' => true,
							  'decorativearts' => true,
							  'delaware' => true,
							  'delmenhorst' => true,
							  'denmark' => true,
							  'depot' => true,
							  'design' => true,
							  'detroit' => true,
							  'dinosaur' => true,
							  'discovery' => true,
							  'dolls' => true,
							  'donostia' => true,
							  'durham' => true,
							  'eastafrica' => true,
							  'eastcoast' => true,
							  'education' => true,
							  'educational' => true,
							  'egyptian' => true,
							  'eisenbahn' => true,
							  'elburg' => true,
							  'elvendrell' => true,
							  'embroidery' => true,
							  'encyclopedic' => true,
							  'england' => true,
							  'entomology' => true,
							  'environment' => true,
							  'environmentalconservation' => true,
							  'epilepsy' => true,
							  'essex' => true,
							  'estate' => true,
							  'ethnology' => true,
							  'exeter' => true,
							  'exhibition' => true,
							  'family' => true,
							  'farm' => true,
							  'farmequipment' => true,
							  'farmers' => true,
							  'farmstead' => true,
							  'field' => true,
							  'figueres' => true,
							  'filatelia' => true,
							  'film' => true,
							  'fineart' => true,
							  'finearts' => true,
							  'finland' => true,
							  'flanders' => true,
							  'florida' => true,
							  'force' => true,
							  'fortmissoula' => true,
							  'fortworth' => true,
							  'foundation' => true,
							  'francaise' => true,
							  'frankfurt' => true,
							  'franziskaner' => true,
							  'freemasonry' => true,
							  'freiburg' => true,
							  'fribourg' => true,
							  'frog' => true,
							  'fundacio' => true,
							  'furniture' => true,
							  'gallery' => true,
							  'garden' => true,
							  'gateway' => true,
							  'geelvinck' => true,
							  'gemological' => true,
							  'geology' => true,
							  'georgia' => true,
							  'giessen' => true,
							  'glas' => true,
							  'glass' => true,
							  'gorge' => true,
							  'grandrapids' => true,
							  'graz' => true,
							  'guernsey' => true,
							  'halloffame' => true,
							  'hamburg' => true,
							  'handson' => true,
							  'harvestcelebration' => true,
							  'hawaii' => true,
							  'health' => true,
							  'heimatunduhren' => true,
							  'hellas' => true,
							  'helsinki' => true,
							  'hembygdsforbund' => true,
							  'heritage' => true,
							  'histoire' => true,
							  'historical' => true,
							  'historicalsociety' => true,
							  'historichouses' => true,
							  'historisch' => true,
							  'historisches' => true,
							  'history' => true,
							  'historyofscience' => true,
							  'horology' => true,
							  'house' => true,
							  'humanities' => true,
							  'illustration' => true,
							  'imageandsound' => true,
							  'indian' => true,
							  'indiana' => true,
							  'indianapolis' => true,
							  'indianmarket' => true,
							  'intelligence' => true,
							  'interactive' => true,
							  'iraq' => true,
							  'iron' => true,
							  'isleofman' => true,
							  'jamison' => true,
							  'jefferson' => true,
							  'jerusalem' => true,
							  'jewelry' => true,
							  'jewish' => true,
							  'jewishart' => true,
							  'jfk' => true,
							  'journalism' => true,
							  'judaica' => true,
							  'judygarland' => true,
							  'juedisches' => true,
							  'juif' => true,
							  'karate' => true,
							  'karikatur' => true,
							  'kids' => true,
							  'koebenhavn' => true,
							  'koeln' => true,
							  'kunst' => true,
							  'kunstsammlung' => true,
							  'kunstunddesign' => true,
							  'labor' => true,
							  'labour' => true,
							  'lajolla' => true,
							  'lancashire' => true,
							  'landes' => true,
							  'lans' => true,
							  'läns' => true,
							  'larsson' => true,
							  'lewismiller' => true,
							  'lincoln' => true,
							  'linz' => true,
							  'living' => true,
							  'livinghistory' => true,
							  'localhistory' => true,
							  'london' => true,
							  'losangeles' => true,
							  'louvre' => true,
							  'loyalist' => true,
							  'lucerne' => true,
							  'luxembourg' => true,
							  'luzern' => true,
							  'mad' => true,
							  'madrid' => true,
							  'mallorca' => true,
							  'manchester' => true,
							  'mansion' => true,
							  'mansions' => true,
							  'manx' => true,
							  'marburg' => true,
							  'maritime' => true,
							  'maritimo' => true,
							  'maryland' => true,
							  'marylhurst' => true,
							  'media' => true,
							  'medical' => true,
							  'medizinhistorisches' => true,
							  'meeres' => true,
							  'memorial' => true,
							  'mesaverde' => true,
							  'michigan' => true,
							  'midatlantic' => true,
							  'military' => true,
							  'mill' => true,
							  'miners' => true,
							  'mining' => true,
							  'minnesota' => true,
							  'missile' => true,
							  'missoula' => true,
							  'modern' => true,
							  'moma' => true,
							  'money' => true,
							  'monmouth' => true,
							  'monticello' => true,
							  'montreal' => true,
							  'moscow' => true,
							  'motorcycle' => true,
							  'muenchen' => true,
							  'muenster' => true,
							  'mulhouse' => true,
							  'muncie' => true,
							  'museet' => true,
							  'museumcenter' => true,
							  'museumvereniging' => true,
							  'music' => true,
							  'national' => true,
							  'nationalfirearms' => true,
							  'nationalheritage' => true,
							  'nativeamerican' => true,
							  'naturalhistory' => true,
							  'naturalhistorymuseum' => true,
							  'naturalsciences' => true,
							  'nature' => true,
							  'naturhistorisches' => true,
							  'natuurwetenschappen' => true,
							  'naumburg' => true,
							  'naval' => true,
							  'nebraska' => true,
							  'neues' => true,
							  'newhampshire' => true,
							  'newjersey' => true,
							  'newmexico' => true,
							  'newport' => true,
							  'newspaper' => true,
							  'newyork' => true,
							  'niepce' => true,
							  'norfolk' => true,
							  'north' => true,
							  'nrw' => true,
							  'nuernberg' => true,
							  'nuremberg' => true,
							  'nyc' => true,
							  'nyny' => true,
							  'oceanographic' => true,
							  'oceanographique' => true,
							  'omaha' => true,
							  'online' => true,
							  'ontario' => true,
							  'openair' => true,
							  'oregon' => true,
							  'oregontrail' => true,
							  'otago' => true,
							  'oxford' => true,
							  'pacific' => true,
							  'paderborn' => true,
							  'palace' => true,
							  'paleo' => true,
							  'palmsprings' => true,
							  'panama' => true,
							  'paris' => true,
							  'pasadena' => true,
							  'pharmacy' => true,
							  'philadelphia' => true,
							  'philadelphiaarea' => true,
							  'philately' => true,
							  'phoenix' => true,
							  'photography' => true,
							  'pilots' => true,
							  'pittsburgh' => true,
							  'planetarium' => true,
							  'plantation' => true,
							  'plants' => true,
							  'plaza' => true,
							  'portal' => true,
							  'portland' => true,
							  'portlligat' => true,
							  'posts-and-telecommunications' => true,
							  'preservation' => true,
							  'presidio' => true,
							  'press' => true,
							  'project' => true,
							  'public' => true,
							  'pubol' => true,
							  'quebec' => true,
							  'railroad' => true,
							  'railway' => true,
							  'research' => true,
							  'resistance' => true,
							  'riodejaneiro' => true,
							  'rochester' => true,
							  'rockart' => true,
							  'roma' => true,
							  'russia' => true,
							  'saintlouis' => true,
							  'salem' => true,
							  'salvadordali' => true,
							  'salzburg' => true,
							  'sandiego' => true,
							  'sanfrancisco' => true,
							  'santabarbara' => true,
							  'santacruz' => true,
							  'santafe' => true,
							  'saskatchewan' => true,
							  'satx' => true,
							  'savannahga' => true,
							  'schlesisches' => true,
							  'schoenbrunn' => true,
							  'schokoladen' => true,
							  'school' => true,
							  'schweiz' => true,
							  'science' => true,
							  'scienceandhistory' => true,
							  'scienceandindustry' => true,
							  'sciencecenter' => true,
							  'sciencecenters' => true,
							  'science-fiction' => true,
							  'sciencehistory' => true,
							  'sciences' => true,
							  'sciencesnaturelles' => true,
							  'scotland' => true,
							  'seaport' => true,
							  'settlement' => true,
							  'settlers' => true,
							  'shell' => true,
							  'sherbrooke' => true,
							  'sibenik' => true,
							  'silk' => true,
							  'ski' => true,
							  'skole' => true,
							  'society' => true,
							  'sologne' => true,
							  'soundandvision' => true,
							  'southcarolina' => true,
							  'southwest' => true,
							  'space' => true,
							  'spy' => true,
							  'square' => true,
							  'stadt' => true,
							  'stalbans' => true,
							  'starnberg' => true,
							  'state' => true,
							  'stateofdelaware' => true,
							  'station' => true,
							  'steam' => true,
							  'steiermark' => true,
							  'stjohn' => true,
							  'stockholm' => true,
							  'stpetersburg' => true,
							  'stuttgart' => true,
							  'suisse' => true,
							  'surgeonshall' => true,
							  'surrey' => true,
							  'svizzera' => true,
							  'sweden' => true,
							  'sydney' => true,
							  'tank' => true,
							  'tcm' => true,
							  'technology' => true,
							  'telekommunikation' => true,
							  'television' => true,
							  'texas' => true,
							  'textile' => true,
							  'theater' => true,
							  'time' => true,
							  'timekeeping' => true,
							  'topology' => true,
							  'torino' => true,
							  'touch' => true,
							  'town' => true,
							  'transport' => true,
							  'tree' => true,
							  'trolley' => true,
							  'trust' => true,
							  'trustee' => true,
							  'uhren' => true,
							  'ulm' => true,
							  'undersea' => true,
							  'university' => true,
							  'usa' => true,
							  'usantiques' => true,
							  'usarts' => true,
							  'uscountryestate' => true,
							  'usculture' => true,
							  'usdecorativearts' => true,
							  'usgarden' => true,
							  'ushistory' => true,
							  'ushuaia' => true,
							  'uslivinghistory' => true,
							  'utah' => true,
							  'uvic' => true,
							  'valley' => true,
							  'vantaa' => true,
							  'versailles' => true,
							  'viking' => true,
							  'village' => true,
							  'virginia' => true,
							  'virtual' => true,
							  'virtuel' => true,
							  'vlaanderen' => true,
							  'volkenkunde' => true,
							  'wales' => true,
							  'wallonie' => true,
							  'war' => true,
							  'washingtondc' => true,
							  'watchandclock' => true,
							  'watch-and-clock' => true,
							  'western' => true,
							  'westfalen' => true,
							  'whaling' => true,
							  'wildlife' => true,
							  'williamsburg' => true,
							  'windmill' => true,
							  'workshop' => true,
							  'york' => true,
							  'yorkshire' => true,
							  'yosemite' => true,
							  'youth' => true,
							  'zoological' => true,
							  'zoology' => true,
							  'ירושלים' => true,
							  'иком' => true
							 ),
							 'mv' => array(
							  'aero' => true,
							  'biz' => true,
							  'com' => true,
							  'coop' => true,
							  'edu' => true,
							  'gov' => true,
							  'info' => true,
							  'int' => true,
							  'mil' => true,
							  'museum' => true,
							  'name' => true,
							  'net' => true,
							  'org' => true,
							  'pro' => true
							 ),
							 'mw' => array(
							  'ac' => true,
							  'biz' => true,
							  'co' => true,
							  'com' => true,
							  'coop' => true,
							  'edu' => true,
							  'gov' => true,
							  'int' => true,
							  'museum' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'mx' => array(
							  'com' => true,
							  'org' => true,
							  'gob' => true,
							  'edu' => true,
							  'net' => true
							 ),
							 'my' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true,
							  'edu' => true,
							  'mil' => true,
							  'name' => true
							 ),
							 'mz' => array(
							  '*' => true
							 ),
							 'na' => array(
							  'info' => true,
							  'pro' => true,
							  'name' => true,
							  'school' => true,
							  'or' => true,
							  'dr' => true,
							  'us' => true,
							  'mx' => true,
							  'ca' => true,
							  'in' => true,
							  'cc' => true,
							  'tv' => true,
							  'ws' => true,
							  'mobi' => true,
							  'co' => true,
							  'com' => true,
							  'org' => true
							 ),
							 'name' => true,
							 'nc' => array(
							  'asso' => true
							 ),
							 'ne' => true,
							 'net' => array(
							  'gb' => true,
							  'se' => true,
							  'uk' => true,
							  'za' => true
							 ),
							 'nf' => array(
							  'com' => true,
							  'net' => true,
							  'per' => true,
							  'rec' => true,
							  'web' => true,
							  'arts' => true,
							  'firm' => true,
							  'info' => true,
							  'other' => true,
							  'store' => true
							 ),
							 'ng' => array(
							  'ac' => true,
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'ni' => array(
							  '*' => true
							 ),
							 'nl' => array(
							  'bv' => true
							 ),
							 'no' => array(
							  'fhs' => true,
							  'vgs' => true,
							  'fylkesbibl' => true,
							  'folkebibl' => true,
							  'museum' => true,
							  'idrett' => true,
							  'priv' => true,
							  'mil' => true,
							  'stat' => true,
							  'dep' => true,
							  'kommune' => true,
							  'herad' => true,
							  'aa' => array(
							   'gs' => true
							  ),
							  'ah' => array(
							   'gs' => true
							  ),
							  'bu' => array(
							   'gs' => true
							  ),
							  'fm' => array(
							   'gs' => true
							  ),
							  'hl' => array(
							   'gs' => true
							  ),
							  'hm' => array(
							   'gs' => true
							  ),
							  'jan-mayen' => array(
							   'gs' => true
							  ),
							  'mr' => array(
							   'gs' => true
							  ),
							  'nl' => array(
							   'gs' => true
							  ),
							  'nt' => array(
							   'gs' => true
							  ),
							  'of' => array(
							   'gs' => true
							  ),
							  'ol' => array(
							   'gs' => true
							  ),
							  'oslo' => array(
							   'gs' => true
							  ),
							  'rl' => array(
							   'gs' => true
							  ),
							  'sf' => array(
							   'gs' => true
							  ),
							  'st' => array(
							   'gs' => true
							  ),
							  'svalbard' => array(
							   'gs' => true
							  ),
							  'tm' => array(
							   'gs' => true
							  ),
							  'tr' => array(
							   'gs' => true
							  ),
							  'va' => array(
							   'gs' => true
							  ),
							  'vf' => array(
							   'gs' => true
							  ),
							  'akrehamn' => true,
							  'åkrehamn' => true,
							  'algard' => true,
							  'ålgård' => true,
							  'arna' => true,
							  'brumunddal' => true,
							  'bryne' => true,
							  'bronnoysund' => true,
							  'brønnøysund' => true,
							  'drobak' => true,
							  'drøbak' => true,
							  'egersund' => true,
							  'fetsund' => true,
							  'floro' => true,
							  'florø' => true,
							  'fredrikstad' => true,
							  'hokksund' => true,
							  'honefoss' => true,
							  'hønefoss' => true,
							  'jessheim' => true,
							  'jorpeland' => true,
							  'jørpeland' => true,
							  'kirkenes' => true,
							  'kopervik' => true,
							  'krokstadelva' => true,
							  'langevag' => true,
							  'langevåg' => true,
							  'leirvik' => true,
							  'mjondalen' => true,
							  'mjøndalen' => true,
							  'mo-i-rana' => true,
							  'mosjoen' => true,
							  'mosjøen' => true,
							  'nesoddtangen' => true,
							  'orkanger' => true,
							  'osoyro' => true,
							  'osøyro' => true,
							  'raholt' => true,
							  'råholt' => true,
							  'sandnessjoen' => true,
							  'sandnessjøen' => true,
							  'skedsmokorset' => true,
							  'slattum' => true,
							  'spjelkavik' => true,
							  'stathelle' => true,
							  'stavern' => true,
							  'stjordalshalsen' => true,
							  'stjørdalshalsen' => true,
							  'tananger' => true,
							  'tranby' => true,
							  'vossevangen' => true,
							  'afjord' => true,
							  'åfjord' => true,
							  'agdenes' => true,
							  'al' => true,
							  'ål' => true,
							  'alesund' => true,
							  'ålesund' => true,
							  'alstahaug' => true,
							  'alta' => true,
							  'áltá' => true,
							  'alaheadju' => true,
							  'álaheadju' => true,
							  'alvdal' => true,
							  'amli' => true,
							  'åmli' => true,
							  'amot' => true,
							  'åmot' => true,
							  'andebu' => true,
							  'andoy' => true,
							  'andøy' => true,
							  'andasuolo' => true,
							  'ardal' => true,
							  'årdal' => true,
							  'aremark' => true,
							  'arendal' => true,
							  'ås' => true,
							  'aseral' => true,
							  'åseral' => true,
							  'asker' => true,
							  'askim' => true,
							  'askvoll' => true,
							  'askoy' => true,
							  'askøy' => true,
							  'asnes' => true,
							  'åsnes' => true,
							  'audnedaln' => true,
							  'aukra' => true,
							  'aure' => true,
							  'aurland' => true,
							  'aurskog-holand' => true,
							  'aurskog-høland' => true,
							  'austevoll' => true,
							  'austrheim' => true,
							  'averoy' => true,
							  'averøy' => true,
							  'balestrand' => true,
							  'ballangen' => true,
							  'balat' => true,
							  'bálát' => true,
							  'balsfjord' => true,
							  'bahccavuotna' => true,
							  'báhccavuotna' => true,
							  'bamble' => true,
							  'bardu' => true,
							  'beardu' => true,
							  'beiarn' => true,
							  'bajddar' => true,
							  'bájddar' => true,
							  'baidar' => true,
							  'báidár' => true,
							  'berg' => true,
							  'bergen' => true,
							  'berlevag' => true,
							  'berlevåg' => true,
							  'bearalvahki' => true,
							  'bearalváhki' => true,
							  'bindal' => true,
							  'birkenes' => true,
							  'bjarkoy' => true,
							  'bjarkøy' => true,
							  'bjerkreim' => true,
							  'bjugn' => true,
							  'bodo' => true,
							  'bodø' => true,
							  'badaddja' => true,
							  'bådåddjå' => true,
							  'budejju' => true,
							  'bokn' => true,
							  'bremanger' => true,
							  'bronnoy' => true,
							  'brønnøy' => true,
							  'bygland' => true,
							  'bykle' => true,
							  'barum' => true,
							  'bærum' => true,
							  'telemark' => array(
							   'bo' => true,
							   'bø' => true
							  ),
							  'nordland' => array(
							   'bo' => true,
							   'bø' => true,
							   'heroy' => true,
							   'herøy' => true
							  ),
							  'bievat' => true,
							  'bievát' => true,
							  'bomlo' => true,
							  'bømlo' => true,
							  'batsfjord' => true,
							  'båtsfjord' => true,
							  'bahcavuotna' => true,
							  'báhcavuotna' => true,
							  'dovre' => true,
							  'drammen' => true,
							  'drangedal' => true,
							  'dyroy' => true,
							  'dyrøy' => true,
							  'donna' => true,
							  'dønna' => true,
							  'eid' => true,
							  'eidfjord' => true,
							  'eidsberg' => true,
							  'eidskog' => true,
							  'eidsvoll' => true,
							  'eigersund' => true,
							  'elverum' => true,
							  'enebakk' => true,
							  'engerdal' => true,
							  'etne' => true,
							  'etnedal' => true,
							  'evenes' => true,
							  'evenassi' => true,
							  'evenášši' => true,
							  'evje-og-hornnes' => true,
							  'farsund' => true,
							  'fauske' => true,
							  'fuossko' => true,
							  'fuoisku' => true,
							  'fedje' => true,
							  'fet' => true,
							  'finnoy' => true,
							  'finnøy' => true,
							  'fitjar' => true,
							  'fjaler' => true,
							  'fjell' => true,
							  'flakstad' => true,
							  'flatanger' => true,
							  'flekkefjord' => true,
							  'flesberg' => true,
							  'flora' => true,
							  'fla' => true,
							  'flå' => true,
							  'folldal' => true,
							  'forsand' => true,
							  'fosnes' => true,
							  'frei' => true,
							  'frogn' => true,
							  'froland' => true,
							  'frosta' => true,
							  'frana' => true,
							  'fræna' => true,
							  'froya' => true,
							  'frøya' => true,
							  'fusa' => true,
							  'fyresdal' => true,
							  'forde' => true,
							  'førde' => true,
							  'gamvik' => true,
							  'gangaviika' => true,
							  'gáŋgaviika' => true,
							  'gaular' => true,
							  'gausdal' => true,
							  'gildeskal' => true,
							  'gildeskål' => true,
							  'giske' => true,
							  'gjemnes' => true,
							  'gjerdrum' => true,
							  'gjerstad' => true,
							  'gjesdal' => true,
							  'gjovik' => true,
							  'gjøvik' => true,
							  'gloppen' => true,
							  'gol' => true,
							  'gran' => true,
							  'grane' => true,
							  'granvin' => true,
							  'gratangen' => true,
							  'grimstad' => true,
							  'grong' => true,
							  'kraanghke' => true,
							  'kråanghke' => true,
							  'grue' => true,
							  'gulen' => true,
							  'hadsel' => true,
							  'halden' => true,
							  'halsa' => true,
							  'hamar' => true,
							  'hamaroy' => true,
							  'habmer' => true,
							  'hábmer' => true,
							  'hapmir' => true,
							  'hápmir' => true,
							  'hammerfest' => true,
							  'hammarfeasta' => true,
							  'hámmárfeasta' => true,
							  'haram' => true,
							  'hareid' => true,
							  'harstad' => true,
							  'hasvik' => true,
							  'aknoluokta' => true,
							  'ákŋoluokta' => true,
							  'hattfjelldal' => true,
							  'aarborte' => true,
							  'haugesund' => true,
							  'hemne' => true,
							  'hemnes' => true,
							  'hemsedal' => true,
							  'more-og-romsdal' => array(
							   'heroy' => true,
							   'sande' => true
							  ),
							  'møre-og-romsdal' => array(
							   'herøy' => true,
							   'sande' => true
							  ),
							  'hitra' => true,
							  'hjartdal' => true,
							  'hjelmeland' => true,
							  'hobol' => true,
							  'hobøl' => true,
							  'hof' => true,
							  'hol' => true,
							  'hole' => true,
							  'holmestrand' => true,
							  'holtalen' => true,
							  'holtålen' => true,
							  'hornindal' => true,
							  'horten' => true,
							  'hurdal' => true,
							  'hurum' => true,
							  'hvaler' => true,
							  'hyllestad' => true,
							  'hagebostad' => true,
							  'hægebostad' => true,
							  'hoyanger' => true,
							  'høyanger' => true,
							  'hoylandet' => true,
							  'høylandet' => true,
							  'ha' => true,
							  'hå' => true,
							  'ibestad' => true,
							  'inderoy' => true,
							  'inderøy' => true,
							  'iveland' => true,
							  'jevnaker' => true,
							  'jondal' => true,
							  'jolster' => true,
							  'jølster' => true,
							  'karasjok' => true,
							  'karasjohka' => true,
							  'kárášjohka' => true,
							  'karlsoy' => true,
							  'galsa' => true,
							  'gálsá' => true,
							  'karmoy' => true,
							  'karmøy' => true,
							  'kautokeino' => true,
							  'guovdageaidnu' => true,
							  'klepp' => true,
							  'klabu' => true,
							  'klæbu' => true,
							  'kongsberg' => true,
							  'kongsvinger' => true,
							  'kragero' => true,
							  'kragerø' => true,
							  'kristiansand' => true,
							  'kristiansund' => true,
							  'krodsherad' => true,
							  'krødsherad' => true,
							  'kvalsund' => true,
							  'rahkkeravju' => true,
							  'ráhkkerávju' => true,
							  'kvam' => true,
							  'kvinesdal' => true,
							  'kvinnherad' => true,
							  'kviteseid' => true,
							  'kvitsoy' => true,
							  'kvitsøy' => true,
							  'kvafjord' => true,
							  'kvæfjord' => true,
							  'giehtavuoatna' => true,
							  'kvanangen' => true,
							  'kvænangen' => true,
							  'navuotna' => true,
							  'návuotna' => true,
							  'kafjord' => true,
							  'kåfjord' => true,
							  'gaivuotna' => true,
							  'gáivuotna' => true,
							  'larvik' => true,
							  'lavangen' => true,
							  'lavagis' => true,
							  'loabat' => true,
							  'loabát' => true,
							  'lebesby' => true,
							  'davvesiida' => true,
							  'leikanger' => true,
							  'leirfjord' => true,
							  'leka' => true,
							  'leksvik' => true,
							  'lenvik' => true,
							  'leangaviika' => true,
							  'leaŋgaviika' => true,
							  'lesja' => true,
							  'levanger' => true,
							  'lier' => true,
							  'lierne' => true,
							  'lillehammer' => true,
							  'lillesand' => true,
							  'lindesnes' => true,
							  'lindas' => true,
							  'lindås' => true,
							  'lom' => true,
							  'loppa' => true,
							  'lahppi' => true,
							  'láhppi' => true,
							  'lund' => true,
							  'lunner' => true,
							  'luroy' => true,
							  'lurøy' => true,
							  'luster' => true,
							  'lyngdal' => true,
							  'lyngen' => true,
							  'ivgu' => true,
							  'lardal' => true,
							  'lerdal' => true,
							  'lærdal' => true,
							  'lodingen' => true,
							  'lødingen' => true,
							  'lorenskog' => true,
							  'lørenskog' => true,
							  'loten' => true,
							  'løten' => true,
							  'malvik' => true,
							  'masoy' => true,
							  'måsøy' => true,
							  'muosat' => true,
							  'muosát' => true,
							  'mandal' => true,
							  'marker' => true,
							  'marnardal' => true,
							  'masfjorden' => true,
							  'meland' => true,
							  'meldal' => true,
							  'melhus' => true,
							  'meloy' => true,
							  'meløy' => true,
							  'meraker' => true,
							  'meråker' => true,
							  'moareke' => true,
							  'moåreke' => true,
							  'midsund' => true,
							  'midtre-gauldal' => true,
							  'modalen' => true,
							  'modum' => true,
							  'molde' => true,
							  'moskenes' => true,
							  'moss' => true,
							  'mosvik' => true,
							  'malselv' => true,
							  'målselv' => true,
							  'malatvuopmi' => true,
							  'málatvuopmi' => true,
							  'namdalseid' => true,
							  'aejrie' => true,
							  'namsos' => true,
							  'namsskogan' => true,
							  'naamesjevuemie' => true,
							  'nååmesjevuemie' => true,
							  'laakesvuemie' => true,
							  'nannestad' => true,
							  'narvik' => true,
							  'narviika' => true,
							  'naustdal' => true,
							  'nedre-eiker' => true,
							  'akershus' => array(
							   'nes' => true
							  ),
							  'buskerud' => array(
							   'nes' => true
							  ),
							  'nesna' => true,
							  'nesodden' => true,
							  'nesseby' => true,
							  'unjarga' => true,
							  'unjárga' => true,
							  'nesset' => true,
							  'nissedal' => true,
							  'nittedal' => true,
							  'nord-aurdal' => true,
							  'nord-fron' => true,
							  'nord-odal' => true,
							  'norddal' => true,
							  'nordkapp' => true,
							  'davvenjarga' => true,
							  'davvenjárga' => true,
							  'nordre-land' => true,
							  'nordreisa' => true,
							  'raisa' => true,
							  'ráisa' => true,
							  'nore-og-uvdal' => true,
							  'notodden' => true,
							  'naroy' => true,
							  'nærøy' => true,
							  'notteroy' => true,
							  'nøtterøy' => true,
							  'odda' => true,
							  'oksnes' => true,
							  'øksnes' => true,
							  'oppdal' => true,
							  'oppegard' => true,
							  'oppegård' => true,
							  'orkdal' => true,
							  'orland' => true,
							  'ørland' => true,
							  'orskog' => true,
							  'ørskog' => true,
							  'orsta' => true,
							  'ørsta' => true,
							  'hedmark' => array(
							   'os' => true,
							   'valer' => true,
							   'våler' => true
							  ),
							  'hordaland' => array(
							   'os' => true
							  ),
							  'osen' => true,
							  'osteroy' => true,
							  'osterøy' => true,
							  'ostre-toten' => true,
							  'østre-toten' => true,
							  'overhalla' => true,
							  'ovre-eiker' => true,
							  'øvre-eiker' => true,
							  'oyer' => true,
							  'øyer' => true,
							  'oygarden' => true,
							  'øygarden' => true,
							  'oystre-slidre' => true,
							  'øystre-slidre' => true,
							  'porsanger' => true,
							  'porsangu' => true,
							  'porsáŋgu' => true,
							  'porsgrunn' => true,
							  'radoy' => true,
							  'radøy' => true,
							  'rakkestad' => true,
							  'rana' => true,
							  'ruovat' => true,
							  'randaberg' => true,
							  'rauma' => true,
							  'rendalen' => true,
							  'rennebu' => true,
							  'rennesoy' => true,
							  'rennesøy' => true,
							  'rindal' => true,
							  'ringebu' => true,
							  'ringerike' => true,
							  'ringsaker' => true,
							  'rissa' => true,
							  'risor' => true,
							  'risør' => true,
							  'roan' => true,
							  'rollag' => true,
							  'rygge' => true,
							  'ralingen' => true,
							  'rælingen' => true,
							  'rodoy' => true,
							  'rødøy' => true,
							  'romskog' => true,
							  'rømskog' => true,
							  'roros' => true,
							  'røros' => true,
							  'rost' => true,
							  'røst' => true,
							  'royken' => true,
							  'røyken' => true,
							  'royrvik' => true,
							  'røyrvik' => true,
							  'rade' => true,
							  'råde' => true,
							  'salangen' => true,
							  'siellak' => true,
							  'saltdal' => true,
							  'salat' => true,
							  'sálát' => true,
							  'sálat' => true,
							  'samnanger' => true,
							  'vestfold' => array(
							   'sande' => true
							  ),
							  'sandefjord' => true,
							  'sandnes' => true,
							  'sandoy' => true,
							  'sandøy' => true,
							  'sarpsborg' => true,
							  'sauda' => true,
							  'sauherad' => true,
							  'sel' => true,
							  'selbu' => true,
							  'selje' => true,
							  'seljord' => true,
							  'sigdal' => true,
							  'siljan' => true,
							  'sirdal' => true,
							  'skaun' => true,
							  'skedsmo' => true,
							  'ski' => true,
							  'skien' => true,
							  'skiptvet' => true,
							  'skjervoy' => true,
							  'skjervøy' => true,
							  'skierva' => true,
							  'skiervá' => true,
							  'skjak' => true,
							  'skjåk' => true,
							  'skodje' => true,
							  'skanland' => true,
							  'skånland' => true,
							  'skanit' => true,
							  'skánit' => true,
							  'smola' => true,
							  'smøla' => true,
							  'snillfjord' => true,
							  'snasa' => true,
							  'snåsa' => true,
							  'snoasa' => true,
							  'snaase' => true,
							  'snåase' => true,
							  'sogndal' => true,
							  'sokndal' => true,
							  'sola' => true,
							  'solund' => true,
							  'songdalen' => true,
							  'sortland' => true,
							  'spydeberg' => true,
							  'stange' => true,
							  'stavanger' => true,
							  'steigen' => true,
							  'steinkjer' => true,
							  'stjordal' => true,
							  'stjørdal' => true,
							  'stokke' => true,
							  'stor-elvdal' => true,
							  'stord' => true,
							  'stordal' => true,
							  'storfjord' => true,
							  'omasvuotna' => true,
							  'strand' => true,
							  'stranda' => true,
							  'stryn' => true,
							  'sula' => true,
							  'suldal' => true,
							  'sund' => true,
							  'sunndal' => true,
							  'surnadal' => true,
							  'sveio' => true,
							  'svelvik' => true,
							  'sykkylven' => true,
							  'sogne' => true,
							  'søgne' => true,
							  'somna' => true,
							  'sømna' => true,
							  'sondre-land' => true,
							  'søndre-land' => true,
							  'sor-aurdal' => true,
							  'sør-aurdal' => true,
							  'sor-fron' => true,
							  'sør-fron' => true,
							  'sor-odal' => true,
							  'sør-odal' => true,
							  'sor-varanger' => true,
							  'sør-varanger' => true,
							  'matta-varjjat' => true,
							  'mátta-várjjat' => true,
							  'sorfold' => true,
							  'sørfold' => true,
							  'sorreisa' => true,
							  'sørreisa' => true,
							  'sorum' => true,
							  'sørum' => true,
							  'tana' => true,
							  'deatnu' => true,
							  'time' => true,
							  'tingvoll' => true,
							  'tinn' => true,
							  'tjeldsund' => true,
							  'dielddanuorri' => true,
							  'tjome' => true,
							  'tjøme' => true,
							  'tokke' => true,
							  'tolga' => true,
							  'torsken' => true,
							  'tranoy' => true,
							  'tranøy' => true,
							  'tromso' => true,
							  'tromsø' => true,
							  'tromsa' => true,
							  'romsa' => true,
							  'trondheim' => true,
							  'troandin' => true,
							  'trysil' => true,
							  'trana' => true,
							  'træna' => true,
							  'trogstad' => true,
							  'trøgstad' => true,
							  'tvedestrand' => true,
							  'tydal' => true,
							  'tynset' => true,
							  'tysfjord' => true,
							  'divtasvuodna' => true,
							  'divttasvuotna' => true,
							  'tysnes' => true,
							  'tysvar' => true,
							  'tysvær' => true,
							  'tonsberg' => true,
							  'tønsberg' => true,
							  'ullensaker' => true,
							  'ullensvang' => true,
							  'ulvik' => true,
							  'utsira' => true,
							  'vadso' => true,
							  'vadsø' => true,
							  'cahcesuolo' => true,
							  'čáhcesuolo' => true,
							  'vaksdal' => true,
							  'valle' => true,
							  'vang' => true,
							  'vanylven' => true,
							  'vardo' => true,
							  'vardø' => true,
							  'varggat' => true,
							  'várggát' => true,
							  'vefsn' => true,
							  'vaapste' => true,
							  'vega' => true,
							  'vegarshei' => true,
							  'vegårshei' => true,
							  'vennesla' => true,
							  'verdal' => true,
							  'verran' => true,
							  'vestby' => true,
							  'vestnes' => true,
							  'vestre-slidre' => true,
							  'vestre-toten' => true,
							  'vestvagoy' => true,
							  'vestvågøy' => true,
							  'vevelstad' => true,
							  'vik' => true,
							  'vikna' => true,
							  'vindafjord' => true,
							  'volda' => true,
							  'voss' => true,
							  'varoy' => true,
							  'værøy' => true,
							  'vagan' => true,
							  'vågan' => true,
							  'voagat' => true,
							  'vagsoy' => true,
							  'vågsøy' => true,
							  'vaga' => true,
							  'vågå' => true,
							  'ostfold' => array(
							   'valer' => true
							  ),
							  'østfold' => array(
							   'våler' => true
							  )
							 ),
							 'np' => array(
							  '*' => true
							 ),
							 'nr' => array(
							  'biz' => true,
							  'info' => true,
							  'gov' => true,
							  'edu' => true,
							  'org' => true,
							  'net' => true,
							  'com' => true
							 ),
							 'nu' => true,
							 'nz' => array(
							  '*' => true
							 ),
							 'om' => array(
							  '*' => true,
							  '!mediaphone' => true,
							  '!nawrastelecom' => true,
							  '!nawras' => true,
							  '!omanmobile' => true,
							  '!omanpost' => true,
							  '!omantel' => true,
							  '!rakpetroleum' => true,
							  '!siemens' => true,
							  '!songfest' => true,
							  '!statecouncil' => true
							 ),
							 'org' => array(
							  'ae' => true,
							  'za' => true
							 ),
							 'pa' => array(
							  'ac' => true,
							  'gob' => true,
							  'com' => true,
							  'org' => true,
							  'sld' => true,
							  'edu' => true,
							  'net' => true,
							  'ing' => true,
							  'abo' => true,
							  'med' => true,
							  'nom' => true
							 ),
							 'pe' => array(
							  'edu' => true,
							  'gob' => true,
							  'nom' => true,
							  'mil' => true,
							  'org' => true,
							  'com' => true,
							  'net' => true
							 ),
							 'pf' => array(
							  'com' => true,
							  'org' => true,
							  'edu' => true
							 ),
							 'pg' => array(
							  '*' => true
							 ),
							 'ph' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true,
							  'edu' => true,
							  'ngo' => true,
							  'mil' => true,
							  'i' => true
							 ),
							 'pk' => array(
							  'com' => true,
							  'net' => true,
							  'edu' => true,
							  'org' => true,
							  'fam' => true,
							  'biz' => true,
							  'web' => true,
							  'gov' => true,
							  'gob' => true,
							  'gok' => true,
							  'gon' => true,
							  'gop' => true,
							  'gos' => true,
							  'info' => true
							 ),
							 'pl' => array(
							  'aid' => true,
							  'agro' => true,
							  'atm' => true,
							  'auto' => true,
							  'biz' => true,
							  'com' => true,
							  'edu' => true,
							  'gmina' => true,
							  'gsm' => true,
							  'info' => true,
							  'mail' => true,
							  'miasta' => true,
							  'media' => true,
							  'mil' => true,
							  'net' => true,
							  'nieruchomosci' => true,
							  'nom' => true,
							  'org' => true,
							  'pc' => true,
							  'powiat' => true,
							  'priv' => true,
							  'realestate' => true,
							  'rel' => true,
							  'sex' => true,
							  'shop' => true,
							  'sklep' => true,
							  'sos' => true,
							  'szkola' => true,
							  'targi' => true,
							  'tm' => true,
							  'tourism' => true,
							  'travel' => true,
							  'turystyka' => true,
							  '6bone' => true,
							  'art' => true,
							  'mbone' => true,
							  'gov' => array(
							   'uw' => true,
							   'um' => true,
							   'ug' => true,
							   'upow' => true,
							   'starostwo' => true,
							   'so' => true,
							   'sr' => true,
							   'po' => true,
							   'pa' => true
							  ),
							  'ngo' => true,
							  'irc' => true,
							  'usenet' => true,
							  'augustow' => true,
							  'babia-gora' => true,
							  'bedzin' => true,
							  'beskidy' => true,
							  'bialowieza' => true,
							  'bialystok' => true,
							  'bielawa' => true,
							  'bieszczady' => true,
							  'boleslawiec' => true,
							  'bydgoszcz' => true,
							  'bytom' => true,
							  'cieszyn' => true,
							  'czeladz' => true,
							  'czest' => true,
							  'dlugoleka' => true,
							  'elblag' => true,
							  'elk' => true,
							  'glogow' => true,
							  'gniezno' => true,
							  'gorlice' => true,
							  'grajewo' => true,
							  'ilawa' => true,
							  'jaworzno' => true,
							  'jelenia-gora' => true,
							  'jgora' => true,
							  'kalisz' => true,
							  'kazimierz-dolny' => true,
							  'karpacz' => true,
							  'kartuzy' => true,
							  'kaszuby' => true,
							  'katowice' => true,
							  'kepno' => true,
							  'ketrzyn' => true,
							  'klodzko' => true,
							  'kobierzyce' => true,
							  'kolobrzeg' => true,
							  'konin' => true,
							  'konskowola' => true,
							  'kutno' => true,
							  'lapy' => true,
							  'lebork' => true,
							  'legnica' => true,
							  'lezajsk' => true,
							  'limanowa' => true,
							  'lomza' => true,
							  'lowicz' => true,
							  'lubin' => true,
							  'lukow' => true,
							  'malbork' => true,
							  'malopolska' => true,
							  'mazowsze' => true,
							  'mazury' => true,
							  'mielec' => true,
							  'mielno' => true,
							  'mragowo' => true,
							  'naklo' => true,
							  'nowaruda' => true,
							  'nysa' => true,
							  'olawa' => true,
							  'olecko' => true,
							  'olkusz' => true,
							  'olsztyn' => true,
							  'opoczno' => true,
							  'opole' => true,
							  'ostroda' => true,
							  'ostroleka' => true,
							  'ostrowiec' => true,
							  'ostrowwlkp' => true,
							  'pila' => true,
							  'pisz' => true,
							  'podhale' => true,
							  'podlasie' => true,
							  'polkowice' => true,
							  'pomorze' => true,
							  'pomorskie' => true,
							  'prochowice' => true,
							  'pruszkow' => true,
							  'przeworsk' => true,
							  'pulawy' => true,
							  'radom' => true,
							  'rawa-maz' => true,
							  'rybnik' => true,
							  'rzeszow' => true,
							  'sanok' => true,
							  'sejny' => true,
							  'siedlce' => true,
							  'slask' => true,
							  'slupsk' => true,
							  'sosnowiec' => true,
							  'stalowa-wola' => true,
							  'skoczow' => true,
							  'starachowice' => true,
							  'stargard' => true,
							  'suwalki' => true,
							  'swidnica' => true,
							  'swiebodzin' => true,
							  'swinoujscie' => true,
							  'szczecin' => true,
							  'szczytno' => true,
							  'tarnobrzeg' => true,
							  'tgory' => true,
							  'turek' => true,
							  'tychy' => true,
							  'ustka' => true,
							  'walbrzych' => true,
							  'warmia' => true,
							  'warszawa' => true,
							  'waw' => true,
							  'wegrow' => true,
							  'wielun' => true,
							  'wlocl' => true,
							  'wloclawek' => true,
							  'wodzislaw' => true,
							  'wolomin' => true,
							  'wroclaw' => true,
							  'zachpomor' => true,
							  'zagan' => true,
							  'zarow' => true,
							  'zgora' => true,
							  'zgorzelec' => true,
							  'gda' => true,
							  'gdansk' => true,
							  'gdynia' => true,
							  'med' => true,
							  'sopot' => true,
							  'gliwice' => true,
							  'krakow' => true,
							  'poznan' => true,
							  'wroc' => true,
							  'zakopane' => true,
							  'co' => true
							 ),
							 'pn' => array(
							  'gov' => true,
							  'co' => true,
							  'org' => true,
							  'edu' => true,
							  'net' => true
							 ),
							 'pr' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true,
							  'edu' => true,
							  'isla' => true,
							  'pro' => true,
							  'biz' => true,
							  'info' => true,
							  'name' => true,
							  'est' => true,
							  'prof' => true,
							  'ac' => true
							 ),
							 'pro' => array(
							  'aca' => true,
							  'bar' => true,
							  'cpa' => true,
							  'jur' => true,
							  'law' => true,
							  'med' => true,
							  'eng' => true
							 ),
							 'ps' => array(
							  'edu' => true,
							  'gov' => true,
							  'sec' => true,
							  'plo' => true,
							  'com' => true,
							  'org' => true,
							  'net' => true
							 ),
							 'pt' => array(
							  'net' => true,
							  'gov' => true,
							  'org' => true,
							  'edu' => true,
							  'int' => true,
							  'publ' => true,
							  'com' => true,
							  'nome' => true
							 ),
							 'pw' => array(
							  'co' => true,
							  'ne' => true,
							  'or' => true,
							  'ed' => true,
							  'go' => true,
							  'belau' => true
							 ),
							 'py' => array(
							  '*' => true
							 ),
							 'qa' => array(
							  '*' => true
							 ),
							 're' => array(
							  'com' => true,
							  'asso' => true,
							  'nom' => true
							 ),
							 'ro' => array(
							  'com' => true,
							  'org' => true,
							  'tm' => true,
							  'nt' => true,
							  'nom' => true,
							  'info' => true,
							  'rec' => true,
							  'arts' => true,
							  'firm' => true,
							  'store' => true,
							  'www' => true
							 ),
							 'rs' => array(
							  'co' => true,
							  'org' => true,
							  'edu' => true,
							  'ac' => true,
							  'gov' => true,
							  'in' => true
							 ),
							 'ru' => array(
							  'ac' => true,
							  'com' => true,
							  'edu' => true,
							  'int' => true,
							  'net' => true,
							  'org' => true,
							  'pp' => true,
							  'adygeya' => true,
							  'altai' => true,
							  'amur' => true,
							  'arkhangelsk' => true,
							  'astrakhan' => true,
							  'bashkiria' => true,
							  'belgorod' => true,
							  'bir' => true,
							  'bryansk' => true,
							  'buryatia' => true,
							  'cbg' => true,
							  'chel' => true,
							  'chelyabinsk' => true,
							  'chita' => true,
							  'chukotka' => true,
							  'chuvashia' => true,
							  'dagestan' => true,
							  'dudinka' => true,
							  'e-burg' => true,
							  'grozny' => true,
							  'irkutsk' => true,
							  'ivanovo' => true,
							  'izhevsk' => true,
							  'jar' => true,
							  'joshkar-ola' => true,
							  'kalmykia' => true,
							  'kaluga' => true,
							  'kamchatka' => true,
							  'karelia' => true,
							  'kazan' => true,
							  'kchr' => true,
							  'kemerovo' => true,
							  'khabarovsk' => true,
							  'khakassia' => true,
							  'khv' => true,
							  'kirov' => true,
							  'koenig' => true,
							  'komi' => true,
							  'kostroma' => true,
							  'krasnoyarsk' => true,
							  'kuban' => true,
							  'kurgan' => true,
							  'kursk' => true,
							  'lipetsk' => true,
							  'magadan' => true,
							  'mari' => true,
							  'mari-el' => true,
							  'marine' => true,
							  'mordovia' => true,
							  'mosreg' => true,
							  'msk' => true,
							  'murmansk' => true,
							  'nalchik' => true,
							  'nnov' => true,
							  'nov' => true,
							  'novosibirsk' => true,
							  'nsk' => true,
							  'omsk' => true,
							  'orenburg' => true,
							  'oryol' => true,
							  'palana' => true,
							  'penza' => true,
							  'perm' => true,
							  'pskov' => true,
							  'ptz' => true,
							  'rnd' => true,
							  'ryazan' => true,
							  'sakhalin' => true,
							  'samara' => true,
							  'saratov' => true,
							  'simbirsk' => true,
							  'smolensk' => true,
							  'spb' => true,
							  'stavropol' => true,
							  'stv' => true,
							  'surgut' => true,
							  'tambov' => true,
							  'tatarstan' => true,
							  'tom' => true,
							  'tomsk' => true,
							  'tsaritsyn' => true,
							  'tsk' => true,
							  'tula' => true,
							  'tuva' => true,
							  'tver' => true,
							  'tyumen' => true,
							  'udm' => true,
							  'udmurtia' => true,
							  'ulan-ude' => true,
							  'vladikavkaz' => true,
							  'vladimir' => true,
							  'vladivostok' => true,
							  'volgograd' => true,
							  'vologda' => true,
							  'voronezh' => true,
							  'vrn' => true,
							  'vyatka' => true,
							  'yakutia' => true,
							  'yamal' => true,
							  'yaroslavl' => true,
							  'yekaterinburg' => true,
							  'yuzhno-sakhalinsk' => true,
							  'amursk' => true,
							  'baikal' => true,
							  'cmw' => true,
							  'fareast' => true,
							  'jamal' => true,
							  'kms' => true,
							  'k-uralsk' => true,
							  'kustanai' => true,
							  'kuzbass' => true,
							  'magnitka' => true,
							  'mytis' => true,
							  'nakhodka' => true,
							  'nkz' => true,
							  'norilsk' => true,
							  'oskol' => true,
							  'pyatigorsk' => true,
							  'rubtsovsk' => true,
							  'snz' => true,
							  'syzran' => true,
							  'vdonsk' => true,
							  'zgrad' => true,
							  'gov' => true,
							  'mil' => true,
							  'test' => true
							 ),
							 'rw' => array(
							  'gov' => true,
							  'net' => true,
							  'edu' => true,
							  'ac' => true,
							  'com' => true,
							  'co' => true,
							  'int' => true,
							  'mil' => true,
							  'gouv' => true
							 ),
							 'sa' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true,
							  'med' => true,
							  'pub' => true,
							  'edu' => true,
							  'sch' => true
							 ),
							 'sb' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'sc' => array(
							  'com' => true,
							  'gov' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true
							 ),
							 'sd' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true,
							  'med' => true,
							  'gov' => true,
							  'info' => true
							 ),
							 'se' => array(
							  'a' => true,
							  'ac' => true,
							  'b' => true,
							  'bd' => true,
							  'brand' => true,
							  'c' => true,
							  'd' => true,
							  'e' => true,
							  'f' => true,
							  'fh' => true,
							  'fhsk' => true,
							  'fhv' => true,
							  'g' => true,
							  'h' => true,
							  'i' => true,
							  'k' => true,
							  'komforb' => true,
							  'kommunalforbund' => true,
							  'komvux' => true,
							  'l' => true,
							  'lanbib' => true,
							  'm' => true,
							  'n' => true,
							  'naturbruksgymn' => true,
							  'o' => true,
							  'org' => true,
							  'p' => true,
							  'parti' => true,
							  'pp' => true,
							  'press' => true,
							  'r' => true,
							  's' => true,
							  'sshn' => true,
							  't' => true,
							  'tm' => true,
							  'u' => true,
							  'w' => true,
							  'x' => true,
							  'y' => true,
							  'z' => true
							 ),
							 'sg' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true,
							  'edu' => true,
							  'per' => true
							 ),
							 'sh' => true,
							 'si' => true,
							 'sk' => true,
							 'sl' => array(
							  'com' => true,
							  'net' => true,
							  'edu' => true,
							  'gov' => true,
							  'org' => true
							 ),
							 'sm' => true,
							 'sn' => array(
							  'art' => true,
							  'com' => true,
							  'edu' => true,
							  'gouv' => true,
							  'org' => true,
							  'perso' => true,
							  'univ' => true
							 ),
							 'so' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'sr' => true,
							 'st' => array(
							  'co' => true,
							  'com' => true,
							  'consulado' => true,
							  'edu' => true,
							  'embaixada' => true,
							  'gov' => true,
							  'mil' => true,
							  'net' => true,
							  'org' => true,
							  'principe' => true,
							  'saotome' => true,
							  'store' => true
							 ),
							 'su' => true,
							 'sv' => array(
							  '*' => true
							 ),
							 'sy' => array(
							  'edu' => true,
							  'gov' => true,
							  'net' => true,
							  'mil' => true,
							  'com' => true,
							  'org' => true
							 ),
							 'sz' => array(
							  'co' => true,
							  'ac' => true,
							  'org' => true
							 ),
							 'tc' => true,
							 'td' => true,
							 'tel' => true,
							 'tf' => true,
							 'tg' => true,
							 'th' => array(
							  'ac' => true,
							  'co' => true,
							  'go' => true,
							  'in' => true,
							  'mi' => true,
							  'net' => true,
							  'or' => true
							 ),
							 'tj' => array(
							  'ac' => true,
							  'biz' => true,
							  'co' => true,
							  'com' => true,
							  'edu' => true,
							  'go' => true,
							  'gov' => true,
							  'int' => true,
							  'mil' => true,
							  'name' => true,
							  'net' => true,
							  'nic' => true,
							  'org' => true,
							  'test' => true,
							  'web' => true
							 ),
							 'tk' => true,
							 'tl' => array(
							  'gov' => true
							 ),
							 'tm' => true,
							 'tn' => array(
							  'com' => true,
							  'ens' => true,
							  'fin' => true,
							  'gov' => true,
							  'ind' => true,
							  'intl' => true,
							  'nat' => true,
							  'net' => true,
							  'org' => true,
							  'info' => true,
							  'perso' => true,
							  'tourism' => true,
							  'edunet' => true,
							  'rnrt' => true,
							  'rns' => true,
							  'rnu' => true,
							  'mincom' => true,
							  'agrinet' => true,
							  'defense' => true,
							  'turen' => true
							 ),
							 'to' => array(
							  'com' => true,
							  'gov' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true,
							  'mil' => true
							 ),
							 'tr' => array(
							  '*' => true,
							  '!nic' => true,
							  '!tsk' => true,
							  'nc' => array(
							   'gov' => true
							  )
							 ),
							 'travel' => true,
							 'tt' => array(
							  'co' => true,
							  'com' => true,
							  'org' => true,
							  'net' => true,
							  'biz' => true,
							  'info' => true,
							  'pro' => true,
							  'int' => true,
							  'coop' => true,
							  'jobs' => true,
							  'mobi' => true,
							  'travel' => true,
							  'museum' => true,
							  'aero' => true,
							  'name' => true,
							  'gov' => true,
							  'edu' => true
							 ),
							 'tv' => true,
							 'tw' => array(
							  'edu' => true,
							  'gov' => true,
							  'mil' => true,
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'idv' => true,
							  'game' => true,
							  'ebiz' => true,
							  'club' => true,
							  '網路' => true,
							  '組織' => true,
							  '商業' => true
							 ),
							 'tz' => array(
							  'ac' => true,
							  'co' => true,
							  'go' => true,
							  'mil' => true,
							  'ne' => true,
							  'or' => true,
							  'sc' => true
							 ),
							 'ua' => array(
							  'com' => true,
							  'edu' => true,
							  'gov' => true,
							  'in' => true,
							  'net' => true,
							  'org' => true,
							  'cherkassy' => true,
							  'chernigov' => true,
							  'chernovtsy' => true,
							  'ck' => true,
							  'cn' => true,
							  'crimea' => true,
							  'cv' => true,
							  'dn' => true,
							  'dnepropetrovsk' => true,
							  'donetsk' => true,
							  'dp' => true,
							  'if' => true,
							  'ivano-frankivsk' => true,
							  'kh' => true,
							  'kharkov' => true,
							  'kherson' => true,
							  'khmelnitskiy' => true,
							  'kiev' => true,
							  'kirovograd' => true,
							  'km' => true,
							  'kr' => true,
							  'ks' => true,
							  'kv' => true,
							  'lg' => true,
							  'lugansk' => true,
							  'lutsk' => true,
							  'lviv' => true,
							  'mk' => true,
							  'nikolaev' => true,
							  'od' => true,
							  'odessa' => true,
							  'pl' => true,
							  'poltava' => true,
							  'rovno' => true,
							  'rv' => true,
							  'sebastopol' => true,
							  'sumy' => true,
							  'te' => true,
							  'ternopil' => true,
							  'uzhgorod' => true,
							  'vinnica' => true,
							  'vn' => true,
							  'zaporizhzhe' => true,
							  'zp' => true,
							  'zhitomir' => true,
							  'zt' => true
							 ),
							 'ug' => array(
							  'co' => true,
							  'ac' => true,
							  'sc' => true,
							  'go' => true,
							  'ne' => true,
							  'or' => true
							 ),
							 'uk' => array(
							  '*' => true,
							  'sch' => array(
							   '*' => true
							  ),
							  '!bl' => true,
							  '!british-library' => true,
							  '!icnet' => true,
							  '!jet' => true,
							  '!nel' => true,
							  '!nhs' => true,
							  '!nls' => true,
							  '!national-library-scotland' => true,
							  '!parliament' => true
							 ),
							 'us' => array(
							  'dni' => true,
							  'fed' => true,
							  'isa' => true,
							  'kids' => true,
							  'nsn' => true,
							  'ak' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'al' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ar' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'as' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'az' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ca' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'co' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ct' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'dc' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'de' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'fl' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ga' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'gu' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'hi' => array(
							   'cc' => true,
							   'lib' => true
							  ),
							  'ia' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'id' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'il' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'in' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ks' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ky' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'la' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ma' => array(
							   'k12' => array(
							    'pvt' => true,
							    'chtr' => true,
							    'paroch' => true
							   ),
							   'cc' => true,
							   'lib' => true
							  ),
							  'md' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'me' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'mi' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'mn' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'mo' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ms' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'mt' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'nc' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'nd' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ne' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'nh' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'nj' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'nm' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'nv' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ny' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'oh' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ok' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'or' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'pa' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'pr' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ri' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'sc' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'sd' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'tn' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'tx' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'ut' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'vi' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'vt' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'va' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'wa' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'wi' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'wv' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  ),
							  'wy' => array(
							   'k12' => true,
							   'cc' => true,
							   'lib' => true
							  )
							 ),
							 'uy' => array(
							  '*' => true
							 ),
							 'uz' => array(
							  'com' => true,
							  'co' => true
							 ),
							 'va' => true,
							 'vc' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true,
							  'mil' => true,
							  'edu' => true
							 ),
							 've' => array(
							  '*' => true
							 ),
							 'vg' => true,
							 'vi' => array(
							  'co' => true,
							  'com' => true,
							  'k12' => true,
							  'net' => true,
							  'org' => true
							 ),
							 'vn' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'edu' => true,
							  'gov' => true,
							  'int' => true,
							  'ac' => true,
							  'biz' => true,
							  'info' => true,
							  'name' => true,
							  'pro' => true,
							  'health' => true
							 ),
							 'vu' => true,
							 'ws' => array(
							  'com' => true,
							  'net' => true,
							  'org' => true,
							  'gov' => true,
							  'edu' => true
							 ),
							 'امارات' => true,
							 '中国' => true,
							 '中國' => true,
							 'مصر' => true,
							 '香港' => true,
							 'الاردن' => true,
							 'ලංකා' => true,
							 'இலங்கை' => true,
							 'فلسطين' => true,
							 'рф' => true,
							 'قطر' => true,
							 'السعودية' => true,
							 '新加坡' => true,
							 'சிங்கப்பூர்' => true,
							 'ไทย' => true,
							 'تونس' => true,
							 '台灣' => true,
							 '台湾' => true,
							 'ye' => array(
							  '*' => true
							 ),
							 'yu' => array(
							  '*' => true
							 ),
							 'za' => array(
							  '*' => true
							 ),
							 'zm' => array(
							  '*' => true
							 ),
							 'zw' => array(
							  '*' => true
							 )
							);
        }

        if (!($result = self::checkDomainsList($domainParts, self::$psl))) {
            // known TLD, invalid domain name
            return false;
        }

        // unknown TLD
        if (!strpos($result, '.')) {
            // fallback to checking that domain "has at least two dots"
            if (2 > ($count = count($domainParts))) {
                return false;
            }
            return $domainParts[$count - 2] . '.' . $domainParts[$count - 1];
        }
        return $result;
    }

   /**
    * Recursive helper method for {@link getRegisteredDomain()}
    *
    * @param  array         remaining domain parts
    * @param  mixed         node in {@link HTTP_Request2_CookieJar::$psl} to check
    * @return string|null   concatenated domain parts, null in case of error
    */
    protected static function checkDomainsList(array $domainParts, $listNode)
    {
        $sub    = array_pop($domainParts);
        $result = null;

        if (!is_array($listNode) || is_null($sub)
            || array_key_exists('!' . $sub, $listNode)
         ) {
            return $sub;

        } elseif (array_key_exists($sub, $listNode)) {
            $result = self::checkDomainsList($domainParts, $listNode[$sub]);

        } elseif (array_key_exists('*', $listNode)) {
            $result = self::checkDomainsList($domainParts, $listNode['*']);

        } else {
            return $sub;
        }

        return (strlen($result) > 0) ? ($result . '.' . $sub) : null;
    }
}

// ----------------------------------------------------------------------------------------- //
//F PEAR://HTTP/Request2.php                                                                 //
// ----------------------------------------------------------------------------------------- //

/**
 * Class representing a HTTP request message
 *
 * PHP version 5
 *
 * LICENSE:
 *
 * Copyright (c) 2008-2011, Alexey Borzov <avb@php.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * The names of the authors may not be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @license    http://opensource.org/licenses/bsd-license.php New BSD License
 * @version    SVN: $Id: Request2.php 308735 2011-02-27 20:31:28Z avb $
 * @link       http://pear.php.net/package/HTTP_Request2
 */

/**
 * Class representing a HTTP request message
 *
 * @category   HTTP
 * @package    HTTP_Request2
 * @author     Alexey Borzov <avb@php.net>
 * @version    Release: 2.0.0beta3
 * @link       http://tools.ietf.org/html/rfc2616#section-5
 */
class HTTP_Request2 implements SplSubject
{
   /**#@+
    * Constants for HTTP request methods
    *
    * @link http://tools.ietf.org/html/rfc2616#section-5.1.1
    */
    const METHOD_OPTIONS = 'OPTIONS';
    const METHOD_GET     = 'GET';
    const METHOD_HEAD    = 'HEAD';
    const METHOD_POST    = 'POST';
    const METHOD_PUT     = 'PUT';
    const METHOD_DELETE  = 'DELETE';
    const METHOD_TRACE   = 'TRACE';
    const METHOD_CONNECT = 'CONNECT';
   /**#@-*/

   /**#@+
    * Constants for HTTP authentication schemes
    *
    * @link http://tools.ietf.org/html/rfc2617
    */
    const AUTH_BASIC  = 'basic';
    const AUTH_DIGEST = 'digest';
   /**#@-*/

   /**
    * Regular expression used to check for invalid symbols in RFC 2616 tokens
    * @link http://pear.php.net/bugs/bug.php?id=15630
    */
    const REGEXP_INVALID_TOKEN = '![\x00-\x1f\x7f-\xff()<>@,;:\\\\"/\[\]?={}\s]!';

   /**
    * Regular expression used to check for invalid symbols in cookie strings
    * @link http://pear.php.net/bugs/bug.php?id=15630
    * @link http://web.archive.org/web/20080331104521/http://cgi.netscape.com/newsref/std/cookie_spec.html
    */
    const REGEXP_INVALID_COOKIE = '/[\s,;]/';

   /**
    * Fileinfo magic database resource
    * @var  resource
    * @see  detectMimeType()
    */
    private static $_fileinfoDb;

   /**
    * Observers attached to the request (instances of SplObserver)
    * @var  array
    */
    protected $observers = array();

   /**
    * Request URL
    * @var  Net_URL2
    */
    protected $url;

   /**
    * Request method
    * @var  string
    */
    protected $method = self::METHOD_GET;

   /**
    * Authentication data
    * @var  array
    * @see  getAuth()
    */
    protected $auth;

   /**
    * Request headers
    * @var  array
    */
    protected $headers = array();

   /**
    * Configuration parameters
    * @var  array
    * @see  setConfig()
    */
    protected $config = array(
        'adapter'           => 'HTTP_Request2_Adapter_Socket',
        'connect_timeout'   => 10,
        'timeout'           => 0,
        'use_brackets'      => true,
        'protocol_version'  => '1.1',
        'buffer_size'       => 16384,
        'store_body'        => true,

        'proxy_host'        => '',
        'proxy_port'        => '',
        'proxy_user'        => '',
        'proxy_password'    => '',
        'proxy_auth_scheme' => self::AUTH_BASIC,

        'ssl_verify_peer'   => true,
        'ssl_verify_host'   => true,
        'ssl_cafile'        => null,
        'ssl_capath'        => null,
        'ssl_local_cert'    => null,
        'ssl_passphrase'    => null,

        'digest_compat_ie'  => false,

        'follow_redirects'  => false,
        'max_redirects'     => 5,
        'strict_redirects'  => false
    );

   /**
    * Last event in request / response handling, intended for observers
    * @var  array
    * @see  getLastEvent()
    */
    protected $lastEvent = array(
        'name' => 'start',
        'data' => null
    );

   /**
    * Request body
    * @var  string|resource
    * @see  setBody()
    */
    protected $body = '';

   /**
    * Array of POST parameters
    * @var  array
    */
    protected $postParams = array();

   /**
    * Array of file uploads (for multipart/form-data POST requests)
    * @var  array
    */
    protected $uploads = array();

   /**
    * Adapter used to perform actual HTTP request
    * @var  HTTP_Request2_Adapter
    */
    protected $adapter;

   /**
    * Cookie jar to persist cookies between requests
    * @var HTTP_Request2_CookieJar
    */
    protected $cookieJar = null;

   /**
    * Constructor. Can set request URL, method and configuration array.
    *
    * Also sets a default value for User-Agent header.
    *
    * @param    string|Net_Url2     Request URL
    * @param    string              Request method
    * @param    array               Configuration for this Request instance
    */
    public function __construct($url = null, $method = self::METHOD_GET, array $config = array())
    {
        $this->setConfig($config);
        if (!empty($url)) {
            $this->setUrl($url);
        }
        if (!empty($method)) {
            $this->setMethod($method);
        }
        $this->setHeader('user-agent', 'HTTP_Request2/2.0.0beta3 ' .
                         '(http://pear.php.net/package/http_request2) ' .
                         'PHP/' . phpversion());
    }

   /**
    * Sets the URL for this request
    *
    * If the URL has userinfo part (username & password) these will be removed
    * and converted to auth data. If the URL does not have a path component,
    * that will be set to '/'.
    *
    * @param    string|Net_URL2 Request URL
    * @return   HTTP_Request2
    * @throws   HTTP_Request2_LogicException
    */
    public function setUrl($url)
    {
        if (is_string($url)) {
            $url = new Net_URL2(
                $url, array(Net_URL2::OPTION_USE_BRACKETS => $this->config['use_brackets'])
            );
        }
        if (!$url instanceof Net_URL2) {
            throw new HTTP_Request2_LogicException(
                'Parameter is not a valid HTTP URL',
                HTTP_Request2_Exception::INVALID_ARGUMENT
            );
        }
        // URL contains username / password?
        if ($url->getUserinfo()) {
            $username = $url->getUser();
            $password = $url->getPassword();
            $this->setAuth(rawurldecode($username), $password? rawurldecode($password): '');
            $url->setUserinfo('');
        }
        if ('' == $url->getPath()) {
            $url->setPath('/');
        }
        $this->url = $url;

        return $this;
    }

   /**
    * Returns the request URL
    *
    * @return   Net_URL2
    */
    public function getUrl()
    {
        return $this->url;
    }

   /**
    * Sets the request method
    *
    * @param    string
    * @return   HTTP_Request2
    * @throws   HTTP_Request2_LogicException if the method name is invalid
    */
    public function setMethod($method)
    {
        // Method name should be a token: http://tools.ietf.org/html/rfc2616#section-5.1.1
        if (preg_match(self::REGEXP_INVALID_TOKEN, $method)) {
            throw new HTTP_Request2_LogicException(
                "Invalid request method '{$method}'",
                HTTP_Request2_Exception::INVALID_ARGUMENT
            );
        }
        $this->method = $method;

        return $this;
    }

   /**
    * Returns the request method
    *
    * @return   string
    */
    public function getMethod()
    {
        return $this->method;
    }

   /**
    * Sets the configuration parameter(s)
    *
    * The following parameters are available:
    * <ul>
    *   <li> 'adapter'           - adapter to use (string)</li>
    *   <li> 'connect_timeout'   - Connection timeout in seconds (integer)</li>
    *   <li> 'timeout'           - Total number of seconds a request can take.
    *                              Use 0 for no limit, should be greater than
    *                              'connect_timeout' if set (integer)</li>
    *   <li> 'use_brackets'      - Whether to append [] to array variable names (bool)</li>
    *   <li> 'protocol_version'  - HTTP Version to use, '1.0' or '1.1' (string)</li>
    *   <li> 'buffer_size'       - Buffer size to use for reading and writing (int)</li>
    *   <li> 'store_body'        - Whether to store response body in response object.
    *                              Set to false if receiving a huge response and
    *                              using an Observer to save it (boolean)</li>
    *   <li> 'proxy_host'        - Proxy server host (string)</li>
    *   <li> 'proxy_port'        - Proxy server port (integer)</li>
    *   <li> 'proxy_user'        - Proxy auth username (string)</li>
    *   <li> 'proxy_password'    - Proxy auth password (string)</li>
    *   <li> 'proxy_auth_scheme' - Proxy auth scheme, one of HTTP_Request2::AUTH_* constants (string)</li>
    *   <li> 'ssl_verify_peer'   - Whether to verify peer's SSL certificate (bool)</li>
    *   <li> 'ssl_verify_host'   - Whether to check that Common Name in SSL
    *                              certificate matches host name (bool)</li>
    *   <li> 'ssl_cafile'        - Cerificate Authority file to verify the peer
    *                              with (use with 'ssl_verify_peer') (string)</li>
    *   <li> 'ssl_capath'        - Directory holding multiple Certificate
    *                              Authority files (string)</li>
    *   <li> 'ssl_local_cert'    - Name of a file containing local cerificate (string)</li>
    *   <li> 'ssl_passphrase'    - Passphrase with which local certificate
    *                              was encoded (string)</li>
    *   <li> 'digest_compat_ie'  - Whether to imitate behaviour of MSIE 5 and 6
    *                              in using URL without query string in digest
    *                              authentication (boolean)</li>
    *   <li> 'follow_redirects'  - Whether to automatically follow HTTP Redirects (boolean)</li>
    *   <li> 'max_redirects'     - Maximum number of redirects to follow (integer)</li>
    *   <li> 'strict_redirects'  - Whether to keep request method on redirects via status 301 and
    *                              302 (true, needed for compatibility with RFC 2616)
    *                              or switch to GET (false, needed for compatibility with most
    *                              browsers) (boolean)</li>
    * </ul>
    *
    * @param    string|array    configuration parameter name or array
    *                           ('parameter name' => 'parameter value')
    * @param    mixed           parameter value if $nameOrConfig is not an array
    * @return   HTTP_Request2
    * @throws   HTTP_Request2_LogicException If the parameter is unknown
    */
    public function setConfig($nameOrConfig, $value = null)
    {
        if (is_array($nameOrConfig)) {
            foreach ($nameOrConfig as $name => $value) {
                $this->setConfig($name, $value);
            }

        } else {
            if (!array_key_exists($nameOrConfig, $this->config)) {
                throw new HTTP_Request2_LogicException(
                    "Unknown configuration parameter '{$nameOrConfig}'",
                    HTTP_Request2_Exception::INVALID_ARGUMENT
                );
            }
            $this->config[$nameOrConfig] = $value;
        }

        return $this;
    }

   /**
    * Returns the value(s) of the configuration parameter(s)
    *
    * @param    string  parameter name
    * @return   mixed   value of $name parameter, array of all configuration
    *                   parameters if $name is not given
    * @throws   HTTP_Request2_LogicException If the parameter is unknown
    */
    public function getConfig($name = null)
    {
        if (null === $name) {
            return $this->config;
        } elseif (!array_key_exists($name, $this->config)) {
            throw new HTTP_Request2_LogicException(
                "Unknown configuration parameter '{$name}'",
                HTTP_Request2_Exception::INVALID_ARGUMENT
            );
        }
        return $this->config[$name];
    }

   /**
    * Sets the autentification data
    *
    * @param    string  user name
    * @param    string  password
    * @param    string  authentication scheme
    * @return   HTTP_Request2
    */
    public function setAuth($user, $password = '', $scheme = self::AUTH_BASIC)
    {
        if (empty($user)) {
            $this->auth = null;
        } else {
            $this->auth = array(
                'user'     => (string)$user,
                'password' => (string)$password,
                'scheme'   => $scheme
            );
        }

        return $this;
    }

   /**
    * Returns the authentication data
    *
    * The array has the keys 'user', 'password' and 'scheme', where 'scheme'
    * is one of the HTTP_Request2::AUTH_* constants.
    *
    * @return   array
    */
    public function getAuth()
    {
        return $this->auth;
    }

   /**
    * Sets request header(s)
    *
    * The first parameter may be either a full header string 'header: value' or
    * header name. In the former case $value parameter is ignored, in the latter
    * the header's value will either be set to $value or the header will be
    * removed if $value is null. The first parameter can also be an array of
    * headers, in that case method will be called recursively.
    *
    * Note that headers are treated case insensitively as per RFC 2616.
    *
    * <code>
    * $req->setHeader('Foo: Bar'); // sets the value of 'Foo' header to 'Bar'
    * $req->setHeader('FoO', 'Baz'); // sets the value of 'Foo' header to 'Baz'
    * $req->setHeader(array('foo' => 'Quux')); // sets the value of 'Foo' header to 'Quux'
    * $req->setHeader('FOO'); // removes 'Foo' header from request
    * </code>
    *
    * @param    string|array    header name, header string ('Header: value')
    *                           or an array of headers
    * @param    string|array|null header value if $name is not an array,
    *                           header will be removed if value is null
    * @param    bool            whether to replace previous header with the
    *                           same name or append to its value
    * @return   HTTP_Request2
    * @throws   HTTP_Request2_LogicException
    */
    public function setHeader($name, $value = null, $replace = true)
    {
        if (is_array($name)) {
            foreach ($name as $k => $v) {
                if (is_string($k)) {
                    $this->setHeader($k, $v, $replace);
                } else {
                    $this->setHeader($v, null, $replace);
                }
            }
        } else {
            if (null === $value && strpos($name, ':')) {
                list($name, $value) = array_map('trim', explode(':', $name, 2));
            }
            // Header name should be a token: http://tools.ietf.org/html/rfc2616#section-4.2
            if (preg_match(self::REGEXP_INVALID_TOKEN, $name)) {
                throw new HTTP_Request2_LogicException(
                    "Invalid header name '{$name}'",
                    HTTP_Request2_Exception::INVALID_ARGUMENT
                );
            }
            // Header names are case insensitive anyway
            $name = strtolower($name);
            if (null === $value) {
                unset($this->headers[$name]);

            } else {
                if (is_array($value)) {
                    $value = implode(', ', array_map('trim', $value));
                } elseif (is_string($value)) {
                    $value = trim($value);
                }
                if (!isset($this->headers[$name]) || $replace) {
                    $this->headers[$name] = $value;
                } else {
                    $this->headers[$name] .= ', ' . $value;
                }
            }
        }

        return $this;
    }

   /**
    * Returns the request headers
    *
    * The array is of the form ('header name' => 'header value'), header names
    * are lowercased
    *
    * @return   array
    */
    public function getHeaders()
    {
        return $this->headers;
    }

   /**
    * Adds a cookie to the request
    *
    * If the request does not have a CookieJar object set, this method simply
    * appends a cookie to "Cookie:" header.
    *
    * If a CookieJar object is available, the cookie is stored in that object.
    * Data from request URL will be used for setting its 'domain' and 'path'
    * parameters, 'expires' and 'secure' will be set to null and false,
    * respectively. If you need further control, use CookieJar's methods.
    *
    * @param    string  cookie name
    * @param    string  cookie value
    * @return   HTTP_Request2
    * @throws   HTTP_Request2_LogicException
    * @see      setCookieJar()
    */
    public function addCookie($name, $value)
    {
        if (!empty($this->cookieJar)) {
            $this->cookieJar->store(array('name' => $name, 'value' => $value),
                                    $this->url);

        } else {
            $cookie = $name . '=' . $value;
            if (preg_match(self::REGEXP_INVALID_COOKIE, $cookie)) {
                throw new HTTP_Request2_LogicException(
                    "Invalid cookie: '{$cookie}'",
                    HTTP_Request2_Exception::INVALID_ARGUMENT
                );
            }
            $cookies = empty($this->headers['cookie'])? '': $this->headers['cookie'] . '; ';
            $this->setHeader('cookie', $cookies . $cookie);
        }

        return $this;
    }

   /**
    * Sets the request body
    *
    * If you provide file pointer rather than file name, it should support
    * fstat() and rewind() operations.
    *
    * @param    string|resource|HTTP_Request2_MultipartBody  Either a string
    *               with the body or filename containing body or pointer to
    *               an open file or object with multipart body data
    * @param    bool    Whether first parameter is a filename
    * @return   HTTP_Request2
    * @throws   HTTP_Request2_LogicException
    */
    public function setBody($body, $isFilename = false)
    {
        if (!$isFilename && !is_resource($body)) {
            if (!$body instanceof HTTP_Request2_MultipartBody) {
                $this->body = (string)$body;
            } else {
                $this->body = $body;
            }
        } else {
            $fileData = $this->fopenWrapper($body, empty($this->headers['content-type']));
            $this->body = $fileData['fp'];
            if (empty($this->headers['content-type'])) {
                $this->setHeader('content-type', $fileData['type']);
            }
        }
        $this->postParams = $this->uploads = array();

        return $this;
    }

   /**
    * Returns the request body
    *
    * @return   string|resource|HTTP_Request2_MultipartBody
    */
    public function getBody()
    {
        if (self::METHOD_POST == $this->method &&
            (!empty($this->postParams) || !empty($this->uploads))
        ) {
            if (0 === strpos($this->headers['content-type'], 'application/x-www-form-urlencoded')) {
                $body = http_build_query($this->postParams, '', '&');
                if (!$this->getConfig('use_brackets')) {
                    $body = preg_replace('/%5B\d+%5D=/', '=', $body);
                }
                // support RFC 3986 by not encoding '~' symbol (request #15368)
                return str_replace('%7E', '~', $body);

            } elseif (0 === strpos($this->headers['content-type'], 'multipart/form-data')) {
                //require_once 'HTTP/Request2/MultipartBody.php';
                return new HTTP_Request2_MultipartBody(
                    $this->postParams, $this->uploads, $this->getConfig('use_brackets')
                );
            }
        }
        return $this->body;
    }

   /**
    * Adds a file to form-based file upload
    *
    * Used to emulate file upload via a HTML form. The method also sets
    * Content-Type of HTTP request to 'multipart/form-data'.
    *
    * If you just want to send the contents of a file as the body of HTTP
    * request you should use setBody() method.
    *
    * If you provide file pointers rather than file names, they should support
    * fstat() and rewind() operations.
    *
    * @param    string  name of file-upload field
    * @param    string|resource|array   full name of local file, pointer to
    *               open file or an array of files
    * @param    string  filename to send in the request
    * @param    string  content-type of file being uploaded
    * @return   HTTP_Request2
    * @throws   HTTP_Request2_LogicException
    */
    public function addUpload($fieldName, $filename, $sendFilename = null,
                              $contentType = null)
    {
        if (!is_array($filename)) {
            $fileData = $this->fopenWrapper($filename, empty($contentType));
            $this->uploads[$fieldName] = array(
                'fp'        => $fileData['fp'],
                'filename'  => !empty($sendFilename)? $sendFilename
                                :(is_string($filename)? basename($filename): 'anonymous.blob') ,
                'size'      => $fileData['size'],
                'type'      => empty($contentType)? $fileData['type']: $contentType
            );
        } else {
            $fps = $names = $sizes = $types = array();
            foreach ($filename as $f) {
                if (!is_array($f)) {
                    $f = array($f);
                }
                $fileData = $this->fopenWrapper($f[0], empty($f[2]));
                $fps[]   = $fileData['fp'];
                $names[] = !empty($f[1])? $f[1]
                            :(is_string($f[0])? basename($f[0]): 'anonymous.blob');
                $sizes[] = $fileData['size'];
                $types[] = empty($f[2])? $fileData['type']: $f[2];
            }
            $this->uploads[$fieldName] = array(
                'fp' => $fps, 'filename' => $names, 'size' => $sizes, 'type' => $types
            );
        }
        if (empty($this->headers['content-type']) ||
            'application/x-www-form-urlencoded' == $this->headers['content-type']
        ) {
            $this->setHeader('content-type', 'multipart/form-data');
        }

        return $this;
    }

   /**
    * Adds POST parameter(s) to the request.
    *
    * @param    string|array    parameter name or array ('name' => 'value')
    * @param    mixed           parameter value (can be an array)
    * @return   HTTP_Request2
    */
    public function addPostParameter($name, $value = null)
    {
        if (!is_array($name)) {
            $this->postParams[$name] = $value;
        } else {
            foreach ($name as $k => $v) {
                $this->addPostParameter($k, $v);
            }
        }
        if (empty($this->headers['content-type'])) {
            $this->setHeader('content-type', 'application/x-www-form-urlencoded');
        }

        return $this;
    }

   /**
    * Attaches a new observer
    *
    * @param    SplObserver
    */
    public function attach(SplObserver $observer)
    {
        foreach ($this->observers as $attached) {
            if ($attached === $observer) {
                return;
            }
        }
        $this->observers[] = $observer;
    }

   /**
    * Detaches an existing observer
    *
    * @param    SplObserver
    */
    public function detach(SplObserver $observer)
    {
        foreach ($this->observers as $key => $attached) {
            if ($attached === $observer) {
                unset($this->observers[$key]);
                return;
            }
        }
    }

   /**
    * Notifies all observers
    */
    public function notify()
    {
        foreach ($this->observers as $observer) {
            $observer->update($this);
        }
    }

   /**
    * Sets the last event
    *
    * Adapters should use this method to set the current state of the request
    * and notify the observers.
    *
    * @param    string  event name
    * @param    mixed   event data
    */
    public function setLastEvent($name, $data = null)
    {
        $this->lastEvent = array(
            'name' => $name,
            'data' => $data
        );
        $this->notify();
    }

   /**
    * Returns the last event
    *
    * Observers should use this method to access the last change in request.
    * The following event names are possible:
    * <ul>
    *   <li>'connect'                 - after connection to remote server,
    *                                   data is the destination (string)</li>
    *   <li>'disconnect'              - after disconnection from server</li>
    *   <li>'sentHeaders'             - after sending the request headers,
    *                                   data is the headers sent (string)</li>
    *   <li>'sentBodyPart'            - after sending a part of the request body,
    *                                   data is the length of that part (int)</li>
    *   <li>'sentBody'                - after sending the whole request body,
    *                                   data is request body length (int)</li>
    *   <li>'receivedHeaders'         - after receiving the response headers,
    *                                   data is HTTP_Request2_Response object</li>
    *   <li>'receivedBodyPart'        - after receiving a part of the response
    *                                   body, data is that part (string)</li>
    *   <li>'receivedEncodedBodyPart' - as 'receivedBodyPart', but data is still
    *                                   encoded by Content-Encoding</li>
    *   <li>'receivedBody'            - after receiving the complete response
    *                                   body, data is HTTP_Request2_Response object</li>
    * </ul>
    * Different adapters may not send all the event types. Mock adapter does
    * not send any events to the observers.
    *
    * @return   array   The array has two keys: 'name' and 'data'
    */
    public function getLastEvent()
    {
        return $this->lastEvent;
    }

   /**
    * Sets the adapter used to actually perform the request
    *
    * You can pass either an instance of a class implementing HTTP_Request2_Adapter
    * or a class name. The method will only try to include a file if the class
    * name starts with HTTP_Request2_Adapter_, it will also try to prepend this
    * prefix to the class name if it doesn't contain any underscores, so that
    * <code>
    * $request->setAdapter('curl');
    * </code>
    * will work.
    *
    * @param    string|HTTP_Request2_Adapter
    * @return   HTTP_Request2
    * @throws   HTTP_Request2_LogicException
    */
    public function setAdapter($adapter)
    {
        if (is_string($adapter)) {
            if (!class_exists($adapter, false)) {
                if (false === strpos($adapter, '_')) {
                    $adapter = 'HTTP_Request2_Adapter_' . ucfirst($adapter);
                }
                if (preg_match('/^HTTP_Request2_Adapter_([a-zA-Z0-9]+)$/', $adapter)) {
                    //include_once str_replace('_', DIRECTORY_SEPARATOR, $adapter) . '.php';
                }
                if (!class_exists($adapter, false)) {
                    throw new HTTP_Request2_LogicException(
                        "Class {$adapter} not found",
                        HTTP_Request2_Exception::MISSING_VALUE
                    );
                }
            }
            $adapter = new $adapter;
        }
        if (!$adapter instanceof HTTP_Request2_Adapter) {
            throw new HTTP_Request2_LogicException(
                'Parameter is not a HTTP request adapter',
                HTTP_Request2_Exception::INVALID_ARGUMENT
            );
        }
        $this->adapter = $adapter;

        return $this;
    }

   /**
    * Sets the cookie jar
    *
    * A cookie jar is used to maintain cookies across HTTP requests and
    * responses. Cookies from jar will be automatically added to the request
    * headers based on request URL.
    *
    * @param HTTP_Request2_CookieJar|bool   Existing CookieJar object, true to
    *                                       create a new one, false to remove
    */
    public function setCookieJar($jar = true)
    {
        if (!class_exists('HTTP_Request2_CookieJar', false)) {
            //require_once 'HTTP/Request2/CookieJar.php';
        }

        if ($jar instanceof HTTP_Request2_CookieJar) {
            $this->cookieJar = $jar;
        } elseif (true === $jar) {
            $this->cookieJar = new HTTP_Request2_CookieJar();
        } elseif (!$jar) {
            $this->cookieJar = null;
        } else {
            throw new HTTP_Request2_LogicException(
                'Invalid parameter passed to setCookieJar()',
                HTTP_Request2_Exception::INVALID_ARGUMENT
            );
        }

        return $this;
    }

   /**
    * Returns current CookieJar object or null if none
    *
    * @return HTTP_Request2_CookieJar|null
    */
    public function getCookieJar()
    {
        return $this->cookieJar;
    }

   /**
    * Sends the request and returns the response
    *
    * @throws   HTTP_Request2_Exception
    * @return   HTTP_Request2_Response
    */
    public function send()
    {
        // Sanity check for URL
        if (!$this->url instanceof Net_URL2
            || !$this->url->isAbsolute()
            || !in_array(strtolower($this->url->getScheme()), array('https', 'http'))
        ) {
            throw new HTTP_Request2_LogicException(
                'HTTP_Request2 needs an absolute HTTP(S) request URL, '
                . ($this->url instanceof Net_URL2
                   ? 'none' : "'" . $this->url->__toString() . "'")
                . ' given',
                HTTP_Request2_Exception::INVALID_ARGUMENT
            );
        }
        if (empty($this->adapter)) {
            $this->setAdapter($this->getConfig('adapter'));
        }
        // magic_quotes_runtime may break file uploads and chunked response
        // processing; see bug #4543. Don't use ini_get() here; see bug #16440.
        if ($magicQuotes = get_magic_quotes_runtime()) {
            set_magic_quotes_runtime(false);
        }
        // force using single byte encoding if mbstring extension overloads
        // strlen() and substr(); see bug #1781, bug #10605
        if (extension_loaded('mbstring') && (2 & ini_get('mbstring.func_overload'))) {
            $oldEncoding = mb_internal_encoding();
            mb_internal_encoding('iso-8859-1');
        }

        try {
            $response = $this->adapter->sendRequest($this);
        } catch (Exception $e) {
        }
        // cleanup in either case (poor man's "finally" clause)
        if ($magicQuotes) {
            set_magic_quotes_runtime(true);
        }
        if (!empty($oldEncoding)) {
            mb_internal_encoding($oldEncoding);
        }
        // rethrow the exception
        if (!empty($e)) {
            throw $e;
        }
        return $response;
    }

   /**
    * Wrapper around fopen()/fstat() used by setBody() and addUpload()
    *
    * @param  string|resource file name or pointer to open file
    * @param  bool            whether to try autodetecting MIME type of file,
    *                         will only work if $file is a filename, not pointer
    * @return array array('fp' => file pointer, 'size' => file size, 'type' => MIME type)
    * @throws HTTP_Request2_LogicException
    */
    protected function fopenWrapper($file, $detectType = false)
    {
        if (!is_string($file) && !is_resource($file)) {
            throw new HTTP_Request2_LogicException(
                "Filename or file pointer resource expected",
                HTTP_Request2_Exception::INVALID_ARGUMENT
            );
        }
        $fileData = array(
            'fp'   => is_string($file)? null: $file,
            'type' => 'application/octet-stream',
            'size' => 0
        );
        if (is_string($file)) {
            $track = @ini_set('track_errors', 1);
            if (!($fileData['fp'] = @fopen($file, 'rb'))) {
                $e = new HTTP_Request2_LogicException(
                    $php_errormsg, HTTP_Request2_Exception::READ_ERROR
                );
            }
            @ini_set('track_errors', $track);
            if (isset($e)) {
                throw $e;
            }
            if ($detectType) {
                $fileData['type'] = self::detectMimeType($file);
            }
        }
        if (!($stat = fstat($fileData['fp']))) {
            throw new HTTP_Request2_LogicException(
                "fstat() call failed", HTTP_Request2_Exception::READ_ERROR
            );
        }
        $fileData['size'] = $stat['size'];

        return $fileData;
    }

   /**
    * Tries to detect MIME type of a file
    *
    * The method will try to use fileinfo extension if it is available,
    * deprecated mime_content_type() function in the other case. If neither
    * works, default 'application/octet-stream' MIME type is returned
    *
    * @param    string  filename
    * @return   string  file MIME type
    */
    protected static function detectMimeType($filename)
    {
        // finfo extension from PECL available
        if (function_exists('finfo_open')) {
            if (!isset(self::$_fileinfoDb)) {
                self::$_fileinfoDb = @finfo_open(FILEINFO_MIME);
            }
            if (self::$_fileinfoDb) {
                $info = finfo_file(self::$_fileinfoDb, $filename);
            }
        }
        // (deprecated) mime_content_type function available
        if (empty($info) && function_exists('mime_content_type')) {
            return mime_content_type($filename);
        }
        return empty($info)? 'application/octet-stream': $info;
    }
}
?>
