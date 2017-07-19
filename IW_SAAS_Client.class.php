<?php
/**
 * @package IW_SAAS
 * @author Tomasz Jaskowiec <Tomasz.Jaskowiec@inteliwise.com>
 * @author Marcin Walkowiak <Marcin.Walkowiak@inteliwise.com>
 * @copyright Copyright (c) 2010, InteliWISE SA
 * @version 1.0
 * @note http://en.wikipedia.org/wiki/KISS_principle
 */


require_once 'IW_SAAS_HTTP_Request2.class.php'; 

/**
 * SAAS Services Client (thin client)
 * 
 * It's main purpose is to provide communication channel to IW_SAAS_Service mangler.
 */
class IW_SAAS_Client {
	
//version of implemented InteliWISE SAAS Platform Client Protocol	
const VERSION                   = 1.0;

//result of command handling was successful	
const RESULT_CODE_OK            = 0;

//result of command handling was unpredictable, fatal error occured	
const RESULT_CODE_FATAL         =-1;

//wrong service name was provided
const RESULT_CODE_WRONG_SERVICE = 1;

//wrong method name was provided
const RESULT_CODE_WRONG_METHOD  = 2;

//wrong params or their content (types) were provided
const RESULT_CODE_WRONG_PARAMS  = 3;

//wrong credentials were provided during authentication process
const RESULT_CODE_WRONG_AUTH    = 4;	

//wrong version of SAAS API Protocol
const RESULT_CODE_WRONG_VERSION = 5;

//wrong session id
const RESULT_CODE_WRONG_SESSION = 6;

//access denied by privileges
const RESULT_CODE_ACCESS_DENIED = 7;

//internal services connectivity problem, eg. when session service is down or no network connection between service and session services
const RESULT_CODE_CONNECTION_PROBLEMS = 8;

//wrong installation selected or passed into
const RESULT_CODE_WRONG_INSTALLATION  = 9;

//no installation selected yet, but is required to operation
const RESULT_CODE_NO_INSTALLATION	  = 10;

//no such variable/setting or user variable by given name
const RESULT_CODE_NO_SUCH_NAME		  = 11;

//duplicate entry, eg. record or name or other entity secured to be unique
const RESULT_CODE_DUPLICATE_ENTITY	  = 12;

//wrong developer code passed
const RESULT_CODE_WRONG_DEVELOPER_CODE = 13;

//internal session identifier - DO NOT USE IT FOR PHP SESSION MANAGEMENT !!!
private $strSession = '';

//address of the SAAS Platform cluster
private $strCluster = 'api.inteliwise.com';

//SSL flag
private $bUseSSL = true;

//magic callback service selector
private $strCallService = '';

//external session link (forced)
private $strForceSession = null;

//code of developer
private $strDeveloper = '';

// rest request data
private $objRestRequest = null;

/**
 * Creates new SAAS Client Wrapper Object for directing various services requests
 *
 * @param string $p_strDeveloperCode identification code of developer using API
 * @param string $p_strClusterAddress IP or URL pointing to actual cluster of SAAS Platform API backend
 * @param boolean $p_bUseSSL flag forcing Secure Socket Layer (HTTPS) call method to hide data passed into SSL data channel
 * @param string & $p_strForceSession reference to session id used during communication, it can be dynamically changed during process (externally), used for debugging purposes
 * @note Please note that most of methods do not allow not secure (non SSL) communication at all.
 */ 	
public function __construct($p_strDeveloperCode='',$p_strClusterAddress = 'api.inteliwise.com', $p_bUseSSL = true,& $p_strForceSession=null) {
		$this->strCluster = $p_strClusterAddress;
		$this->bUseSSL = $p_bUseSSL;
		$this->strForceSession = & $p_strForceSession;
		$this->strDeveloper = $p_strDeveloperCode;
		$this->objRestRequest = null;
}

/**
 * Magic service name selector
 **/
public function & __get ($p_strProperty) {
	$this->strCallService = $p_strProperty;
	return $this;
}

/**
 * Magic method selector
 **/
public function __call ($p_strMethod , $p_arrArguments = array() ) {
	if (count($p_arrArguments) == 2) //in+out params pair
		return $this->call($this->strCallService,$p_strMethod,$p_arrArguments[0],$p_arrArguments[1]);
	if (count($p_arrArguments) == 1) //only in-params
		return $this->call($this->strCallService,$p_strMethod,$p_arrArguments[0]);
	if (count($p_arrArguments) == 0) //no params at all
		return $this->call($this->strCallService,$p_strMethod);
	else return IW_SAAS_Client::RESULT_CODE_FATAL;
}


/**
 * Gets client IP from HTTP request (including proxied http).
 *
 * @return string retrieved client IP number
 */ 	
private function getClientIP() {
    foreach (array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                    return $ip;
                }
            }
        }
    }
    return '127.0.0.1';
}	


/**
 * Calls SAAS service's method at the cluster site
 *
 * @param string $p_strServiceName name of the service to be called
 * @param string $p_strMethodName name of the method of the service to be called
 * @param mixed  $p_objData data object to be passed to method (encapsulates method parameters)
 * @param mixed & $p_objDataOut returnet data object as a result of method call data processing (encapsulates various number of returned results)
 * @return integer result code (consult defined constants IW_SAAS_Client::RESULT_CODE_*)
 */ 	
private function call($p_strServiceName='', $p_strMethodName='', $p_objData=null, & $p_objDataOut=null) {

	$p_time=microtime(true);

	$p_objDataOut = null;
	
	if ($this->strForceSession !== NULL) $this->strSession = (string) $this->strForceSession;
	
	$commObject=(object) array('service'=>$p_strServiceName, 'version'=>IW_SAAS_Client::VERSION,
                         'method'=>$p_strMethodName, 'data'=>$p_objData,
                         'session'=>$this->strSession,'clientIp'=>$this->getClientIP(),
                         'developer'=>$this->strDeveloper);
	$commObject = json_encode($commObject);
	
	$commURL = ($this->bUseSSL?'https://':'http://').$this->strCluster.'/'.$p_strServiceName.'/'.$p_strMethodName;
	
	$result =  $this->restCall($commURL,$commObject);
	
	if ($result!==FALSE) {
		$result=(object) @json_decode($result);
		
		$ok = true;
		if ((!isset($result->version)) ||
		   (!isset($result->service)) ||
		   (!isset($result->method))  ||
		   (!isset($result->result)))  $ok = false;
		
		if ($ok)
			if (($result->service != $p_strServiceName) || ($result->method != $p_strMethodName)) $ok = false;
		
		if ($ok) {
			if (isset($result->data)) $p_objDataOut = $result->data;
			
			if ((isset($result->session)) && ($this->strForceSession===null)) $this->strSession = (string) $result->session;
			
			return $result->result;
		} else return IW_SAAS_Client::RESULT_CODE_FATAL;	
					
	} else return IW_SAAS_Client::RESULT_CODE_CONNECTION_PROBLEMS;
	
}

/**
 * Clears http context when serializing object
 *
 */ 
public function __sleep() {
		if (!isset($this->objRestRequest)) {
				$this->objRestRequest->setBody('');			
		}
	
		return array('strCluster','strSession', 'bUseSSL', 'strCallService', 'strForceSession','strDeveloper','objRestRequest');
}


/**
 * Posts data in JSON body and retrieves result
 *
 * @param string $p_strURL full URL to connect to
 * @param string $p_strBody body of POST data
 * @return string|boolean return string result body if successfull or FALSE if something went wrong
 */ 
private function restCall($p_strURL ='', $p_strBody = '') {
  ob_start();
  $res = false;
  
  try {
  	if (!isset($this->objRestRequest)) {
  	  $restRequest = new HTTP_Request2($p_strURL, HTTP_Request2::METHOD_POST, array(
          'connect_timeout' => 5,
          'timeout'         => 30,
          'ssl_verify_peer' => false,
          'ssl_verify_host' => false,
          'protocol_version' => '1.1'
        ));


      $restRequest->setHeader('Accept',    'application/json');
      $restRequest->setHeader('Accept-Encoding', 'gzip, deflate');
      $restRequest->setHeader('Content-type',    'application/json');
      
      $this->objRestRequest = $restRequest;
  	}
    $this->objRestRequest->setUrl($p_strURL);
    $this->objRestRequest->setBody($p_strBody);
  
    $restResponse = $this->objRestRequest->send();
    $res = $restResponse->getBody();
    
  }
  catch(Exception $ex) {
	  }
  
	
  ob_end_clean();

  return $res;	
}


} // end of class

?>
