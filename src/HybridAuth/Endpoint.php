<?php
/*!
* HybridAuth
* http://hybridauth.sourceforge.net | http://github.com/hybridauth/hybridauth
* (c) 2009-2012, HybridAuth authors | http://hybridauth.sourceforge.net/licenses.html
*/

/**
 * HybridAuth_Endpoint class
 *
 * HybridAuth_Endpoint class provides a simple way to handle the OpenID and OAuth endpoint.
 */
class HybridAuth_Endpoint {
    public static $request = NULL;
    public static $initDone = FALSE;

    /**
    * Process the current request
    *
    * $request - The current request parameters. Leave as NULL to default to use $_REQUEST.
    */
    public static function process( $request = NULL )
    {
        // Setup request variable
        HybridAuth_Endpoint::$request = $request;

        if ( is_null(HybridAuth_Endpoint::$request) ){
            // Fix a strange behavior when some provider call back ha endpoint
            // with /index.php?hauth.done={provider}?{args}...
            // >here we need to recreate the $_REQUEST
            if ( strrpos( $_SERVER["QUERY_STRING"], '?' ) ) {
                $_SERVER["QUERY_STRING"] = str_replace( "?", "&", $_SERVER["QUERY_STRING"] );

                parse_str( $_SERVER["QUERY_STRING"], $_REQUEST );
            }

            HybridAuth_Endpoint::$request = $_REQUEST;
        }

        // If openid_policy requested, we return our policy document
        if ( isset( HybridAuth_Endpoint::$request["get"] ) && HybridAuth_Endpoint::$request["get"] == "openid_policy" ) {
            HybridAuth_Endpoint::processOpenidPolicy();
        }

        // If openid_xrds requested, we return our XRDS document
        if ( isset( HybridAuth_Endpoint::$request["get"] ) && HybridAuth_Endpoint::$request["get"] == "openid_xrds" ) {
            HybridAuth_Endpoint::processOpenidXRDS();
        }

        // If we get a hauth.start
        if ( isset( HybridAuth_Endpoint::$request["hauth_start"] ) && HybridAuth_Endpoint::$request["hauth_start"] ) {
            HybridAuth_Endpoint::processAuthStart();
        }
        // Else if hauth.done
        elseif ( isset( HybridAuth_Endpoint::$request["hauth_done"] ) && HybridAuth_Endpoint::$request["hauth_done"] ) {
            HybridAuth_Endpoint::processAuthDone();
        }
        // Else we advertise our XRDS document, something supposed to be done from the Realm URL page
        else {
            HybridAuth_Endpoint::processOpenidRealm();
        }
    }

    /**
    * Process OpenID policy request
    */
    public static function processOpenidPolicy()
    {
        $output = file_get_contents( dirname(__FILE__) . "/resources/openid_policy.html" );
        print $output;
        die();
    }

    /**
    * Process OpenID XRDS request
    */
    public static function processOpenidXRDS()
    {
        header("Content-Type: application/xrds+xml");

        $output = str_replace
        (
            "{RETURN_TO_URL}",
            str_replace(
                array("<", ">", "\"", "'", "&"), array("&lt;", "&gt;", "&quot;", "&apos;", "&amp;"),
                HybridAuth_Auth::getCurrentUrl( false )
            ),
            file_get_contents( dirname(__FILE__) . "/resources/openid_xrds.xml" )
        );
        print $output;
        die();
    }

    /**
    * Process OpenID realm request
    */
    public static function processOpenidRealm()
    {
        $output = str_replace
        (
            "{X_XRDS_LOCATION}",
            htmlentities( HybridAuth_Auth::getCurrentUrl( false ), ENT_QUOTES, 'UTF-8' ) . "?get=openid_xrds&v=" . HybridAuth_Auth::$version,
            file_get_contents( dirname(__FILE__) . "/resources/openid_realm.html" )
        );
        print $output;
        die();
    }

    /**
    * define:endpoint step 3.
    */
    public static function processAuthStart()
    {
        HybridAuth_Endpoint::authInit();

        $provider_id = trim( strip_tags( HybridAuth_Endpoint::$request["hauth_start"] ) );

        # check if page accessed directly
        if( ! HybridAuth_Auth::storage()->get( "hauth_session.$provider_id.hauth_endpoint" ) ) {
            HybridAuth_Logger::error( "Endpoint: hauth_endpoint parameter is not defined on hauth_start, halt login process!" );

            header( "HTTP/1.0 404 Not Found" );
            die( "You cannot access this page directly." );
        }

        # define:hybrid.endpoint.php step 2.
        $hauth = HybridAuth_Auth::setup( $provider_id );

        # if REQUESTed hauth_idprovider is wrong, session not created, etc.
        if( ! $hauth ) {
            HybridAuth_Logger::error( "Endpoint: Invalide parameter on hauth_start!" );

            header( "HTTP/1.0 404 Not Found" );
            die( "Invalide parameter! Please return to the login page and try again." );
        }

        try {
            HybridAuth_Logger::info( "Endpoint: call adapter [{$provider_id}] loginBegin()" );

            $hauth->adapter->loginBegin();
        }
        catch ( Exception $e ) {
            HybridAuth_Logger::error( "Exception:" . $e->getMessage(), $e );
            HybridAuth_Error::setError( $e->getMessage(), $e->getCode(), $e->getTraceAsString(), $e );

            $hauth->returnToCallbackUrl();
        }

        die();
    }

    /**
    * define:endpoint step 3.1 and 3.2
    */
    public static function processAuthDone()
    {
        HybridAuth_Endpoint::authInit();

        $provider_id = trim( strip_tags( HybridAuth_Endpoint::$request["hauth_done"] ) );

        $hauth = HybridAuth_Auth::setup( $provider_id );

        if( ! $hauth ) {
            HybridAuth_Logger::error( "Endpoint: Invalide parameter on hauth_done!" );

            $hauth->adapter->setUserUnconnected();

            header("HTTP/1.0 404 Not Found");
            die( "Invalide parameter! Please return to the login page and try again." );
        }

        try {
            HybridAuth_Logger::info( "Endpoint: call adapter [{$provider_id}] loginFinish() " );

            $hauth->adapter->loginFinish();
        }
        catch( Exception $e ){
            HybridAuth_Logger::error( "Exception:" . $e->getMessage(), $e );
            HybridAuth_Error::setError( $e->getMessage(), $e->getCode(), $e->getTraceAsString(), $e );

            $hauth->adapter->setUserUnconnected();
        }

        HybridAuth_Logger::info( "Endpoint: job done. retrun to callback url." );

        $hauth->returnToCallbackUrl();
        die();
    }

    public static function authInit()
    {
        if ( ! HybridAuth_Endpoint::$initDone) {
            HybridAuth_Endpoint::$initDone = TRUE;

            # Init HybridAuth_Auth
            try {
                require_once realpath( dirname( __FILE__ ) )  . "/Storage.php";

                $storage = new HybridAuth_Storage();

                // Check if HybridAuth_Auth session already exist
                if ( ! $storage->config( "CONFIG" ) ) {
                    header( "HTTP/1.0 404 Not Found" );
                    die( "You cannot access this page directly." );
                }

                HybridAuth_Auth::initialize( $storage->config( "CONFIG" ) );
            }
            catch ( Exception $e ){
                HybridAuth_Logger::error( "Endpoint: Error while trying to init HybridAuth_Auth" );

                header( "HTTP/1.0 404 Not Found" );
                die( "Oophs. Error!" );
            }
        }
    }
}
