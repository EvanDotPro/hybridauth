<?php
/*!
* HybridAuth
* http://hybridauth.sourceforge.net | http://github.com/hybridauth/hybridauth
* (c) 2009-2012, HybridAuth authors | http://hybridauth.sourceforge.net/licenses.html
*/

/**
 * Errors manager
 *
 * HybridAuth errors are stored in Hybrid::storage() and not displayed directly to the end user
 */
class HybridAuth_Error
{
    /**
    * store error in session
    */
    public static function setError( $message, $code = NULL, $trace = NULL, $previous = NULL )
    {
        HybridAuth_Logger::info( "Enter HybridAuth_Error::setError( $message )" );

        HybridAuth_Auth::storage()->set( "hauth_session.error.status"  , 1         );
        HybridAuth_Auth::storage()->set( "hauth_session.error.message" , $message  );
        HybridAuth_Auth::storage()->set( "hauth_session.error.code"    , $code     );
        HybridAuth_Auth::storage()->set( "hauth_session.error.trace"   , $trace    );
        HybridAuth_Auth::storage()->set( "hauth_session.error.previous", $previous );
    }

    /**
    * clear the last error
    */
    public static function clearError()
    {
        HybridAuth_Logger::info( "Enter HybridAuth_Error::clearError()" );

        HybridAuth_Auth::storage()->delete( "hauth_session.error.status"   );
        HybridAuth_Auth::storage()->delete( "hauth_session.error.message"  );
        HybridAuth_Auth::storage()->delete( "hauth_session.error.code"     );
        HybridAuth_Auth::storage()->delete( "hauth_session.error.trace"    );
        HybridAuth_Auth::storage()->delete( "hauth_session.error.previous" );
    }

    /**
    * Checks to see if there is a an error.
    *
    * @return boolean True if there is an error.
    */
    public static function hasError()
    {
        return (bool) HybridAuth_Auth::storage()->get( "hauth_session.error.status" );
    }

    /**
    * return error message
    */
    public static function getErrorMessage()
    {
        return HybridAuth_Auth::storage()->get( "hauth_session.error.message" );
    }

    /**
    * return error code
    */
    public static function getErrorCode()
    {
        return HybridAuth_Auth::storage()->get( "hauth_session.error.code" );
    }

    /**
    * return string detailled error backtrace as string.
    */
    public static function getErrorTrace()
    {
        return HybridAuth_Auth::storage()->get( "hauth_session.error.trace" );
    }

    /**
    * @return string detailled error backtrace as string.
    */
    public static function getErrorPrevious()
    {
        return HybridAuth_Auth::storage()->get( "hauth_session.error.previous" );
    }
}
