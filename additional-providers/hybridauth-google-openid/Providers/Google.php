<?php
/*!
* HybridAuth
* http://hybridauth.sourceforge.net | http://github.com/hybridauth/hybridauth
* (c) 2009-2012, HybridAuth authors | http://hybridauth.sourceforge.net/licenses.html
*/

/**
 * HybridAuth_Providers_Google OpenID based
 *
 * Provided as a way to keep backward compatibility for Google OpenID based on HybridAuth <= 2.0.8
 *
 * http://hybridauth.sourceforge.net/userguide/IDProvider_info_Google.html
 */
class HybridAuth_Providers_Google extends HybridAuth_Provider_Model_OpenID
{
    var $openidIdentifier = "https://www.google.com/accounts/o8/id";

    /**
    * finish login step
    */
    function loginFinish()
    {
        parent::loginFinish();

        $this->user->profile->emailVerified = $this->user->profile->email;

        // restore the user profile
        HybridAuth_Auth::storage()->set( "hauth_session.{$this->providerId}.user", $this->user );
    }
}
