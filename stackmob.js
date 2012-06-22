/*
 Copyright 2012 StackMob Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

(function() {
  var root = this;

  /**
   * This is a utility method to read cookies.  Since we aren't guaranteed to have jQuery or other libraries, a cookie reader is bundled here.
   */
  function readCookie(name) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for ( var i = 0; i < ca.length; i++) {
      var c = ca[i];
      while (c.charAt(0) == ' ')
        c = c.substring(1, c.length);
      if (c.indexOf(nameEQ) == 0)
        return c.substring(nameEQ.length, c.length);
    }
    return null;
  }

  /**
   * Convenience method to get the StackMob session cookie value.
   */
  function getSessionCookieValue() {
    return readCookie(StackMob.loggedInCookie);
  }


  /**
   * The StackMob object is the core of the JS SDK.  It holds static variables, methods, and configuration information.
   * 
   * It is the only variable introduced globally. 
   */
  window.StackMob = root.StackMob = {

    //Default API Version.  Set to 0 for your Development API.  Production APIs are 1, 2, 3+
    DEFAULT_API_VERSION : 0,

    /**
     * StackMob provides an authentication capabilities out of the box.  When you create your StackMob account, a default User schema `user` is created for you.  The primary key field is what's used for login.  The default primary key is `username`, and the default password field is `password`.  
     */
    DEFAULT_LOGIN_SCHEMA : 'user',
    DEFAULT_LOGIN_FIELD : 'username',
    DEFAULT_PASSWORD_FIELD : 'password',

    //Radians are defined for use with the geospatial methods.
    EARTH_RADIANS_MI : 3956.6,
    EARTH_RADIANS_KM : 6367.5,

    //Backbone.js will think you're updating an object if you provide an ID.  This flag is used internally in the JS SDK to force a POST rather than a PUT if you provide an object ID.
    FORCE_CREATE_REQUEST : 'stackmob_force_create_request',
    
    //These constants are used internally in the JS SDK to help with queries involving arrays.
    ARRAY_FIELDNAME : 'stackmob_array_fieldname',
    ARRAY_VALUES : 'stackmob_array_values',
    
    //This flag is used internally in the JS SDK to help with deletion of objects in relationships.
    CASCADE_DELETE : 'stackmob_cascade_delete',
    
    //These constants are intended for public use to help with deletion of objects in relationships.
    HARD_DELETE : true,
    SOFT_DELETE : false,

    //This specifies the server-side API this instance of the JS SDK should point to.  It's set to the Development environment (0) by default.  This should be over-ridden when the user initializes their StackMob instance. 
    apiVersion : 0,
    
    //The current version of the JS SDK.
    sdkVersion : "0.5.0",

    //This holds the application public key when the JS SDK is initialized to connect to StackMob's services via OAuth 2.0.
    publicKey : null,

    //Internal variables to hold some simple information about the currently logged in user.  The cookie is used in non-OAuth 2.0 login mode.
    loggedInCookie : null,
    loggedInUser : null,

    /**
     * The Storage object lives within the StackMob object and provides an abstraction layer for client storage.  It's intended for internal use within the JS SDK.  The JS SDK is currently using HTML5's Local Storage feature to persist key/value items.
     * 
     * Though the JS SDK uses some cookies at the moment, it will be phased out in the near future as the JS SDK moves fully to OAuth 2.0.
     */
    Storage : {
      
      //Since the underlying client side storage implementation may not be name-spaced, we'll prefix our saved keys with `STORAGE_PREFIX`.
      STORAGE_PREFIX : 'stackmob.',

      //Use this to save things to local storage as a key/value pair.
      persist : function(key, value) {
        //If there's an HTML5 implementation of Local Storage available, then use it.  Otherwise, there's no fallback at this point in time.
        if (localStorage)
          localStorage.setItem(this.STORAGE_PREFIX + key, value);
      },
      
      //Read a value from local storage given the `key`.
      retrieve : function(key) {
        if (localStorage)
          return localStorage.getItem(this.STORAGE_PREFIX + key);
        else
          null;
      },
      
      //Remove a value from local storage given the `key`.
      remove : function(key) {
        if (localStorage)
          localStorage.removeItem(this.STORAGE_PREFIX + key);
      }
    },

    //This returns the current logged in user's login id: username, email (whatever is defined as the primary key).
    getLoggedInUser : function() {
      
      var storedUser = ((!this.isOAuth2Mode() && this.Storage
          .retrieve(this.loggedInUserKey)) || this.Storage.retrieve('oauth2_user'));
      //The logged in user's ID is saved in local storage until removed, so we need to check to make sure that the user has valid login credentials before returning the login ID.
      return (this.isLoggedIn() && storedUser) ? storedUser : null;
    },
    
    /** 
     * We'll return true or false depending on if the user has a valid login cookie (non-OAuth 2.0 implementation) or valid OAuth 2.0 credentials.
     * 
     * This is a "dumb" method in that this simply checks for the presence of login credentials, not if they're valid.  The server checks the validity of the credentials on each API request, however.  It's here for convenience.
     * 
     */
    isLoggedIn : function() {
      return (getSessionCookieValue() != null && !this.isLoggedOut())
          || this.hasValidOAuth();
    },
    
    //A convenience method to see if the given `username` is that of the logged in user.
    isUserLoggedIn : function(username) {
      return username == this.getLoggedInUser();
    },
    
    /**
     * Checks to see if a user is logged out (doesn't have login credentials)
     */
    isLoggedOut : function() {
      
      //If we're in OAuth 2.0 mode, then they're logged out if they don't have valid OAuth 2.0 credentials.
      if (this.isOAuth2Mode())
        return !this.hasValidOAuth();

      //If we're in non OAuth 2.0 mode, being logged in is indicated by the presence of a logged in cookie.
      var cookieValue = getSessionCookieValue();

      //If we don't have a cookie, then we must be logged out.
      if (!cookieValue)
        return true;

      //If we have a cookie value that's JSON, that means it's unencrypted and hence is logged out.  (There may be a cookie even if they're logged out.)
      try {
        return JSON.parse(cookieValue);
      } catch (err) {
        return false;
      }
    },
    
    //An internally used method to get the scheme to use for API requests.
    getScheme : function() {
      return this.secure === true ? 'https' : 'http';
    },
    
    //An internally used method to get the development API URL.
    getDevAPIBase : function() {
      
      //If you've requested a full URL path, then we'll use a full path.  Otherwise we'll use a relative path.
      //A full path is particularly useful for PhoneGap implementations where the app isn't running on a StackMob server.
      //Note that the JS SDK currently doesn't support the full path for custom domains yet.
      return this.fullURL === true ? this.getScheme() + '://dev.'
          + this.appName + '.' + this.clientSubdomain
          + '.stackmobapp.com/' : '/';
    },
    
    //An internally used method to get the production API URL.    
    getProdAPIBase : function() {
      return this.fullURL === true ? this.getScheme() + '://'
          + this.appName + '.' + this.clientSubdomain
          + '.stackmobapp.com/' : '/';
    },
    
    //This is an internally used method to get the API URL no matter what the context - development, production, etc.  This envelopes `getDevAPIBase` and `getProdAPIBase` in that this method is smart enough to choose which of the URLs to use.
    getBaseURL : function() {
      /*
       * `apiURL` serves as a way to override the API URL regardless of any other setting.
       *
       * FIXME: when not using a full url, it should probably be relative path, not what's currently in the window. 
       */
      return StackMob['apiURL'] || 
          (StackMob['fullURL'] === true ? 
              (StackMob['apiVersion'] === 0 ? StackMob
                  .getDevAPIBase()
                  : StackMob.getProdAPIBase())
              : (window.location.protocol + '//'
                  + window.location.hostname + ':'
                  + window.location.port) + '/');
    },
    
    //The JS SDK calls this to throw an error.
    throwError : function(msg) {
      throw new Error(msg);
      logger.debug(requestHeaders);
    },
    
    //The JS SDK calls this specifically when there's a URL error.
    urlError : function() {
      this.throwError('A "url" property or function must be specified');
    },
    
    //Some methods are OAuth 2.0 only.  This is used internally in the JS SDK to throw an error if a public key is required in initialization.
    requirePublicKey : function() {
      if (!StackMob.publicKey)
        this.throwError("Error: This requires that you initialize StackMob with a public key.");
    },
    
    //Checks to see if the JS SDK is in OAuth 2.0 mode or not.
    isOAuth2Mode : function() {
      return !isNaN(StackMob['publicKey'] && !StackMob['privateKey']);
    },
    
    prepareCredsForSaving: function(accessToken, macKey, expires, user) {
      //For convenience, the JS SDK will save the expiration date of these credentials locally so that the developer can check for it if need be.
        var unvalidated_expiretime = (new Date()).getTime()
            + (expires * 1000);  
        return {
          'oauth2_accessToken' : accessToken,
          'oauth2_macKey' : macKey,
          'oauth2_expires' : unvalidated_expiretime,
          'oauth2_user' : user
        };              
    },

    //Saves the OAuth 2.0 credentials (passed in as JSON) to client storage.
    saveOAuthCredentials : function(creds) {
      var accessToken = creds['oauth2_accessToken'];
      
      //Because the server sends back how long the credentials are valid for and not the expiration date, we construct the expiration date on the client side.  For the login scenario where we are using OAuth 2.0's redirect URL mechanism and where a user refreshes the logged-in redirected URL page, we don't want to incorrectly generate and save a new expiration date.  If the access token is the same, then leave the expiration date as is.
      //FIXME:  don't even pass in the expires value if we dont' intend to save it.  Move this logic out to handleOAuthCallback.  This check is happening too late down the line.      
      if (this.Storage.retrieve('oauth2_accessToken') != accessToken) {
        this.Storage.persist('oauth2_expires', creds['oauth2_expires']);
      }

      this.Storage.persist('oauth2_accessToken', accessToken);
      this.Storage.persist('oauth2_macKey', creds['oauth2_macKey']);
      this.Storage.persist('oauth2_user', creds['oauth2_user']);
    },

    //StackMob validates OAuth 2.0 credentials upon each request and will send back a error message if the credentials have expired.  To save the trip, developers can check to see if their user has valid OAuth 2.0 credentials that indicate the user is logged in.
    hasValidOAuth : function() {
      //If we aren't running in OAuth 2.0 mode, then kick out early.
      if (!this.isOAuth2Mode())
        return false;
        
      //Check to see if we have all the necessary OAuth 2.0 credentials locally AND if the credentials have expired.
      var creds = this.getOAuthCredentials();
      var expires = creds['oauth2_expires'] || 0;
      return _.all([ creds['oauth2_accessToken'], creds['oauth2_macKey'],
          expires ], _.identity)
          && //if no accesstoken, mackey, or expires..
          (new Date()).getTime() <= expires; //if the current time is past the expired time.
    },

    //Retrieve the OAuth 2.0 credentials from client storage.
    getOAuthCredentials : function() {
      var oauth_accessToken = StackMob.Storage
          .retrieve('oauth2_accessToken');
      var oauth_macKey = StackMob.Storage.retrieve('oauth2_macKey');
      var oauth_expires = StackMob.Storage.retrieve('oauth2_expires');
      return {
        'oauth2_accessToken' : oauth_accessToken,
        'oauth2_macKey' : oauth_macKey,
        'oauth2_expires' : oauth_expires
      };
    },
    
    //Returns the date (in milliseconds) for when the current user's OAuth 2.0 credentials expire.
    getOAuthExpireTime : function() {
      var expires = this.Storage.retrieve('oauth2_expires');
      return expires ? parseInt(expires) : null;
    },
    
    //This is an internally used map that works with Backbone.js.  It maps methods to HTTP Verbs used when making ajax calls.
    METHOD_MAP : {
      "create" : "POST",
      "read" : "GET",
      "update" : "PUT",
      "delete" : "DELETE",

      "addRelationship" : "POST",
      "appendAndSave" : "PUT",
      "deleteAndSave" : "DELETE",

      "login" : "GET",
      "accessToken" : "POST",
      "logout" : "GET",
      "forgotPassword" : "POST",
      "loginWithTempAndSetNewPassword" : "GET",
      "resetPassword" : "POST",

      "loginWithFacebookToken" : "GET",
      "createUserWithFacebook" : "GET",
      "linkUserWithFacebook" : "GET",

      "cc" : "GET"
    },

    /**
     * Convenience method to retrieve the value of a key in an object.  If it's a function, give its return value.
     */
    getProperty : function(object, prop) {
      if (!(object && object[prop]))
        return null;
      return _.isFunction(object[prop]) ? object[prop]() : object[prop];
    },
    
    /**
     * Externally called by user to initialize their StackMob config.
     */
    init : function(options) {
      options = options || {};

      //Run stuff before StackMob is initialized.
      this.initStart(options);
      

      this.userSchema = options['userSchema']
          || this.DEFAULT_LOGIN_SCHEMA;
      this.loginField = options['loginField'] || this.DEFAULT_LOGIN_FIELD;
      this.passwordField = options['passwordField']
          || this.DEFAULT_PASSWORD_FIELD;
      this.newPasswordField = options['newPasswordField']
          || 'new_password';

      this.apiVersion = options['apiVersion'] || this.DEFAULT_API_VERSION;
      this.appName = this.getProperty(options, "appName")
          || this.throwError("An appName must be specified");
      this.clientSubdomain = this.getProperty(options, "clientSubdomain");
      this.loggedInCookie = 'session_' + this.appName;
      this.loggedInUserKey = this.loggedInCookie + '_user';

      this.publicKey = options['publicKey'];
      this.apiURL = options['apiURL'];

      if (this.isOAuth2Mode()
          && (!root.Crypto || isNaN(root.Crypto && root.Crypto.HMAC))) {
        var script = document.createElement('script');
        script
            .setAttribute('src',
                'https://s3.amazonaws.com/static.stackmob.com/js/2.5.3-crypto-sha1-hmac.js');
        script.setAttribute('type', 'text/javascript');
        var loaded = false;
        var loadFunction = function() {
          if (loaded)
            return;
          loaded = true;
        };
        script.onload = loadFunction;
        script.onreadystatechange = loadFunction;

        var headID = document.getElementsByTagName("head")[0];
        headID.appendChild(script);
      }
      
      this.oauth2targetdomain = options['oauth2targetdomain'] || this.oauth2targetdomain || 'www.stackmob.com';

      this.secure = options['secure'] === true;
      this.fullURL = options['fullURL'] === true || options['phonegap'] === true || this.fullURL;
      this.ajax = options['ajax'] || this.ajax;
      this.debug = this.apiVersion === 0;
      
      this.urlRoot = options['urlRoot'] || this.getBaseURL();

      this.initEnd(options);
      //placeholder for any actions a developer may want to implement via _extend

      return this;
    },
    initStart : function(options) {
    },
    initEnd : function(options) {
    }
  };
}).call(this);

/**
 * StackMob JS SDK
 * BackBone.js-based
 * Backbone.js Version 0.9.2
 * No OAuth - for use with StackMob's HTML5 Product
 */
(function() {
  var root = this;

  var $ = root.jQuery || root.Ext || root.Zepto;

  function createBaseString(ts, nonce, method, uri, host, port) {
    var nl = '\u000A';
    return ts + nl + nonce + nl + method + nl + uri + nl + host + nl + port
        + nl + nl;
  }

  function bin2String(array) {
    var result = "";
    for ( var i = 0; i < array.length; i++) {
      result += String.fromCharCode(array[i]);
    }
    return result;
  }

  function generateMAC(method, id, key, hostWithPort, url) {
    var splitHost = hostWithPort.split(':');
    var hostNoPort = splitHost.length > 1 ? splitHost[0] : hostWithPort;
    var port = splitHost.length > 1 ? splitHost[1] : 80;

    var ts = Math.round(new Date().getTime() / 1000);
    var nonce = "n" + Math.round(Math.random() * 10000);

    var base = createBaseString(ts, nonce, method, url, hostNoPort, port);

    var bstring = bin2String(Crypto.HMAC(Crypto.SHA1, base, key, {
      asBytes : true
    }));
    var mac = btoa(bstring);
    return 'MAC id="' + id + '",ts="' + ts + '",nonce="' + nonce
        + '",mac="' + mac + '"';
  }

  _
      .extend(
          StackMob,
          {

            isSencha : function() {
              return root.Ext;
            },
            isZepto : function() {
              return root.Zepto;
            },
            initEnd : function(options) {
              createStackMobModel();
              createStackMobCollection();
              createStackMobUserModel();
            },
            cc : function(method, params, options) {
              this.customcode(method, params, options);
            },
            customcode : function(method, params, options) {
              options = options || {};
              options['data'] = options['data'] || {};
              _.extend(options['data'], params);
              options['url'] = this.debug ? this.getDevAPIBase()
                  : this.getProdAPIBase();
              this.sync.call(StackMob, method, null, options);
            },
            sync : function(method, model, options) {
              options = options || {};
              //Override to allow 'Model#save' to force create even if the id (primary key) is set in the model and hence !isNew() in BackBone
              var forceCreateRequest = options[StackMob.FORCE_CREATE_REQUEST] === true
              if (forceCreateRequest) {
                method = 'create';
              }

              function _prepareBaseURL(model, params) {
                //User didn't override the URL so use the one defined in the model
                if (!params['url']) {
                  if (model)
                    params['url'] = StackMob.getProperty(
                        model, "url");
                }

                var notCustomCode = method != 'cc';
                var notNewModel = (model && model.isNew && !model
                    .isNew());
                var notForcedCreateRequest = !forceCreateRequest;
                var isArrayMethod = (method == 'addRelationship'
                    || method == 'appendAndSave' || method == 'deleteAndSave');

                if (_isExtraMethodVerb(method)) {//Extra Method Verb? Add it to the model url. (e.g. /user/login)
                  var endpoint = method;

                  params['url'] += (params['url']
                      .charAt(params['url'].length - 1) == '/' ? ''
                      : '/')
                      + endpoint;
                } else if (isArrayMethod || notCustomCode
                    && notNewModel
                    && notForcedCreateRequest) {//append ID in URL if necessary
                  params['url'] += (params['url']
                      .charAt(params['url'].length - 1) == '/' ? ''
                      : '/')
                      + encodeURIComponent(model
                          .get(model
                              .getPrimaryKeyField()));

                  if (isArrayMethod) {
                    params['url'] += '/'
                        + options[StackMob.ARRAY_FIELDNAME];
                  }

                  if (method == 'deleteAndSave') {
                    var ids = '';

                    if (_
                        .isArray(options[StackMob.ARRAY_VALUES])) {
                      ids = _
                          .map(
                              options[StackMob.ARRAY_VALUES],
                              function(id) {
                                return encodeURIComponent(id);
                              }).join(',');
                    } else {
                      ids = encodeURIComponent(options[StackMob.ARRAY_VALUES]);
                    }

                    params['url'] += '/' + ids
                  }
                }

              }

              function _prepareHeaders(params, options) {
                //Prepare Request Headers
                params['headers'] = params['headers'] || {};

                //Add API Version Number to Request Headers

                //let users overwrite this if they know what they're doing
                params['headers'] = _
                    .extend(
                        {
                          "Accept" : 'application/vnd.stackmob+json; version='
                              + StackMob['apiVersion']
                        }, params['headers']);

                //dont' let users overwrite the stackmob headers though..
                _.extend(params['headers'], {
                  "X-StackMob-User-Agent" : "StackMob (JS; "
                      + StackMob['sdkVersion'] + ")/"
                      + StackMob['appName']
                });

                if (StackMob['publicKey']
                    && !StackMob['privateKey']) {
                  params['headers']['X-StackMob-API-Key'] = StackMob['publicKey'];
                  params['headers']['X-StackMob-Proxy-Plain'] = 'stackmob-api';
                } else {
                  params['headers']['X-StackMob-Proxy'] = 'stackmob-api';
                }

                //let users overwrite this if they know what they're doing
                if (StackMob.isOAuth2Mode() && method === 'accessToken') {
                  params['contentType'] = 'application/x-www-form-urlencoded';
                } else if (_.include([ 'PUT', 'POST' ],
                    StackMob.METHOD_MAP[method]))
                  params['contentType'] = params['contentType']
                      || 'application/json';

                if (!isNaN(options[StackMob.CASCADE_DELETE])) {
                  params['headers']['X-StackMob-CascadeDelete'] = options[StackMob.CASCADE_DELETE] == true;
                }

                //If this is an advanced query, check headers
                if (options['query']) {
                  //TODO throw error if no query object given
                  var queryObj = params['query']
                      || throwError("No StackMobQuery object provided to the query call.");

                  if (queryObj['selectFields']) {
                    if (queryObj['selectFields'].length > 0) {
                      params['headers']["X-StackMob-Select"] = queryObj['selectFields']
                          .join();
                    }
                  }

                  //Add Range Headers
                  if (queryObj['range']) {
                    params['headers']['Range'] = 'objects='
                        + queryObj['range']['start']
                        + '-'
                        + queryObj['range']['end'];
                  }

                  //Add Query Parameters to Parameter Map
                  _
                      .extend(params['data'],
                          queryObj['params']);

                  //Add OrderBy Headers
                  if (queryObj['orderBy']
                      && queryObj['orderBy'].length > 0) {
                    var orderList = queryObj['orderBy'];
                    var order = '';
                    var size = orderList.length;
                    for ( var i = 0; i < size; i++) {
                      order += orderList[i];
                      if (i + 1 < size)
                        order += ',';
                    }
                    params['headers']["X-StackMob-OrderBy"] = order;
                  }
                }
              }

              function _prepareRequestBody(method, params,
                  options) {
                options = options || {};
                
                function toParams(obj) {
                  var params = _.map(_.keys(obj), function(key) { 
                    return key + '=' + encodeURIComponent(obj[key]);
                  });
                  
                  return params.join('&');
                }

                //Set the reqeuest body
                if (StackMob.isOAuth2Mode() && method === 'accessToken' ) {
                  params['data'] = toParams(params['data']);
                } else if (params['type'] == 'POST'
                    || params['type'] == 'PUT') {
                  if (method == 'resetPassword'
                      || method == 'forgotPassword') {
                    params['data'] = JSON
                        .stringify(params['data']);
                  } else if (method == 'addRelationship'
                      || method == 'appendAndSave') {
                    if (options
                        && options[StackMob.ARRAY_VALUES])
                      params['data'] = JSON
                          .stringify(options[StackMob.ARRAY_VALUES]);
                  } else if (model) {
                    var json = model.toJSON();
                    delete json['lastmoddate'];
                    delete json['createddate'];
                    params['data'] = JSON.stringify(_
                        .extend(json, params['data']));
                  } else
                    params['data'] = JSON
                        .stringify(params.data);
                } else if (params['type'] == "GET") {
                  if (!_.isEmpty(params['data'])) {
                    params['url'] += '?';
                    var path = toParams(params['data']);
                    params['url'] += path;
                  }
                  delete params['data'];
                  //we shouldn't be passing anything up as data in a GET call
                } else {
                  delete params['data'];
                }
              }

              function _prepareAjaxClientParams(params) {
                params = params || {};
                //Prepare 3rd party ajax settings
                params['processData'] = false;
                //Put Accept into the header for jQuery
                params['accepts'] = params['headers']["Accept"];
              }

              function _prepareAuth(method, params) {
                if (model.schemaName == StackMob['userSchema'] && _
                    .include([ 'create', 'accessToken' ],
                        method)) {//if you're creating a user or logging in
                  return;
                  //then don't add an Authorization Header
                }

                var host = StackMob.getBaseURL();
                
                var path = params['url'].replace(new RegExp(
                    host, 'g'), '/');
                var sighost = host.replace(
                    new RegExp('^http://|^https://', 'g'),
                    '').replace(new RegExp('/'), '');

                var accessToken = StackMob.Storage
                    .retrieve('oauth2_accessToken');
                var macKey = StackMob.Storage
                    .retrieve('oauth2_macKey');
                var expires = StackMob.Storage
                    .retrieve('oauth2_expires');

                if (StackMob.isOAuth2Mode() && accessToken
                    && macKey) {
                  var authHeaders = generateMAC(
                      StackMob.METHOD_MAP[method]
                          || 'GET', accessToken,
                      macKey, sighost, path);
                  if (authHeaders)
                    params['headers']['Authorization'] = authHeaders;
                }
              }

              function _isExtraMethodVerb(method) {
                return !_.include([ 'create', 'update',
                    'delete', 'read', 'query',
                    'deleteAndSave', 'appendAndSave',
                    'addRelationship' ], method);
              }

              //Determine what kind of call to make: GET, POST, PUT, DELETE
              var type = options['httpVerb'] || StackMob.METHOD_MAP[method] || 'GET';

              //Prepare query configuration
              var params = _.extend({
                type : type,
                dataType : 'json'
              }, options);

              params['data'] = params['data'] || {};

              _prepareBaseURL(model, params);
              _prepareHeaders(params, options);
              _prepareRequestBody(method, params, options);
              _prepareAjaxClientParams(params);
              _prepareAuth(method, params);

              StackMob.makeAPICall(model, params, method);
            },
            makeAPICall : function(model, params, method) {
              if (StackMob['ajax']) {
                return StackMob['ajax'](model, params, method);
              } else if (StackMob.isSencha()) {
                return StackMob['ajaxOptions']['sencha'](model,
                    params, method);
              } else if (StackMob.isZepto()) {
                return StackMob['ajaxOptions']['zepto'](model,
                    params, method);
              } else {
                return StackMob['ajaxOptions']['jquery'](model,
                    params, method);
              }
            }
          });
  //end of StackMob

  var createStackMobModel = function() {

    /**
     * Abstract Class representing a StackMob Model
     */
    StackMob.Model = Backbone.Model
        .extend({

          urlRoot : StackMob['urlRoot'],

          url : function() {
            var base = StackMob['urlRoot'] || StackMob.urlError();
            base += this.schemaName;
            return base;
          },
          getPrimaryKeyField : function() {
            return this.schemaName + '_id';
          },
          constructor : function() {
            this.setIDAttribute();
            //have to do this because I want to set this.id before this.set is called in default constructor
            Backbone.Model.prototype.constructor.apply(this,
                arguments);
          },
          initialize : function(attributes, options) {
            StackMob.getProperty(this, 'schemaName')
                || StackMob
                    .throwError('A schemaName must be defined');
            this.setIDAttribute();
          },
          setIDAttribute : function() {
            this.idAttribute = this.getPrimaryKeyField();
          },
          parse : function(data, xhr) {
            if (!data
                || (data && (!data['text'] || data['text'] == '')))
              return data;

            var attrs = JSON.parse(data['text']);

            return attrs;
          },
          sync : function(method, model, options) {
            StackMob.sync.call(this, method, this, options);
          },
          create : function(options) {
            var newOptions = {};
            newOptions[StackMob.FORCE_CREATE_REQUEST] = true;
            _.extend(newOptions, options)
            this.save(null, newOptions);
          },
          query : function(stackMobQuery, options) {
            options = options || {};
            _.extend(options, {
              query : stackMobQuery
            })
            this.fetch(options);
          },
          fetchExpanded : function(depth, options) {
            if (depth < 0 || depth > 3)
              StackMob
                  .throwError('Depth must be between 0 and 3 inclusive.');
            var newOptions = {};
            _.extend(newOptions, options);
            newOptions['data'] = newOptions['data'] || {};
            newOptions['data']['_expand'] = depth;

            this.fetch(newOptions);
          },
          getAsModel : function(fieldName, model) {
            var obj = this.get(fieldName);
            if (!obj)
              return {};
            else {
              if (_.isArray(obj)) {
                return _.map(obj, function(o) {
                  return new model(o);
                });
              } else {
                return new model(obj);
              }
            }
          },
          //Supporting from JS SDK V0.1.0
          appendAndCreate : function(fieldName, values, options) {
            this.addRelationship(fieldName, values, options);
          },
          addRelationship : function(fieldName, values, options) {
            options = options || {};
            options[StackMob.ARRAY_FIELDNAME] = fieldName;
            options[StackMob.ARRAY_VALUES] = values;
            StackMob.sync.call(this, 'addRelationship', this,
                options);
          },
          appendAndSave : function(fieldName, values, options) {
            options = options || {};
            options[StackMob.ARRAY_FIELDNAME] = fieldName;
            options[StackMob.ARRAY_VALUES] = values;
            StackMob.sync
                .call(this, 'appendAndSave', this, options);
          },
          deleteAndSave : function(fieldName, values, cascadeDelete,
              options) {
            options = options || {};
            options[StackMob.ARRAY_FIELDNAME] = fieldName;
            options[StackMob.ARRAY_VALUES] = values;
            options[StackMob.CASCADE_DELETE] = cascadeDelete;
            StackMob.sync
                .call(this, 'deleteAndSave', this, options);
          },
          setBinaryFile : function(fieldName, filename, filetype,
              base64EncodedData) {
            var binaryValueString = 'Content-Type: ' + filetype
                + '\n' + 'Content-Disposition: attachment; '
                + 'filename=' + filename + '\n'
                + 'Content-Transfer-Encoding: base64\n\n'
                + base64EncodedData;
            this.set(fieldName, binaryValueString);
          }

        });

  };
  var createStackMobCollection = function() {
    StackMob.Collection = Backbone.Collection
        .extend({
          initialize : function() {
            this.model
                || StackMob
                    .throwError('Please specify a StackMob.Model for this collection. e.g., var Items = StackMob.Collection.extend({ model: Item });');
            this.schemaName = (new this.model()).schemaName;
          },
          url : function() {
            var base = StackMob['urlRoot'] || StackMob.urlError();
            base += this.schemaName;
            return base;
          },

          parse : function(data, xhr) {
            if (!data
                || (data && (!data['text'] || data['text'] == '')))
              return data;

            var attrs = JSON.parse(data['text']);
            return attrs;
          },
          sync : function(method, model, options) {
            StackMob.sync.call(this, method, this, options);
          },
          query : function(stackMobQuery, options) {
            options = options || {};
            _.extend(options, {
              query : stackMobQuery
            })
            this.fetch(options);
          },
          create : function(model, options) {
            var newOptions = {};
            newOptions[StackMob.FORCE_CREATE_REQUEST] = true;
            _.extend(newOptions, options);
            Backbone.Collection.prototype.create.call(this, model,
                newOptions);
          },

          count : function(stackMobQuery, options) {
            stackMobQuery = stackMobQuery
                || new StackMob.Collection.Query();
            options = options || {};
            options.stackmob_count = true;
            var success = options.success;

            var successFunc = function(xhr) {
              if (xhr && xhr.getAllResponseHeaders) {
                var responseHeader = xhr
                    .getResponseHeader('Content-Range');
                var count = -1;
                if (responseHeader) {
                  count = responseHeader.substring(
                      responseHeader.indexOf('/') + 1,
                      responseHeader.length)
                }

                if (success) {
                  success(count);
                }
              } else success(xhr); //not actually xhr but actual value
            }

            options.success = successFunc;

            //check to see stackMobQuery is actually a StackMob.Collection.Query object before passing along
            if (stackMobQuery.setRange)
              options.query = (stackMobQuery).setRange(0, 0);
            return (this.sync || Backbone.sync).call(this, 'query',
                this, options)

          }
        });
  };
  var createStackMobUserModel = function() {
    /**
     * User object
     */
    StackMob.User = StackMob.Model
        .extend({

          idAttribute : StackMob['loginField'],

          schemaName : StackMob['userSchema'],

          getPrimaryKeyField : function() {
            return StackMob.loginField;
          },
          isLoggedIn : function() {
            return StackMob.isUserLoggedIn(this
                .get(StackMob['loginField']));
          },
          
          /**
           * Login method for non-OAuth 2.0.  
           * 
           * THIS WILL BE DEPRECATED IN FUTURE VERSIONS
           */
          login : function(keepLoggedIn, options) {
            options = options || {};
            var remember = isNaN(keepLoggedIn) ? false
                : keepLoggedIn;
            
            options['data'] = options['data'] || {};
            
            options['data'][StackMob.loginField] = this
                .get(StackMob.loginField);
            options['data'][StackMob.passwordField] = this
                .get(StackMob.passwordField);
            
            if (StackMob.isOAuth2Mode()) options['data']['token_type'] = 'mac';    
                
            var user = this;

            options['stackmob_onaccessToken'] = function(result) {
              if (StackMob.isOAuth2Mode()) {
                var oauth2Creds = result;
                
                var accessToken = oauth2Creds['access_token'];
                var macKey = oauth2Creds['mac_key'];
                var expires = oauth2Creds['expires_in'];
                
                var creds = StackMob.prepareCredsForSaving(accessToken, macKey, expires, user.get(StackMob.loginField));
  
                //...then let's save the OAuth credentials to local storage.
                StackMob.saveOAuthCredentials(creds);
              }
              
              StackMob.Storage.persist(StackMob.loggedInUserKey,
                    user.get(StackMob['loginField']));
            };

            (this.sync || Backbone.sync).call(this, (StackMob.isOAuth2Mode() ? 'accessToken' : 'login'), this,
                options);
          },
          logout : function(options) {
            options = options || {};
            options['data'] = options['data'] || {};
            options['stackmob_onlogout'] = function() {
              StackMob.Storage.remove(StackMob.loggedInUserKey);
              StackMob.Storage.remove('oauth2_accessToken');
              StackMob.Storage.remove('oauth2_macKey');
              StackMob.Storage.remove('oauth2_expires');
              StackMob.Storage.remove('oauth2_user');
            };

            (this.sync || Backbone.sync).call(this, "logout", this,
                options);
          },
          loginWithFacebookToken : function(facebookAccessToken,
              keepLoggedIn, options) {
            options = options || {};
            options['data'] = options['data'] || {};
            _.extend(options['data'], {
              "fb_at" : facebookAccessToken
            });

            (this.sync || Backbone.sync).call(this,
                "facebookLogin", this, options);
          },
          createUserWithFacebook : function(facebookAccessToken,
              options) {
            options = options || {};
            options['data'] = options['data'] || {};
            _.extend(options['data'], {
              "fb_at" : facebookAccessToken
            });

            options['data'][StackMob.loginField] = options[StackMob['loginField']]
                || this.get(StackMob['loginField']);

            (this.sync || Backbone.sync).call(this,
                "createUserWithFacebook", this, options);
          },
          //Use after a user has logged in with a regular user account and you want to add Facebook to their account
          linkUserWithFacebook : function(facebookAccessToken,
              options) {
            options = options || {};
            options['data'] = options['data'] || {};
            _.extend(options['data'], {
              "fb_at" : facebookAccessToken
            });

            (this.sync || Backbone.sync).call(this,
                "linkUserWithFacebook", this, options);
          },
          loginWithTempAndSetNewPassword : function(tempPassword,
              newPassword, keepLoggedIn, options) {
            options = options || {};
            options['data'] = options['data'] || {};
            var obj = {};
            obj[StackMob.passwordField] = oldPassword;
            this.set(obj);
            options['data'][StackMob.newPasswordField] = newPassword;
            this.login(keepLoggedIn, options);
          },
          forgotPassword : function(options) {
            options = options || {};
            options['data'] = options['data'] || {};
            options['data'][StackMob.loginField] = this
                .get(StackMob.loginField);
            (this.sync || Backbone.sync).call(this,
                "forgotPassword", this, options);
          },
          resetPassword : function(oldPassword, newPassword, options) {
            options = options || {};
            options['data'] = options['data'] || {};
            options['data']['old'] = {
              password : oldPassword
            };
            options['data']['new'] = {
              password : newPassword
            };
            (this.sync || Backbone.sync).call(this,
                "resetPassword", this, options);
          }
        });

    /**
     * Collection of users
     */
    StackMob.Users = StackMob.Collection.extend({
      model : StackMob.User
    });

    /*
     * Object to help users make StackMob Queries
     *
     * //Example query for users with age < 25, order by age ascending.  Return second set of 25 results.
     * var q = new StackMob.Query();
     * q.lt('age', 25).orderByAsc('age').setRange(25, 49);
     */

    StackMob.GeoPoint = function(lat, lon) {
      if (_.isNumber(lat)) {
        this.lat = lat;
        this.lon = lon;
      } else {
        this.lat = lat['lat'];
        this.lon = lat['lon'];
      }

    }

    StackMob.GeoPoint.prototype.toJSON = function() {
      return {
        lat : this.lat,
        lon : this.lon
      };
    }

    StackMob.Model.Query = function() {
      this.selectFields = [];
      this.params = {};
    }

    _.extend(StackMob.Model.Query.prototype, {
      select : function(key) {
        this.selectFields.push(key);
        return this;
      },
      setExpand : function(depth) {
        this.params['_expand'] = depth;
        return this;
      }
    })

    StackMob.Collection.Query = function() {
      this.params = {};
      this.orderBy = [];
      this.range = null;
    }

    StackMob.Collection.Query.prototype = new StackMob.Model.Query;
    StackMob.Collection.Query.prototype.constructor = StackMob.Collection.Query;

    //Give the StackMobQuery its methods
    _.extend(StackMob.Collection.Query.prototype, {
      addParam : function(key, value) {
        this.params[key] = value;
        return this;
      },
      equals : function(field, value) {
        this.params[field] = value;
        return this;
      },
      
      lt : function(field, value) {
        this.params[field + '[lt]'] = value;
        return this;
      },
      lte : function(field, value) {
        this.params[field + '[lte]'] = value;
        return this;
      },
      gt : function(field, value) {
        this.params[field + '[gt]'] = value;
        return this;
      },
      gte : function(field, value) {
        this.params[field + '[gte]'] = value;
        return this;
      },
      notEquals : function(field, value) {
        this.params[field + '[ne]'] = value;
        return this;
      },
      isNull : function(field) {
        this.params[field + '[null]'] = true;
        return this;
      },
      isNotNull : function(field) {
        this.params[field + '[null]'] = false;
        return this;
      },
      mustBeOneOf : function(field, value) {
        var inValue = '';
        if (_.isArray(value)) {
          var newValue = '';
          var size = value.length;
          for ( var i = 0; i < size; i++) {
            inValue += value[i];
            if (i + 1 < size)
              inValue += ',';
          }
        } else
          inValue = value;

        this.params[field + '[in]'] = inValue;
        return this;
      },
      orderAsc : function(field) {
        this.orderBy.push(field + ':asc');
        return this;
      },
      orderDesc : function(field) {
        this.orderBy.push(field + ':desc');
        return this;
      },
      
      
 
      
      setRange : function(start, end) {
        this.range = {
          'start' : start,
          'end' : end
        };
        return this;
      },
      mustBeNear : function(field, smGeoPoint, distance) {
        this.params[field + '[near]'] = smGeoPoint.lat + ','
            + smGeoPoint.lon + ',' + distance;
        return this;
      },
      mustBeNearMi : function(field, smGeoPoint, miles) {
        this.mustBeNear(field, smGeoPoint, miles
            / StackMob.EARTH_RADIANS_MI);
        return this;
      },
      mustBeNearKm : function(field, smGeoPoint, miles) {
        this.mustBeNear(field, smGeoPoint, miles
            / StackMob.EARTH_RADIANS_KM);
        return this;
      },
      isWithin : function(field, smGeoPoint, distance) {
        this.params[field + '[within]'] = smGeoPoint.lat + ','
            + smGeoPoint.lon + ',' + distance;
        return this;
      },
      isWithinMi : function(field, smGeoPoint, distance) {
        this.isWithin(field, smGeoPoint, distance
            / StackMob.EARTH_RADIANS_MI);
        return this;
      },
      isWithinKm : function(field, smGeoPoint, distance) {
        this.isWithin(field, smGeoPoint, distance
            / StackMob.EARTH_RADIANS_KM);
        return this;
      },
      isWithinBox : function(field, smGeoPoint1, smGeoPoint2) {
        this.params[field + '[within]'] = smGeoPoint1.lat + ','
            + smGeoPoint1.lon + ',' + smGeoPoint2.lat + ','
            + smGeoPoint2.lon;
        return this;
      }
    });
    //end extend StackMobQuery.prototype
  };
}).call(this);

(function() {
  var root = this;
  var $ = root.jQuery || root.Ext || root.Zepto;
  _.extend(StackMob,
      {
        ajaxOptions : {
          'sencha' : function(model, params, method) {
            var success = params['success'];
            var defaultSuccess = function(response, options) {
              
              var result = response && response.responseText ? JSON.parse(response.responseText) : null;

              if (_.isFunction(params['stackmob_on' + method]))
                params['stackmob_on' + method](result);

              if (result) {
                
                model.clear();

                if (StackMob.isOAuth2Mode() && method === 'accessToken' && result['stackmob']) {
                  //If we have "stackmob" in the response, that means we're getting stackmob data back.
                  //pass the user back to the user's success callback
                  result = result['stackmob']['user'];
                  success(result);  
                } else {
                  if (params["stackmob_count"] === true) {
                    success(response);
                  } else if (!model.set(result))
                    return false;
                  success(model);
                }
              } else
                success();

            };
            params['success'] = defaultSuccess;

            var error = params['error'];

            var defaultError = function(response, request) {
              var result = response.responseText ? JSON
                  .parse(response.responseText) : response;
              (function(m, d) {
                error(d);
              }).call(StackMob, model, result);
            }
            params['error'] = defaultError;

            var hash = {};
            hash['url'] = params['url'];
            hash['headers'] = params['headers'];
            hash['params'] = params['data'];
            hash['success'] = params['success'];
            hash['failure'] = params['error'];
            hash['disableCaching'] = false;
            hash['method'] = params['type'];

            return $.Ajax.request(hash);
          },
          'zepto' : function(model, params, method) {
            var success = params['success'];

            var defaultSuccess = function(response, result, xhr) {
              var result = response ? JSON.parse(response) : null;
              
              if (_.isFunction(params['stackmob_on' + method]))
                params['stackmob_on' + method](result);

              if (result) {
                model.clear();
                
                if (StackMob.isOAuth2Mode() && method === 'accessToken' && result['stackmob']) {
                  //If we have "stackmob" in the response, that means we're getting stackmob data back.
                  //pass the user back to the user's success callback
                  result = result['stackmob']['user'];
                  success(result);  
                } else {
                  //if we're not OAuth 2.0 login, just run the regular success.
                  if (params["stackmob_count"] === true) {
                    success(xhr);
                  } else if (!model.set(result))
                    return false;
                  success(model);
                }
                
              } else success();
                
                
                

            };
            params['success'] = defaultSuccess;

            var error = params['error'];

            var defaultError = function(response, request) {
              var result = response.responseText ? JSON
                  .parse(response.responseText) : response;
              (function(m, d) {
                error(d);
              }).call(StackMob, model, result);
            }
            params['error'] = defaultError;

            var hash = {};
            hash['url'] = params['url'];
            hash['headers'] = params['headers'];
            hash['type'] = params['type'];
            hash['data'] = params['data'];
            hash['success'] = defaultSuccess;
            hash['error'] = defaultError;

            return $.ajax(hash);
          },
          'jquery' : function(model, params, method) {
            params['beforeSend'] = function(jqXHR, settings) {
              jqXHR.setRequestHeader("Accept",
                  settings['accepts']);
              if (!_.isEmpty(settings['headers'])) {

                for (key in settings['headers']) {
                  jqXHR.setRequestHeader(key,
                      settings['headers'][key]);
                }
              }
            };
            
            var err = params['error'];

            params['error'] = function(jqXHR, textStatus,
                errorThrown) {

              var data;

              if (jqXHR && (jqXHR.responseText || jqXHR.text)) {
                var result = JSON.parse(jqXHR.responseText
                    || jqXHR.text);
                data = result;
              }

              (function(m, d) {
                if (err)
                  err(d);
              }).call(StackMob, model, data);
            }

            var success = params['success'];

            var defaultSuccess = function(model, status, xhr) {

              var result;
              if (model && model.toJSON) {
                result = model;
              } else if (model
                  && (model.responseText || model.text)) {
                var json = JSON.parse(model.responseText
                    || model.text);
                result = json;
              } else if (model) {
                result = model;
              }

              if (params["stackmob_count"] === true) {
                result = xhr;
              }

              /**
               * If there's an internal success callback function, execute it.
               */
              if (_.isFunction(params['stackmob_on' + method]))
                params['stackmob_on' + method](result);

              if (success) {
                /**
                 * In OAuth 2.0 mode, a successful login response will have the OAuth 2.0 credentials as well as the full user object in the response.
                 * But the user's success callback is only expecting the user, so let's deal with that here.
                 */
                if (StackMob.isOAuth2Mode() && method === 'accessToken' && result['stackmob']) {
                  //If we have "stackmob" in the response, that means we're getting stackmob data back.
                  //pass the user back to the user's success callback
                  result = result['stackmob']['user'];
                  success(result);  
                } else {
                  //if we're not OAuth 2.0 login, just run the regular success.
                  success(result);
                }
                
              }

            };
            
            params['success'] = defaultSuccess;

            
            return $.ajax(params);
          }
        }
      });
}).call(this);
