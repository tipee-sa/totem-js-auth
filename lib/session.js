/*jslint browser: true */
/*global define */

define(['srp', 'jquery', 'otp', 'cryptojs'], function (Srp, jQuery, Otp, CryptoJS) {
    'use strict';

    var /**
         *  Nom du scheme d'authentification HTTP à utiliser
         *
         *  @type {String}
         */
        auth_scheme = 'TIPI-TOKEN',

        /**
         *  Nom du stockage dans le localstorage pour les données de sessions
         *
         *  @type {String}
         */
        store_key = 'tipi_session',

        /**
         *  Temp entre les pings de session
         *
         *  @type {Number}
         */
        ping_interval_time = 60 * 1000, //  60 sec

        /**
         *  Instance de session. (Singleton)
         *
         *  @type {Object}
         */
        instance = null,

        /**
         *  Version de l'API à utiliser sur le serveur
         *  ~2 = 2.*.*
         *
         *  @type {String}
         */
        api_version = '~2',

        /**
         *  Objet de gestion de la session utilisateur. Singleton.
         *
         *  @type {Object}
         */
        session = {},

        /**
         *  Objet de configuration du module d'authentification Tipi.
         *
         *  @type {Object}
         */
        config = {};

    session.prototype = {
        /**
         *  Créer une requête de session.
         *
         *  @returns {jQuery.Deferred} Objet de promesse jQuery
         */
        make_request: function (add_clear) {
            var that = this;

            this.promise = this.promise || jQuery.Deferred();

            jQuery.ajax(
                config.tipi_url + 'session/login',
                {
                    type: 'POST',
                    data: this.getRequest(add_clear),
                    headers: {
                        'Accept-Version': api_version
                    }
                }
            ).done(
                this.getResponseHandler()
            ).fail(function (xhr) {
                var result = null;

                if (xhr.status === 422) {
                    result = JSON.parse(xhr.responseText);

                    if (result.error === 'partial_user' && result.clear === true) {
                        return that.make_request(true);
                    }
                } else if (xhr.status === 0 && xhr.statusText === 'error') {
                    that.promise.reject('no_con');
                } else if (xhr.status === 404) {
                    that.promise.reject('password');
                } else if (xhr.status === 403) {
                    result = JSON.parse(xhr.responseText);

                    if (result.error === 'partial_user_failure') {
                        that.promise.reject('password');
                    }
                }

                that.promise.reject('unknown');
            });

            return this.promise.promise();
        },

        /**
         *  Créer une objet de données pour la requête d'authentification.
         *
         *  @returns {object} Objet à poster lors de la requête.
         */
        getRequest: function (add_clear) {
            var request = {};

            this.srp = new Srp(this.username, this.password);

            request = {
                username: this.username,
                namespace: this.namespace,
                A: this.srp.getAString()
            };

            if (add_clear) {
                request.clear = this.password;
            }

            return request;
        },

        /**
         *  Créer un handler pour le retour de la requête d'authentification.
         *
         *  @return {function} Fonction de gestion de la réponse.
         */
        getResponseHandler: function () {
            var that = this,
                fn = function (data) {
                    if (data.sess_id !== undefined) {
                        this.session_success(data.sess_id, data.user_id, data.key);
                    } else if (data.B !== undefined && data.s !== undefined) {
                        this.srp.setB(data.B);
                        this.srp.sets(data.s);
                        this.validateKey();
                    } else {
                        this.promise.reject();
                        this.promise = null;
                    }
                };

            return function (data) {
                fn.apply(that, [data]);
            };
        },

        /**
         *  Valide la clef retournée par le serveur.
         */
        validateKey: function () {
            var that = this,
                M1 = "";

            try {
                M1 = this.srp.getM1String();
            } catch (e) {
                that.promise.reject();
            }

            jQuery.post(
                config.tipi_url + 'session/login',
                {
                    M1: M1,
                    password: this.password,
                }
            ).done(function (data) {
                if (data.M2 && data.M2 === that.srp.getM2String()) {
                    that.session_success(data.sess_id, data.user_id);
                } else {
                    that.promise.reject('password');
                }
            }).fail(function (jqXHR) {
                if (jqXHR.status === 400) {
                    that.promise.reject('password');
                }

                if (jqXHR.status === 404) {
                    that.promise.reject();
                }
            });
        },

        /**
         *  Valide la clef retournée par le serveur.
         */
        validatePasskeyAccess: function () {
            var that = this;

            that.promise = that.promise || jQuery.Deferred();

            jQuery.post(
                config.tipi_url + 'session/login',
                {
                    sessionId: that.authentificationSession,
                    authentificationData: that.authentificationData
                }
            ).done(function (data) {
                if (data.success) {
                    that.key = that.authentificationSession;
                    that.sess_id = data.sess_id;
                    that.user = data.user_id;

                    that.touch();
                    that.persist();
                    that.startPing();

                    that.promise.resolve();
                    that.promise = null;
                    that.authentificationSession = null;
                } else {
                    that.promise.reject('passkey');
                }
            }).fail(function (jqXHR) {
                if (jqXHR.status === 400) {
                    that.promise.reject('passkey');
                }

                if (jqXHR.status === 404) {
                    that.promise.reject();
                }
            });

            return that.promise.promise();
        },

        /**
         *  La session a été établie avec success.
         *
         *  @param {String} session Id de session attribué par le serveur.
         *  @param {String} id Id du user
         */
        session_success: function (session, id, key) {
            if (!key) {
                //  Récupère la clef et nettoye l'objet srp.
                this.key = this.srp.getK();
                delete this.srp;
            } else {
                this.key = key;
            }
            this.sess_id = session;
            this.user = id;
            this.password = null;

            this.touch();
            this.persist();
            this.startPing();

            this.promise.resolve();
            this.promise = null;
        },

        /**
         *  Écris la session dans le localStorage pour utilisation ultérieur.
         */
        persist: function () {
            localStorage.setItem(
                store_key,
                JSON.stringify({
                    user: this.user,
                    key: this.key,
                    sess_id: this.sess_id,
                    heartbeat: this.heartbeat
                })
            );
        },

        /**
         *  Création du générateur Otp
         *
         *  @returns {Otp}
         */
        getOtpGenerator: function () {
            if (!this.generator) {
                this.generator = Otp.create(this.key, config.tipi_url + 'time');
            }

            return this.generator || null;
        },

        /**
         *  Es-ce que la session est valide?
         *
         *  @returns {Boolean} Vrais ou faux.
         */
        isValid: function () {
            var valid = (this.heartbeat + config.timeout) > Math.floor((new Date()) / 1000);

            if (!valid || !this.sess_id) {
                this.destroy();
            }

            return valid;
        },

        /**
         *  Mise à jour du heartbeat de la session locale
         */
        touch: function () {
            this.heartbeat = Math.floor((new Date()) / 1000);
        },

        /**
         *  Démarre les pings de sessions sur le serveur
         *
         *  @see ping
         */
        startPing: function (immediate) {
            var that = this;

            if (immediate) {
                that.ping();
            }

            if (this.ping_interval) {
                window.clearInterval(this.ping_interval);
            }

            this.ping_interval = window.setInterval(function () {
                that.ping();
            }, ping_interval_time);
        },

        /**
         *  Génère un jetton d'authentification.
         *
         *  @param {Function} callback
         *  @returns {String} Jetton d'identification pour l'api.
         */
        getToken: function (callback) {
            var that = this;

            //  Pas de bras, pas de chocolat.
            if (!this.isValid() || !this.getOtpGenerator()) {
                return callback(null);
            }

            this.getOtpGenerator().getCode(false, function (code) {
                if (!that.isValid()) {
                    return callback(null);
                }

                var token = null;

                token = auth_scheme + ' sessid="';

                token += CryptoJS.enc.Base64.stringify(
                    CryptoJS.enc.Hex.parse(that.sess_id)
                );

                token += '", sign="';

                token += CryptoJS.enc.Base64.stringify(
                    CryptoJS.HmacSHA256(
                        that.sess_id,
                        code
                    )
                );

                token += '"';

                return callback(token);
            });
        },

        /**
         *  Génération d'un jeton de requête sur un sujet. Valable pour cette session entière.
         *  Utilisé pour les fichiers statiques
         *
         *  @param   {String} subject Sujet de la requête. (url)
         *
         *  @returns {String}         Jetton
         */
        getStaticToken: function (subject) {
            var token = null;

            // Enlève la partie du querystring.
            subject = subject.match(/.+\/\?|.+\?|.+/)[0].replace(/\/\?|\?/, '');

            token = CryptoJS.enc.Base64.stringify(
                CryptoJS.HmacSHA256(
                    window.encodeURI(subject),
                    this.key
                )
            );

            return token;
        },

        /**
         *  Ajout les informations d'identification à un objet de config jQuery.ajax.
         *
         *  jQuery.ajay(url, session.authentify({
         *      type: 'POST',
         *      data: {
         *          key: 'value'
         *      }
         *  }));
         *
         *  @param   {Object} options Options de la requête ajax
         *  @param   {Function} callback
         *
         *  @returns {Object}         Options avec les informations d'identification
         */
        authentify: function (options, callback) {
            this.getToken(function (token) {
                if (!token) {
                    return callback(null);
                }

                options = options || {};
                options.headers = options.headers || {};

                options.headers.Authorization = token;
                options.headers['Accept-Version'] = api_version;

                return callback(options);
            });
        },

        /**
         *  Ajout un jeton static sur une url
         *
         *  @param   {String} url
         *
         *  @returns {String}
         */
        authentifyUrl: function (url) {
            url += (url.indexOf('?') !== -1 ? '&' : '?') + jQuery.param({
                sessid: CryptoJS.enc.Base64.stringify(
                    CryptoJS.enc.Hex.parse(this.sess_id)
                ),
                token: this.getStaticToken(url)
            });

            return url;
        },

        /**
         *  "Ping" la session sur le serveur.
         *  Vérifie si elle est toujours valide et met à jour le timeout.
         *
         *  @param {Function} callback
         *
         *  @returns {[type]} [description]
         */
        ping: function (callback) {
            var that = this;

            this.authentify(
                {
                    type: 'POST',
                    data: {
                        timestamp: this.getOtpGenerator().getTime()
                    }
                },
                function (options) {
                    jQuery.ajax(
                        config.tipi_url + 'session/ping',
                        options
                    ).done(function (data) {
                        if (data.success) {
                            that.touch();
                            that.persist();
                        } else {
                            that.destroy();
                        }

                        if (callback) {
                            return callback();
                        }
                    }).fail(function (error) {
                        if (error.status === 404) {
                            that.destroy();
                        }

                        if (callback) {
                            return callback(error);
                        }
                    });
                }
            );
        },

        /**
         *  Déconnexion d'une session
         */
        logout: function () {
            this.authentify(
                {
                    type: 'POST'
                },
                function (options) {
                    jQuery.ajax(
                        config.tipi_url + 'session/logout',
                        options
                    );
                }
            );

            this.destroy();
        },

        /**
         *  Reset des valeurs de base de la session
         */
        reset: function () {
            this.user = null;
            this.key = null;
            this.sess_id = null;
            this.heartbeat = null;
            this.generator = null;
        },

        /**
         *  Détruit la session en cours.
         */
        destroy: function () {
            if (this.ping_interval) {
                window.clearInterval(this.ping_interval);
            }

            this.reset();

            if (config && config.logout_url) {
                jQuery.get(config.logout_url).done(function () {
                    window.location.reload();
                });
            }

            this.persist();
        },

        /**
         *  Initialise la session.
         *  Vérifie si un cookie existe déjà.
         */
        init: function (withPing) {
            var sess = JSON.parse(localStorage.getItem(store_key));

            if (sess) {
                this.user = sess.user || null;
                this.key = sess.key || null;
                this.sess_id = sess.sess_id || null;
                this.heartbeat = sess.heartbeat || null;
                this.generator = null;

                if (this.isValid()) {
                    this.startPing(undefined === withPing ? true : withPing);
                }
            }
        },

        /**
         *  Login d'un utilisateur pour créer une nouvelle session
         *
         *  @param   {String} username
         *  @param   {String} password
         *  @param   {String} @namespace Nom du namespace de l'application dans Tipi
         *
         *  @returns {jQuery.Deferred}          Promesse
         */
        login: function (username, password, namespace) {
            this.username = username || '';
            this.password = password || '';
            this.namespace = namespace || config.namespace;

            //  Simplification du user, évite les fautes de frappes, majuscules, espaces, ponctuation, etc.
            this.username = this.username.toLowerCase().replace(/[^a-zA-Z0-9]+/g, '');

            this.promise = null;
            this.reset();

            return this.make_request();
        },

        /**
         *  Login d'un utilisateur pour créer une nouvelle session en utilisant une clé d'accès
         *
         *  @param   {String} authentificationSession
         *  @param   {Object} authentificationData
         *
         *  @returns {jQuery.Deferred}          Promesse
         */
        loginPasskey: function (authentificationSession, authentificationData) {
            this.authentificationSession = authentificationSession;
            this.authentificationData = authentificationData;
            this.username = '';
            this.password = '';
            this.namespace = config.namespace;

            this.promise = null;
            this.reset();

            return this.validatePasskeyAccess();
        },

        /**
         *  Lecture des données de l'utilisateur
         *
         *  @param {String} namespace Nom du namespace voulu
         *  @returns {jQuery.Deferred} Objet de promesse jQuery
         */
        getUserData: function (namespace) {
            var promise = jQuery.Deferred();

            if (!namespace) {
                promise.reject(new Error('No namespace'));
                return promise.promise();
            }

            this.authentify({}, function (options) {
                jQuery.ajax(
                    config.tipi_url + 'users/data/' + namespace,
                    options
                ).done(function (data) {
                    promise.resolve(data);
                }).fail(function () {
                    promise.reject(new Error('Unable to get data'));
                });
            });

            return promise.promise();
        },

        /**
         *  Écriture des données utilisateur
         *
         *  @param {String} namespace Nom du namespace
         *  @param {Object} data      Données
         *  @returns {jQuery.Deferred} Objet de promesse jQuery
         */
        setUserData: function (namespace, data) {
            var promise = jQuery.Deferred();

            if (!namespace) {
                promise.reject(new Error('No namespace'));
                return promise.promise();
            }

            this.authentify({}, function (options) {
                options.data = JSON.stringify(data);
                options.contentType = 'application/json';
                options.type = 'PUT';

                jQuery.ajax(
                    config.tipi_url + 'users/data/' + namespace,
                    options
                ).done(function (data) {
                    promise.resolve(data);
                }).fail(function () {
                    promise.reject(new Error('Unable to set data'));
                });
            });

            return promise.promise();
        }
    };

    /**
     *  Création d'un nouvel objet de session pour le client.
     *
     *  @constructor
     */
    function create_session() {
        instance = Object.create(session.prototype, {
            user: {
                value: null,
                enumerable: false,
                writable: true
            },
            password: {
                value: null,
                enumerable: false,
                writable: true
            },
            sess_id: {
                value: null,
                enumerable: false,
                writable: true
            },
            generator: {
                value: null,
                enumerable: false,
                writable: true
            }
        });

        instance.init();

        return instance;
    }

    /**
     *  Défini la configuration du module d'authentification Tipi.
     *
     *  tipi_url:  URL de l'api Tipi.
     *  timeout:   Timeout en secondes avant déconnection.
     *  namespace: Namespace à utiliser pour la connection.
     *
     *  @param {Object} configuration
     */
    session.setConfig = function (configuration) {
        config = configuration;
    };

    /**
     *  Retourne l'instance de session.
     *
     *  @returns {Object} La session
     */
    session.getInstance = function (force) {
        if (force || instance === null) {
            instance = create_session();
        }

        return instance;
    };

    return session;
});
