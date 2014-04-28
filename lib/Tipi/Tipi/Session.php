<?php

namespace Tipi\Tipi;

use Tipi\Tipi;

class Session {
	/**
	 *  Instance du singleton Session.
	 *
	 *  @var Tipi\Tipi\Session
	 */
	private static $instance = null;

	/**
	 *  Lecture de l'instance de Session
	 *
	 *  @return Tipi\Tipi\Session Instance du singleton
	 */
	public static function getInstance() {
		if (self::$instance === null) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 *  Constructeur privé. (Singleton)
	 */
	private function __construct() {}

	/**
	 *  Id de la session courante.
	 *
	 *  @var string
	 */
	private static $sessid = null;

	/**
	 *  Lecture du header Authorization.
	 *
	 *  @return string Token d'authentification complet.
	 */
	private function getAuthorization() {
		$auth = '';
		$headers = getallheaders();

		if (isset($headers['Authorization'])) {
			$auth = $headers['Authorization'];
		} else if (isset($headers['authorization'])) {
			$auth = $headers['authorization'];
		}

		return $auth;
	}

	/**
	 *  Défini un id de session.
	 *  Utilisé si l'id est dans la session PHP mais pas dans la requête utilisateur.
	 *
	 *  @param string $sessid Id de la session
	 *  @return Tipi\Tipi\Session $this
	 */
	public function setId($sessid) {
		self::$sessid = $sessid;

		return $this;
	}

	/**
	 *  Lecture de l'id de session pour la requête courante.
	 *
	 *  @param boolean $force_read Force la lecture dans le header HTTP
	 *  @return  string      ID de la session
	 */
	public function getId($force_read = false) {
		if ($force_read || self::$sessid === null) {
			preg_match(
				'/(?:sessid=")(?P<sessid>[a-z0-9\/+=\-]+)(?:")/i',
				$this->getAuthorization(),
				$token
			);

			if (!isset($token['sessid']) || empty($token['sessid'])) {
				return null;
			}

			self::$sessid = bin2hex(base64_decode($token['sessid']));
		}

		return self::$sessid;
	}

	/**
	 *  Vérifie si la session de l'utilisateur est bien active sur le serveur
	 *
	 *  @return boolean
	 */
	public function isValid() {
		$result = Tipi::getInstance()->makeRequest('session/ping', 'POST', array(
			'sess_id' => $this->getId(),
			'timestamp' => time()
		));

		$result = json_decode($result, true);

		return isset($result['success']) && $result['success'] === true;
	}
}