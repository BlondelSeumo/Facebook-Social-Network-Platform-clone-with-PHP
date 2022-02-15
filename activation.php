<?php

/**
 * activation
 * 
 * @package Sngine
 * @author Zamblek
 */

// fetch bootstrap
require('bootstrap.php');

// valid inputs
if (!isset($_GET['code'])) {
	_error(404);
}

// user access
if (!$user->_logged_in) {
	user_login();
}

try {

	// activation
	$user->activation_email($_GET['code']);
	redirect();
} catch (Exception $e) {
	_error(__("Error"), $e->getMessage());
}
